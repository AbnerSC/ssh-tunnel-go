package proxy

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ssh-tunnel-go/internal/logging"
)

const (
	// relayBufSize 单向转发缓冲大小。SSH 通道单包上限 32KB，取 4 倍可减少
	// 读系统调用与写入调度次数；实测仍受对端通道窗口限制，此处只降低本地开销。
	relayBufSize = 128 * 1024
	// DefaultIdleTimeout 转发阶段双向静默的上限，超过即回收连接。
	//
	// 长连接在客户端休眠、切换网络或 NAT 表项超时后会变成「两端都不说话、
	// 也没有 FIN」的僵尸连接：Relay 的两个 goroutine 永久阻塞在 Read 上，
	// 连接名额、goroutine 与两向 relayBufSize 缓冲都不会释放（线上日志里
	// active 长期停在 90+ 而 downMB 十几小时几乎不增长就是这个现象）。
	// 走 SSH 时僵尸通道还会占住通道窗口，拖慢同一条会话上新通道的建立。
	// 30 分钟远大于常见协议的心跳间隔（TCP keepalive / WebSocket ping
	// 一般在 60s 内），不会误伤正常空闲连接；可用 IDLE_TIMEOUT 调整，0 表示不回收。
	DefaultIdleTimeout = 30 * time.Minute
	// idleCheckMin / idleCheckMax 空闲检查的扫描间隔上下限：
	// 太密会空转唤醒，太疏则回收不及时。
	idleCheckMin = time.Second
	idleCheckMax = 30 * time.Second
)

// idleTimeoutNanos 当前生效的空闲回收时限（纳秒），0 表示不回收。
// 用原子值而不是普通变量：SetIdleTimeout 可能在监听协程运行后被调用。
var idleTimeoutNanos atomic.Int64

func init() {
	idleTimeoutNanos.Store(int64(DefaultIdleTimeout))
}

// SetIdleTimeout 设置转发阶段的空闲回收时限；d <= 0 表示关闭空闲回收。
//
// 必须在启动监听之前调用，新连接在进入转发时读取一次当前值。
func SetIdleTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	idleTimeoutNanos.Store(int64(d))
}

// currentIdleTimeout 返回当前生效的空闲回收时限。
func currentIdleTimeout() time.Duration {
	return time.Duration(idleTimeoutNanos.Load())
}

// relayBufPool 复用单向转发缓冲。
//
// 原实现每连接每方向新分配 128KB：并发上升后 garbage 与常驻内存都按
// 连接数线性增长（GC 回收前还会叠加一倍峰值）。改为池化后，
// 稳定期的缓冲数量只与同时在转发的连接数相关。
var relayBufPool = sync.Pool{
	New: func() any { return make([]byte, relayBufSize) },
}

// getRelayBuf 取出一个满长缓冲；池内出现异常切片时退回新分配。
func getRelayBuf() []byte {
	if buf, ok := relayBufPool.Get().([]byte); ok && cap(buf) >= relayBufSize {
		return buf[:relayBufSize]
	}
	return make([]byte, relayBufSize)
}

// putRelayBuf 归还缓冲；过短的切片不入池，避免污染后续使用方。
func putRelayBuf(buf []byte) {
	if cap(buf) < relayBufSize {
		return
	}
	relayBufPool.Put(buf[:relayBufSize])
}

// Relay 在两条连接之间做双向转发。
//
// 参数约定：a 为客户端连接，b 为目标连接；据此区分上行/下行字节统计。
// 正常 EOF 时只做半关闭（CloseWrite），保留反向数据通道——上传结束不代表下载结束；
// 出错时双向关闭，避免对端 goroutine 永久阻塞。
// 双向静默超过空闲时限时由看门狗主动关闭，回收僵尸连接（见 DefaultIdleTimeout）。
func Relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	// lastActive 最近一次成功转发数据的时刻（纳秒），供空闲看门狗判定僵尸连接。
	// 读或写任一侧有进展都算活动：单向大流量（如下载挂起）期间另一方向静默属正常。
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())

	pipe := func(dst, src net.Conn, counter *atomic.Int64, done chan<- struct{}) {
		defer func() { done <- struct{}{} }()
		// 不用 io.Copy：其内部缓冲固定 32KB，且目标为 *net.TCPConn 时会走
		// ReadFrom 而忽略自定义缓冲，导致包装后的 SSH 通道侧始终是小块读写。
		// 缓冲从池中取，结束时归还；Write 为同步调用，返回后不会再引用该切片。
		buf := getRelayBuf()
		defer putRelayBuf(buf)
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				counter.Add(int64(n))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					closeBoth()
					return
				}
				lastActive.Store(time.Now().UnixNano())
			}
			if rerr != nil {
				if rerr != io.EOF {
					closeBoth()
					return
				}
				break
			}
		}
		closeWrite(dst)
	}

	done := make(chan struct{}, 2)
	go pipe(b, a, &bytesUp, done)
	go pipe(a, b, &bytesDown, done)
	// 看门狗单独一个协程：主流程要等两个 pipe 都结束，
	// 若把超时检查塞进同一个 select，pipe 结束与超时到点会互相拖住。
	stopWatch := make(chan struct{})
	go watchIdle(&lastActive, currentIdleTimeout(), closeBoth, stopWatch)
	<-done
	<-done
	close(stopWatch)
	closeBoth()
}

// watchIdle 监视双向静默时长，到点即关闭两侧连接，唤醒阻塞在 Read 上的转发协程。
//
// 客户端休眠/掉线/换网后本端收不到任何事件，Read 不会返回，也就没有 EOF 可依赖，
// 只能靠定时器兜底回收。
func watchIdle(lastActive *atomic.Int64, idle time.Duration, closeBoth func(), stop <-chan struct{}) {
	if idle <= 0 {
		return
	}
	ticker := time.NewTicker(idleCheckInterval(idle))
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			if now.Sub(time.Unix(0, lastActive.Load())) < idle {
				continue
			}
			logging.Debug("relay", "连接空闲超时，已关闭", "idle", idle.String())
			closeBoth()
			return
		}
	}
}

// idleCheckInterval 按空闲时限的 1/10 扫描，并限制在 [1s, 30s]。
func idleCheckInterval(idle time.Duration) time.Duration {
	d := idle / 10
	if d < idleCheckMin {
		d = idleCheckMin
	}
	if d > idleCheckMax {
		d = idleCheckMax
	}
	return d
}

// closeWrite 半关闭写方向，支持 *net.TCPConn 与 SSH 通道连接。
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
