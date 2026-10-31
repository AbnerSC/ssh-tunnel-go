package proxy

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// relayBufSize 单向转发缓冲大小。SSH 通道单包上限 32KB，取 4 倍可减少
// 读系统调用与写入调度次数；实测仍受对端通道窗口限制，此处只降低本地开销。
const relayBufSize = 128 * 1024

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
func Relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

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
	<-done
	<-done
	closeBoth()
}

// closeWrite 半关闭写方向，支持 *net.TCPConn 与 SSH 通道连接。
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
