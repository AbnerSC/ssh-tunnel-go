package proxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// 并发连接限制参数。
//
// 代理直接面对不可信网络：不限制并发连接时，攻击者无需任何凭据，
// 只要建立大量连接并保持沉默，就能按「每连接 goroutine + 读缓冲」线性
// 吃掉内存；进入转发阶段后每连接还要占两向 relayBufSize 缓冲。
// 这里按「进程总量」与「单来源 IP」双维度设上限，超限的连接直接关闭。
const (
	// DefaultMaxConns 默认的进程内并发连接上限。
	// 按转发阶段每连接约 256KB（两向 relayBufSize）估算，默认值约 64MB，
	// 与 README 示例的 mem_limit=128m 相匹配；可用 MAX_CONNS 覆盖
	DefaultMaxConns = 256
	// DefaultMaxConnsPerIP 默认的单来源 IP 并发连接上限，挡住单机发起的连接洪泛。
	// 必须小于全局上限，否则单个 IP 就能把全局配额吃光；可用 MAX_CONNS_PER_IP 覆盖
	DefaultMaxConnsPerIP = 32
	// rejectLogInterval 连接被拒日志的最小输出间隔：
	// 洪泛期间每次拒绝都写日志，反而会用日志把磁盘打满
	rejectLogInterval = time.Second
)

// defaultLimiter 全进程共用的限制器，Serve 启动监听时绑定它的当前值。
//
// 用原子指针而不是普通变量：SetConnectionLimits 可能在监听协程运行后
// 被调用（测试或未来的热更新），普通变量会与其竞争。
var defaultLimiter atomic.Pointer[connLimiter]

func init() {
	defaultLimiter.Store(newConnLimiter(DefaultMaxConns, DefaultMaxConnsPerIP))
}

// currentLimiter 返回当前生效的限制器。
func currentLimiter() *connLimiter { return defaultLimiter.Load() }

// SetConnectionLimits 设置全局与每来源 IP 的并发连接上限；小于等于 0 表示该维度不限制。
//
// 必须在启动监听之前调用：Serve 在启动时取一次限制器并长期使用，
// 之后再调用只影响之后启动的监听。
func SetConnectionLimits(maxTotal, maxPerIP int) {
	defaultLimiter.Store(newConnLimiter(maxTotal, maxPerIP))
}

// connLimiter 全局 + 每来源 IP 的并发连接限制。
//
// 键与认证限速共用 remoteKey（取来源 IP），因此同一台机器上的
// 多个客户端共享每 IP 配额；nil 指针表示不限制（仅供测试与内部调用）。
type connLimiter struct {
	maxTotal int
	maxPerIP int

	mu       sync.Mutex
	total    int
	perIP    map[string]int
	lastLog  time.Time
	rejected int
}

// newConnLimiter 创建限制器；maxTotal/maxPerIP 小于等于 0 表示该维度不限制。
func newConnLimiter(maxTotal, maxPerIP int) *connLimiter {
	return &connLimiter{
		maxTotal: maxTotal,
		maxPerIP: maxPerIP,
		perIP:    make(map[string]int),
	}
}

// acquire 尝试占用一个连接名额；成功返回释放函数，失败返回 false。
// 释放函数只能调用一次，由调用方用 defer 执行。
func (l *connLimiter) acquire(remote net.Addr) (func(), bool) {
	if l == nil {
		return func() {}, true
	}
	key := remoteKey(remote)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.maxTotal > 0 && l.total >= l.maxTotal {
		l.rejected++
		return nil, false
	}
	if key != "" && l.maxPerIP > 0 && l.perIP[key] >= l.maxPerIP {
		l.rejected++
		return nil, false
	}
	l.total++
	if key != "" {
		l.perIP[key]++
	}
	return func() { l.release(key) }, true
}

// release 归还名额。socks5/http 的处理器结束时调用。
func (l *connLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total > 0 {
		l.total--
	}
	if key == "" {
		return
	}
	if n := l.perIP[key]; n > 1 {
		l.perIP[key] = n - 1
	} else if n == 1 {
		// 计数归零即删除条目，避免 map 随历史来源数量无限增长
		delete(l.perIP, key)
	}
}

// shouldLogReject 按间隔节流拒绝日志，返回本次是否输出以及上次输出以来的拒绝次数。
func (l *connLimiter) shouldLogReject(now time.Time) (bool, int) {
	if l == nil {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastLog) < rejectLogInterval {
		return false, 0
	}
	l.lastLog = now
	n := l.rejected
	l.rejected = 0
	return true, n
}

// stats 返回当前占用的连接总数与已记录的来源 IP 数（供测试与排障使用）。
func (l *connLimiter) stats() (total, ips int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.perIP)
}
