package proxy

import (
	"net"
	"testing"
	"time"
)

// tcpAddr 构造带端口来源地址，便于按 IP 分组测试。
func tcpAddr(ip string, port int) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// waitFor 轮询等待条件成立，超时即失败。
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}

// TestConnLimiterGlobalCap 全局上限：名额用满后一律拒绝，释放后恢复。
func TestConnLimiterGlobalCap(t *testing.T) {
	l := newConnLimiter(2, 10)

	r1, ok := l.acquire(tcpAddr("10.0.0.1", 1))
	if !ok {
		t.Fatal("首个连接应被受理")
	}
	r2, ok := l.acquire(tcpAddr("10.0.0.2", 1))
	if !ok {
		t.Fatal("第二个连接应被受理")
	}
	if _, ok := l.acquire(tcpAddr("10.0.0.3", 1)); ok {
		t.Fatal("超过全局上限应被拒绝")
	}

	r1()
	if _, ok := l.acquire(tcpAddr("10.0.0.3", 1)); !ok {
		t.Fatal("释放名额后应重新受理")
	}
	if total, _ := l.stats(); total != 2 {
		t.Fatalf("占用数应为 2，实际 %d", total)
	}
	r2()
}

// TestConnLimiterPerIPCap 每 IP 上限：同一来源超限被拒，其他来源不受影响。
func TestConnLimiterPerIPCap(t *testing.T) {
	l := newConnLimiter(10, 2)

	for i := 0; i < 2; i++ {
		if _, ok := l.acquire(tcpAddr("10.0.0.1", 1000+i)); !ok {
			t.Fatalf("第 %d 个同源连接应被受理", i+1)
		}
	}
	if _, ok := l.acquire(tcpAddr("10.0.0.1", 1002)); ok {
		t.Fatal("同一来源超过每 IP 上限应被拒绝")
	}
	if _, ok := l.acquire(tcpAddr("10.0.0.2", 1000)); !ok {
		t.Fatal("其他来源不应受该 IP 配额影响")
	}
	if total, ips := l.stats(); total != 3 || ips != 2 {
		t.Fatalf("统计异常: total=%d ips=%d", total, ips)
	}
}

// TestConnLimiterReleaseCleansUp 释放后来源记录必须删除，避免 map 随历史来源增长。
func TestConnLimiterReleaseCleansUp(t *testing.T) {
	l := newConnLimiter(10, 2)
	release, ok := l.acquire(tcpAddr("10.0.0.1", 1))
	if !ok {
		t.Fatal("连接应被受理")
	}
	release()
	if total, ips := l.stats(); total != 0 || ips != 0 {
		t.Fatalf("释放后应无残留: total=%d ips=%d", total, ips)
	}
	// 同一 IP 再次申请不应被历史计数拖累
	if r, ok := l.acquire(tcpAddr("10.0.0.1", 2)); !ok {
		t.Fatal("释放后同一来源应可再次占用")
	} else {
		r()
	}
}

// TestConnLimiterUnknownRemote 来源未知（remote 为 nil）时只受全局上限约束。
func TestConnLimiterUnknownRemote(t *testing.T) {
	l := newConnLimiter(10, 1)
	r1, ok := l.acquire(nil)
	if !ok {
		t.Fatal("未知来源也应受理")
	}
	r2, ok := l.acquire(nil)
	if !ok {
		t.Fatal("每 IP 上限不应对未知来源生效")
	}
	r1()
	r2()

	strict := newConnLimiter(1, 1)
	if _, ok := strict.acquire(nil); !ok {
		t.Fatal("首个连接应被受理")
	}
	if _, ok := strict.acquire(nil); ok {
		t.Fatal("全局上限对未知来源同样必须生效")
	}
}

// TestConnLimiterNil 未启用限制时（nil）一律放行，释放函数可安全调用。
func TestConnLimiterNilAcquire(t *testing.T) {
	var l *connLimiter
	release, ok := l.acquire(tcpAddr("10.0.0.1", 1))
	if !ok {
		t.Fatal("nil 限制器应放行")
	}
	release()
	if fired, _ := l.shouldLogReject(time.Now()); fired {
		t.Fatal("nil 限制器不应输出拒绝日志")
	}
	if total, ips := l.stats(); total != 0 || ips != 0 {
		t.Fatalf("nil 限制器统计应为 0: %d/%d", total, ips)
	}
}

// TestConnLimiterLogThrottle 拒绝日志必须节流，避免洪泛时把日志写满。
func TestConnLimiterLogThrottle(t *testing.T) {
	l := newConnLimiter(1, 1)
	if _, ok := l.acquire(tcpAddr("10.0.0.1", 1)); !ok {
		t.Fatal("首个连接应被受理")
	}
	if _, ok := l.acquire(tcpAddr("10.0.0.2", 1)); ok {
		t.Fatal("超过上限应被拒绝")
	}

	now := time.Now()
	fired, n := l.shouldLogReject(now)
	if !fired || n != 1 {
		t.Fatalf("首次拒绝应输出日志: fired=%v n=%d", fired, n)
	}
	if fired, _ := l.shouldLogReject(now.Add(10 * time.Millisecond)); fired {
		t.Fatal("间隔内不应重复输出拒绝日志")
	}
	if fired, n := l.shouldLogReject(now.Add(2 * time.Second)); !fired || n != 0 {
		t.Fatalf("超过间隔后应再次输出: fired=%v n=%d", fired, n)
	}
}

// TestServeRejectsBeyondLimit 验证监听层接入限制：超限连接被立即关闭，
// 处理结束（含 panic 路径）后名额归还。
func TestServeRejectsBeyondLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()

	limiter := newConnLimiter(1, 1)
	started := make(chan struct{}, 4)
	hold := make(chan struct{})
	go serve(ln, "test", func(conn net.Conn) {
		defer conn.Close()
		select {
		case started <- struct{}{}:
		default:
		}
		<-hold
	}, limiter)

	first, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer first.Close()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("首个连接未被受理")
	}

	// 名额已满：服务端应直接关闭新连接，不进入处理函数
	second, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("超过上限的连接应被立即关闭")
	}

	// 处理函数退出后名额应归还
	close(hold)
	waitFor(t, 2*time.Second, func() bool {
		total, _ := limiter.stats()
		return total == 0
	})
}

// TestDefaultLimitMatchesMemoryBudget 默认上限必须与内存预算匹配：
// 转发阶段每个连接占用两向 relayBufSize 缓冲，上限过高会让小内存容器被 OOM。
func TestDefaultLimitMatchesMemoryBudget(t *testing.T) {
	if DefaultMaxConnsPerIP <= 0 || DefaultMaxConnsPerIP >= DefaultMaxConns {
		t.Fatalf("每 IP 上限必须大于 0 且小于全局上限: perIP=%d total=%d", DefaultMaxConnsPerIP, DefaultMaxConns)
	}
	budget := int64(DefaultMaxConns) * 2 * relayBufSize
	if budget > 96<<20 {
		t.Fatalf("全局上限对应缓冲占用 %d MiB，超出 96MiB 预算", budget>>20)
	}
	// 默认限制器在包初始化时就按默认值建好，未显式设置时即以此为生效值
	if lim := defaultLimiter.Load(); lim.maxTotal != DefaultMaxConns || lim.maxPerIP != DefaultMaxConnsPerIP {
		t.Fatalf("默认限制器未按默认参数初始化: total=%d perIP=%d", lim.maxTotal, lim.maxPerIP)
	}
}

// TestSetConnectionLimits SetConnectionLimits 应替换全局限制器，0 表示不限制。
func TestSetConnectionLimits(t *testing.T) {
	orig := defaultLimiter.Load()
	t.Cleanup(func() { defaultLimiter.Store(orig) })

	SetConnectionLimits(9, 4)
	lim := currentLimiter()
	if lim.maxTotal != 9 || lim.maxPerIP != 4 {
		t.Fatalf("上限未生效: total=%d perIP=%d", lim.maxTotal, lim.maxPerIP)
	}

	// 0 交给 connLimiter 解释为不限制
	SetConnectionLimits(0, 0)
	if lim := currentLimiter(); lim.maxTotal != 0 || lim.maxPerIP != 0 {
		t.Fatalf("0 应表示不限制: total=%d perIP=%d", lim.maxTotal, lim.maxPerIP)
	}
}

// TestServeUsesGlobalLimiter Serve 应绑定启动时的全局限制器，
// 从而让 main 里 SetConnectionLimits 的设置真正作用于两个代理端口。
func TestServeUsesGlobalLimiter(t *testing.T) {
	orig := defaultLimiter.Load()
	t.Cleanup(func() { defaultLimiter.Store(orig) })
	SetConnectionLimits(1, 1)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	hold := make(chan struct{})
	go Serve(ln, "test", func(net.Conn) { <-hold })
	t.Cleanup(func() {
		close(hold)
		_ = ln.Close()
	})

	first, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("建立首个连接失败: %v", err)
	}
	defer first.Close()

	second, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("建立超限连接失败: %v", err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("全局上限为 1 时，第二个连接应被拒绝")
	}
}
