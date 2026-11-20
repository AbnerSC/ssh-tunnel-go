package proxy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock 可手动推进的时钟，避免测试依赖真实等待。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func mustAddrs(t *testing.T, values ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("解析测试地址失败: %v", err)
		}
		out = append(out, addr)
	}
	return out
}

func TestResolverIPLiteralSkipsLookup(t *testing.T) {
	var calls atomic.Int32
	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, errors.New("不应被调用")
	})

	addrs, err := r.Lookup(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("IP 字面量应直接返回: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("IP 字面量结果错误: %v", addrs)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("IP 字面量不应触发 DNS 查询，实际 %d 次", n)
	}
}

func TestResolverCachesWithinTTL(t *testing.T) {
	clock := newFakeClock()
	var calls atomic.Int32
	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return mustAddrs(t, "127.0.0.1"), nil
	})
	r.now = clock.now

	for i := 0; i < 3; i++ {
		addrs, err := r.Lookup(context.Background(), "example.test")
		if err != nil || len(addrs) != 1 {
			t.Fatalf("第 %d 次解析失败: %v %v", i, addrs, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("TTL 内应只查询一次，实际 %d 次", n)
	}

	clock.advance(directResolveTTL + time.Second)
	if _, err := r.Lookup(context.Background(), "example.test"); err != nil {
		t.Fatalf("缓存过期后应重新查询: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("缓存过期后应重新查询，实际 %d 次", n)
	}
}

func TestResolverStaleOnFailure(t *testing.T) {
	clock := newFakeClock()
	var calls atomic.Int32
	var fail atomic.Bool
	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, &netError{"i/o timeout"}
		}
		return mustAddrs(t, "127.0.0.1"), nil
	})
	r.now = clock.now

	if _, err := r.Lookup(context.Background(), "example.test"); err != nil {
		t.Fatalf("首次解析应成功: %v", err)
	}

	fail.Store(true)
	clock.advance(2 * time.Minute) // 超过 TTL，仍在 stale 窗口内
	addrs, err := r.Lookup(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("解析失败时应沿用旧地址: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("旧地址不正确: %v", addrs)
	}
	base := calls.Load()

	// 退避窗口内不重复查询上游
	clock.advance(time.Second)
	if _, err := r.Lookup(context.Background(), "example.test"); err != nil {
		t.Fatalf("退避窗口内应继续沿用旧地址: %v", err)
	}
	if calls.Load() != base {
		t.Fatalf("退避窗口内不应重复查询，实际 %d -> %d", base, calls.Load())
	}

	// 退避结束后允许再次尝试，失败仍沿用旧地址
	clock.advance(directResolveBackoff)
	if _, err := r.Lookup(context.Background(), "example.test"); err != nil {
		t.Fatalf("退避结束后失败仍应沿用旧地址: %v", err)
	}
	if calls.Load() != base+1 {
		t.Fatalf("退避结束后应重新查询一次，实际 %d -> %d", base, calls.Load())
	}
}

func TestResolverFailureWithoutStale(t *testing.T) {
	clock := newFakeClock()
	var calls atomic.Int32
	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, &netError{"i/o timeout"}
	})
	r.now = clock.now

	if _, err := r.Lookup(context.Background(), "example.test"); err == nil {
		t.Fatal("无旧地址时解析失败应返回错误")
	}
	// 负缓存窗口内不重复查询
	if _, err := r.Lookup(context.Background(), "example.test"); err == nil {
		t.Fatal("负缓存窗口内仍应返回错误")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("负缓存窗口内应只查询一次，实际 %d 次", n)
	}

	clock.advance(directResolveNegative + time.Second)
	if _, err := r.Lookup(context.Background(), "example.test"); err == nil {
		t.Fatal("负缓存过期后仍应返回错误")
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("负缓存过期后应重新查询，实际 %d 次", n)
	}
}

func TestResolverSingleflight(t *testing.T) {
	var calls atomic.Int32
	r := newResolver(func(ctx context.Context, _ string) ([]netip.Addr, error) {
		calls.Add(1)
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return mustAddrs(t, "127.0.0.1"), nil
	})

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := r.Lookup(context.Background(), "example.test")
			if err != nil {
				errs <- err
				return
			}
			if len(addrs) != 1 {
				errs <- errors.New("地址数量错误")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发解析失败: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("并发请求应合并为一次查询，实际 %d 次", n)
	}
}

func TestResolverPreferIPv4(t *testing.T) {
	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		return mustAddrs(t, "::1", "127.0.0.1"), nil
	})
	addrs, err := r.Lookup(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(addrs) != 2 || !addrs[0].Is4() {
		t.Fatalf("IPv4 应排在前面: %v", addrs)
	}
}

func TestLocalDialerUsesResolver(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	_ = echoHost

	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		return mustAddrs(t, "127.0.0.1"), nil
	})
	dialer := LocalDialer{Timeout: time.Second, Resolver: r}
	conn, err := dialer.DialContext(context.Background(), "echo.test", echoPort)
	if err != nil {
		t.Fatalf("域名拨号失败: %v", err)
	}
	_ = conn.Close()
}

// 解析失败要保持 net.Dialer 惯用格式，运维能直接按日志关键字检索。
func TestLocalDialerLookupError(t *testing.T) {
	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		return nil, &netError{"i/o timeout"}
	})
	dialer := LocalDialer{Timeout: time.Second, Resolver: r}
	_, err := dialer.DialContext(context.Background(), "www.toutiao.com", 443)
	if err == nil {
		t.Fatal("解析失败时拨号应返回错误")
	}
	if !strings.Contains(err.Error(), "dial tcp: lookup www.toutiao.com") {
		t.Fatalf("错误信息应保持 dial tcp: lookup <host> 格式: %v", err)
	}
}

// 解析耗时不能被建连超时切断：DNS 重试慢于建连超时时仍需拨号成功。
// 这是线上日志里「直连目标后正好 3s 报 lookup i/o timeout」的根因回归。
func TestLocalDialerSlowLookupStillDials(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	_ = echoHost

	r := newResolver(func(ctx context.Context, _ string) ([]netip.Addr, error) {
		select {
		case <-time.After(300 * time.Millisecond):
			return mustAddrs(t, "127.0.0.1"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	dialer := LocalDialer{Timeout: 100 * time.Millisecond, Resolver: r}
	conn, err := dialer.DialContext(context.Background(), "slow.test", echoPort)
	if err != nil {
		t.Fatalf("解析慢于建连超时时不应失败: %v", err)
	}
	_ = conn.Close()
}

// 多个地址必须共享同一份建连预算，不能因为地址多就把总耗时成倍拉长。
func TestLocalDialerConnectBudgetShared(t *testing.T) {
	r := newResolver(func(context.Context, string) ([]netip.Addr, error) {
		// 192.0.2.0/24 是保留的测试网段，正常网络不可达
		return mustAddrs(t, "192.0.2.1", "192.0.2.2", "192.0.2.3"), nil
	})
	dialer := LocalDialer{Timeout: 200 * time.Millisecond, Resolver: r}
	started := time.Now()
	if _, err := dialer.DialContext(context.Background(), "blackhole.test", 443); err == nil {
		t.Fatal("不可达地址应返回错误")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("多地址应共享建连预算，实际耗时 %s", elapsed)
	}
}

// netError 模拟 net.DNSError 的超时错误（避免测试依赖真实 DNS）。
type netError struct{ msg string }

func (e *netError) Error() string   { return e.msg }
func (e *netError) Timeout() bool   { return true }
func (e *netError) Temporary() bool { return true }
