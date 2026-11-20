package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"ssh-tunnel-go/internal/logging"
)

const (
	// directLookupTimeout 直连域名解析的总时限。
	//
	// 不能与建连超时共用 3s：Go 内置解析器在 UDP 查询无响应时要等到单次
	// 查询超时（通常 5s）才会重发第二次，3s 在第一次丢包时就直接放弃，
	// 日志表现为 lookup <host>: i/o timeout。这里给足两次尝试的时间，
	// 链路抖动一次仍能解析成功。
	directLookupTimeout = 10 * time.Second
	// directResolveTTL 解析成功结果的缓存时长。
	// 行情类客户端每条连接都重新建连，没有缓存时每次都要查询上游 DNS，
	// 高频请求会被 DNS 限速；TTL 内复用结果可显著降低查询量。
	directResolveTTL = 60 * time.Second
	// directResolveStale 解析失败时继续沿用上次成功结果的时长。
	// 域名指向的地址通常长期稳定，DNS 短暂故障不应直接打断业务连接。
	directResolveStale = 30 * time.Minute
	// directResolveBackoff 有旧地址可用时，解析失败后的重试间隔，
	// 避免每条连接都重新打上游放大限速。
	directResolveBackoff = 5 * time.Second
	// directResolveNegative 解析失败且无旧地址可用时的负缓存时长，
	// 挡住同一时刻的重复查询。
	directResolveNegative = time.Second
	// directResolveWarnInterval 同一域名沿用旧地址告警的最小间隔。
	directResolveWarnInterval = time.Minute
	// directResolveMaxEntries 缓存条目上限，超出时清理过期条目。
	directResolveMaxEntries = 4096
)

// defaultResolver 进程级共享的直连解析器。
var defaultResolver = NewResolver()

// defaultLookup 使用系统解析器查询域名地址。
func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Resolver 直连域名的解析器：带 TTL 缓存、并发合并与失败兜底。
//
// 直连目标由本机解析（TUN 模式下这条查询会进 sing-box 的 DNS 分流），
// 解析链路抖动时会出现「同一域名时好时坏」的现象。缓存让 TTL 内不再
// 重复查询，并发请求合并成一次，解析失败时沿用上次成功地址兜底，
// 避免把 DNS 故障直接放大成业务连接失败。
type Resolver struct {
	lookup   func(ctx context.Context, host string) ([]netip.Addr, error)
	now      func() time.Time
	timeout  time.Duration
	ttl      time.Duration
	stale    time.Duration
	backoff  time.Duration
	negative time.Duration
	warnGap  time.Duration

	mu      sync.Mutex
	entries map[string]*resolveEntry
	calls   map[string]*resolveCall
}

// resolveEntry 单个域名的解析缓存。
type resolveEntry struct {
	addrs    []netip.Addr // 最近一次成功解析结果
	lastOK   time.Time    // 最近一次成功时间
	expire   time.Time    // addrs 的缓存有效期
	failAt   time.Time    // 最近一次失败时间（零值表示没有失败）
	failErr  error        // 最近一次失败原因
	lastWarn time.Time    // 沿用旧地址告警的最近输出时间
}

// resolveCall 进行中的解析，用于并发合并（singleflight）。
type resolveCall struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// NewResolver 创建使用系统解析器与内置参数的解析缓存。
func NewResolver() *Resolver {
	return newResolver(defaultLookup)
}

// newResolver 按指定查询函数创建解析缓存；测试通过它注入假查询与时钟。
func newResolver(lookup func(ctx context.Context, host string) ([]netip.Addr, error)) *Resolver {
	return &Resolver{
		lookup:   lookup,
		now:      time.Now,
		timeout:  directLookupTimeout,
		ttl:      directResolveTTL,
		stale:    directResolveStale,
		backoff:  directResolveBackoff,
		negative: directResolveNegative,
		warnGap:  directResolveWarnInterval,
		entries:  make(map[string]*resolveEntry),
		calls:    make(map[string]*resolveCall),
	}
}

// Lookup 解析域名并返回可拨号地址；IP 字面量直接返回自身。
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{addr}, nil
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if name == "" {
		return nil, errors.New("空主机名")
	}

	r.mu.Lock()
	now := r.now()
	entry := r.entries[name]
	// 新鲜缓存：直接用，不产生任何查询
	if entry != nil && entry.failErr == nil && now.Before(entry.expire) {
		addrs := cloneAddrs(entry.addrs)
		r.mu.Unlock()
		return addrs, nil
	}
	// 失败退避窗口：有旧地址时用旧地址，没有时直接返回上次错误
	if entry != nil && !entry.failAt.IsZero() && now.Sub(entry.failAt) < r.retryGate(entry, now) {
		if addrs, ok := r.staleAddrs(entry, now); ok {
			r.mu.Unlock()
			return cloneAddrs(addrs), nil
		}
		err := entry.failErr
		r.mu.Unlock()
		return nil, err
	}
	// 已有同域名的查询在进行：等待它的结果，避免并发打爆上游
	if call, ok := r.calls[name]; ok {
		r.mu.Unlock()
		select {
		case <-call.done:
			return cloneAddrs(call.addrs), call.err
		case <-ctx.Done():
			return nil, normalizeLookupErr(name, ctx.Err())
		}
	}
	call := &resolveCall{done: make(chan struct{})}
	r.calls[name] = call
	r.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, r.timeout)
	started := time.Now()
	addrs, err := r.lookup(lookupCtx, name)
	cancel()

	r.mu.Lock()
	now = r.now()
	if err == nil && len(addrs) == 0 {
		err = errors.New("域名无可用地址")
	}
	if err == nil {
		addrs = preferIPv4(addrs)
		r.entries[name] = &resolveEntry{addrs: addrs, lastOK: now, expire: now.Add(r.ttl)}
		call.addrs, call.err = cloneAddrs(addrs), nil
		logging.Debug("proxy", "直连域名解析完成", "host", name, "addrs", len(addrs),
			"elapsed", time.Since(started).Round(time.Millisecond))
	} else {
		err = normalizeLookupErr(name, err)
		failed := r.entries[name]
		if failed == nil {
			failed = &resolveEntry{}
			r.entries[name] = failed
		}
		failed.failAt = now
		failed.failErr = err
		if old, ok := r.staleAddrs(failed, now); ok {
			if now.Sub(failed.lastWarn) >= r.warnGap {
				failed.lastWarn = now
				logging.Warn("proxy", "直连域名解析失败，沿用上次解析结果",
					"host", name, "err", err, "staleAddrs", len(old))
			}
			call.addrs, call.err = cloneAddrs(old), nil
		} else {
			call.addrs, call.err = nil, err
		}
	}
	r.evictLocked(now)
	delete(r.calls, name)
	close(call.done)
	r.mu.Unlock()

	return cloneAddrs(call.addrs), call.err
}

// retryGate 返回失败后到下次真正查询前的最短间隔。
func (r *Resolver) retryGate(entry *resolveEntry, now time.Time) time.Duration {
	if _, ok := r.staleAddrs(entry, now); ok {
		return r.backoff
	}
	return r.negative
}

// staleAddrs 返回可继续沿用的旧解析结果。
func (r *Resolver) staleAddrs(entry *resolveEntry, now time.Time) ([]netip.Addr, bool) {
	if entry == nil || len(entry.addrs) == 0 {
		return nil, false
	}
	if now.Sub(entry.lastOK) > r.stale {
		return nil, false
	}
	return entry.addrs, true
}

// evictLocked 在缓存超限时清理条目；调用方需持有锁。
func (r *Resolver) evictLocked(now time.Time) {
	if len(r.entries) <= directResolveMaxEntries {
		return
	}
	for name, e := range r.entries {
		if _, busy := r.calls[name]; busy {
			continue
		}
		if e.failErr != nil && now.Sub(e.failAt) >= r.backoff {
			delete(r.entries, name)
		}
	}
	// 仍超限：删除最久未成功解析的条目
	for len(r.entries) > directResolveMaxEntries {
		oldestName := ""
		var oldest time.Time
		for name, e := range r.entries {
			if _, busy := r.calls[name]; busy {
				continue
			}
			if oldestName == "" || e.lastOK.Before(oldest) {
				oldestName, oldest = name, e.lastOK
			}
		}
		if oldestName == "" {
			return
		}
		delete(r.entries, oldestName)
	}
}

// preferIPv4 把 IPv4 地址排到前面。
//
// 部署环境以 IPv4 为主，IPv6 无默认路由时先试 v6 只会白等一次
// （有路由但不可达时会吃掉整个建连超时）；v6 地址保留在后面兜底。
func preferIPv4(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() {
			out = append(out, a.Unmap())
		}
	}
	for _, a := range addrs {
		if !a.Is4() && !a.Is4In6() {
			out = append(out, a)
		}
	}
	return out
}

// cloneAddrs 复制地址列表，避免调用方修改缓存内容。
func cloneAddrs(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	return append([]netip.Addr(nil), addrs...)
}

// normalizeLookupErr 让解析错误保持 net.DNSError 的惯用格式
// （如 lookup host on 1.1.1.1:53: i/o timeout），便于运维按关键字检索。
func normalizeLookupErr(name string, err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
	}
	return fmt.Errorf("lookup %s: %w", name, err)
}
