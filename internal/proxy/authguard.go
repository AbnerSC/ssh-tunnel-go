package proxy

import (
	"crypto/subtle"
	"net"
	"sync"
	"time"

	"ssh-tunnel-go/internal/logging"
)

// 认证失败的限速参数。
//
// 代理端口暴露在网络上，任何实现都能每秒发起数百次认证尝试（实测同一 TCP
// 连接上不加节流时可达 290 次/秒），弱口令几乎必然被猜中。这里按来源 IP
// 统计失败次数，达到阈值后直接拒绝一段时间，并让调用方在失败次数过多时
// 断开连接，把爆破速率压到不可用。
const (
	// authFailWindow 失败计数的滑动窗口
	authFailWindow = time.Minute
	// authFailLimit 窗口内允许的失败次数
	authFailLimit = 10
	// authBanDuration 超过阈值后的封禁时长
	authBanDuration = 5 * time.Minute
	// authCleanupThreshold 记录表超过该规模时清理过期项
	authCleanupThreshold = 1024
)

// authGuard 按来源 IP 限制认证失败频率。
//
// 之所以同时限制「单连接失败次数」与「每 IP 失败频率」：
// 前者挡住单连接上的无限重试（HTTP 407 后不断开连接时的爆破），
// 后者挡住并发多连接的分布式尝试。
type authGuard struct {
	mu        sync.Mutex
	entries   map[string]*authFailState
	limit     int
	window    time.Duration
	banFor    time.Duration
	lastSweep time.Time
}

type authFailState struct {
	fails    int
	firstAt  time.Time
	bannedTo time.Time
}

// newAuthGuard 创建认证限速器。
func newAuthGuard() *authGuard {
	return &authGuard{
		entries: make(map[string]*authFailState),
		limit:   authFailLimit,
		window:  authFailWindow,
		banFor:  authBanDuration,
	}
}

// Blocked 判断来源是否处于封禁期。guard 为 nil 时不限制（供测试与内部调用）。
func (g *authGuard) Blocked(remote net.Addr) bool {
	if g == nil {
		return false
	}
	key := remoteKey(remote)
	if key == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.entries[key]
	if st == nil {
		return false
	}
	if time.Now().Before(st.bannedTo) {
		return true
	}
	return false
}

// Fail 记录一次认证失败，返回该来源是否已被封禁。
func (g *authGuard) Fail(remote net.Addr) bool {
	if g == nil {
		return false
	}
	key := remoteKey(remote)
	if key == "" {
		return false
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)

	st := g.entries[key]
	if st == nil || now.Sub(st.firstAt) > g.window {
		st = &authFailState{firstAt: now}
		g.entries[key] = st
	}
	st.fails++
	if st.fails >= g.limit {
		st.bannedTo = now.Add(g.banFor)
		logging.Warn("proxy", "认证失败次数过多，来源已被临时封禁",
			"remote", key, "fails", st.fails, "banFor", g.banFor.Round(time.Second))
		return true
	}
	return false
}

// Reset 认证成功后清除该来源的失败记录。
func (g *authGuard) Reset(remote net.Addr) {
	if g == nil {
		return
	}
	key := remoteKey(remote)
	if key == "" {
		return
	}
	g.mu.Lock()
	delete(g.entries, key)
	g.mu.Unlock()
}

// sweepLocked 定期清理过期记录，避免 map 随来源数量无限增长。
func (g *authGuard) sweepLocked(now time.Time) {
	if len(g.entries) < authCleanupThreshold || now.Sub(g.lastSweep) < g.window {
		return
	}
	g.lastSweep = now
	for k, st := range g.entries {
		if now.After(st.bannedTo) && now.Sub(st.firstAt) > g.window {
			delete(g.entries, k)
		}
	}
}

// remoteKey 提取来源 IP 作为限速键。
func remoteKey(remote net.Addr) string {
	if remote == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return remote.String()
	}
	return host
}

// credentialMatch 以常量时间比较账号密码，避免通过响应时间推断正确前缀。
func credentialMatch(gotUser, gotPass, wantUser, wantPass string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser))
	passOK := subtle.ConstantTimeCompare([]byte(gotPass), []byte(wantPass))
	return userOK&passOK == 1
}
