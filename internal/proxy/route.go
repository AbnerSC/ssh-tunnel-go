package proxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"ssh-tunnel-go/internal/direct"
	"ssh-tunnel-go/internal/logging"
)

// Credentials 代理账号密码，socks5 与 http 代理共用。
type Credentials struct {
	User     string
	Password string
	Enabled  bool
	// guard 认证失败限速；nil 表示不限制（仅供内部调用与测试）
	guard *authGuard
}

// NewCredentials 两个字段都非空时启用认证
// 同时创建失败限速器，挡住弱口令爆破。
func NewCredentials(user, password string) Credentials {
	return Credentials{
		User:     user,
		Password: password,
		Enabled:  user != "" && password != "",
		guard:    newAuthGuard(),
	}
}

// Dialer 建立到目标地址的连接。
type Dialer interface {
	DialContext(ctx context.Context, host string, port int) (net.Conn, error)
}

// LocalDialer 由本机直接连接目标。
type LocalDialer struct {
	// Timeout 建连超时
	Timeout time.Duration
	// Resolver 直连域名解析缓存；nil 使用进程级共享实例
	Resolver *Resolver
}

// DialContext 实现 Dialer。
//
// 解析与建连分开计时：域名解析要覆盖 DNS 重试窗口（见 Resolver），
// 建连超时只约束 TCP 握手，不能把两者绑在同一个 3s 上。解析完成后
// 逐个地址尝试，避免把已解析的域名再交给 Dialer 二次解析；
// 所有地址共享同一份建连预算，避免域名解析出十几个地址时把总耗时
// 放大成「地址数 × 超时」。
func (d LocalDialer) DialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	addrs, err := d.resolver().Lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	// 建连预算独立于解析预算：解析已在上一步消耗掉自己的时限，
	// 这里只给握手留 timeout，且多个地址共用。
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{KeepAlive: 15 * time.Second}
	var lastErr error
	for _, addr := range addrs {
		conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if dialCtx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dial tcp: %s 无可用地址", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return nil, lastErr
}

// resolver 返回使用的解析器：优先显式注入，未注入时用进程级共享缓存。
func (d LocalDialer) resolver() *Resolver {
	if d.Resolver != nil {
		return d.Resolver
	}
	return defaultResolver
}

// Route 按直连规则在「本地直连」与「SSH 隧道」之间分流。
type Route struct {
	// Proto 日志中的协议名（socks5 / http）
	Proto string
	// Direct 本地直连实现
	Direct Dialer
	// Tunnel SSH 隧道实现，nil 表示未配置服务器（全部本地直连）
	Tunnel Dialer
	// Rules 直连规则，nil 表示不命中任何直连
	Rules *direct.Rules
}

// Dial 选择出口并建立连接。
func (r *Route) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if r.Tunnel == nil || r.Rules.IsDirect(host) {
		logging.Info(r.Proto, "直连目标", "target", target)
		return r.Direct.DialContext(ctx, host, port)
	}
	return r.Tunnel.DialContext(ctx, host, port)
}
