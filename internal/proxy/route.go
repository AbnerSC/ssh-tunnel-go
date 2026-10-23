package proxy

import (
	"context"
	"net"
	"strconv"
	"time"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/direct"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
)

// Credentials 代理账号密码，socks5 与 http 代理共用。
type Credentials struct {
	User     string
	Password string
	Enabled  bool
}

// NewCredentials 两个字段都非空时启用认证（与 Java 版一致）。
func NewCredentials(user, password string) Credentials {
	return Credentials{User: user, Password: password, Enabled: user != "" && password != ""}
}

// Dialer 建立到目标地址的连接。
type Dialer interface {
	DialContext(ctx context.Context, host string, port int) (net.Conn, error)
}

// LocalDialer 由本机直接连接目标。
type LocalDialer struct {
	// Timeout 建连超时，与 Java 版 NetClient 的 3s 保持一致
	Timeout time.Duration
}

// DialContext 实现 Dialer。
func (d LocalDialer) DialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
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
