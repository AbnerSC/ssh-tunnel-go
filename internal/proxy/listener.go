package proxy

import (
	"errors"
	"net"
	"runtime/debug"
	"strconv"
	"time"

	"ssh-tunnel-go/internal/logging"
)

// ListenTCP 监听本地端口（含 IPv6 与 IPv4）
func ListenTCP(port int) (net.Listener, error) {
	return ListenTCPOn("", port)
}

// ListenTCPOn 在指定地址上监听；addr 为空表示全部网卡。
//
// 单独提供地址参数的用途是收紧暴露面：无认证时仅监听 127.0.0.1，
// 避免代理被外部直接当成内网跳板（仅靠防火墙并不是应用层能依赖的边界）。
func ListenTCPOn(addr string, port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
}

// Serve 接受连接并逐连接并发处理。
//
// SOCKS5 与 HTTP 代理必须共用同一个限制器（见 currentLimiter）：各自持有一份时，
// 攻击者只要同时打两个端口就能拿到双倍上限。
//
// 单连接处理中发生 panic 只影响该连接：代理直接面对不可信输入，
// 不能让一条畸形请求终止整个进程。
func Serve(ln net.Listener, component string, handler func(net.Conn)) {
	serve(ln, component, handler, currentLimiter())
}

// serve 使用指定的限制器接受连接，便于测试注入小额上限。
func serve(ln net.Listener, component string, handler func(net.Conn), limiter *connLimiter) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// 文件句柄耗尽等瞬时错误：退避后继续，避免监听器永久退出
			logging.Warn(component, "接受连接失败", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		release, ok := limiter.acquire(conn.RemoteAddr())
		if !ok {
			// 超限直接关闭：不回 407/0xFF 等应答，避免给洪泛方额外反馈
			if shouldLog, rejected := limiter.shouldLogReject(time.Now()); shouldLog {
				logging.Warn(component, "并发连接数已达上限，已拒绝新连接",
					"remote", conn.RemoteAddr(),
					"maxTotal", limiter.maxTotal, "maxPerIP", limiter.maxPerIP,
					"rejected", rejected)
			}
			_ = conn.Close()
			continue
		}
		go func() {
			defer release()
			activeConns.Add(1)
			totalConns.Add(1)
			defer activeConns.Add(-1)
			defer func() {
				if r := recover(); r != nil {
					logging.Error(component, "连接处理异常，已关闭该连接",
						"remote", conn.RemoteAddr(), "panic", r, "stack", string(debug.Stack()))
					_ = conn.Close()
				}
			}()
			handler(conn)
		}()
	}
}
