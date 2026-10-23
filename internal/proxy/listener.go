package proxy

import (
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
)

// ListenTCP 监听本地端口（含 IPv6 与 IPv4），与 Java 版 NetServer 一致。
func ListenTCP(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", port))
}

// Serve 接受连接并逐连接并发处理。
//
// 单连接处理中发生 panic 只影响该连接：代理直接面对不可信输入，
// 不能让一条畸形请求终止整个进程。
func Serve(ln net.Listener, component string, handler func(net.Conn)) {
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
		go func() {
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
