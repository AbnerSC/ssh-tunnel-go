package sshpool

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/config"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/proxy"
)

// remoteBindHost -R 转发在服务器侧的绑定地址，与 Java 版 localhost 语义一致（仅监听回环）
const remoteBindHost = "127.0.0.1"

// conn 一条已认证的 SSH 会话及其在服务器侧打开的远程转发监听。
type conn struct {
	client *ssh.Client
	index  int

	closed    atomic.Bool
	closeOnce sync.Once
	remoteOne sync.Once

	mu        sync.Mutex
	listeners []net.Listener
}

func (c *conn) alive() bool {
	return c != nil && !c.closed.Load()
}

// close 幂等关闭：先停掉 -R 监听，再关闭会话。
func (c *conn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.mu.Lock()
		listeners := c.listeners
		c.listeners = nil
		c.mu.Unlock()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		_ = c.client.Close()
	})
}

// startRemotes 在主会话上建立全部 -R 远程端口转发，只执行一次。
func (c *conn) startRemotes(items []config.CopyItem) {
	c.remoteOne.Do(func() {
		for _, item := range items {
			c.listenRemote(item)
		}
	})
}

// listenRemote 建立单个远程转发监听。
//
// 会话刚重建时服务器侧旧监听可能尚未释放，端口会短暂被占用；
// 这里退避重试几次，避免一次失败就永久丢失该转发规则（直到下次重新选举）。
func (c *conn) listenRemote(item config.CopyItem) {
	addr := net.JoinHostPort(remoteBindHost, strconv.Itoa(item.TargetPort))
	var ln net.Listener
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if !c.alive() {
			return
		}
		ln, err = c.client.Listen("tcp", addr)
		if err == nil {
			break
		}
		logging.Warn("ssh", "远程转发监听失败", "port", item.TargetPort, "attempt", attempt, "err", err)
		if attempt < 3 {
			time.Sleep(time.Second)
		}
	}
	if err != nil {
		logging.Error("ssh", "远程转发监听最终失败", "port", item.TargetPort, "err", err)
		return
	}

	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		_ = ln.Close()
		return
	}
	c.listeners = append(c.listeners, ln)
	c.mu.Unlock()
	logging.Info("ssh", "转发到远程成功", "item", item.String())
	go c.acceptRemote(ln, item)
}

// acceptRemote 处理服务器侧转发进来的连接：本地直连目标后双向转发。
func (c *conn) acceptRemote(ln net.Listener, item config.CopyItem) {
	local := proxy.LocalDialer{Timeout: 3 * time.Second}
	targetAddr := net.JoinHostPort(item.Host, strconv.Itoa(item.Port))
	for {
		remoteConn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer remoteConn.Close()
			target, err := local.DialContext(context.Background(), item.Host, item.Port)
			if err != nil {
				logging.Warn("ssh", "远程转发无法连接目标", "target", targetAddr, "err", err)
				return
			}
			defer target.Close()
			proxy.Relay(remoteConn, target)
		}()
	}
}

// startLocals 建立全部 -L 本地监听。
func (p *Pool) startLocals() {
	for _, item := range p.cfg.Locals {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(item.TargetPort))
		if err != nil {
			logging.Warn("ssh", "本地转发监听失败", "port", item.TargetPort, "err", err)
			continue
		}
		logging.Info("ssh", "本地转发端口监听成功", "port", item.TargetPort)
		p.localMu.Lock()
		p.locals = append(p.locals, ln)
		p.localMu.Unlock()
		go p.acceptLocal(ln, item)
	}
}

// acceptLocal 处理本机 -L 监听上的连接：从池中轮询选一条会话打开 direct-tcpip 通道。
//
// 不固定使用主会话：主会话只承担 -R（服务器侧监听必须落在一条固定会话上），
// -L 流量分散到整个池才能利用多条 SSH 连接，也避免主会话断开时 -L 全部中断。
func (p *Pool) acceptLocal(ln net.Listener, item config.CopyItem) {
	targetAddr := net.JoinHostPort(item.Host, strconv.Itoa(item.Port))
	for {
		localConn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer localConn.Close()
			// 复用池的拨号逻辑（轮询 + 换会话重试），命中即将断开的会话时自动重试
			ctx, cancel := context.WithTimeout(context.Background(), channelConnectTimeout)
			target, err := p.DialContext(ctx, item.Host, item.Port)
			cancel()
			if err != nil {
				logging.Warn("ssh", "本地转发打开通道失败", "target", targetAddr, "err", err)
				return
			}
			defer target.Close()
			proxy.Relay(localConn, target)
		}()
	}
}
