package sshpool

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/config"
)

// testSSHServer 进程内最小 sshd：支持密码认证、direct-tcpip 与 tcpip-forward。
type testSSHServer struct {
	ln     net.Listener
	config *ssh.ServerConfig

	mu       sync.Mutex
	forwards map[int]net.Listener
	conns    []*ssh.ServerConn
}

func newTestSSHServer(t *testing.T, user, password string) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成主机密钥失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("创建签名器失败: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("认证失败")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	s := &testSSHServer{ln: ln, config: cfg, forwards: make(map[int]net.Listener)}
	go s.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		for _, l := range s.forwards {
			_ = l.Close()
		}
		s.mu.Unlock()
	})
	return s
}

func (s *testSSHServer) port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

func (s *testSSHServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *testSSHServer) handle(netConn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.config)
	if err != nil {
		_ = netConn.Close()
		return
	}
	s.mu.Lock()
	s.conns = append(s.conns, sshConn)
	s.mu.Unlock()

	go s.handleGlobalRequests(sshConn, reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "direct-tcpip":
			go s.handleDirectTCPIP(nc)
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

// handleGlobalRequests 处理 tcpip-forward（-R）与 keepalive。
func (s *testSSHServer) handleGlobalRequests(sshConn *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var payload struct {
				Addr string
				Port uint32
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(payload.Port))))
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			s.mu.Lock()
			s.forwards[int(payload.Port)] = ln
			s.mu.Unlock()
			_ = req.Reply(true, nil)
			go s.serveForward(sshConn, ln, payload.Addr, int(payload.Port))
		case "cancel-tcpip-forward":
			var payload struct {
				Addr string
				Port uint32
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err == nil {
				s.mu.Lock()
				if ln, ok := s.forwards[int(payload.Port)]; ok {
					_ = ln.Close()
					delete(s.forwards, int(payload.Port))
				}
				s.mu.Unlock()
			}
			_ = req.Reply(true, nil)
		default:
			// keepalive@openssh.com 等全局请求一律应答成功
			_ = req.Reply(true, nil)
		}
	}
}

// serveForward 服务器侧监听，把每个连入连接通过 forwarded-tcpip 通道转给客户端。
func (s *testSSHServer) serveForward(sshConn *ssh.ServerConn, ln net.Listener, addr string, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			payload := struct {
				Addr       string
				Port       uint32
				OriginAddr string
				OriginPort uint32
			}{Addr: addr, Port: uint32(port), OriginAddr: "127.0.0.1", OriginPort: 12345}
			ch, reqs, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&payload))
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			defer ch.Close()
			relayBoth(conn, ch)
		}()
	}
}

func (s *testSSHServer) handleDirectTCPIP(nc ssh.NewChannel) {
	var payload struct {
		Host       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &payload); err != nil {
		_ = nc.Reject(ssh.Prohibited, "bad payload")
		return
	}
	target, err := net.DialTimeout("tcp",
		net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port))), 3*time.Second)
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()
	relayBoth(target, ch)
}

func (s *testSSHServer) hasForward(port int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.forwards[port]
	return ok
}

// relayBoth 双向转发，任一方向结束后关闭两端（测试用简易实现）。
func relayBoth(a, b io.ReadWriteCloser) {
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	closeAll()
	<-done
}

// startEcho 启动回显服务，返回主机与端口。
func startEcho(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动回显服务失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return "127.0.0.1", port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	waitForTimeout(t, what, 5*time.Second, cond)
}

// waitForTimeout 与 waitFor 相同，但可指定等待上限；
// 重连类断言需覆盖 runSlot 的 reconnectWait 退避时间，不能用默认 5s。
func waitForTimeout(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

func startPool(t *testing.T, cfg *config.SSHConfig) (*Pool, context.CancelFunc) {
	t.Helper()
	pool := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)
	t.Cleanup(func() {
		cancel()
		pool.Close()
	})
	waitFor(t, "SSH 会话建立", func() bool { return pool.pick() != nil })
	return pool, cancel
}

func echoOnce(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("回显不一致: %q", got)
	}
}

func TestPoolTunnel(t *testing.T) {
	srv := newTestSSHServer(t, "root", "secret")
	echoHost, echoPort := startEcho(t)

	pool, _ := startPool(t, &config.SSHConfig{
		Addr: "127.0.0.1", Port: srv.port(), User: "root", Password: "secret", Pool: 2,
	})

	conn, err := pool.DialContext(context.Background(), echoHost, echoPort)
	if err != nil {
		t.Fatalf("通过隧道建连失败: %v", err)
	}
	defer conn.Close()
	echoOnce(t, conn, "tunnel-ok")
}

func TestPoolNoSession(t *testing.T) {
	pool := New(&config.SSHConfig{Addr: "127.0.0.1", Port: 1, User: "root", Password: "x", Pool: 1})
	if _, err := pool.DialContext(context.Background(), "127.0.0.1", 80); !errors.Is(err, ErrNoSession) {
		t.Fatalf("未连接时应返回 ErrNoSession, got %v", err)
	}
}

func TestPoolLocalForward(t *testing.T) {
	srv := newTestSSHServer(t, "root", "secret")
	echoHost, echoPort := startEcho(t)
	localPort := freePort(t)

	startPool(t, &config.SSHConfig{
		Addr: "127.0.0.1", Port: srv.port(), User: "root", Password: "secret", Pool: 1,
		Locals: []config.CopyItem{{Host: echoHost, Port: echoPort, TargetPort: localPort}},
	})

	var conn net.Conn
	waitFor(t, "本地转发可用", func() bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), time.Second)
		if err != nil {
			return false
		}
		conn = c
		return true
	})
	defer conn.Close()
	echoOnce(t, conn, "local-forward-ok")
}

func TestPoolRemoteForward(t *testing.T) {
	srv := newTestSSHServer(t, "root", "secret")
	echoHost, echoPort := startEcho(t)
	remotePort := freePort(t)

	startPool(t, &config.SSHConfig{
		Addr: "127.0.0.1", Port: srv.port(), User: "root", Password: "secret", Pool: 1,
		Remotes: []config.CopyItem{{Host: echoHost, Port: echoPort, TargetPort: remotePort}},
	})

	waitFor(t, "服务器侧远程转发监听", func() bool { return srv.hasForward(remotePort) })

	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 3*time.Second)
	if err != nil {
		t.Fatalf("连接远程转发端口失败: %v", err)
	}
	defer conn.Close()
	echoOnce(t, conn, "remote-forward-ok")
}

func TestPoolAuthFailureKeepsRetrying(t *testing.T) {
	srv := newTestSSHServer(t, "root", "secret")
	pool := New(&config.SSHConfig{
		Addr: "127.0.0.1", Port: srv.port(), User: "root", Password: "wrong", Pool: 1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	pool.Start(ctx)
	defer func() {
		cancel()
		pool.Close()
	}()

	time.Sleep(500 * time.Millisecond)
	if c := pool.pick(); c != nil {
		t.Fatal("密码错误不应建立会话")
	}
}

func TestPoolReconnectAfterServerRestart(t *testing.T) {
	srv := newTestSSHServer(t, "root", "secret")
	echoHost, echoPort := startEcho(t)
	port := srv.port()

	pool, _ := startPool(t, &config.SSHConfig{
		Addr: "127.0.0.1", Port: port, User: "root", Password: "secret", Pool: 1,
	})
	first := pool.pick()
	if first == nil {
		t.Fatal("首个会话未建立")
	}

	// 关闭服务器侧连接，模拟链路中断；池应在退避后重连（同端口重新监听）
	srv.mu.Lock()
	for _, c := range srv.conns {
		_ = c.Close()
	}
	srv.conns = nil
	srv.mu.Unlock()
	_ = srv.ln.Close()
	waitFor(t, "会话断开", func() bool { return pool.pick() == nil })

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("端口 %d 无法重新监听，跳过重连断言: %v", port, err)
	}
	srv.ln = ln
	go srv.serve()

	// 断线后 runSlot 固定退避 reconnectWait(5s) 才重连，等待上限必须大于该值
	waitForTimeout(t, "重连成功", 3*reconnectWait, func() bool {
		c := pool.pick()
		return c != nil && c != first
	})
	conn, err := pool.DialContext(context.Background(), echoHost, echoPort)
	if err != nil {
		t.Fatalf("重连后建连失败: %v", err)
	}
	defer conn.Close()
	echoOnce(t, conn, "reconnect-ok")
}
