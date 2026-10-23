package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// startEchoServer 启动回显服务器，返回可访问的主机与端口。
func startEchoServer(t *testing.T) (string, int) {
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
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// startSocks5 启动 SOCKS5 服务并返回监听地址。
func startSocks5(t *testing.T, creds Credentials, route *Route) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go ServeSocks5(ln, creds, route)
	return ln.Addr().String()
}

func directRoute(proto string) *Route {
	return &Route{Proto: proto, Direct: LocalDialer{Timeout: time.Second}}
}

func mustRead(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("读取 %d 字节失败: %v", n, err)
	}
	return buf
}

func writeConn(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
}

func socksRequest(host string, port int) []byte {
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(req, 1)
		req = append(req, ip...)
	} else {
		req = socksDomainRequest(host, port)
		return req
	}
	return append(req, byte(port>>8), byte(port))
}

// socksDomainRequest 强制使用域名类型(ATYP=3)的请求。
func socksDomainRequest(host string, port int) []byte {
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	return append(req, byte(port>>8), byte(port))
}

func TestSocks5NoAuth(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	addr := startSocks5(t, Credentials{}, directRoute("socks5"))

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	writeConn(t, conn, []byte{5, 1, 0})
	if got := mustRead(t, conn, 2); got[0] != 5 || got[1] != 0 {
		t.Fatalf("握手应答错误: %v", got)
	}

	writeConn(t, conn, socksRequest(echoHost, echoPort))
	// 应答回显请求地址：VER REP RSV ATYP + IPv4(4) + PORT(2)
	reply := mustRead(t, conn, 10)
	if reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("CONNECT 应答错误: %v", reply)
	}

	payload := []byte("hello socks5")
	writeConn(t, conn, payload)
	if got := mustRead(t, conn, len(payload)); string(got) != string(payload) {
		t.Fatalf("回显不一致: %q", got)
	}
}

func TestSocks5DomainATYP(t *testing.T) {
	_, echoPort := startEchoServer(t)
	addr := startSocks5(t, Credentials{}, directRoute("socks5"))

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	writeConn(t, conn, []byte{5, 1, 0})
	mustRead(t, conn, 2)

	host := "127.0.0.1"
	writeConn(t, conn, socksDomainRequest(host, echoPort))
	// 应答回显请求地址：VER REP + RSV ATYP LEN + 域名 + PORT
	reply := mustRead(t, conn, 2+3+len(host)+2)
	if reply[0] != 5 || reply[1] != 0 || reply[3] != 3 || string(reply[5:5+len(host)]) != host {
		t.Fatalf("域名类型应答错误: %v", reply)
	}

	payload := []byte("domain ok")
	writeConn(t, conn, payload)
	if got := mustRead(t, conn, len(payload)); string(got) != string(payload) {
		t.Fatalf("回显不一致: %q", got)
	}
}

func TestSocks5Auth(t *testing.T) {
	_, echoPort := startEchoServer(t)
	creds := NewCredentials("user", "pwd123")
	addr := startSocks5(t, creds, directRoute("socks5"))

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	writeConn(t, conn, []byte{5, 2, 0, 2})
	if got := mustRead(t, conn, 2); got[0] != 5 || got[1] != 2 {
		t.Fatalf("应选择账号密码认证: %v", got)
	}

	auth := []byte{1, 4}
	auth = append(auth, "user"...)
	auth = append(auth, 6)
	auth = append(auth, "pwd123"...)
	writeConn(t, conn, auth)
	if got := mustRead(t, conn, 2); got[0] != 1 || got[1] != 0 {
		t.Fatalf("认证应通过: %v", got)
	}

	writeConn(t, conn, socksRequest("127.0.0.1", echoPort))
	if reply := mustRead(t, conn, 10); reply[1] != 0 {
		t.Fatalf("CONNECT 应成功: %v", reply)
	}

	payload := []byte("auth ok")
	writeConn(t, conn, payload)
	if got := mustRead(t, conn, len(payload)); string(got) != string(payload) {
		t.Fatalf("回显不一致: %q", got)
	}
}

func TestSocks5AuthFailed(t *testing.T) {
	creds := NewCredentials("user", "pwd123")
	addr := startSocks5(t, creds, directRoute("socks5"))

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	writeConn(t, conn, []byte{5, 1, 2})
	mustRead(t, conn, 2)

	auth := []byte{1, 4}
	auth = append(auth, "user"...)
	auth = append(auth, 7)
	auth = append(auth, "wrongpw"...)
	writeConn(t, conn, auth)
	if got := mustRead(t, conn, 2); got[0] != 1 || got[1] != 1 {
		t.Fatalf("认证应失败: %v", got)
	}

	// 认证失败后服务端应关闭连接
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("认证失败后连接应关闭")
	}
}

func TestSocks5MethodNotSupported(t *testing.T) {
	addr := startSocks5(t, NewCredentials("user", "pwd"), directRoute("socks5"))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	writeConn(t, conn, []byte{5, 1, 0})
	if got := mustRead(t, conn, 2); got[0] != 5 || got[1] != 0xFF {
		t.Fatalf("应拒绝不支持的认证方式: %v", got)
	}
}

func TestSocks5DialFailure(t *testing.T) {
	// 先占一个端口再释放，确保目标端口无人监听
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	addr := startSocks5(t, Credentials{}, directRoute("socks5"))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	writeConn(t, conn, []byte{5, 1, 0})
	mustRead(t, conn, 2)
	writeConn(t, conn, socksRequest("127.0.0.1", closedPort))

	reply := mustRead(t, conn, 10)
	if reply[1] != 0x03 {
		t.Fatalf("连接失败应返回 0x03: %v", reply)
	}
}

func TestSocks5UnsupportedCommand(t *testing.T) {
	addr := startSocks5(t, Credentials{}, directRoute("socks5"))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	writeConn(t, conn, []byte{5, 1, 0})
	mustRead(t, conn, 2)
	// CMD=2(BIND)：与 Java 版一致，不回包直接关闭
	writeConn(t, conn, []byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80})

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("不支持的命令应直接关闭连接")
	}
}
