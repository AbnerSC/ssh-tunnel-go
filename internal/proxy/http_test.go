package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// startHTTPProxy 启动 HTTP 代理服务并返回监听地址。
func startHTTPProxy(t *testing.T, creds Credentials, route *Route) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go ServeHTTP(ln, creds, route)
	return ln.Addr().String()
}

func dialProxy(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, bufio.NewReader(conn)
}

// readHead 读取一个完整的响应头（含结尾空行）。
func readHead(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("读取响应头失败: %v (已读 %q)", err, sb.String())
		}
		sb.WriteString(line)
		if line == "\r\n" {
			return sb.String()
		}
	}
}

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func TestHTTPConnect(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))

	conn, br := dialProxy(t, addr)
	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", echoHost, echoPort, echoHost)
	writeConn(t, conn, []byte(req))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 200 Connection Established") {
		t.Fatalf("CONNECT 应答错误: %q", head)
	}

	payload := []byte("tls-or-any-bytes")
	writeConn(t, conn, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("读取隧道数据失败: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("隧道数据不一致: %q", got)
	}
}

func TestHTTPAuthRetryOnSameConnection(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))

	conn, br := dialProxy(t, addr)
	target := fmt.Sprintf("%s:%d", echoHost, echoPort)

	// 第一次不带凭据：407，且连接保持
	writeConn(t, conn, []byte("CONNECT "+target+" HTTP/1.1\r\nHost: "+echoHost+"\r\n\r\n"))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 407 Proxy Authentication Required") {
		t.Fatalf("应返回 407: %q", head)
	}

	// 同一连接上带凭据重试（git/libcurl 的行为）
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + echoHost +
		"\r\nProxy-Authorization: " + basicAuth("user", "pwd123") + "\r\n\r\n"
	writeConn(t, conn, []byte(req))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 200 Connection Established") {
		t.Fatalf("重试后应返回 200: %q", head)
	}

	payload := []byte("retry-ok")
	writeConn(t, conn, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("读取隧道数据失败: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("隧道数据不一致: %q", got)
	}
}

// TestHTTPAuthWithLFOnlyClient 只发 LF 换行的客户端也应能通过认证：
// readHeader 与头部切分必须使用同一套换行规则。
func TestHTTPAuthWithLFOnlyClient(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))

	conn, br := dialProxy(t, addr)
	req := "CONNECT " + echoHost + ":" + fmt.Sprint(echoPort) + " HTTP/1.1\n" +
		"Proxy-Authorization: " + basicAuth("user", "pwd123") + "\n\n"
	writeConn(t, conn, []byte(req))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 200 Connection Established") {
		t.Fatalf("LF 换行的请求应通过认证: %q", head)
	}
}

// TestHTTPForwardPhaseClearsReadDeadline 验证进入转发阶段后读截止时间被清除。
// 残留的 15s 头部超时会让持续超过 15s 的大文件下载被截断。
func TestHTTPForwardPhaseClearsReadDeadline(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	client, server := net.Pipe()
	defer client.Close()

	rec := &deadlineRecorder{Conn: server}
	go func() {
		defer server.Close()
		handleHTTP(rec, Credentials{}, directRoute("http"))
	}()

	req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\n\r\n", echoHost, echoPort)
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("写入请求失败: %v", err)
	}
	br := bufio.NewReader(client)
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 200") {
		t.Fatalf("应返回 200: %q", head)
	}

	rec.mu.Lock()
	last := rec.last
	rec.mu.Unlock()
	if !last.IsZero() {
		t.Fatalf("转发阶段应清除读截止时间，实际为 %v", last)
	}
}

// deadlineRecorder 记录最后一次读截止时间。
type deadlineRecorder struct {
	net.Conn
	mu   sync.Mutex
	last time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.last = t
	d.mu.Unlock()
	return d.Conn.SetReadDeadline(t)
}

func TestSplitHeaderLines(t *testing.T) {
	cases := []struct {
		name string
		head string
		want []string
	}{
		{"CRLF", "GET / HTTP/1.1\r\nHost: a\r\nX: 1", []string{"GET / HTTP/1.1", "Host: a", "X: 1"}},
		{"LF", "GET / HTTP/1.1\nHost: a\nX: 1", []string{"GET / HTTP/1.1", "Host: a", "X: 1"}},
		{"混合", "GET / HTTP/1.1\r\nHost: a\nX: 1", []string{"GET / HTTP/1.1", "Host: a", "X: 1"}},
		{"单行", "GET / HTTP/1.1", []string{"GET / HTTP/1.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitHeaderLines([]byte(tc.head))
			if len(got) != len(tc.want) {
				t.Fatalf("行数 = %d, want %d: %q", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("第 %d 行 = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestHTTPForwardRewrite(t *testing.T) {
	// 原始 TCP 目标服务，用于校验代理改写后的字节
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动目标服务失败: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	received := make(chan string, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var sb strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			sb.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		body := make([]byte, 3)
		if _, err := io.ReadFull(br, body); err == nil {
			sb.Write(body)
		}
		received <- sb.String()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))
	conn, br := dialProxy(t, addr)
	req := "POST http://127.0.0.1:" + fmt.Sprint(targetPort) + "/path?q=1 HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Connection: keep-alive\r\n" +
		"X-Test: 1\r\n\r\nabc"
	writeConn(t, conn, []byte(req))

	resp, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if !strings.HasPrefix(string(resp), "HTTP/1.1 200 OK") || !strings.HasSuffix(string(resp), "ok") {
		t.Fatalf("转发响应异常: %q", resp)
	}

	select {
	case head := <-received:
		want := "POST /path?q=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Test: 1\r\nConnection: close\r\n\r\nabc"
		if head != want {
			t.Fatalf("改写后的请求不一致:\n got %q\nwant %q", head, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("目标服务未收到请求")
	}
}

func TestHTTPForwardWithAuth(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动目标服务失败: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	headCh := make(chan string, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var sb strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			sb.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		headCh <- sb.String()
		_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
	}()

	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))
	conn, br := dialProxy(t, addr)
	req := "GET http://127.0.0.1:" + fmt.Sprint(targetPort) + "/ HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Proxy-Authorization: " + basicAuth("user", "pwd123") + "\r\n\r\n"
	writeConn(t, conn, []byte(req))

	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	select {
	case head := <-headCh:
		if strings.Contains(strings.ToLower(head), "proxy-authorization") {
			t.Fatalf("Proxy-Authorization 应被剔除: %q", head)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("目标服务未收到请求")
	}
}

func TestHTTPBadRequestForOriginForm(t *testing.T) {
	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))
	conn, br := dialProxy(t, addr)
	writeConn(t, conn, []byte("GET /origin-form HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("应返回 400: %q", head)
	}
}

func TestHTTPBadGateway(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))
	conn, br := dialProxy(t, addr)
	writeConn(t, conn, []byte(fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n", closedPort)))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 502 Bad Gateway") {
		t.Fatalf("应返回 502: %q", head)
	}
}

func TestHTTPHeaderTooLarge(t *testing.T) {
	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))
	conn, br := dialProxy(t, addr)
	// 发送超过 64KB 且不带 \r\n\r\n 的头部
	chunk := []byte(strings.Repeat("A", 8*1024))
	for i := 0; i < 9; i++ {
		if _, err := conn.Write(chunk); err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("超大头部应直接关闭连接")
	}
}

func TestParseHostPort(t *testing.T) {
	cases := []struct {
		in       string
		def      int
		wantHost string
		wantPort int
		wantOK   bool
	}{
		{"example.com", 443, "example.com", 443, true},
		{"example.com:8443", 443, "example.com", 8443, true},
		{"127.0.0.1:80", 443, "127.0.0.1", 80, true},
		{"[::1]:8080", 443, "::1", 8080, true},
		{"[::1]", 443, "::1", 443, true},
		{"", 443, "", 0, false},
		{"[::1", 443, "", 0, false},
		{"example.com:abc", 443, "", 0, false},
	}
	for _, c := range cases {
		host, port, ok := parseHostPort(c.in, c.def)
		if ok != c.wantOK || host != c.wantHost || port != c.wantPort {
			t.Fatalf("parseHostPort(%q) = (%q,%d,%v), want (%q,%d,%v)",
				c.in, host, port, ok, c.wantHost, c.wantPort, c.wantOK)
		}
	}
}

func TestCheckBasicAuth(t *testing.T) {
	creds := NewCredentials("user", "pwd123")
	cases := map[string]bool{
		basicAuth("user", "pwd123"):                          true,
		"basic " + basicAuth("user", "pwd123")[6:]:           true,
		basicAuth("user", "wrong"):                           false,
		base64.StdEncoding.EncodeToString([]byte("nocolon")): false,
		"Bearer token":                                       false,
		"":                                                   false,
	}
	for header, want := range cases {
		if got := checkBasicAuth(header, creds); got != want {
			t.Fatalf("checkBasicAuth(%q) = %v, want %v", header, got, want)
		}
	}
}
