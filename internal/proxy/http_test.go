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

// TestHTTPLeadingBlankLineBeforeRequestLine 验证请求行之前的空行被忽略。
//
// RFC 7230 §3.5 要求接收方忽略请求行前的空行；若在此返回空头部，
// 上层解析 lines[0] 会越界 panic，连接被直接关闭。
func TestHTTPLeadingBlankLineBeforeRequestLine(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))

	conn, br := dialProxy(t, addr)
	req := fmt.Sprintf("\r\n\r\nCONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", echoHost, echoPort, echoHost)
	writeConn(t, conn, []byte(req))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 200 Connection Established") {
		t.Fatalf("前导空行应被忽略: %q", head)
	}

	payload := []byte("after-blank-line")
	writeConn(t, conn, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("读取隧道数据失败: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("隧道数据不一致: %q", got)
	}
}

// TestHTTPEmptyHeadIsBadRequest 校验空头部的兜底处理：返回 400 而不是 panic。
func TestHTTPEmptyHeadIsBadRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		handleHTTPRequest(server, bufio.NewReader(server), nil, Credentials{}, directRoute("http"), nil, new(int))
	}()

	br := bufio.NewReader(client)
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("空头部应返回 400: %q", head)
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
		"Keep-Alive: timeout=5\r\n" +
		"X-Forwarded-For: 6.6.6.6\r\n" +
		"X-Real-IP: 6.6.6.6\r\n" +
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
		// 逐跳头（Proxy-Connection/Connection/Keep-Alive）与可伪造来源的身份头
		// （X-Forwarded-For/X-Real-IP）被剔除，Host 改写为 URI 指定的目标
		want := "POST /path?q=1 HTTP/1.1\r\nX-Test: 1\r\nHost: 127.0.0.1:" +
			fmt.Sprint(targetPort) + "\r\nConnection: close\r\n\r\nabc"
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

// TestHTTPForwardRejectsTECL 同时带 Transfer-Encoding 与 Content-Length 时直接拒绝。
//
// 两个字段共存是请求走私的原语：代理与源站若取不同字段切分消息边界，
// 后面的字节会被当成下一个请求处理。
func TestHTTPForwardRejectsTECL(t *testing.T) {
	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))
	conn, br := dialProxy(t, addr)
	req := "POST http://127.0.0.1:1/ HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 6\r\n\r\n0\r\n\r\n"
	writeConn(t, conn, []byte(req))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("TE+CL 同时出现应返回 400: %q", head)
	}
}

// TestHTTPForwardRejectsUserInfoHost URI 中带 user@host 时拒绝。
//
// 否则 hostPortStr 会把 "user@host" 整段当成主机名，既可能被解析成
// 与实际连接目标不一致的主机，也让 Host 改写失去意义。
func TestHTTPForwardRejectsUserInfoHost(t *testing.T) {
	addr := startHTTPProxy(t, Credentials{}, directRoute("http"))
	conn, br := dialProxy(t, addr)
	writeConn(t, conn, []byte("GET http://user@127.0.0.1:1/ HTTP/1.1\r\nHost: x\r\n\r\n"))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("含 userinfo 的 URI 应返回 400: %q", head)
	}
}

// TestHTTPAuthBansAfterRepeatedFailures 同一来源连续失败达阀值后必须断开连接。
//
// 旧实现每次 407 后都不断开也不限速，单条 TCP 连接上实测可达约 290 次/秒，
// 弱口令必然被猜中。
func TestHTTPAuthBansAfterRepeatedFailures(t *testing.T) {
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))
	conn, br := dialProxy(t, addr)

	bad := "CONNECT 127.0.0.1:1 HTTP/1.1\r\nProxy-Authorization: " +
		basicAuth("user", "wrong") + "\r\n\r\n"
	for i := 0; i < authFailLimit; i++ {
		writeConn(t, conn, []byte(bad))
		if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 407 ") {
			t.Fatalf("第 %d 次失败应返回 407: %q", i+1, head)
		}
	}

	// 达到阀值后连接应被关闭，无法继续在同一个连接上爆破
	writeConn(t, conn, []byte(bad))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("达到失败阀值后应断开连接")
	}
}

// TestAuthGuardBansAndResets 限速器的计数与清除行为。
func TestAuthGuardBansAndResets(t *testing.T) {
	guard := newAuthGuard()
	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	for i := 0; i < authFailLimit-1; i++ {
		if guard.Fail(remote) {
			t.Fatalf("第 %d 次不应封禁", i+1)
		}
	}
	if !guard.Fail(remote) {
		t.Fatal("达到阀值应封禁")
	}
	if !guard.Blocked(remote) {
		t.Fatal("封禁期内应返回 Blocked")
	}
	// 其他来源不受影响
	if guard.Blocked(&net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1234}) {
		t.Fatal("不应影响其他来源")
	}
	guard.Reset(remote)
	if guard.Blocked(remote) {
		t.Fatal("重置后应解除封禁")
	}
}

// TestCredentialMatch 常量时间比较的正确性（长度不等也必须安全返回 false）。
func TestCredentialMatch(t *testing.T) {
	if !credentialMatch("u", "p", "u", "p") {
		t.Fatal("相同凭据应匹配")
	}
	for _, tc := range [][4]string{
		{"u", "p", "u", "p2"},
		{"u", "p", "u2", "p"},
		{"", "p", "u", "p"},
		{"u", "p", "", ""},
		{"user", "pwd", "user", "pw"},
	} {
		if credentialMatch(tc[0], tc[1], tc[2], tc[3]) {
			t.Fatalf("不应匹配: %+v", tc)
		}
	}
}

// TestHTTPBannedSourceRejectedBeforeParsing 封禁期内不解析任何请求，直接 407 断开。
//
// 仅在认证失败分支检查封禁是不够的：封禁期内携带正确凭据依旧能通过，
// 每条新连接也仍能再试一次，爆破速率等于没被限制。
func TestHTTPBannedSourceRejectedBeforeParsing(t *testing.T) {
	creds := NewCredentials("user", "pwd123")
	client, server := net.Pipe()
	defer client.Close()

	// 把该来源直接打入封禁期，模拟连续失败达到阀值后的状态
	for i := 0; i < authFailLimit; i++ {
		creds.guard.Fail(client.RemoteAddr())
	}
	if !creds.guard.Blocked(client.RemoteAddr()) {
		t.Fatal("前置条件失败：来源应处于封禁期")
	}

	go func() {
		defer server.Close()
		handleHTTP(server, creds, directRoute("http"))
	}()

	// 不发送任何请求，封禁来源也应立即收到 407
	br := bufio.NewReader(client)
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 407 ") {
		t.Fatalf("封禁来源应直接收到 407: %q", head)
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

// --- Jetty / Apache HttpClient（Nexus 3 使用的客户端族）兼容性回归 ---

// TestHTTPProxyAuthenticateAdvertisesCharsetUTF8 校验 407 应答声明 charset="UTF-8"。
//
// Apache HttpClient 4.x 的 BasicScheme 在没有 charset 参数时按 ISO-8859-1 编码
// 凭据，本代理按 UTF-8 原始字节比较，密码含非 ASCII 字符时永远对不上。
func TestHTTPProxyAuthenticateAdvertisesCharsetUTF8(t *testing.T) {
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))
	conn, br := dialProxy(t, addr)

	writeConn(t, conn, []byte("CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n"))
	head := readHead(t, br)
	if !strings.HasPrefix(head, "HTTP/1.1 407 ") {
		t.Fatalf("应返回 407: %q", head)
	}
	if !strings.Contains(head, `charset="UTF-8"`) {
		t.Fatalf("Proxy-Authenticate 应声明 UTF-8 charset: %q", head)
	}
}

// TestHTTPBasicAuthUnicodePassword UTF-8 密码在声明 charset="UTF-8" 后能被
// Apache HttpClient 正确编码并通过校验（此前会因 ISO-8859-1 编码不一致失败）。
func TestHTTPBasicAuthUnicodePassword(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	user, pass := "nexus-admin", "päss中"
	creds := NewCredentials(user, pass)
	addr := startHTTPProxy(t, creds, directRoute("http"))
	conn, br := dialProxy(t, addr)
	target := fmt.Sprintf("%s:%d", echoHost, echoPort)

	// 客户端按 UTF-8 生成凭据（对应 charset="UTF-8" 的语义）
	req := "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: " +
		basicAuth(user, pass) + "\r\n\r\n"
	writeConn(t, conn, []byte(req))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 200 ") {
		t.Fatalf("UTF-8 密码应通过认证: %q", head)
	}

	// ISO-8859-1 编码的同一份凭据必须失败——保证 charset 声明真的生效而非
	// 退化成任意字节都能通过（避免误把不匹配放成匹配）
	conn2, br2 := dialProxy(t, addr)
	latin := encodeLatin1(user + ":" + pass)
	req2 := "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: Basic " + latin +
		"\r\n\r\n"
	writeConn(t, conn2, []byte(req2))
	if head := readHead(t, br2); !strings.HasPrefix(head, "HTTP/1.1 407 ") {
		t.Fatalf("ISO-8859-1 编码的 UTF-8 密码不应通过: %q", head)
	}
}

// encodeLatin1 按 ISO-8859-1 语义把字符串逐字符压到单字节再做 base64，
// 复现 Apache HttpClient 未收到 charset 参数时的凭据序列化行为。
// 超出 0xFF 的字符按 Java CharsetEncoder 的默认替换策略处理成 '?'。
func encodeLatin1(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r <= 0xFF {
			b = append(b, byte(r))
		} else {
			b = append(b, '?')
		}
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestHTTPReactiveAuthMissingHeaderNotBanned 复现 Nexus 3 侧最常见的场景：一批连接
// 每条首请求都不带 Proxy-Authorization（Apache HttpClient 的质询探测），且这些连接
// 随后被客户端直接丢弃（尚未走到带凭据的重试）。
//
// 关键：阶段一不做「成功重试」，避免 guard.Reset 把计数清零掩盖问题——
// 修复前把「没带凭据」也算作爆破失败，30 条连接必然累积到 10 次阈值并封禁来源，
// 末尾 Blocked 断言在旧实现下必然失败（旧行为回归可被捕获）。
func TestHTTPReactiveAuthMissingHeaderNotBanned(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))
	target := fmt.Sprintf("%s:%d", echoHost, echoPort)

	const n = authFailLimit * 3
	for i := 0; i < n; i++ {
		conn, br := dialProxy(t, addr)
		// 只发不带凭据的首请求：应收到 407；不重试、不触发 Reset
		writeConn(t, conn, []byte("CONNECT "+target+" HTTP/1.1\r\n\r\n"))
		if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 407 ") {
			t.Fatalf("第 %d 条连接首请求应收到 407: %q", i+1, head)
		}
		_ = conn.Close()
	}

	// 走完质询探测后来源仍处于「未封禁」状态
	if creds.guard.Blocked(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}) {
		t.Fatal("reactive 认证的首请求不应触发封禁")
	}

	// 随后正常带凭据的请求应无障碍通过
	conn, br := dialProxy(t, addr)
	req := "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: " +
		basicAuth("user", "pwd123") + "\r\n\r\n"
	writeConn(t, conn, []byte(req))
	if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 200 ") {
		t.Fatalf("质询探测后带凭据请求应通过: %q", head)
	}
	_ = conn.Close()
}

// TestHTTPPerConnChallengeCap 同一条连接反复只发无凭据请求时，超过每连接质询上限
// 后必须关连接，防止「无凭据不计数」被用来在同一连接上无限拿 407 空转占坑。
func TestHTTPPerConnChallengeCap(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))
	target := fmt.Sprintf("%s:%d", echoHost, echoPort)

	conn, br := dialProxy(t, addr)
	for i := 0; i < httpMaxChallengesPerConn; i++ {
		writeConn(t, conn, []byte("CONNECT "+target+" HTTP/1.1\r\n\r\n"))
		if head := readHead(t, br); !strings.HasPrefix(head, "HTTP/1.1 407 ") {
			t.Fatalf("第 %d 次质询应收到 407: %q", i+1, head)
		}
	}
	// 达到上限后连接应被关闭，无法继续在同一连接上空转
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("超过每连接质询上限后应断开连接")
	}
}

// TestHTTPForwardPostBodyReactiveAuthClosesConnection POST 带正文 + 首请求未带凭据时，
// 407 必须携带 Connection: close，避免客户端的重试请求与已发出的正文在同一连接上串包。
func TestHTTPForwardPostBodyReactiveAuthClosesConnection(t *testing.T) {
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))
	conn, br := dialProxy(t, addr)

	req := "POST http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n" +
		"Content-Length: 3\r\n\r\nabc"
	writeConn(t, conn, []byte(req))
	head := readHead(t, br)
	if !strings.HasPrefix(head, "HTTP/1.1 407 ") {
		t.Fatalf("POST 未带凭据应回 407: %q", head)
	}
	if !strings.Contains(strings.ToLower(head), "connection: close") {
		t.Fatalf("带正文的 407 必须显式关闭连接: %q", head)
	}
	// close 变体同样要声明 charset（与 keep-alive 变体一致，否则含非 ASCII 密码仍不匹配）
	if !strings.Contains(head, `charset="UTF-8"`) {
		t.Fatalf("close 变体的 Proxy-Authenticate 也应声明 UTF-8: %q", head)
	}
}

// TestHTTPForwardPostBodyReactiveAuthFullFlow 复现 Apache HttpClient 处理 POST 上传的完整流：
// 第一次 TCP 连接不带凭据 → 407+close；第二次 TCP 连接带凭据 → 转发到目标。
func TestHTTPForwardPostBodyReactiveAuthFullFlow(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动目标服务失败: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	done := make(chan string, 1)
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
		body := make([]byte, 5)
		if _, err := io.ReadFull(br, body); err == nil {
			sb.Write(body)
		}
		done <- sb.String()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))

	// 第一条连接：不带凭据的 POST，收到 407+close
	c1, b1 := dialProxy(t, addr)
	writeConn(t, c1, []byte("POST http://127.0.0.1:"+fmt.Sprint(targetPort)+"/up HTTP/1.1\r\n"+
		"Host: 127.0.0.1\r\nContent-Length: 5\r\n\r\nhello"))
	head := readHead(t, b1)
	if !strings.HasPrefix(head, "HTTP/1.1 407 ") || !strings.Contains(strings.ToLower(head), "connection: close") {
		t.Fatalf("首请求应收到 407+close: %q", head)
	}
	_ = c1.Close()

	// 第二条连接：带凭据重试
	c2, b2 := dialProxy(t, addr)
	writeConn(t, c2, []byte("POST http://127.0.0.1:"+fmt.Sprint(targetPort)+"/up HTTP/1.1\r\n"+
		"Host: 127.0.0.1\r\nContent-Length: 5\r\nProxy-Authorization: "+basicAuth("user", "pwd123")+
		"\r\n\r\nhello"))
	resp, err := io.ReadAll(b2)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if !strings.HasPrefix(string(resp), "HTTP/1.1 200 OK") {
		t.Fatalf("重试后应完成转发: %q", resp)
	}

	select {
	case got := <-done:
		if !strings.Contains(got, "hello") {
			t.Fatalf("目标侧未收到正文: %q", got)
		}
		if strings.Contains(strings.ToLower(got), "proxy-authorization") {
			t.Fatalf("Proxy-Authorization 应被剔除: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("目标服务未收到请求")
	}
}

// TestHTTPBasicAuthLenientWhitespace 认证方案与凭据之间出现多余空格或制表符时
// 仍应识别（RFC 7235 只允许 SP，但 Java 生态里老 Jetty client / 手工拼装的
// 客户端偶尔会给出 "Basic\t" 或 "Basic  " 这类形态）。
func TestHTTPBasicAuthLenientWhitespace(t *testing.T) {
	creds := NewCredentials("user", "pwd123")
	b64 := base64.StdEncoding.EncodeToString([]byte("user:pwd123"))
	cases := map[string]bool{
		"Basic " + b64:       true,
		"Basic  " + b64:      true,  // 双空格
		"Basic\t" + b64:      true,  // 制表符
		"  Basic " + b64:     true,  // 前置空白（parseHTTPHeaders 已 TrimSpace，这里覆盖直接调用）
		"BASIC " + b64:       true,  // 大小写
		"Basic" + b64:        false, // 缺少分隔空白
		"Bearer " + b64:      false,
		"BasicAuther " + b64: false,
	}
	for header, want := range cases {
		if got := checkBasicAuth(header, creds); got != want {
			t.Fatalf("checkBasicAuth(%q) = %v, want %v", header, got, want)
		}
	}
}

// TestHTTPConcurrentReactiveAuthNoBan 并发场景下模拟 PoolingHttpClientConnectionManager
// 一次性发起多路 CONNECT：验证不会出现「一部分连接被误封」的时序问题。
func TestHTTPConcurrentReactiveAuthNoBan(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)
	creds := NewCredentials("user", "pwd123")
	addr := startHTTPProxy(t, creds, directRoute("http"))
	target := fmt.Sprintf("%s:%d", echoHost, echoPort)

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()
			br := bufio.NewReader(conn)
			writeReq(conn, "CONNECT "+target+" HTTP/1.1\r\n\r\n")
			if head := readHeadOrErr(br); !strings.HasPrefix(head, "HTTP/1.1 407 ") {
				errCh <- fmt.Errorf("首请求应收到 407: %q", head)
				return
			}
			writeReq(conn, "CONNECT "+target+" HTTP/1.1\r\nProxy-Authorization: "+
				basicAuth("user", "pwd123")+"\r\n\r\n")
			if head := readHeadOrErr(br); !strings.HasPrefix(head, "HTTP/1.1 200 ") {
				errCh <- fmt.Errorf("重试应通过: %q", head)
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func writeReq(conn net.Conn, s string) {
	_, _ = io.WriteString(conn, s)
}

func readHeadOrErr(br *bufio.Reader) string {
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			return sb.String()
		}
		if line == "\r\n" {
			return sb.String()
		}
	}
}
