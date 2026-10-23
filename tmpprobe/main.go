// 临时边界场景测试工具（测试完成后删除）
//
//	go run ./tmpprobe -http 172.17.1.213:11825 -socks 172.17.1.213:11823 -u user -pw pass -target 172.81.101.78:19090
//
// 覆盖：SOCKS5 非常规命令/畸形握手/慢速客户端、HTTP 畸形请求/超长头/407 同连接重试/
// IPv6 目标、半开连接中断、空闲长连接、chunked 上传。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	httpAddr  = flag.String("http", "", "HTTP 代理地址")
	socksAddr = flag.String("socks", "", "SOCKS5 代理地址")
	user      = flag.String("u", "", "代理账号")
	pass      = flag.String("pw", "", "代理密码")
	target    = flag.String("target", "", "测试目标 host:port")
)

func main() {
	flag.Parse()
	results := [][3]string{}

	record := func(name string, ok bool, detail string) {
		flag := "FAIL"
		if ok {
			flag = "PASS"
		}
		results = append(results, [3]string{flag, name, detail})
		fmt.Printf("[%s] %-46s %s\n", flag, name, detail)
	}

	// E1 SOCKS5 UDP ASSOCIATE
	rep, err := socksCmd(*socksAddr, 3)
	record("E1 SOCKS5 UDP ASSOCIATE 回 0x07", err == nil && rep == 0x07, fmt.Sprintf("rep=0x%02x err=%v", rep, err))

	// E2 SOCKS5 BIND
	rep, err = socksCmd(*socksAddr, 2)
	record("E2 SOCKS5 BIND 回 0x07", err == nil && rep == 0x07, fmt.Sprintf("rep=0x%02x err=%v", rep, err))

	// E3 SOCKS5 非法 ATYP
	rep, err = socksBadAtyp(*socksAddr)
	record("E3 SOCKS5 非法ATYP 回 0x08", err == nil && rep == 0x08, fmt.Sprintf("rep=0x%02x err=%v", rep, err))

	// E4 SOCKS5 无可用认证方法
	code, err := socksNoMethod(*socksAddr)
	record("E4 SOCKS5 无可用认证方法回 0xFF", err == nil && code == 0xFF, fmt.Sprintf("method=0x%02x err=%v", code, err))

	// E5 SOCKS5 慢速客户端（不发数据应被 5s 超时关闭）
	// 关闭时读端必然得到 EOF，不能把 EOF 当作失败
	d, err := socksSlow(*socksAddr)
	record("E5 SOCKS5 空连接 5s 内被关闭", d < 8*time.Second, fmt.Sprintf("closed_after=%v err=%v", d.Round(100*time.Millisecond), err))

	// E6 HTTP 畸形请求行
	line, err := httpGarbage(*httpAddr)
	record("E6 HTTP 畸形请求行回 400", err == nil && strings.Contains(line, "400"), fmt.Sprintf("resp=%q err=%v", line, err))

	// E7 HTTP 407 后同连接带凭据重试
	ok, detail := http407Retry(*httpAddr, *user, *pass, *target)
	record("E7 HTTP 407 后同连接重试成功", ok, detail)

	// E8 HTTP 超长请求头
	ok, detail = httpHugeHeader(*httpAddr, *user, *pass)
	record("E8 HTTP 超长请求头被拒绝", ok, detail)

	// E9 HTTP CONNECT IPv6 字面量（服务端无 IPv6 应快速回 502，不挂起）
	ok, detail = httpConnectV6(*httpAddr, *user, *pass)
	record("E9 HTTP CONNECT IPv6 快速失败", ok, detail)

	// E10 下载中途断开不影响后续请求
	ok, detail = abortMidDownload(*httpAddr, *user, *pass, *target)
	record("E10 下载中途断开后服务仍正常", ok, detail)

	// E11 空闲长连接保持
	ok, detail = idleSocksConn(*socksAddr, *user, *pass, *target)
	record("E11 SOCKS5 长连接空闲 45s 不断开", ok, detail)

	// E12 chunked 上传透传
	ok, detail = httpChunkedUpload(*httpAddr, *user, *pass, *target)
	record("E12 HTTP chunked 上传透传", ok, detail)

	// E13 HEAD 绝对 URI（目标服务器可能不支持 HEAD，此时透传 501 也说明转发成功）
	ok, detail = httpHead(*httpAddr, *user, *pass, *target)
	record("E13 HTTP HEAD 绝对URI 转发成功", ok, detail)

	// E14 请求行前的裸 CRLF（RFC 7230 §3.5 应忽略；旧版本会因空头部 panic 直接断连）
	ok, detail = httpLeadingBlankLine(*httpAddr, *user, *pass, *target)
	record("E14 HTTP 前导空行被忽略", ok, detail)

	fails := 0
	for _, r := range results {
		if r[0] == "FAIL" {
			fails++
		}
	}
	fmt.Printf("\nsummary: %d/%d passed\n", len(results)-fails, len(results))
}

func dialSocks() (net.Conn, error) {
	return net.DialTimeout("tcp", *socksAddr, 5*time.Second)
}

// socksHandshake 完成 greeting + 认证，返回连接。
func socksHandshake(c net.Conn) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 2, 0, 2}); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := readFull(c, resp[:]); err != nil {
		return err
	}
	if resp[1] != 2 {
		return fmt.Errorf("server chose method %d", resp[1])
	}
	auth := []byte{1, byte(len(*user))}
	auth = append(auth, *user...)
	auth = append(auth, byte(len(*pass)))
	auth = append(auth, *pass...)
	if _, err := c.Write(auth); err != nil {
		return err
	}
	var ar [2]byte
	if _, err := readFull(c, ar[:]); err != nil {
		return err
	}
	if ar[1] != 0 {
		return fmt.Errorf("auth failed")
	}
	return nil
}

func socksCmd(addr string, cmd byte) (byte, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if err := socksHandshake(c); err != nil {
		return 0, err
	}
	host, port, _ := net.SplitHostPort(*target)
	ip := net.ParseIP(host).To4()
	req := []byte{5, cmd, 0, 1}
	req = append(req, ip...)
	p := atoi(port)
	req = append(req, byte(p>>8), byte(p))
	if _, err := c.Write(req); err != nil {
		return 0, err
	}
	var hdr [4]byte
	if _, err := readFull(c, hdr[:]); err != nil {
		return 0, err
	}
	return hdr[1], nil
}

func socksBadAtyp(addr string) (byte, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if err := socksHandshake(c); err != nil {
		return 0, err
	}
	if _, err := c.Write([]byte{5, 1, 0, 9, 0, 80}); err != nil {
		return 0, err
	}
	var hdr [4]byte
	if _, err := readFull(c, hdr[:]); err != nil {
		return 0, err
	}
	return hdr[1], nil
}

func socksNoMethod(addr string) (byte, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0x01}); err != nil { // 仅 GSSAPI
		return 0, err
	}
	var resp [2]byte
	if _, err := readFull(c, resp[:]); err != nil {
		return 0, err
	}
	return resp[1], nil
}

func socksSlow(addr string) (time.Duration, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	start := time.Now()
	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	_, err = c.Read(buf)
	return time.Since(start), err
}

func httpProxyDial() (net.Conn, error) {
	c, err := net.DialTimeout("tcp", *httpAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	return c, nil
}

func httpGarbage(addr string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("GARBAGE\r\n\r\n")); err != nil {
		return "", err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	return line, err
}

// readHTTPHead 读完一个完整的响应头（含结尾空行）。
//
// 407 应答除状态行外还带 Proxy-Authenticate 等头部，
// 不读完就在同一连接上重试会把上一次的残留头部当成新响应。
func readHTTPHead(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		if line == "\r\n" || line == "\n" {
			return sb.String(), nil
		}
	}
}

func http407Retry(addr, user, pass, target string) (bool, string) {
	c, err := httpProxyDial()
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	host, port, _ := net.SplitHostPort(target)
	req := fmt.Sprintf("GET http://%s:%s/ping HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
	if _, err := c.Write([]byte(req)); err != nil {
		return false, err.Error()
	}
	br := bufio.NewReader(c)
	head, err := readHTTPHead(br)
	if err != nil || !strings.Contains(head, "407") {
		return false, fmt.Sprintf("first=%q err=%v", truncate(head, 80), err)
	}
	// 同一连接带凭据重试
	req2 := fmt.Sprintf("GET http://%s:%s/ping HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		host, port, host, port, basic(user, pass))
	if _, err := c.Write([]byte(req2)); err != nil {
		return false, err.Error()
	}
	head2, err := readHTTPHead(br)
	if err != nil || !strings.Contains(head2, "200") {
		return false, fmt.Sprintf("retry=%q err=%v", truncate(head2, 80), err)
	}
	return true, "407 then 200"
}

func basic(user, pass string) string {
	return base64Std(user + ":" + pass)
}

func httpHugeHeader(addr, user, pass string) (bool, string) {
	c, err := httpProxyDial()
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	host, port, _ := net.SplitHostPort(*target)
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET http://%s:%s/ping HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n",
		host, port, host, port, basic(user, pass))
	big := strings.Repeat("X-Pad: "+strings.Repeat("a", 1000)+"\r\n", 80)
	sb.WriteString(big)
	sb.WriteString("\r\n")
	if _, err := c.Write([]byte(sb.String())); err != nil {
		return true, "write broke (closed early)"
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return true, "connection closed as expected"
	}
	return false, fmt.Sprintf("got %q", line)
}

func httpConnectV6(addr, user, pass string) (bool, string) {
	c, err := httpProxyDial()
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	req := fmt.Sprintf("CONNECT [2606:4700::6810:b8f1]:80 HTTP/1.1\r\nHost: [2606:4700::6810:b8f1]:80\r\nProxy-Authorization: Basic %s\r\n\r\n",
		basic(user, pass))
	start := time.Now()
	if _, err := c.Write([]byte(req)); err != nil {
		return false, err.Error()
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	took := time.Since(start)
	if err != nil {
		return true, fmt.Sprintf("closed after %v (acceptable)", took.Round(time.Millisecond))
	}
	return strings.Contains(line, "502"), fmt.Sprintf("%q after %v", strings.TrimSpace(line), took.Round(time.Millisecond))
}

func abortMidDownload(addr, user, pass, target string) (bool, string) {
	host, port, _ := net.SplitHostPort(target)
	for i := 0; i < 3; i++ {
		c, err := httpProxyDial()
		if err != nil {
			return false, err.Error()
		}
		req := fmt.Sprintf("GET http://%s:%s/down?size=20971520 HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			host, port, host, port, basic(user, pass))
		c.Write([]byte(req))
		buf := make([]byte, 65536)
		read := 0
		for read < 1<<20 {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			read += n
		}
		c.Close() // 中途强行断开
	}
	// 后续请求应正常
	c, err := httpProxyDial()
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	req := fmt.Sprintf("GET http://%s:%s/ping HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		host, port, host, port, basic(user, pass))
	c.Write([]byte(req))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return false, fmt.Sprintf("follow-up failed: %v", err)
	}
	return strings.Contains(line, "200"), fmt.Sprintf("follow-up %q", strings.TrimSpace(line))
}

func idleSocksConn(addr, user, pass, target string) (bool, string) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	if err := socksHandshake(c); err != nil {
		return false, err.Error()
	}
	host, port, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host).To4()
	req := []byte{5, 1, 0, 1}
	req = append(req, ip...)
	p := atoi(port)
	req = append(req, byte(p>>8), byte(p))
	if _, err := c.Write(req); err != nil {
		return false, err.Error()
	}
	var hdr [10]byte
	if _, err := readFull(c, hdr[:]); err != nil {
		return false, err.Error()
	}
	if hdr[1] != 0 {
		return false, fmt.Sprintf("connect rep=0x%02x", hdr[1])
	}
	// 建立隧道后不发任何字节，空闲 45s 再发请求：验证隧道本身不会空闲超时断开。
	// （之前先发一次带 Connection: close 的请求再空等，是目标服务主动关闭连接，
	// 测不出隧道行为）
	time.Sleep(45 * time.Second)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte("GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		return false, fmt.Sprintf("after idle write: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		return false, fmt.Sprintf("after idle: %v", err)
	}
	return strings.Contains(string(buf[:n]), "200"), fmt.Sprintf("alive after 45s idle, read %d bytes", n)
}

func httpChunkedUpload(addr, user, pass, target string) (bool, string) {
	c, err := httpProxyDial()
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	host, port, _ := net.SplitHostPort(target)
	body := strings.Repeat("hello", 1000)
	req := fmt.Sprintf("POST http://%s:%s/up HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n"+
		"Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n%x\r\n%s\r\n0\r\n\r\n",
		host, port, host, port, basic(user, pass), len(body), body)
	wantLen := len(body)
	if _, err := c.Write([]byte(req)); err != nil {
		return false, err.Error()
	}
	br := bufio.NewReader(c)
	head, err := readHTTPHead(br)
	if err != nil {
		return false, err.Error()
	}
	if !strings.Contains(head, "200") {
		return false, truncate(head, 80)
	}
	// 目标为 HTTP/1.0，响应后关闭连接：读到 EOF 即为完整响应体
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var sb strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, rerr := br.Read(tmp)
		sb.Write(tmp[:n])
		if rerr != nil {
			break
		}
	}
	got := sb.String()
	return strings.Contains(got, fmt.Sprint(wantLen)), fmt.Sprintf("resp head=%q body~%q", strings.TrimSpace(head[:strings.IndexByte(head, '\n')]), truncate(strings.TrimSpace(got), 40))
}

func httpHead(addr, user, pass, target string) (bool, string) {
	c, err := httpProxyDial()
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	host, port, _ := net.SplitHostPort(target)
	req := fmt.Sprintf("HEAD http://%s:%s/ping HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		host, port, host, port, basic(user, pass))
	if _, err := c.Write([]byte(req)); err != nil {
		return false, err.Error()
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return false, err.Error()
	}
	return strings.HasPrefix(line, "HTTP/1."), fmt.Sprintf("%q（目标不支持 HEAD 时透传 501 属正常）", strings.TrimSpace(line))
}

// httpLeadingBlankLine 先发裸 CRLF 再发正常请求。
// RFC 7230 §3.5：接收方必须忽略请求行之前的空行。
func httpLeadingBlankLine(addr, user, pass, target string) (bool, string) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	host, port, _ := net.SplitHostPort(target)
	req := fmt.Sprintf("\r\n\r\nGET http://%s:%s/ping HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		host, port, host, port, basic(user, pass))
	if _, err := c.Write([]byte(req)); err != nil {
		return false, err.Error()
	}
	br := bufio.NewReader(c)
	head, err := readHTTPHead(br)
	if err != nil {
		return false, fmt.Sprintf("closed/err=%v（旧版会因空头部 panic 直接断连）", err)
	}
	return strings.Contains(head, "200"), fmt.Sprintf("%q", truncate(head, 40))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func base64Std(s string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		v := uint32(chunk[0])<<16 | uint32(chunk[1])<<8 | uint32(chunk[2])
		out.WriteByte(table[(v>>18)&63])
		out.WriteByte(table[(v>>12)&63])
		if n > 1 {
			out.WriteByte(table[(v>>6)&63])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(table[v&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}
