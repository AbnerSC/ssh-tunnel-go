package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
)

const (
	// httpHeaderTimeout 等待请求头首字节的超时
	httpHeaderTimeout = 5 * time.Second
	// httpHeaderTotalTimeout 收完整个请求头的总时限。
	// 只限制首字节不够：逐字节慢速发送（Slowloris）会永久占用连接；
	// 正常客户端的头部远小于该值，不受影响。
	httpHeaderTotalTimeout = 15 * time.Second
	// httpMaxHeaderSize 请求头上限，超过视为非法连接直接关闭
	httpMaxHeaderSize = 64 * 1024
	// httpReadBuffer 每连接初始读缓冲。常规请求头可在一个缓冲内读完；
	// 头部较大时由 readHeader 按需累积（上限 httpMaxHeaderSize），
	// 避免高并发下每连接固定 64KB 的内存开销。
	httpReadBuffer = 4 * 1024
)

var (
	// errHeaderTooLarge 请求头超过上限
	errHeaderTooLarge = errors.New("http: 请求头过大")
)

// 应答报文与 Java 版逐字节保持一致（ISO-8859-1 编码即原始字节）
var (
	replyEstablished  = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	replyBadGateway   = []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	replyBadRequest   = []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	replyAuthRequired = []byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"ssh-tunnel\"\r\nContent-Length: 0\r\n\r\n")
)

// ServeHTTP 启动 HTTP 代理服务。
func ServeHTTP(ln net.Listener, creds Credentials, route *Route) {
	Serve(ln, "http", func(conn net.Conn) {
		handleHTTP(conn, creds, route)
	})
}

// handleHTTP 处理单条客户端连接。
//
// 与 Java 版一致：认证失败回 407 但不断开连接，客户端可在同一连接上带凭据重试；
// 其余请求（CONNECT 隧道 / 普通转发）转发结束后立即关闭连接。
func handleHTTP(conn net.Conn, creds Credentials, route *Route) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	logging.Debug("http", "http代理收到连接请求", "remote", remote)

	br := bufio.NewReaderSize(conn, httpReadBuffer)
	for {
		head, err := readHeader(conn, br)
		if err != nil {
			if err == errHeaderTooLarge {
				logging.Warn("http", "http代理请求头过大，关闭", "remote", remote)
			} else if !errors.Is(err, io.EOF) {
				logging.Debug("http", "http代理读取请求头失败", "remote", remote, "err", err)
			}
			return
		}
		if !handleHTTPRequest(conn, br, head, creds, route, remote) {
			return
		}
	}
}

// handleHTTPRequest 解析并派发单个请求，返回 true 表示继续在同一连接上读下一个请求（仅 407 场景）。
func handleHTTPRequest(conn net.Conn, br *bufio.Reader, head []byte, creds Credentials, route *Route,
	remote net.Addr) bool {
	lines := splitHeaderLines(head)
	// readHeader 已跳过请求行前的空行，正常不会为空；这里兜底防御，
	// 避免畸形输入（如只有 CRLF 的连接）导致 lines[0] 越界 panic
	if len(lines) == 0 {
		writeAndClose(conn, replyBadRequest)
		return false
	}
	// 用 Fields 容忍多个空格，同时避免空字段导致 index 越界
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		writeAndClose(conn, replyBadRequest)
		return false
	}
	method := strings.ToUpper(fields[0])
	uri := fields[1]
	version := "HTTP/1.1"
	if len(fields) > 2 {
		version = fields[2]
	}
	headers := parseHTTPHeaders(lines)

	// 认证：http 代理使用 Proxy-Authorization: Basic
	if creds.Enabled && !checkBasicAuth(headers["proxy-authorization"], creds) {
		logging.Warn("http", "http代理认证不通过", "remote", remote)
		// 不携带 Connection: close：客户端可在同一连接上带凭据重试，
		// 避免高并发下每个请求都要「新连接→407→关连接→再新连接」的双连接模式
		_ = writeAll(conn, replyAuthRequired)
		return true
	}

	// 认证通过，进入转发阶段：必须清除握手阶段的读截止时间。
	// readHeader 设置的 15s 总时限只用于收请求头，若残留到转发阶段，
	// 任何持续超过 15s 的下载都会在 io.Copy 读时超时并断开（大文件被截断）。
	_ = conn.SetReadDeadline(time.Time{})

	if method == "CONNECT" {
		handleConnect(conn, br, uri, route, remote)
	} else {
		handleForward(conn, br, method, uri, version, lines, route, remote)
	}
	return false
}

// handleConnect CONNECT 隧道：多用于 HTTPS，建立到 host:port 的透传连接后回 200。
func handleConnect(conn net.Conn, br *bufio.Reader, uri string, route *Route, remote net.Addr) {
	host, port, ok := parseHostPort(uri, 443)
	if !ok {
		writeAndClose(conn, replyBadRequest)
		return
	}
	logging.Debug("http", "http代理 CONNECT 请求", "target", net.JoinHostPort(host, strconv.Itoa(port)), "remote", remote)

	target, err := route.Dial(context.Background(), host, port)
	if err != nil {
		logging.Warn("http", "http代理无法连接请求", "target", net.JoinHostPort(host, strconv.Itoa(port)), "err", err)
		writeAndClose(conn, replyBadGateway)
		return
	}
	defer target.Close()

	// 握手包内可能已带上 TLS 数据，先写给目标，再回 200 给客户端
	if err := drainBuffered(br, target); err != nil {
		return
	}
	if err := writeAll(conn, replyEstablished); err != nil {
		return
	}
	logging.Debug("http", "http代理目标连接成功", "target", net.JoinHostPort(host, strconv.Itoa(port)), "remote", remote)
	Relay(&bufferedConn{Conn: conn, r: br}, target)
}

// handleForward 普通 HTTP 转发：客户端发送绝对 URI（http://host/path），改写为源站形式后转发，
// 并强制 Connection: close 以保证单请求单连接的正确性。
func handleForward(conn net.Conn, br *bufio.Reader, method, uri, version string, lines []string,
	route *Route, remote net.Addr) {
	if !strings.HasPrefix(uri, "http://") {
		// 非绝对 URI（源站形式）不应发给代理，视为非法
		writeAndClose(conn, replyBadRequest)
		return
	}
	rest := uri[len("http://"):]
	hostPortStr := rest
	path := "/"
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		hostPortStr = rest[:slash]
		path = rest[slash:]
	}
	host, port, ok := parseHostPort(hostPortStr, 80)
	if !ok {
		writeAndClose(conn, replyBadRequest)
		return
	}

	// 重建请求报文：请求行改为源站形式，剔除逐跳/代理专用头，追加 Connection: close
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(path)
	sb.WriteByte(' ')
	sb.WriteString(version)
	sb.WriteString("\r\n")
	for _, line := range lines[1:] {
		c := strings.IndexByte(line, ':')
		if c < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:c]))
		if key == "proxy-authorization" || key == "proxy-connection" || key == "connection" {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	logging.Debug("http", "http代理转发请求", "method", method, "target", targetAddr, "path", path, "remote", remote)
	target, err := route.Dial(context.Background(), host, port)
	if err != nil {
		logging.Warn("http", "http代理无法连接请求", "target", targetAddr, "err", err)
		writeAndClose(conn, replyBadGateway)
		return
	}
	defer target.Close()

	// 普通转发无需向客户端应答（等待目标响应）；改写后的请求报文作为首包写给目标
	if err := writeAll(target, []byte(sb.String())); err != nil {
		return
	}
	if err := drainBuffered(br, target); err != nil {
		return
	}
	logging.Debug("http", "http代理目标连接成功", "target", targetAddr, "remote", remote)
	Relay(&bufferedConn{Conn: conn, r: br}, target)
}

// readHeader 读取一个完整的请求头（不含结尾的 \r\n\r\n）。
//
// 首字节到达前受 httpHeaderTimeout 约束；首字节到达后整个头部受
// httpHeaderTotalTimeout 约束。读取按行进行（ReadSlice），
// 比逐字节 ReadByte 少几个数量级的函数调用，在头部较大或并发较高时差距明显。
func readHeader(conn net.Conn, br *bufio.Reader) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(httpHeaderTimeout))
	if _, err := br.Peek(1); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(httpHeaderTotalTimeout))

	head := make([]byte, 0, 512)
	for {
		line, err := br.ReadSlice('\n')
		if isBlankLine(line) {
			if len(head) == 0 {
				// 请求行之前的空行按 RFC 7230 §3.5 应被忽略（部分客户端复用连接时会
				// 多发一个 CRLF）。若在此直接返回，调用方拿到空头部会在解析请求行时
				// 越界 panic，因此继续读到真正的请求行为止。
				if err != nil {
					return nil, err
				}
				continue
			}
			// head 已含此前各行的行尾 CRLF，去掉最后一行的行尾即为调用方约定的头部
			switch {
			case len(head) >= 2 && head[len(head)-2] == '\r':
				return head[:len(head)-2], nil
			case len(head) >= 1 && head[len(head)-1] == '\n':
				return head[:len(head)-1], nil
			default:
				return head, nil
			}
		}
		head = append(head, line...)
		if len(head) > httpMaxHeaderSize {
			return nil, errHeaderTooLarge
		}
		if err == bufio.ErrBufferFull {
			// 单行超过读缓冲：已累积的片段保留，继续读该行剩余部分
			continue
		}
		if err != nil {
			return nil, err
		}
	}
}

// isBlankLine 判断是否为结束头部的空行（兼容 CRLF 与 LF）。
func isBlankLine(line []byte) bool {
	return len(line) == 2 && line[0] == '\r' && line[1] == '\n' ||
		len(line) == 1 && line[0] == '\n'
}

// splitHeaderLines 按 CRLF / LF 切分请求头。
//
// readHeader 对两种行尾都接受，这里必须用同一套切分规则：
// 若只按 CRLF 切，只发 LF 的客户端会把整个头部当成一行，
// 导致 Proxy-Authorization 等字段被漏读。
func splitHeaderLines(head []byte) []string {
	lines := make([]string, 0, 16)
	start := 0
	for i, b := range head {
		if b != '\n' {
			continue
		}
		end := i
		if end > start && head[end-1] == '\r' {
			end--
		}
		lines = append(lines, string(head[start:end]))
		start = i + 1
	}
	if start < len(head) {
		lines = append(lines, string(head[start:]))
	}
	return lines
}

// parseHTTPHeaders 解析头部字段，key 统一小写，同名取最后一个（与 Java 版 Map.put 一致）。
func parseHTTPHeaders(lines []string) map[string]string {
	headers := make(map[string]string, len(lines))
	for _, line := range lines[1:] {
		c := strings.IndexByte(line, ':')
		if c < 0 {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(line[:c]))] = strings.TrimSpace(line[c+1:])
	}
	return headers
}

// checkBasicAuth 校验 Proxy-Authorization: Basic base64(user:password)。
func checkBasicAuth(header string, creds Credentials) bool {
	if len(header) < 6 || !strings.EqualFold(header[:6], "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[6:]))
	if err != nil {
		return false
	}
	str := string(decoded)
	idx := strings.IndexByte(str, ':')
	if idx < 0 {
		return false
	}
	return str[:idx] == creds.User && str[idx+1:] == creds.Password
}

// parseHostPort 解析 host:port，兼容 IPv6 字面量 [::1]:port；未给出端口时使用 defaultPort。
func parseHostPort(hp string, defaultPort int) (string, int, bool) {
	if hp == "" {
		return "", 0, false
	}
	if hp[0] == '[' {
		end := strings.IndexByte(hp, ']')
		if end < 0 {
			return "", 0, false
		}
		host := hp[1:end]
		if host == "" {
			return "", 0, false
		}
		if end+1 < len(hp) {
			if hp[end+1] != ':' {
				return "", 0, false
			}
			port, err := strconv.Atoi(hp[end+2:])
			if err != nil || !validPort(port) {
				return "", 0, false
			}
			return host, port, true
		}
		return host, defaultPort, true
	}
	c := strings.LastIndexByte(hp, ':')
	if c < 0 {
		return hp, defaultPort, true
	}
	port, err := strconv.Atoi(hp[c+1:])
	if err != nil || !validPort(port) {
		return "", 0, false
	}
	return hp[:c], port, true
}

// validPort 校验端口范围，避免 "host:0"、"host:-1" 这类请求进入拨号阶段。
func validPort(port int) bool {
	return port > 0 && port <= 65535
}

// drainBuffered 把 bufio 中已预读的字节写给目标（CONNECT 的 TLS 首包 / 普通转发的请求体）。
func drainBuffered(br *bufio.Reader, w io.Writer) error {
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	data, err := br.Peek(n)
	if err != nil {
		return err
	}
	if err := writeAll(w, data); err != nil {
		return err
	}
	_, err = br.Discard(n)
	return err
}

// writeAndClose 写出应答后由上层 defer 关闭连接（Java 版为 write 完成后即 close）。
func writeAndClose(conn net.Conn, reply []byte) {
	_ = writeAll(conn, reply)
}

// bufferedConn 让 Relay 先消费 bufio 中的残留数据，再直接读原始连接。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// Read 优先从 bufio 读取（其中可能已有预读的请求体或隧道数据）。
func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// CloseWrite 透传半关闭能力，保证上传结束后下载通道仍然可用。
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
