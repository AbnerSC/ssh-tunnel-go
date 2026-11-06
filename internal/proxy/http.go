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

	"git.pi.mmxx.fun/dengming/ssh-tunnel-go/internal/logging"
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
	// httpWriteTimeout 写质询/错误应答的截止时间：客户端若只写不读，
	// 填满发送缓冲后 writeAll 会无限阻塞，长期占用连接名额与 goroutine。
	httpWriteTimeout = 5 * time.Second
	// httpDrainTimeout / httpMaxDrainBytes 关闭前为规避 RST 而排空残留字节的
	// 时限与上限，避免被超大/无限正文拖住（见 writeChallengeAndClose）。
	httpDrainTimeout  = 250 * time.Millisecond
	httpMaxDrainBytes = 256 * 1024
	// httpMaxChallengesPerConn 单连接上允许的 keep-alive 质询轮次上限。
	// 缺失凭据不再计入爆破计数后，需要用它补回旧实现由 guard 提供的隐式上界：
	// 正常 RFC 7235 客户端 1 轮质询即带凭据重试，这里留足冗余；
	// 反复只拿 407 的连接（无凭据空转或流水线攻击）超过上限即关闭。
	httpMaxChallengesPerConn = 5
)

var (
	// errHeaderTooLarge 请求头超过上限
	errHeaderTooLarge = errors.New("http: 请求头过大")
)

// 应答报文与 Java 版逐字节保持一致（ISO-8859-1 编码即原始字节）。
//
// 407 分成两种：
//   - replyAuthRequired：不带 Connection: close，客户端可在同一连接上带凭据重试
//     （CONNECT / GET / HEAD 这类没有正文的请求走这条路径，省一次 TCP 握手）；
//   - replyAuthRequiredClose：带 Connection: close，用于请求已经附带正文的场景，
//     避免客户端把正文连同请求头一起写完才收到 407，代理没读完的正文残留在
//     socket 缓冲里被当成下一个请求行（Apache HttpClient / Jetty client 的
//     POST 上传会踩到这个坑，Nexus 3 的 mvn deploy / docker push 都是 POST/PUT）。
//
// Proxy-Authenticate 显式声明 charset="UTF-8"（RFC 7617）：
// Apache HttpClient 4.x 的 BasicScheme 在没有 charset 参数时按 ISO-8859-1 编码
// 凭据，与本代理按 UTF-8 原始字节比较的语义不一致，密码含非 ASCII 字符时永远
// 匹配不上，用户侧表现同样是「http 代理认证不通过」。
var (
	replyEstablished  = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	replyBadGateway   = []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	replyBadRequest   = []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	authChallengeHead = "Proxy-Authenticate: Basic realm=\"ssh-tunnel\", charset=\"UTF-8\"\r\n"
	replyAuthRequired = []byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
		authChallengeHead + "Content-Length: 0\r\n\r\n")
	replyAuthRequiredClose = []byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
		authChallengeHead + "Content-Length: 0\r\nConnection: close\r\n\r\n")
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
	// challenges 统计本连接上已发出的 keep-alive 质询轮次，用于封顶（见 handleHTTPRequest）。
	challenges := 0
	for {
		// 封禁拦截放在读请求之前：已处于封禁期的来源连一个请求也不处理。
		// 仅在认证失败分支里检查是不够的——封禁期内携带正确凭据仍能通过，
		// 且每次新连接都能再试一次，爆破速率并没有真正被压下去。
		if creds.Enabled && creds.guard.Blocked(remote) {
			logging.Warn("http", "来源处于认证封禁期，已断开", "remote", remote)
			// 本分支紧接着 return 、defer 会关连接，应答必须声明 Connection: close，
			// 并走优雅关闭避免 RST 丢掉刚发出的 407（否则 Apache / Jetty HttpClient
			// 会把它当作可复用连接重试，对端看到的却是 reset/EOF）。
			writeChallengeAndClose(conn, replyAuthRequiredClose)
			return
		}
		head, err := readHeader(conn, br)
		if err != nil {
			if err == errHeaderTooLarge {
				logging.Warn("http", "http代理请求头过大，关闭", "remote", remote)
			} else if !errors.Is(err, io.EOF) {
				logging.Debug("http", "http代理读取请求头失败", "remote", remote, "err", err)
			}
			return
		}
		if !handleHTTPRequest(conn, br, head, creds, route, remote, &challenges) {
			return
		}
	}
}

// handleHTTPRequest 解析并派发单个请求，返回 true 表示继续在同一连接上读下一个请求（仅 407 场景）。
func handleHTTPRequest(conn net.Conn, br *bufio.Reader, head []byte, creds Credentials, route *Route,
	remote net.Addr, challenges *int) bool {
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

	// 认证：http 代理使用 Proxy-Authorization: Basic。
	//
	// 必须把「没带凭据」与「凭据不匹配」区分开——Apache HttpClient / Jetty
	// HttpClient / java.net.http.HttpClient 默认都按 RFC 7235 的质询-重试流走：
	// 首请求故意不带 Proxy-Authorization，收到 407 后再带凭据重试。Nexus 3 使用
	// PoolingHttpClientConnectionManager 并发抓 Maven Central / Docker Hub，
	// 一分钟内在同一来源 IP 上会留下十几条「不带凭据的首请求」，若一律计入
	// 爆破失败，10 次阈值一到就把 Nexus 主机 IP 封禁 5 分钟，用户侧表现为
	// 持续报「http代理认证不通过」。这里只在带凭据但校验失败时计入爆破计数。
	if creds.Enabled {
		auth := headers["proxy-authorization"]
		if !checkBasicAuth(auth, creds) {
			// mustClose 表示本次必须关连接（而非在同一连接上继续重试）。
			mustClose := false
			if auth != "" {
				// 带凭据但校验失败：计入爆破计数，达阈值即封禁。
				mustClose = creds.guard.Fail(remote)
				logging.Warn("http", "http代理认证不通过", "remote", remote, "banned", mustClose)
			} else {
				// 未携带凭据属协议握手，不计入爆破；但也不受 guard 封顶，
				// 用每连接质询次数上限补回隐式上界，防止单连接无限拿 407 空转占坑。
				logging.Debug("http", "请求缺少 Proxy-Authorization，要求认证", "remote", remote)
				*challenges++
				if *challenges >= httpMaxChallengesPerConn {
					logging.Debug("http", "同一连接质询次数达上限，关闭", "remote", remote)
					mustClose = true
				}
			}
			// 需要关连接，或请求带正文（正文可能已随请求头到达，不消费就会串到
			// 下一请求）时，走优雅关闭让客户端在新连接上重试。
			if mustClose || requestHasBody(method, lines, headers) {
				writeChallengeAndClose(conn, replyAuthRequiredClose)
				return false
			}
			if !writeChallenge(conn, replyAuthRequired) {
				return false
			}
			return true
		}
		creds.guard.Reset(remote)
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
	if !ok || host == "" || strings.ContainsRune(host, '@') {
		writeAndClose(conn, replyBadRequest)
		return
	}

	// 同时出现 Transfer-Encoding 与 Content-Length 是典型的请求走私原语：
	// 代理与源站取不同字段切分消息边界时会串包，这里直接拒绝
	headers := parseHTTPHeaders(lines)
	if _, hasTE := headers["transfer-encoding"]; hasTE {
		if _, hasCL := headers["content-length"]; hasCL {
			logging.Warn("http", "拒绝同时带 Transfer-Encoding 与 Content-Length 的请求", "remote", remote)
			writeAndClose(conn, replyBadRequest)
			return
		}
	}

	// 重建请求报文：请求行改为源站形式，剔除逐跳/代理专用头，追加 Connection: close
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(path)
	sb.WriteByte(' ')
	sb.WriteString(version)
	sb.WriteString("\r\n")
	drop := hopByHopSet(headers["connection"])
	for _, line := range lines[1:] {
		c := strings.IndexByte(line, ':')
		if c < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:c]))
		if _, skip := drop[key]; skip {
			continue
		}
		// Host 必须改写为 URI 指定的目标：透传客户端自带的 Host 会让代理变成
		// 「连 A 却说成 B」的绕过手段（虚拟主机/回源访问控制/缓存投毒）
		if key == "host" {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}
	sb.WriteString("Host: ")
	sb.WriteString(hostPortStr)
	sb.WriteString("\r\nConnection: close\r\n\r\n")

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

// hopByHopHeaders 逐跳头：只对单段连接有意义，代理不得透传给下一跳（RFC 7230 §6.1）。
//
// 透传这些头会带来实际风险：Keep-Alive/Connection 会改变源站的连接复用行为，
// Proxy-* 会把代理凭据泄露给源站。
//
// 刻意不包含 transfer-encoding：本代理不解析请求体，剔除它会让 chunked 报文
// 被当成普通正文发送，反而造成报文错位；报文边界安全靠「TE 与 CL 同时出现则拒绝」
// 以及强制 Connection: close 保证。
var hopByHopHeaders = []string{
	"connection", "proxy-connection", "keep-alive", "te", "trailer",
	"upgrade", "proxy-authorization", "proxy-authenticate",
}

// clientSpoofHeaders 可能被内网服务用来判断来源身份的头。
//
// 本代理不属于请求链路中的反向代理，不会追加这些头；若继续透传客户端自带的取值，
// 任何能访问代理的人都能把来源伪装成任意内网地址（实测 X-Forwarded-For /
// X-Real-IP 原样送达目标），基于这些头做访问控制的内网服务会被直接绕过。
var clientSpoofHeaders = []string{
	"x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
	"x-real-ip", "forwarded", "via",
}

// hopByHopSet 返回本次请求需要剔除的头部集合：固定逐跳头 + Connection 头里列举的字段名。
func hopByHopSet(connection string) map[string]struct{} {
	drop := make(map[string]struct{}, len(hopByHopHeaders)+len(clientSpoofHeaders)+4)
	for _, h := range hopByHopHeaders {
		drop[h] = struct{}{}
	}
	for _, h := range clientSpoofHeaders {
		drop[h] = struct{}{}
	}
	for _, token := range strings.Split(connection, ",") {
		if name := strings.ToLower(strings.TrimSpace(token)); name != "" {
			drop[name] = struct{}{}
		}
	}
	return drop
}

// requestHasBody 判断请求是否可能带正文，用于决定 407 走 keep-alive 还是关连接。
//
// 采用保守策略：只要「读不出安全边界」就按有正文处理（关连接），因为
// 一旦误判为无正文，未消费的字节会被当成下一个请求行，造成串包/走私。
// 不只看 map（同名取最后会掩盖重复头），而是扫描原始行统计出现次数：
//   - Content-Length / Transfer-Encoding 重复出现 → 无法安全切分 → 有正文；
//   - 出现 Transfer-Encoding（含 chunked、gzip,chunked 等）→ 保守按有正文；
//   - Content-Length 非数字或 >0 → 有正文（数字解析兼容 "0000"）；
//   - 既无 CL 也无 TE 的 POST/PUT/PATCH 仍可能以关连接定界→ 保守按有正文。
//
// CONNECT / GET / HEAD 以上都不命中，返回 false（无正文，可同连接重试）。
func requestHasBody(method string, lines []string, headers map[string]string) bool {
	clCount, teCount := 0, 0
	for _, line := range lines[1:] {
		c := strings.IndexByte(line, ':')
		if c < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(line[:c])) {
		case "content-length":
			clCount++
		case "transfer-encoding":
			teCount++
		}
	}
	if clCount > 1 || teCount > 1 {
		return true
	}
	if teCount > 0 {
		return true
	}
	if cl := strings.TrimSpace(headers["content-length"]); cl != "" {
		if n, err := strconv.ParseUint(cl, 10, 64); err != nil || n > 0 {
			return true
		}
	}
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// checkBasicAuth 校验 Proxy-Authorization: Basic base64(user:password)。
// 凭据比较使用常量时间，避免响应时间差异泄露正确前缀。
//
// 认证方案与凭据之间按 RFC 7235 只允许 SP，但 Java 生态里偶见使用 HTAB
// 或多空格的实现（例如某些老 Jetty client 拼装出来的头），这里一并容忍，
// 避免合法客户端因空白字符差异被判为认证失败。
func checkBasicAuth(header string, creds Credentials) bool {
	header = strings.TrimLeft(header, " \t")
	if len(header) < 5 || !strings.EqualFold(header[:5], "Basic") {
		return false
	}
	rest := header[5:]
	if rest == "" {
		return false
	}
	// 方案名之后必须紧跟空白，避免把 "BasicAuthentication" 之类的畸形值当成凭据
	if rest[0] != ' ' && rest[0] != '\t' {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return false
	}
	str := string(decoded)
	idx := strings.IndexByte(str, ':')
	if idx < 0 {
		return false
	}
	return credentialMatch(str[:idx], str[idx+1:], creds.User, creds.Password)
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

// writeChallenge 发送 keep-alive 质询应答（不带 Connection: close）。
//
// 带写截止时间：客户端若只写不读，填满发送缓冲后 writeAll 会无限阻塞，
// 长期占用连接名额与 goroutine（readHeader 设置的读截止时间对写不起作用）。
// 写成功返回 true 并清除写截止时间（后续正常读写不应再带超时）；写失败返回 false。
func writeChallenge(conn net.Conn, reply []byte) bool {
	_ = conn.SetWriteDeadline(time.Now().Add(httpWriteTimeout))
	err := writeAll(conn, reply)
	if err != nil {
		return false
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return true
}

// writeChallengeAndClose 发送 407 应答后准备关闭连接。
//
// 不能直接 Close 就返回：若请求带正文，正文可能仍在内核接收队列里没读完，
// close() 在存在未读数据时会发 RST 而非 FIN，RST 会让对端丢弃「已送达但
// 尚未读」的响应字节——客户端于是拿到 Connection reset 而不是 407，
// Apache/Jetty HttpClient 会把它归为 I/O 异常，不会触发 reactive 重试。
// 这里先半关闭发出 FIN 告知响应结束，再在短窗口内有界排空残留字节，
// 最后交给 defer conn.Close()。排空设上限与超时，避免被超大/无限正文拖住。
func writeChallengeAndClose(conn net.Conn, reply []byte) {
	_ = conn.SetWriteDeadline(time.Now().Add(httpWriteTimeout))
	_ = writeAll(conn, reply)
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(httpDrainTimeout))
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, httpMaxDrainBytes))
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
