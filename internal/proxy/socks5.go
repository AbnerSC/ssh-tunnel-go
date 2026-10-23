package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
)

const (
	// socksHandshakeTimeout 握手阶段读超时：对应 Java 版「连接后 5s 内未收到数据即关闭」，
	// 这里按问候、认证、请求分阶段各限时 5s（见 handleSocks5）。
	socksHandshakeTimeout = 5 * time.Second
	// socksAuthVersion RFC1929 账号密码认证版本号
	socksAuthVersion = 1
	// socksCmdConnect RFC1928 CONNECT 命令
	socksCmdConnect = 1

	// 以下为 RFC1928 应答码（REP）
	// replySucceeded 请求成功
	replySucceeded = 0x00
	// replyNetworkUnreachable 目标网络/主机不可达
	replyNetworkUnreachable = 0x03
	// replyCmdNotSupported 不支持的命令（UDP ASSOCIATE / BIND）
	replyCmdNotSupported = 0x07
	// replyAddrNotSupported 不支持的地址类型
	replyAddrNotSupported = 0x08
)

// ServeSocks5 启动 SOCKS5 服务。
func ServeSocks5(ln net.Listener, creds Credentials, route *Route) {
	Serve(ln, "socks5", func(conn net.Conn) {
		handleSocks5(conn, creds, route)
	})
}

func handleSocks5(conn net.Conn, creds Credentials, route *Route) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	logging.Debug("socks5", "收到连接请求", "remote", remote)

	_ = conn.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		logging.Debug("socks5", "读取握手失败", "remote", remote, "err", err)
		return
	}
	if greeting[0] != 5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// 握手按阶段限时：问候、认证、请求各自最多 5s。
	// 不放宽为「整段握手一个超时」，避免慢速客户端在上一阶段耗尽时间后被误断，
	// 也不会让不发言的客户端长期占用 goroutine。
	if creds.Enabled {
		if !hasMethod(methods, 0x02) {
			// 客户端不支持账号密码认证，拒绝
			_ = writeAll(conn, []byte{5, 0xFF})
			return
		}
		if err := writeAll(conn, []byte{5, 0x02}); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
		if !authSocks5(conn, creds, remote) {
			return
		}
	} else {
		if err := writeAll(conn, []byte{5, 0x00}); err != nil {
			return
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
	host, port, atyp, ok := readRequest(conn, remote)
	if !ok {
		return
	}
	// 握手完成，清除读超时：转发阶段是长连接，不能带任何截止时间
	_ = conn.SetReadDeadline(time.Time{})
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	logging.Debug("socks5", "收到代理请求", "target", targetAddr, "atyp", atypName(atyp), "remote", remote)

	target, err := route.Dial(context.Background(), host, port)
	if err != nil {
		logging.Warn("socks5", "无法连接目标", "target", targetAddr, "atyp", atypName(atyp), "err", err)
		_ = writeAll(conn, replyFixed(replyNetworkUnreachable))
		return
	}
	defer target.Close()

	if err := writeAll(conn, replyFixed(replySucceeded)); err != nil {
		return
	}
	logging.Info("socks5", "目标连接成功", "target", targetAddr, "remote", remote)
	started := time.Now()
	Relay(conn, target)
	// 连接存活时长是区分「握手即被对端断开」与「长时间挂起」的关键信号
	logging.Debug("socks5", "连接已断开", "target", targetAddr, "remote", remote,
		"elapsed", time.Since(started).Round(time.Millisecond))
}

func hasMethod(methods []byte, want byte) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}

// authSocks5 处理 RFC1929 账号密码认证。
func authSocks5(conn net.Conn, creds Credentials, remote net.Addr) bool {
	var ver [1]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil || ver[0] != socksAuthVersion {
		_ = writeAll(conn, []byte{1, 1})
		return false
	}
	var l [1]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		_ = writeAll(conn, []byte{1, 1})
		return false
	}
	user := make([]byte, int(l[0]))
	if _, err := io.ReadFull(conn, user); err != nil {
		_ = writeAll(conn, []byte{1, 1})
		return false
	}
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		_ = writeAll(conn, []byte{1, 1})
		return false
	}
	pass := make([]byte, int(l[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		_ = writeAll(conn, []byte{1, 1})
		return false
	}
	logging.Debug("socks5", "收到认证账号", "user", string(user), "remote", remote)
	if string(user) != creds.User || string(pass) != creds.Password {
		logging.Warn("socks5", "代理认证不通过", "user", string(user), "remote", remote)
		_ = writeAll(conn, []byte{1, 1})
		return false
	}
	logging.Debug("socks5", "代理认证通过", "user", string(user), "remote", remote)
	return writeAll(conn, []byte{1, 0}) == nil
}

// readRequest 读取连接请求，返回目标主机、端口与地址类型（ATYP）。
//
// 只接受 CONNECT：UDP ASSOCIATE 与 BIND 无法通过 SSH 隧道承载（隧道只有
// TCP 通道），按 RFC1928 明确回 REP=0x07，让客户端立即回退到 TCP；
// 静默关闭会让客户端一直等到超时，表现为「连上了但打不开」。
func readRequest(conn net.Conn, remote net.Addr) (string, int, byte, bool) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, 0, false
	}
	if hdr[0] != 5 {
		return "", 0, 0, false
	}
	if hdr[1] != socksCmdConnect {
		logging.Debug("socks5", "不支持的请求命令，回 0x07", "cmd", hdr[1], "remote", remote)
		_ = writeAll(conn, replyFixed(replyCmdNotSupported))
		return "", 0, 0, false
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, 0, false
		}
		host = net.IP(addr).String()
	case 0x03: // 域名，交给对端按域名解析
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", 0, 0, false
		}
		addr := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, 0, false
		}
		host = string(addr)
	case 0x04: // IPv6，透传给服务端按字面地址连接
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, 0, false
		}
		var arr [16]byte
		copy(arr[:], addr)
		host = netip.AddrFrom16(arr).String()
	default:
		logging.Debug("socks5", "不支持的地址类型，回 0x08", "atyp", hdr[3], "remote", remote)
		_ = writeAll(conn, replyFixed(replyAddrNotSupported))
		return "", 0, 0, false
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", 0, 0, false
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	if host == "" || port <= 0 || port > 65535 {
		// 空域名/非法端口无法构成有效目标，直接关闭
		logging.Debug("socks5", "请求目标非法", "host", host, "port", port, "remote", remote)
		return "", 0, 0, false
	}
	return host, port, hdr[3], true
}

// replyFixed 构造 REP 应答，BND.ADDR 固定为 0.0.0.0:0。
//
// 不回显请求地址：请求是域名(ATYP=0x03)时，回显会让只按固定长度
// （IPv4 4 字节 / IPv6 16 字节）读取 BND.ADDR 的客户端解析错位，
// 表现为服务端日志显示连接成功、客户端却立刻断开重连。
// 大多数实现（curl、浏览器、各类 SDK）都会忽略 BND.ADDR，固定回环地址最稳妥。
func replyFixed(code byte) []byte {
	return []byte{5, code, 0, 0x01, 0, 0, 0, 0, 0, 0}
}

// atypName 供日志区分目标是域名还是 IP 字面量：
// 域名说明客户端做的是远端 DNS，IP 则说明解析发生在客户端侧。
func atypName(atyp byte) string {
	switch atyp {
	case 0x01:
		return "ipv4"
	case 0x03:
		return "domain"
	case 0x04:
		return "ipv6"
	default:
		return "unknown"
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
