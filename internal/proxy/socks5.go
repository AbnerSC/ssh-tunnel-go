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
	// socksHandshakeTimeout 握手阶段超时：Java 版为「连接后 5s 内未收到数据即关闭」，
	// 收到首个数据后即取消，这里用读超时等价实现。
	socksHandshakeTimeout = 5 * time.Second
	// socksAuthVersion RFC1929 账号密码认证版本号
	socksAuthVersion = 1
	// socksCmdConnect RFC1928 CONNECT 命令
	socksCmdConnect = 1
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
	host, port, rawAddr, ok := readRequest(conn, remote)
	if !ok {
		return
	}
	// 握手完成，清除读超时：转发阶段是长连接，不能带任何截止时间
	_ = conn.SetReadDeadline(time.Time{})
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	logging.Debug("socks5", "收到代理请求", "target", targetAddr, "remote", remote)

	target, err := route.Dial(context.Background(), host, port)
	if err != nil {
		logging.Warn("socks5", "无法连接目标", "target", targetAddr, "err", err)
		// 0x03 = Network unreachable，失败应答同样回显请求地址
		_ = writeAll(conn, appendReply(0x03, rawAddr))
		return
	}
	defer target.Close()

	if err := writeAll(conn, appendReply(0x00, rawAddr)); err != nil {
		return
	}
	logging.Info("socks5", "目标连接成功", "target", targetAddr, "remote", remote)
	Relay(conn, target)
	logging.Debug("socks5", "连接已断开", "target", targetAddr, "remote", remote)
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

// readRequest 读取连接请求，返回目标主机、端口与应答所需的原始地址字段（RSV/ATYP/ADDR/PORT）。
func readRequest(conn net.Conn, remote net.Addr) (string, int, []byte, bool) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, nil, false
	}
	if hdr[0] != 5 || hdr[1] != socksCmdConnect {
		// 不支持的命令：与 Java 版一致，不回包直接关闭
		logging.Debug("socks5", "不支持的请求命令", "cmd", hdr[1], "remote", remote)
		return "", 0, nil, false
	}

	var host string
	var addrBytes []byte
	// addrPrefix 域名类型的长度字节：应答原样回显请求地址（Java 版 bytes[2:reqLen]），
	// 缺了它客户端无法解析应答
	var addrPrefix []byte
	switch hdr[3] {
	case 0x01: // IPv4
		addrBytes = make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			return "", 0, nil, false
		}
		host = net.IP(addrBytes).String()
	case 0x03: // 域名
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", 0, nil, false
		}
		addrPrefix = []byte{l[0]}
		addrBytes = make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			return "", 0, nil, false
		}
		host = string(addrBytes)
	case 0x04: // IPv6，透传给服务端按字面地址连接
		addrBytes = make([]byte, 16)
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			return "", 0, nil, false
		}
		var arr [16]byte
		copy(arr[:], addrBytes)
		host = netip.AddrFrom16(arr).String()
	default:
		return "", 0, nil, false
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", 0, nil, false
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	if host == "" || port <= 0 || port > 65535 {
		// 空域名/非法端口无法构成有效目标，直接关闭（不回包，与不支持的命令一致）
		logging.Debug("socks5", "请求目标非法", "host", host, "port", port, "remote", remote)
		return "", 0, nil, false
	}

	raw := make([]byte, 0, 2+len(addrPrefix)+len(addrBytes)+2)
	raw = append(raw, hdr[2], hdr[3])
	raw = append(raw, addrPrefix...)
	raw = append(raw, addrBytes...)
	raw = append(raw, portBytes[:]...)
	return host, port, raw, true
}

func appendReply(code byte, rawAddr []byte) []byte {
	out := make([]byte, 0, 2+len(rawAddr))
	out = append(out, 5, code)
	return append(out, rawAddr...)
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
