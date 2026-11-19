package tun

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"ssh-tunnel-go/internal/logging"
)

const (
	// resolvConfPath 系统 DNS 配置路径（Windows 上不存在，读取失败视为无系统 DNS）
	resolvConfPath = "/etc/resolv.conf"
)

// virtualIfacePrefixes 需要跳过枚举的虚拟网卡名前缀。
//
// tun*/utun*/tap* 是本程序（或同类工具）创建的隧道网卡，wg/tailscale/zt
// 是用户态 VPN；它们的前缀不是真实局域网，纳入排除只会把隧道自身
// 从 TUN 路由中挖掉。
var virtualIfacePrefixes = []string{"tun", "tap", "utun", "wg", "tailscale", "zt"}

// lanExcludeCIDRs 生成局域网前缀的路由排除列表（CIDR 字符串）。
//
// TUN 全量接管（auto_route + 默认 0/0 路由）会把本机所有出站流量都送进
// tun0，其中也包括本机作为服务端（sshd、Web 服务等）返回给局域网客户端的
// 回程流量。这些连接不经过 sing-box 的入站，用户态协议栈收到 mid-stream
// 报文只能回 RST，表现为 TUN 启动后所有入站连接立即断开。
//
// 因此在路由层排除各网卡所在的局域网前缀，让回程流量走原始路径；
// 系统 DNS 服务器地址是例外：DNS 劫持依赖查询报文进入 TUN，需要从
// LAN 前缀中把 DNS 地址单独扣除（前缀拆分），同时保住 DNS 分流与 fake-ip。
func lanExcludeCIDRs() []string {
	if runtime.GOOS != "linux" {
		// TUN 模式仅支持 Linux，其他平台保持配置生成行为不变
		return nil
	}
	prefixes := lanPrefixes()
	if len(prefixes) == 0 {
		return nil
	}
	dns := systemDNSServers(localAddrs())
	var out []string
	for _, p := range prefixes {
		for _, part := range subtractAddrs(p, dns) {
			out = append(out, part.String())
		}
	}
	logging.Info("tun", "局域网前缀已加入路由排除",
		"lanPrefixes", joinPrefixes(prefixes), "excludes", len(out), "keptDNS", joinAddrs(dns))
	return out
}

// lanPrefixes 枚举本机 UP 状态、非回环、非隧道网卡的地址前缀。
//
// 包括物理网卡与 docker 网桥等虚拟网桥：它们的流量同样不应该被 TUN
// 抓走（容器网络、宿主机到容器的访问依赖原始路由）。
func lanPrefixes() []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		logging.Warn("tun", "枚举网卡失败，无法计算局域网路由排除", "err", err)
		return nil
	}
	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualIface(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, ok := ifacePrefix(a)
			if !ok {
				continue
			}
			if _, dup := seen[prefix]; dup {
				continue
			}
			seen[prefix] = struct{}{}
			out = append(out, prefix)
		}
	}
	return out
}

// ifacePrefix 把接口地址转换为规范化的网段前缀。
func ifacePrefix(a net.Addr) (netip.Prefix, bool) {
	ipnet, ok := a.(*net.IPNet)
	if !ok || ipnet.IP == nil {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() ||
		addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return netip.Prefix{}, false
	}
	ones, bits := ipnet.Mask.Size()
	if ones <= 0 || bits == 0 {
		return netip.Prefix{}, false
	}
	prefix, err := addr.Prefix(ones)
	if err != nil {
		return netip.Prefix{}, false
	}
	prefix = prefix.Masked()
	// /31 与 /32（IPv6 的 /127、/128）只覆盖本机或点对端地址，没有排除价值
	if prefix.Bits() >= prefix.Addr().BitLen()-1 {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// isVirtualIface 判断网卡名是否属于隧道类虚拟网卡。
func isVirtualIface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range virtualIfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// localAddrs 返回本机所有接口地址集合，用于识别「DNS 指向本机」的情形。
func localAddrs() map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{})
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			if addr, ok := netip.AddrFromSlice(ipnet.IP); ok {
				out[addr.Unmap()] = struct{}{}
			}
		}
	}
	return out
}

// systemDNSServers 解析 resolv.conf 的 nameserver 列表。
//
// 回环地址（systemd-resolved 的 127.0.0.53）与指向本机的地址其查询走
// loopback，不经过 TUN、无法劫持，从「保留进 TUN」的集合中剔除并提示。
func systemDNSServers(local map[netip.Addr]struct{}) []netip.Addr {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		logging.Warn("tun", "读取系统DNS配置失败，局域网前缀整段排除（DNS 查询不进 TUN）",
			"path", resolvConfPath, "err", err)
		return nil
	}
	return parseResolvConf(string(data), local)
}

// parseResolvConf 从 resolv.conf 内容中提取可被 TUN 劫持的 DNS 服务器地址。
func parseResolvConf(content string, local map[netip.Addr]struct{}) []netip.Addr {
	var out []netip.Addr
	seen := make(map[netip.Addr]struct{})
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() {
			logging.Warn("tun", "系统DNS为回环地址，本机DNS查询无法被TUN劫持（该查询不会命中fake-ip）", "dns", addr)
			continue
		}
		if _, self := local[addr]; self {
			logging.Warn("tun", "系统DNS指向本机地址，DNS查询走回环栈不经过TUN", "dns", addr)
			continue
		}
		if addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// subtractAddrs 返回从 p 中扣除 addrs 后剩余的前缀集合（前缀拆分）。
//
// 例：172.17.1.0/24 扣除 172.17.1.1 后得到 172.17.1.2/31、172.17.1.4/30、
// 172.17.1.8/29、172.17.1.16/28、172.17.1.32/27、172.17.1.64/26、
// 172.17.1.128/25。
func subtractAddrs(p netip.Prefix, addrs []netip.Addr) []netip.Prefix {
	if !p.IsValid() {
		return nil
	}
	p = p.Masked()
	var inside []netip.Addr
	for _, a := range addrs {
		if a.Is4() != p.Addr().Is4() {
			continue
		}
		if p.Contains(a) {
			inside = append(inside, a)
		}
	}
	if len(inside) == 0 {
		return []netip.Prefix{p}
	}
	// 前缀收窄到单个地址且该地址需要扣除：无剩余
	if p.Bits() == p.Addr().BitLen() {
		return nil
	}
	half := p.Bits() + 1
	left := netip.PrefixFrom(p.Addr(), half)
	right := netip.PrefixFrom(halfStart(p.Addr(), half), half)
	return append(subtractAddrs(left, inside), subtractAddrs(right, inside)...)
}

// halfStart 返回 halfBits 位前缀右半部分的起始地址。
func halfStart(start netip.Addr, halfBits int) netip.Addr {
	if start.Is4() {
		b := start.As4()
		v := binary.BigEndian.Uint32(b[:]) + uint32(1)<<uint(32-halfBits)
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], v)
		return netip.AddrFrom4(out)
	}
	b := start.As16()
	shift := uint(128 - halfBits)
	carry := uint16(1) << (shift % 8)
	for i := 15 - int(shift/8); i >= 0 && carry != 0; i-- {
		sum := uint16(b[i]) + carry
		b[i] = byte(sum)
		carry = sum >> 8
	}
	return netip.AddrFrom16(b)
}

// joinPrefixes 把网段列表拼成逗号分隔字符串（仅用于日志）。
func joinPrefixes(list []netip.Prefix) string {
	parts := make([]string, 0, len(list))
	for _, p := range list {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// joinAddrs 把地址列表拼成逗号分隔字符串（仅用于日志）。
func joinAddrs(list []netip.Addr) string {
	parts := make([]string, 0, len(list))
	for _, a := range list {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}
