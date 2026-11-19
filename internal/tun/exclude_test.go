package tun

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

// TestSubtractAddrsSingle 经典场景：LAN /24 前缀扣除一个 DNS 地址，
// 补集必须恰好覆盖其余 255 个地址且不含被扣除地址。
func TestSubtractAddrsSingle(t *testing.T) {
	p := netip.MustParsePrefix("172.17.1.0/24")
	got := subtractAddrs(p, []netip.Addr{netip.MustParseAddr("172.17.1.1")})
	want := []string{
		"172.17.1.0/32", "172.17.1.2/31", "172.17.1.4/30",
		"172.17.1.8/29", "172.17.1.16/28", "172.17.1.32/27",
		"172.17.1.64/26", "172.17.1.128/25",
	}
	gotStrings := make([]string, 0, len(got))
	for _, part := range got {
		gotStrings = append(gotStrings, part.String())
	}
	if !slices.Equal(gotStrings, want) {
		t.Fatalf("拆分结果异常:\n got %v\nwant %v", gotStrings, want)
	}

	// 逐地址验证：除 DNS 外的所有地址都在补集中，DNS 不在
	var covered int
	for i := 0; i < 256; i++ {
		addr := netip.AddrFrom4([4]byte{172, 17, 1, byte(i)})
		in := false
		for _, part := range got {
			if part.Contains(addr) {
				in = true
				break
			}
		}
		if i == 1 {
			if in {
				t.Fatal("被保留的 DNS 地址不应出现在排除补集中")
			}
			continue
		}
		if !in {
			t.Fatalf("地址 %s 缺失于补集", addr)
		}
		covered++
	}
	if covered != 255 {
		t.Fatalf("补集覆盖数量异常: %d", covered)
	}
}

// TestSubtractAddrsMultiple 多个扣除地址（含前缀外的地址应被忽略）。
func TestSubtractAddrsMultiple(t *testing.T) {
	p := netip.MustParsePrefix("172.17.1.0/24")
	addrs := []netip.Addr{
		netip.MustParseAddr("172.17.1.1"),
		netip.MustParseAddr("172.17.1.200"),
		netip.MustParseAddr("8.8.8.8"), // 前缀外，不应影响结果
	}
	got := subtractAddrs(p, addrs)
	var covered int
	for i := 0; i < 256; i++ {
		addr := netip.AddrFrom4([4]byte{172, 17, 1, byte(i)})
		in := false
		for _, part := range got {
			if part.Contains(addr) {
				in = true
				break
			}
		}
		if i == 1 || i == 200 {
			if in {
				t.Fatalf("扣除地址 %s 不应出现在补集中", addr)
			}
			continue
		}
		if !in {
			t.Fatalf("地址 %s 缺失于补集", addr)
		}
		covered++
	}
	if covered != 254 {
		t.Fatalf("补集覆盖数量异常: %d", covered)
	}
}

// TestSubtractAddrsEdges 边界：无扣除、单地址前缀、异族地址。
func TestSubtractAddrsEdges(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/8")
	if got := subtractAddrs(p, nil); len(got) != 1 || got[0] != p {
		t.Fatalf("无扣除时应原样返回: %v", got)
	}
	// /32 恰好等于扣除地址：无剩余
	single := netip.MustParsePrefix("172.17.1.1/32")
	if got := subtractAddrs(single, []netip.Addr{netip.MustParseAddr("172.17.1.1")}); len(got) != 0 {
		t.Fatalf("/32 扣除自身后应为空: %v", got)
	}
	// IPv6 地址不影响 IPv4 前缀
	if got := subtractAddrs(p, []netip.Addr{netip.MustParseAddr("fc00::1")}); len(got) != 1 || got[0] != p {
		t.Fatalf("异族地址不应影响 IPv4 拆分: %v", got)
	}
}

// TestSubtractAddrsIPv6 IPv6 前缀拆分：数量为位长（/128-/64），且不包含扣除地址。
func TestSubtractAddrsIPv6(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/64")
	dns := netip.MustParseAddr("2001:db8::1")
	got := subtractAddrs(p, []netip.Addr{dns})
	if len(got) != 64 {
		t.Fatalf("IPv6 /64 单地址拆分应得 64 条前缀，实际 %d", len(got))
	}
	var coveredCount uint64
	for _, part := range got {
		coveredCount += uint64(1) << (128 - part.Bits())
		if part.Contains(dns) {
			t.Fatalf("补集不应包含扣除地址: %s", part)
		}
	}
	// 2^64 总地址 - 1 个被扣除
	want := ^uint64(0)
	if coveredCount != want {
		t.Fatalf("补集地址数量异常: %d，期望 %d", coveredCount, want)
	}
}

// TestRouteExcludes 纯函数：网段扣除 DNS 地址后返回补集，并报告被保留
// 进 TUN 的 DNS 地址（调用方据此输出边界告警）。
func TestRouteExcludes(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("172.17.1.0/24"),
		netip.MustParsePrefix("10.251.252.0/24"),
		netip.MustParsePrefix("2001:db8::/120"),
	}
	dns := []netip.Addr{
		netip.MustParseAddr("172.17.1.213"), // 落在第一个网段
		netip.MustParseAddr("2001:db8::53"), // 落在第三个网段
		netip.MustParseAddr("8.8.8.8"),      // 不在任何网段，不应被报告
	}
	excludes, kept := routeExcludes(prefixes, dns)
	wantKept := []netip.Addr{netip.MustParseAddr("172.17.1.213"), netip.MustParseAddr("2001:db8::53")}
	if !slices.Equal(kept, wantKept) {
		t.Fatalf("kept 应仅包含落在网段内的 DNS: %v，期望 %v", kept, wantKept)
	}
	for _, s := range []string{"172.17.1.213", "2001:db8::53"} {
		addr := netip.MustParseAddr(s)
		for _, e := range excludes {
			if netip.MustParsePrefix(e).Contains(addr) {
				t.Fatalf("kept DNS %s 不应出现在排除列表: %v", s, excludes)
			}
		}
	}
	// 无 DNS 相交的网段应整段保留为排除项
	if !slices.Contains(excludes, "10.251.252.0/24") {
		t.Fatalf("无 DNS 的网段应整段排除: %v", excludes)
	}
	// 拆分后的补集仍覆盖同网段内的其他地址
	if !slices.Contains(excludes, "172.17.1.0/25") {
		t.Fatalf("DNS 之外的地址应仍被排除: %v", excludes)
	}
}

// TestSubtractAddrsIPv6MultiDNS 同一 IPv6 /64 内扣除多个 DNS 地址：
// 补集应逐地址覆盖除 DNS 外的全部 2^64-2 个地址，且各前缀互不重叠。
func TestSubtractAddrsIPv6MultiDNS(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/64")
	dns1 := netip.MustParseAddr("2001:db8::53")
	dns2 := netip.MustParseAddr("2001:db8:0:0:ffff::1")
	got := subtractAddrs(p, []netip.Addr{dns1, dns2})
	var total uint64
	for i, part := range got {
		if part.Contains(dns1) || part.Contains(dns2) {
			t.Fatalf("补集不应包含扣除地址: %s", part)
		}
		total += uint64(1) << (128 - part.Bits())
		for _, other := range got[i+1:] {
			if part.Contains(other.Addr()) || other.Contains(part.Addr()) {
				t.Fatalf("补集前缀不应重叠: %s / %s", part, other)
			}
		}
	}
	if want := ^uint64(0) - 1; total != want {
		t.Fatalf("补集地址数量异常: %d，期望 %d", total, want)
	}
}

// TestSubtractAddrsNetworkBroadcast 扣除网络地址与广播地址（多 DNS 位于
// /24 两端）时，补集恰好覆盖中间 254 个地址。
func TestSubtractAddrsNetworkBroadcast(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/24")
	addrs := []netip.Addr{netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.255")}
	got := subtractAddrs(p, addrs)
	var covered int
	for i := 0; i < 256; i++ {
		addr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		in := false
		for _, part := range got {
			if part.Contains(addr) {
				in = true
				break
			}
		}
		if i == 0 || i == 255 {
			if in {
				t.Fatalf("扣除地址 %s 不应出现在补集中", addr)
			}
			continue
		}
		if !in {
			t.Fatalf("地址 %s 缺失于补集", addr)
		}
		covered++
	}
	if covered != 254 {
		t.Fatalf("补集覆盖数量异常: %d", covered)
	}
}

// TestHalfStart 验证前缀右半起点计算（v4/v6）。
func TestHalfStart(t *testing.T) {
	cases := []struct {
		start    string
		halfBits int
		want     string
	}{
		{"172.17.1.0", 25, "172.17.1.128"},
		{"172.17.1.0", 31, "172.17.1.2"},
		{"172.17.1.0", 32, "172.17.1.1"},
		{"2001:db8::", 65, "2001:db8:0:0:8000::"},
		{"2001:db8::", 128, "2001:db8::1"},
		{"2001:db8::ffff:ffff:ffff:ffff", 128, "2001:db8:0:1::"},
	}
	for _, c := range cases {
		got := halfStart(netip.MustParseAddr(c.start), c.halfBits)
		if got != netip.MustParseAddr(c.want) {
			t.Fatalf("halfStart(%s, %d) = %s，期望 %s", c.start, c.halfBits, got, c.want)
		}
	}
}

// TestIfacePrefix 接口地址到前缀的映射与过滤。
func TestIfacePrefix(t *testing.T) {
	mk := func(ip string, ones, bitsTotal int) *net.IPNet {
		return &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(ones, bitsTotal)}
	}
	cases := []struct {
		name string
		ipn  *net.IPNet
		want string
		ok   bool
	}{
		{"v4 /24", mk("172.17.1.229", 24, 32), "172.17.1.0/24", true},
		{"v4 /16", mk("172.17.0.1", 16, 32), "172.17.0.0/16", true},
		{"回环", mk("127.0.0.1", 8, 32), "", false},
		{"链路本地", mk("169.254.1.2", 16, 32), "", false},
		{"组播", mk("224.0.0.1", 4, 32), "", false},
		{"v4 /32", mk("10.1.2.3", 32, 32), "", false},
		{"v4 /31", mk("10.1.2.3", 31, 32), "", false},
		{"v6 /64", mk("2408:8207:1234:5678::1", 64, 128), "2408:8207:1234:5678::/64", true},
		{"v6 /128", mk("2001:db8::1", 128, 128), "", false},
		{"v4 地址配 v6 掩码", mk("10.1.2.3", 24, 128), "", false},
		{"v4 掩码长度超过地址族", &net.IPNet{IP: net.ParseIP("10.1.2.3").To4(), Mask: net.CIDRMask(48, 128)}, "", false},
	}
	for _, c := range cases {
		got, ok := ifacePrefix(c.ipn)
		if ok != c.ok {
			t.Fatalf("%s: ok=%v，期望 %v", c.name, ok, c.ok)
		}
		if ok && got.String() != c.want {
			t.Fatalf("%s: got %q，期望 %q", c.name, got, c.want)
		}
	}
}

// TestIsVirtualIface 隧道类网卡名过滤（物理网卡与 docker 网桥不应被过滤）。
func TestIsVirtualIface(t *testing.T) {
	cases := map[string]bool{
		"tun0": true, "utun3": true, "tap0": true, "wg0": true,
		"tailscale0": true, "ztabc123": true,
		"enp6s18": false, "eth0": false, "docker0": false, "br-1a2b3c": false, "lo": false,
	}
	for name, want := range cases {
		if got := isVirtualIface(name); got != want {
			t.Fatalf("isVirtualIface(%q) = %v，期望 %v", name, got, want)
		}
	}
}

// TestParseResolvConf resolv.conf 解析：仅保留可被 TUN 劫持的服务器地址。
func TestParseResolvConf(t *testing.T) {
	content := `# Generated by dhclient
search lan
nameserver 172.17.1.1
nameserver 127.0.0.53
nameserver 172.17.1.229
nameserver fe80::1
nameserver 8.8.8.8
nameserver 8.8.8.8
options edns0
`
	local := map[netip.Addr]struct{}{netip.MustParseAddr("172.17.1.229"): {}}
	got := parseResolvConf(content, local)
	want := []netip.Addr{netip.MustParseAddr("172.17.1.1"), netip.MustParseAddr("8.8.8.8")}
	if !slices.Equal(got, want) {
		t.Fatalf("解析结果异常: %v，期望 %v", got, want)
	}
}

// TestParseResolvConfGlobalIPv6 全局 IPv6 nameserver 会走「前缀扣除」路径，
// 必须保留在返回列表中（link-local 除外）。
func TestParseResolvConfGlobalIPv6(t *testing.T) {
	content := "nameserver 2400:3200::1\nnameserver 2400:3200::1\nnameserver fe80::1\n"
	got := parseResolvConf(content, nil)
	want := []netip.Addr{netip.MustParseAddr("2400:3200::1")}
	if !slices.Equal(got, want) {
		t.Fatalf("全局 IPv6 nameserver 应被保留且去重: %v", got)
	}
}

// TestParseResolvConfEmpty 空内容与非 nameserver 行。
func TestParseResolvConfEmpty(t *testing.T) {
	if got := parseResolvConf("", nil); len(got) != 0 {
		t.Fatalf("空内容应返回空列表: %v", got)
	}
	if got := parseResolvConf("nameserver\nnameserver not-an-ip\n", nil); len(got) != 0 {
		t.Fatalf("非法行应被忽略: %v", got)
	}
}
