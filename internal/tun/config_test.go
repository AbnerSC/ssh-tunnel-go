package tun

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// baseOptions 返回一个可用的最小配置：本地 SOCKS 出站 + 一个 SSH 服务器 IP。
// 默认值与 config 层保持一致（fake-ip 默认开启）。
func baseOptions() Options {
	return Options{
		SocksHost: "127.0.0.1",
		SocksPort: 6666,
		SSHHosts:  []string{"203.0.113.9"},
		GeoSites:  []string{"cn"},
		FakeIP:    true,
	}
}

// findRouteRule 返回第一个满足条件的路由规则索引。
func findRouteRule(cfg *BoxConfig, match func(BoxRouteRule) bool) int {
	for i, rule := range cfg.Route.Rules {
		if match(rule) {
			return i
		}
	}
	return -1
}

func TestBuildConfigDefaults(t *testing.T) {
	cfg, err := BuildConfig(baseOptions())
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}

	// 日志
	if cfg.Log.Level != "warn" || !cfg.Log.Timestamp {
		t.Fatalf("日志配置异常: %+v", cfg.Log)
	}

	// DNS：local/tcp/udp/fakeip 四个服务器；final 必须是真实解析器
	//（sing-box >= 1.12 禁止 fakeip 作默认服务器），fake-ip 由末尾 A/AAAA 规则实现
	types := make([]string, 0, len(cfg.DNS.Servers))
	for _, s := range cfg.DNS.Servers {
		types = append(types, s.Type)
	}
	if !slices.Equal(types, []string{"local", "tcp", "udp", "fakeip"}) {
		t.Fatalf("DNS 服务器类型异常: %v", types)
	}
	if cfg.DNS.Servers[1].Server != "8.8.8.8" || cfg.DNS.Servers[1].Detour != "proxy" {
		t.Fatalf("dns-proxy 配置异常: %+v", cfg.DNS.Servers[1])
	}
	// dns-cn 不绑定 detour：sing-box >= 1.12 禁止 detour 指向空 direct 出站，
	// 空 detour 本身就是直连拨号
	if cfg.DNS.Servers[2].Server != "223.5.5.5" || cfg.DNS.Servers[2].Detour != "" {
		t.Fatalf("dns-cn 配置异常: %+v", cfg.DNS.Servers[2])
	}
	if cfg.DNS.Final != "dns-proxy" || cfg.DNS.Strategy != "prefer_ipv4" {
		t.Fatalf("DNS final/strategy 异常: %+v", cfg.DNS)
	}
	fakeRule := cfg.DNS.Rules[len(cfg.DNS.Rules)-1]
	if fakeRule.Server != "dns-fakeip" || !slices.Equal(fakeRule.QueryType, []string{"A", "AAAA"}) {
		t.Fatalf("末尾应为 A/AAAA 走 fake-ip 的规则（否则 fakeip 服务器不生效）: %+v", fakeRule)
	}
	if len(cfg.DNS.Rules) == 0 || cfg.DNS.Rules[0].Server != "dns-local" {
		t.Fatalf("首条 DNS 规则应为内网域名走 dns-local: %+v", cfg.DNS.Rules)
	}

	// TUN inbound
	in := cfg.Inbounds[0]
	if in.Type != "tun" || !in.AutoRoute || !in.StrictRoute || in.Stack != "gvisor" {
		t.Fatalf("TUN inbound 配置异常: %+v", in)
	}
	if len(in.Address) != 2 {
		t.Fatalf("TUN 地址数量异常: %v", in.Address)
	}

	// 出站：socks 指向本地代理，direct 兜底
	if len(cfg.Outbounds) != 2 || cfg.Outbounds[0].Type != "socks" || cfg.Outbounds[1].Type != "direct" {
		t.Fatalf("出站配置异常: %+v", cfg.Outbounds)
	}
	if cfg.Outbounds[0].Server != "127.0.0.1" || cfg.Outbounds[0].ServerPort != 6666 {
		t.Fatalf("socks 出站地址异常: %+v", cfg.Outbounds[0])
	}

	// 路由规则顺序：sniff -> hijack-dns -> process_path -> ...
	if cfg.Route.Rules[0].Action != actionSniff {
		t.Fatalf("首条规则应为 sniff: %+v", cfg.Route.Rules[0])
	}
	if cfg.Route.Rules[1].Action != actionHijackDNS || cfg.Route.Rules[1].Protocol != "dns" {
		t.Fatalf("次条规则应为 hijack-dns: %+v", cfg.Route.Rules[1])
	}
	procIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return len(r.ProcessPath) > 0 })
	if procIdx < 0 || cfg.Route.Rules[procIdx].Outbound != "direct" {
		t.Fatal("缺少进程级防回环规则（ssh-tunnel 自身出站应直连）")
	}
	// process_name 是 process_path 失配（二进制被替换/改名）时的第二重防护
	nameIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return len(r.ProcessName) > 0 })
	if nameIdx < 0 || cfg.Route.Rules[nameIdx].Outbound != "direct" {
		t.Fatal("缺少进程名级防回环规则（process_path 失配时的兜底）")
	}
	if nameIdx != procIdx+1 {
		t.Fatalf("process_name 兜底规则应紧随 process_path: %d/%d", procIdx, nameIdx)
	}

	// SSH 服务器 IP 必须直连
	sshIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.IPCIDR, "203.0.113.9/32") })
	if sshIdx < 0 || cfg.Route.Rules[sshIdx].Outbound != "direct" {
		t.Fatal("缺少 SSH 服务器直连规则")
	}

	// cn 域名直连分流（内嵌 dlc.dat）
	cnIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.DomainSuffix, "baidu.com") })
	if cnIdx < 0 || cfg.Route.Rules[cnIdx].Outbound != "direct" {
		t.Fatal("缺少 cn 域名直连规则")
	}
	if got := len(cfg.Route.Rules[cnIdx].DomainSuffix); got < 5000 {
		t.Fatalf("cn 域名规则数量异常: %d", got)
	}

	// UDP：非直连目标的 QUIC 拒绝（私网/DIRECT_IP 先直连放行），其余默认直连
	cidrIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.IPCIDR, "10.0.0.0/8") })
	if cidrIdx < 0 {
		t.Fatal("缺少私网直连规则")
	}
	quicIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return r.Network == "udp" && r.Port == 443 })
	if quicIdx < 0 || cfg.Route.Rules[quicIdx].Action != actionReject {
		t.Fatal("缺少 QUIC(UDP 443) 拒绝规则")
	}
	// 顺序即语义：私网/DIRECT_IP 的 QUIC 按直连处理，必须排在拒绝规则之前
	if quicIdx < cidrIdx {
		t.Fatalf("QUIC 拒绝规则应位于直连 CIDR 之后: quic=%d cidr=%d", quicIdx, cidrIdx)
	}
	udpIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return r.Network == "udp" && r.Port == 0 })
	if udpIdx < 0 || cfg.Route.Rules[udpIdx].Outbound != "direct" {
		t.Fatal("默认 UDP 策略应为直连放行")
	}

	// final 与自动检测接口
	if cfg.Route.Final != "proxy" || !cfg.Route.AutoDetectInterface || cfg.Route.DefaultDomainResolver != "dns-cn" {
		t.Fatalf("路由收尾配置异常: %+v", cfg.Route)
	}
}

func TestBuildConfigUDPPolicyBlock(t *testing.T) {
	o := baseOptions()
	o.UDPPolicy = UDPPolicyBlock
	cfg, err := BuildConfig(o)
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	idx := findRouteRule(cfg, func(r BoxRouteRule) bool { return r.Network == "udp" && r.Port == 0 })
	if idx < 0 || cfg.Route.Rules[idx].Action != actionReject {
		t.Fatal("UDP_POLICY=block 时普通 UDP 应拒绝")
	}
}

func TestBuildConfigFakeIPDisabled(t *testing.T) {
	o := baseOptions()
	o.FakeIP = false
	cfg, err := BuildConfig(o)
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	if cfg.DNS.Final != "dns-proxy" {
		t.Fatalf("关闭 fake-ip 后 final 应为 dns-proxy: %q", cfg.DNS.Final)
	}
	for _, s := range cfg.DNS.Servers {
		if s.Type == "fakeip" {
			t.Fatal("关闭 fake-ip 后不应再出现 fakeip 服务器")
		}
	}
	for _, r := range cfg.DNS.Rules {
		if r.Server == "dns-fakeip" {
			t.Fatal("关闭 fake-ip 后不应再出现指向 dns-fakeip 的规则")
		}
	}
}

func TestBuildConfigSocksAuth(t *testing.T) {
	o := baseOptions()
	o.SocksUser = "user"
	o.SocksPassword = "pwd123"
	cfg, err := BuildConfig(o)
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	proxy := cfg.Outbounds[0]
	if proxy.Username != "user" || proxy.Password != "pwd123" {
		t.Fatalf("socks 认证字段缺失: %+v", proxy)
	}

	// 未配置认证时序列化结果中不应出现空凭据字段
	plain, err := BuildConfig(baseOptions())
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	data, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if strings.Contains(string(data), `"username"`) {
		t.Fatal("未配置认证时不应写入 username 字段")
	}
}

func TestBuildConfigForceAndDirectDomains(t *testing.T) {
	o := baseOptions()
	o.ForceDomains = []string{"googleapis.cn"}
	o.DirectDomains = []string{"corp.example"}
	o.DirectIPs = []string{"198.51.100.0/24", "198.51.100.7"}
	cfg, err := BuildConfig(o)
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}

	forceIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.DomainSuffix, "googleapis.cn") })
	if forceIdx < 0 || cfg.Route.Rules[forceIdx].Outbound != "proxy" {
		t.Fatal("FORCE_DOMAIN 应优先走代理")
	}
	// force 规则必须排在 cn 直连规则之前
	cnIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.DomainSuffix, "baidu.com") })
	if forceIdx > cnIdx {
		t.Fatal("FORCE_DOMAIN 规则应排在 cn 直连之前")
	}

	// 用户直连域名并入直连规则；裸 IP 补全为 /32
	directIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.DomainSuffix, "corp.example") })
	if directIdx < 0 || cfg.Route.Rules[directIdx].Outbound != "direct" {
		t.Fatal("DIRECT_DOMAIN 应走直连")
	}
	if !slices.Contains(cfg.Route.Rules[directIdx].IPCIDR, "198.51.100.7/32") &&
		findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.IPCIDR, "198.51.100.7/32") }) < 0 {
		t.Fatal("裸 IP 应补全为 /32")
	}
	if findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.IPCIDR, "198.51.100.0/24") }) < 0 {
		t.Fatal("CIDR 直连规则缺失")
	}
}

func TestBuildConfigRouteExclude(t *testing.T) {
	o := baseOptions()
	// 模拟 manager.Run 的合并结果：SSH 地址解析后进入排除列表
	o.RouteExclude = mergeResolvedExcludes(context.Background(), []string{"192.0.2.0/24"}, o.SSHHosts)
	cfg, err := BuildConfig(o)
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	excludes := cfg.Inbounds[0].RouteExcludeAddress
	for _, want := range []string{"192.0.2.0/24", "203.0.113.9/32"} {
		if !slices.Contains(excludes, want) {
			t.Fatalf("route_exclude_address 应包含 %s: %v", want, excludes)
		}
	}
	// 排除项同时出现在直连 IP 规则中（路由层之外的兜底）
	ipIdx := findRouteRule(cfg, func(r BoxRouteRule) bool { return slices.Contains(r.IPCIDR, "192.0.2.0/24") })
	if ipIdx < 0 || cfg.Route.Rules[ipIdx].Outbound != "direct" {
		t.Fatal("排除网段应同时进入直连 IP 规则")
	}
}

// TestNormalizeCIDR 网段归一：裸 IP 补全掩码、前缀长度与点分掩码等价、
// 带主机位的输入做掩码化，非法掩码被拒绝（与代理层 direct 规则一致）。
func TestNormalizeCIDR(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"1.2.3.4", "1.2.3.4/32", true},
		{"::1", "::1/128", true},
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"10.1.2.3/8", "10.0.0.0/8", true},
		{"192.168.0.0/255.255.0.0", "192.168.0.0/16", true},
		{"192.168.1.5/255.255.255.0", "192.168.1.0/24", true},
		{"fd00::1/64", "fd00::/64", true},
		{"10.0.0.0/255.0.255.0", "", false},
		{"10.0.0.0/33", "", false},
		{"10.0.0.0/abc", "", false},
		{"not-an-ip/24", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeCIDR(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("%q => %q %v，期望 %q %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestBuildConfigInvalidOptions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"缺少 SOCKS 端口", func(o *Options) { o.SocksPort = 0 }, "SOCKS 端口"},
		{"UDP 策略非法", func(o *Options) { o.UDPPolicy = "drop" }, "UDP 策略非法"},
		{"协议栈非法", func(o *Options) { o.Stack = "xx" }, "协议栈非法"},
		{"DNS 缺少协议", func(o *Options) { o.DNSProxy = "8.8.8.8" }, "TUN_DNS_PROXY"},
		{"DNS 协议不支持", func(o *Options) { o.DNSCN = "ftp://1.1.1.1" }, "TUN_DNS_CN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := baseOptions()
			c.mutate(&o)
			_, err := BuildConfig(o)
			if err == nil {
				t.Fatalf("%s 应报错", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("报错应包含 %q，实际: %v", c.want, err)
			}
		})
	}
}

func TestParseDNSServer(t *testing.T) {
	cases := []struct {
		raw        string
		wantType   string
		wantServer string
		wantPort   int
		wantPath   string
		wantErr    bool
	}{
		{"tcp://8.8.8.8", "tcp", "8.8.8.8", 0, "", false},
		{"udp://223.5.5.5:5353", "udp", "223.5.5.5", 5353, "", false},
		{"tls://dns.google", "tls", "dns.google", 0, "", false},
		{"https://dns.google/dns-query", "https", "dns.google", 0, "/dns-query", false},
		{"https://1.1.1.1:8443/dns-query", "https", "1.1.1.1", 8443, "/dns-query", false},
		{"local", "local", "", 0, "", false},
		{"8.8.8.8", "", "", 0, "", true},
		{"ftp://8.8.8.8", "", "", 0, "", true},
		{"udp://", "", "", 0, "", true},
		{"udp://:53", "", "", 0, "", true},
		{"udp:///foo", "", "", 0, "", true},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			srv, err := parseDNSServer(c.raw, "tag", "detour")
			if c.wantErr {
				if err == nil {
					t.Fatalf("%q 应报错", c.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q 解析失败: %v", c.raw, err)
			}
			if srv.Type != c.wantType || srv.Server != c.wantServer || srv.ServerPort != c.wantPort || srv.Path != c.wantPath {
				t.Fatalf("%q 解析结果异常: %+v", c.raw, srv)
			}
			if srv.Tag != "tag" {
				t.Fatalf("%q tag 异常: %+v", c.raw, srv)
			}
			// local 使用系统解析器，不绑定出站
			if c.wantType != "local" && srv.Detour != "detour" {
				t.Fatalf("%q detour 异常: %+v", c.raw, srv)
			}
		})
	}
}

// TestParseDNSServerDomainResolver 域名形式的 DNS 服务器必须携带 domain_resolver
// （sing-box >= 1.12 的 DNS 拨号器固定 DirectResolver，缺会拒绝启动）；
// 已绑定 detour 或 IP 字面量时不需要。
func TestParseDNSServerDomainResolver(t *testing.T) {
	cases := []struct {
		raw, detour  string
		wantResolver bool
	}{
		{"https://dns.alidns.com/dns-query", "", true},
		{"tls://dns.google", "", true},
		{"https://dns.google/dns-query", "proxy", false},
		{"udp://223.5.5.5", "", false},
	}
	for _, c := range cases {
		srv, err := parseDNSServer(c.raw, "tag", c.detour)
		if err != nil {
			t.Fatalf("%q 解析失败: %v", c.raw, err)
		}
		got := srv.DomainResolver != nil && srv.DomainResolver.Server == "dns-local"
		if got != c.wantResolver {
			t.Fatalf("%q detour=%q domain_resolver=%+v，期望 %v", c.raw, c.detour, srv.DomainResolver, c.wantResolver)
		}
	}
}

func TestSplitSSHHosts(t *testing.T) {
	cidrs, domains := splitSSHHosts([]string{"1.2.3.4", "example.com", "root@5.6.7.8", "2001:db8::1", "a.com,1.1.1.1"})
	wantCIDRs := []string{"1.2.3.4/32", "5.6.7.8/32", "2001:db8::1/128", "1.1.1.1/32"}
	for _, want := range wantCIDRs {
		if !slices.Contains(cidrs, want) {
			t.Fatalf("IP 拆分缺失 %s: %v", want, cidrs)
		}
	}
	for _, want := range []string{"example.com", "a.com"} {
		if !slices.Contains(domains, want) {
			t.Fatalf("域名拆分缺失 %s: %v", want, domains)
		}
	}
}

func TestMergeResolvedExcludesLiteral(t *testing.T) {
	// IP 字面量（含 user@ 前缀）应直接进入排除列表，不做 DNS 解析
	out := mergeResolvedExcludes(context.Background(), nil, []string{"1.2.3.4", "root@5.6.7.8"})
	for _, want := range []string{"1.2.3.4", "5.6.7.8"} {
		if !slices.Contains(out, want) {
			t.Fatalf("排除列表应包含 %s: %v", want, out)
		}
	}
}

// TestMergeResolvedExcludesCanceledContext 已取消时不做 DNS 解析，立即返回原有排除项。
func TestMergeResolvedExcludesCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := mergeResolvedExcludes(ctx, []string{"192.0.2.0/24"}, []string{"example.com"})
	if len(out) != 1 || out[0] != "192.0.2.0/24" {
		t.Fatalf("取消后应立即返回原有排除项: %v", out)
	}
}

func TestWriteConfig(t *testing.T) {
	cfg, err := BuildConfig(baseOptions())
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	path := filepath.Join(t.TempDir(), "nested", "box.json")
	got, err := WriteConfig(cfg, path)
	if err != nil {
		t.Fatalf("WriteConfig 失败: %v", err)
	}
	if got != path {
		t.Fatalf("显式路径应原样返回: %q", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("生成的配置不是合法 JSON: %v", err)
	}
	route, ok := parsed["route"].(map[string]any)
	if !ok {
		t.Fatal("缺少 route 段")
	}
	rules, ok := route["rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatal("缺少 route.rules")
	}
	first, ok := rules[0].(map[string]any)
	if !ok || first["action"] != "sniff" {
		t.Fatalf("首条规则 action 异常: %v", rules[0])
	}
}

func TestWriteConfigAutoPath(t *testing.T) {
	cfg, err := BuildConfig(baseOptions())
	if err != nil {
		t.Fatalf("BuildConfig 失败: %v", err)
	}
	path, err := WriteConfig(cfg, "")
	if err != nil {
		t.Fatalf("WriteConfig 失败: %v", err)
	}
	defer os.Remove(path)

	base := filepath.Base(path)
	if !strings.HasPrefix(base, "ssh-tunnel-tun-") || !strings.HasSuffix(base, ".json") {
		t.Fatalf("自动配置文件名应为随机模式: %q", base)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("读取配置信息失败: %v", err)
	}
	// TUN 仅支持 Linux，可以直接断言 0600 权限
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("配置含明文凭据，权限应为 0600: %o", perm)
	}
}
