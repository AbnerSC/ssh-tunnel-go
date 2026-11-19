// Package tun 通过托管 sing-box 子进程实现全局流量接管（TUN 模式）。
//
// ssh-tunnel-go 本身是 SOCKS5/HTTP 应用层代理，只有显式配置代理的应用才能使用；
// 本包在它前面加一层 L3 接管：生成 sing-box 配置（TUN inbound + DNS 分流 +
// 路由规则），并把 sing-box 作为子进程拉起，使本机全部流量自动进入代理链路。
// 未开启 TUN_MODE 时本包不参与任何流程，原代理方式行为不变。
package tun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ssh-tunnel-go/internal/direct"
	"ssh-tunnel-go/internal/logging"
)

const (
	// UDPPolicyDirect 非 DNS/QUIC 的 UDP 流量放行直连（默认，与未开启 TUN 时行为一致）
	UDPPolicyDirect = "direct"
	// UDPPolicyBlock 非 DNS/QUIC 的 UDP 流量一律拒绝
	UDPPolicyBlock = "block"

	// StackGVisor 用户态协议栈（默认）
	StackGVisor = "gvisor"
	// StackSystem 内核态系统协议栈
	StackSystem = "system"
	// StackMixed 混合协议栈（TCP 走系统栈，UDP 走 gvisor）
	StackMixed = "mixed"

	// LogLevelWarn sing-box 默认日志级别：只保留警告与错误
	LogLevelWarn = "warn"

	defaultDNSProxy = "tcp://8.8.8.8"
	defaultDNSCN    = "udp://223.5.5.5"

	// defaultConfigPattern 自动生成配置的临时文件名模式：随机后缀 + 0600，
	// 避免固定路径被预置符号链接劫持，也避免多次运行互相覆盖
	defaultConfigPattern = "ssh-tunnel-tun-*.json"
	// deletedSuffix Linux 上二进制被替换/删除后 /proc/self/exe 指向路径的后缀
	deletedSuffix = " (deleted)"
	// commNameMax Linux /proc/<pid>/comm 的进程名长度上限
	commNameMax = 15

	fakeIPRange  = "198.18.0.0/15"
	tunAddressV4 = "172.19.0.1/30"
	tunAddressV6 = "fdfe:dcba:9876::1/126"

	// MinMajorVersion / MinMinorVersion TUN 模式要求的最低 sing-box 版本：
	// 1.12 起 DNS server 改用 type 字段的新语法，低版本会直接拒绝配置
	MinMajorVersion = 1
	MinMinorVersion = 12

	// route action（sing-box 1.11+ rule action 语法）
	actionRoute     = "route"
	actionReject    = "reject"
	actionSniff     = "sniff"
	actionHijackDNS = "hijack-dns"
)

// privateCIDRs 私网/链路本地网段默认直连，避免内网设备访问被绕道远端。
var privateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "fc00::/7", "fe80::/10",
}

// privateSuffixes 内网/本地域名后缀，解析走系统 DNS，不误送代理。
var privateSuffixes = []string{"local", "lan", "internal", "home.arpa", "localhost"}

// Options TUN 全局接管的生成参数。
type Options struct {
	// ConfigPath 生成的 sing-box 配置输出路径；空表示在系统临时目录创建随机文件名的配置，
	// 并在 Run 退出时删除（显式指定时保留，便于排障）
	ConfigPath string
	// SocksHost / SocksPort 本地 SOCKS5 代理地址（TUN 的唯一出站）
	SocksHost string
	SocksPort int
	// SocksUser / SocksPassword 代理认证；两者同时非空时写入 socks outbound
	SocksUser     string
	SocksPassword string
	// SSHHosts SSH 服务器地址（IP 或域名），用于排除，防止隧道流量被二次抓回 TUN
	SSHHosts []string
	// DirectIPs / DirectDomains / GeoSites / ForceDomains 复用主程序的直连分流配置
	DirectIPs     []string
	DirectDomains []string
	GeoSites      []string
	ForceDomains  []string
	// RouteExclude 额外排除的网段（追加在 SSH 地址之后）
	RouteExclude []string
	// UDPPolicy 非 DNS/QUIC 的 UDP 处理策略：direct 或 block
	UDPPolicy string
	// FakeIP 是否对走代理的域名返回 fake-ip（保证域名分流精准）
	FakeIP bool
	// DNSProxy 走代理的 DNS（tcp://、udp://、tls://、https://）
	DNSProxy string
	// DNSCN 直连解析 cn 域名用的 DNS
	DNSCN string
	// Stack TUN 协议栈
	Stack string
	// LogLevel sing-box 日志级别
	LogLevel string
	// AutoRedirect Linux 专属 nftables 加速
	AutoRedirect bool
}

// BoxConfig sing-box 配置根结构（>= 1.12 语法）。
type BoxConfig struct {
	Log       BoxLog        `json:"log"`
	DNS       BoxDNS        `json:"dns"`
	Inbounds  []BoxInbound  `json:"inbounds"`
	Outbounds []BoxOutbound `json:"outbounds"`
	Route     BoxRoute      `json:"route"`
}

// BoxLog 日志配置。
type BoxLog struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

// BoxDNS DNS 模块配置。
type BoxDNS struct {
	Servers  []BoxDNSServer `json:"servers"`
	Rules    []BoxDNSRule   `json:"rules"`
	Final    string         `json:"final"`
	Strategy string         `json:"strategy"`
}

// BoxDNSServer DNS 服务器（1.12 新格式，type 决定协议）。
type BoxDNSServer struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Path       string `json:"path,omitempty"`
	Detour     string `json:"detour,omitempty"`
	// DomainResolver 域名形式的服务器地址用什么解析；sing-box >= 1.12 的
	// DNS 服务器拨号器固定为 DirectResolver，缺省会拒绝启动
	DomainResolver *BoxDomainResolver `json:"domain_resolver,omitempty"`
	Inet4Range     string             `json:"inet4_range,omitempty"`
}

// BoxDomainResolver 域名解析器引用（server 为 DNS 服务器 tag）。
type BoxDomainResolver struct {
	Server string `json:"server"`
}

// BoxDNSRule DNS 分流规则。
type BoxDNSRule struct {
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	// QueryType 按查询类型分流（如 A/AAAA），用于把 fake-ip 限定在地址记录查询上
	QueryType []string `json:"query_type,omitempty"`
	Server    string   `json:"server"`
}

// BoxInbound TUN 入站。
type BoxInbound struct {
	Type                string   `json:"type"`
	Tag                 string   `json:"tag"`
	Address             []string `json:"address"`
	AutoRoute           bool     `json:"auto_route"`
	StrictRoute         bool     `json:"strict_route"`
	Stack               string   `json:"stack"`
	AutoRedirect        bool     `json:"auto_redirect,omitempty"`
	RouteExcludeAddress []string `json:"route_exclude_address,omitempty"`
}

// BoxOutbound 出站（socks 或 direct）。
type BoxOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
}

// BoxRoute 路由配置。
type BoxRoute struct {
	Rules                 []BoxRouteRule `json:"rules"`
	Final                 string         `json:"final"`
	AutoDetectInterface   bool           `json:"auto_detect_interface"`
	DefaultDomainResolver string         `json:"default_domain_resolver,omitempty"`
}

// BoxRouteRule 路由规则。
type BoxRouteRule struct {
	Protocol      string   `json:"protocol,omitempty"`
	ProcessPath   []string `json:"process_path,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	Network       string   `json:"network,omitempty"`
	Port          int      `json:"port,omitempty"`
	Action        string   `json:"action"`
	Outbound      string   `json:"outbound,omitempty"`
}

// applyDefaults 填充可选配置的默认值。
func (o *Options) applyDefaults() {
	if o.SocksHost == "" {
		o.SocksHost = "127.0.0.1"
	}
	o.UDPPolicy = strings.ToLower(strings.TrimSpace(o.UDPPolicy))
	if o.UDPPolicy == "" {
		o.UDPPolicy = UDPPolicyDirect
	}
	o.Stack = strings.ToLower(strings.TrimSpace(o.Stack))
	if o.Stack == "" {
		o.Stack = StackGVisor
	}
	o.LogLevel = strings.ToLower(strings.TrimSpace(o.LogLevel))
	if o.LogLevel == "" {
		o.LogLevel = LogLevelWarn
	}
	if o.DNSProxy == "" {
		o.DNSProxy = defaultDNSProxy
	}
	if o.DNSCN == "" {
		o.DNSCN = defaultDNSCN
	}
}

// validate 校验取值域。取值写错时直接报错，避免生成一份静默失效的接管配置。
func (o *Options) validate() error {
	if o.SocksPort <= 0 || o.SocksPort > 65535 {
		return fmt.Errorf("TUN 模式需要有效的本地 SOCKS 端口，当前: %d", o.SocksPort)
	}
	switch o.UDPPolicy {
	case UDPPolicyDirect, UDPPolicyBlock:
	default:
		return fmt.Errorf("TUN UDP 策略非法: %q（可选 direct/block）", o.UDPPolicy)
	}
	switch o.Stack {
	case StackGVisor, StackSystem, StackMixed:
	default:
		return fmt.Errorf("TUN 协议栈非法: %q（可选 gvisor/system/mixed）", o.Stack)
	}
	switch o.LogLevel {
	case "trace", "debug", "info", "warn", "error", "fatal", "panic":
	default:
		return fmt.Errorf("sing-box 日志级别非法: %q", o.LogLevel)
	}
	return nil
}

// BuildConfig 生成 sing-box 配置。
//
// 规则顺序即优先级，每一条都对应一个明确的回环/分流约束：
//  1. sniff 与 hijack-dns：嗅探域名、劫持全部 DNS 查询（必须在最前）；
//  2. process_path/process_name 放行 ssh-tunnel 自身出站：代理进程的本地
//     直连流量回到 TUN 后不再二次送进 SOCKS，否则会形成 代理→TUN→代理 的
//     死循环；路径规则之外再加进程名规则，二进制被替换/改名时仍有兜底；
//  3. SSH 服务器地址直连：隧道本身的连接不能被 TUN 抓走；
//  4. FORCE_DOMAIN 走代理，cn 域名/用户直连域名/私网走直连；
//  5. QUIC(udp 443) 对非直连目标拒绝：隧道不承载 UDP，让浏览器回退 TCP 走代理，
//     避免 QUIC 直连绕过代理造成出口 IP 分裂；私网/DIRECT_IP 等直连目标已在
//     上一组规则放行，QUIC 与 TCP 保持一致的直连语义；
//  6. 其余 UDP 按策略直连或拒绝（同样因为隧道只有 TCP 通道）。
func BuildConfig(o Options) (*BoxConfig, error) {
	o.applyDefaults()
	if err := o.validate(); err != nil {
		return nil, err
	}

	cnSuffix, cnFull, cnKeywords := buildGeoRules(o.GeoSites)
	directDomains := normalizeDomains(o.DirectDomains)
	forceDomains := normalizeDomains(o.ForceDomains)
	directCIDRs := normalizeCIDRList(o.DirectIPs, "直连")
	excludes := normalizeCIDRList(o.RouteExclude, "排除")
	// 自动排除各网卡的局域网前缀：TUN 全量接管会把「本机作为服务端时的
	// 回程流量」也路由进 tun0，用户态协议栈对 mid-stream 报文只能回 RST，
	// 表现为 TUN 启动后入站连接全部断开。LAN 前缀在内核路由层直接排除后
	// 回程走原始路径；系统 DNS 地址会从排除集合中单独扣除（前缀拆分），
	// 保证 DNS 查询仍能进 TUN 被劫持（见 lanExcludeCIDRs）。
	excludes = mergeLists(excludes, lanExcludeCIDRs())
	sshCIDRs, sshDomains := splitSSHHosts(o.SSHHosts)

	dnsProxy, err := parseDNSServer(o.DNSProxy, "dns-proxy", "proxy")
	if err != nil {
		return nil, fmt.Errorf("TUN_DNS_PROXY 配置错误: %w", err)
	}
	// dns-cn 不绑定 detour：sing-box >= 1.12 禁止 detour 指向「空 direct 出站」
	//（启动即报 detour to an empty direct outbound makes no sense），
	// 空 detour 的拨号语义就是直连，且同样受 TUN 自身流量标记保护，不会回环。
	dnsCN, err := parseDNSServer(o.DNSCN, "dns-cn", "")
	if err != nil {
		return nil, fmt.Errorf("TUN_DNS_CN 配置错误: %w", err)
	}
	servers := []BoxDNSServer{
		{Type: "local", Tag: "dns-local"},
		dnsProxy,
		dnsCN,
	}
	dnsRules := buildDNSRules(directDomains, forceDomains, sshDomains, cnSuffix, cnFull, cnKeywords)
	if o.FakeIP {
		servers = append(servers, BoxDNSServer{Type: "fakeip", Tag: "dns-fakeip", Inet4Range: fakeIPRange})
		// sing-box >= 1.12 不允许 fakeip 服务器作为默认(final)服务器：默认服务器
		// 还要回答 MX/TXT/SVCB 等非地址类查询，必须是真实解析器（否则启动即报
		// "default server cannot be fakeip"）。因此 final 保持 dns-proxy，
		// 末尾用 A/AAAA 规则把未命中直连/强制规则的被代理域名交给 fake-ip。
		dnsRules = append(dnsRules, BoxDNSRule{QueryType: []string{"A", "AAAA"}, Server: "dns-fakeip"})
	}

	cfg := &BoxConfig{
		Log: BoxLog{Level: o.LogLevel, Timestamp: true},
		DNS: BoxDNS{
			Servers:  servers,
			Rules:    dnsRules,
			Final:    "dns-proxy",
			Strategy: "prefer_ipv4",
		},
		Inbounds: []BoxInbound{{
			Type:                "tun",
			Tag:                 "tun-in",
			Address:             []string{tunAddressV4, tunAddressV6},
			AutoRoute:           true,
			StrictRoute:         true,
			Stack:               o.Stack,
			AutoRedirect:        o.AutoRedirect,
			RouteExcludeAddress: excludes,
		}},
		Outbounds: []BoxOutbound{
			{
				Type:       "socks",
				Tag:        "proxy",
				Server:     o.SocksHost,
				ServerPort: o.SocksPort,
				Username:   o.SocksUser,
				Password:   o.SocksPassword,
			},
			{Type: "direct", Tag: "direct"},
		},
		Route: BoxRoute{
			Rules:                 buildRouteRules(o, cnSuffix, cnFull, cnKeywords, directDomains, forceDomains, sshDomains, sshCIDRs, directCIDRs, excludes),
			Final:                 "proxy",
			AutoDetectInterface:   true,
			DefaultDomainResolver: "dns-cn",
		},
	}
	logging.Info("tun", "sing-box配置已生成",
		"socks", fmt.Sprintf("%s:%d", o.SocksHost, o.SocksPort),
		"cnSuffix", len(cnSuffix), "cnFull", len(cnFull), "cnKeyword", len(cnKeywords),
		"directDomains", len(directDomains), "forceDomains", len(forceDomains),
		"routeExcludes", len(excludes), "sshExcludes", len(sshCIDRs)+len(sshDomains))
	return cfg, nil
}

// buildRouteRules 按优先级组装路由规则（顺序敏感，见 BuildConfig 注释）。
func buildRouteRules(o Options, cnSuffix, cnFull, cnKeywords, directDomains, forceDomains, sshDomains, sshCIDRs, directCIDRs, excludes []string) []BoxRouteRule {
	rules := []BoxRouteRule{
		{Action: actionSniff},
		{Protocol: "dns", Action: actionHijackDNS},
	}
	exePaths := executablePaths()
	if len(exePaths) > 0 {
		rules = append(rules, BoxRouteRule{ProcessPath: exePaths, Action: actionRoute, Outbound: "direct"})
	}
	// process_path 依赖路径精确匹配，二进制被包升级替换（/proc/self/exe 带
	// " (deleted)" 后缀）或以改名副本运行时会静默失配，再用进程名兜底一层
	if names := executableNames(exePaths); len(names) > 0 {
		rules = append(rules, BoxRouteRule{ProcessName: names, Action: actionRoute, Outbound: "direct"})
	}
	if len(sshCIDRs) > 0 {
		rules = append(rules, BoxRouteRule{IPCIDR: sshCIDRs, Action: actionRoute, Outbound: "direct"})
	}
	if len(sshDomains) > 0 {
		rules = append(rules, BoxRouteRule{Domain: sshDomains, Action: actionRoute, Outbound: "direct"})
	}
	if len(forceDomains) > 0 {
		rules = append(rules, BoxRouteRule{DomainSuffix: forceDomains, Action: actionRoute, Outbound: "proxy"})
	}
	if suffix := mergeLists(directDomains, cnSuffix); len(suffix)+len(cnFull)+len(cnKeywords) > 0 {
		rules = append(rules, BoxRouteRule{
			DomainSuffix:  suffix,
			Domain:        cnFull,
			DomainKeyword: cnKeywords,
			Action:        actionRoute,
			Outbound:      "direct",
		})
	}
	// 直连 IP：私网段 + 显式排除 + SSH 服务器 + 用户 DIRECT_IP
	rules = append(rules, BoxRouteRule{
		IPCIDR:   mergeLists(privateCIDRs, excludes, sshCIDRs, directCIDRs),
		Action:   actionRoute,
		Outbound: "direct",
	})
	// 非直连目标的 QUIC 拒绝，强制回退 TCP；私网/DIRECT_IP 等直连目标已被
	// 上一组 ip_cidr 规则放行，保持与 TCP 直连一致的语义
	rules = append(rules, BoxRouteRule{Network: "udp", Port: 443, Action: actionReject})
	if o.UDPPolicy == UDPPolicyBlock {
		rules = append(rules, BoxRouteRule{Network: "udp", Action: actionReject})
	} else {
		rules = append(rules, BoxRouteRule{Network: "udp", Action: actionRoute, Outbound: "direct"})
	}
	return rules
}

// buildDNSRules 组装 DNS 分流规则（顺序敏感：force 优先于用户直连域名）。
func buildDNSRules(directDomains, forceDomains, sshDomains, cnSuffix, cnFull, cnKeywords []string) []BoxDNSRule {
	rules := []BoxDNSRule{
		{DomainSuffix: privateSuffixes, Server: "dns-local"},
	}
	if len(sshDomains) > 0 {
		// SSH 服务器域名必须走系统解析：一旦返回 fake-ip，
		// 隧道自身的连接会被 TUN 抓走并还原域名，徒增一次解析往返
		rules = append(rules, BoxDNSRule{Domain: sshDomains, Server: "dns-local"})
	}
	if len(forceDomains) > 0 {
		rules = append(rules, BoxDNSRule{DomainSuffix: forceDomains, Server: "dns-proxy"})
	}
	if len(directDomains) > 0 {
		rules = append(rules, BoxDNSRule{DomainSuffix: directDomains, Server: "dns-local"})
	}
	if len(cnSuffix)+len(cnFull)+len(cnKeywords) > 0 {
		rules = append(rules, BoxDNSRule{
			DomainSuffix:  cnSuffix,
			Domain:        cnFull,
			DomainKeyword: cnKeywords,
			Server:        "dns-cn",
		})
	}
	return rules
}

// buildGeoRules 把内置 dlc.dat 的 geosite 列表转换成 sing-box 域名规则。
//
// 复用主程序内嵌的 dlc.dat（v2fly domain-list-community），TUN 层的
// cn 直连分流与代理层使用同一份数据，且不依赖外部网络。
// 正则规则跳过：Go RE2 与 sing-box 的正则语法不完全兼容，成本高收益低。
func buildGeoRules(sites []string) (suffix, full, keywords []string) {
	if len(sites) == 0 {
		return nil, nil, nil
	}
	parsed, err := direct.ParseDLC(sites)
	if err != nil {
		logging.Warn("tun", "解析内置dlc.dat失败，TUN层不加载域名直连分流", "err", err)
		return nil, nil, nil
	}
	seen := make(map[string]struct{})
	appendRule := func(dst *[]string, prefix, value string) {
		v := strings.ToLower(strings.TrimSpace(value))
		if v == "" {
			return
		}
		key := prefix + v
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		*dst = append(*dst, v)
	}
	for _, site := range sites {
		name := strings.ToLower(strings.TrimSpace(site))
		if name == "" {
			continue
		}
		list, ok := parsed[name]
		if !ok {
			logging.Warn("tun", "dlc.dat中不存在该geosite列表", "site", name)
			continue
		}
		for _, rule := range list {
			switch rule.Type {
			case direct.TypeDomain:
				appendRule(&suffix, "s:", rule.Value)
			case direct.TypeFull:
				appendRule(&full, "f:", rule.Value)
			case direct.TypeKeyword:
				appendRule(&keywords, "k:", rule.Value)
			}
		}
	}
	sort.Strings(suffix)
	sort.Strings(full)
	sort.Strings(keywords)
	logging.Info("tun", "geosite直连规则已转换", "suffix", len(suffix), "full", len(full), "keyword", len(keywords))
	return suffix, full, keywords
}

// executablePaths 返回本进程的可执行文件路径，用于进程级防回环规则。
func executablePaths() []string {
	exe, err := os.Executable()
	if err != nil {
		logging.Warn("tun", "获取可执行文件路径失败，进程级防回环规则缺失（依赖 SSH 地址与私网直连规则兜底）", "err", err)
		return nil
	}
	paths := []string{exe}
	// Linux 上二进制被替换后 /proc/self/exe 会带 " (deleted)" 后缀，
	// sing-box 侧看到的是替换前的原始路径，去后缀的形态同样写入规则
	if trimmed := strings.TrimSuffix(exe, deletedSuffix); trimmed != exe {
		paths = append(paths, trimmed)
	}
	if real, evalErr := filepath.EvalSymlinks(exe); evalErr == nil && real != exe {
		paths = append(paths, real)
	}
	return paths
}

// executableNames 根据可执行文件路径推导进程名，用于 process_name 备用防回环规则。
//
// 路径匹配在二进制被升级替换、以改名副本或 wrapper 启动时会失配；
// 进程名规则不受路径变化影响，是第二重防护。
func executableNames(paths []string) []string {
	var names []string
	seen := make(map[string]struct{})
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || name == "." || name == string(filepath.Separator) {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	for _, p := range paths {
		name := filepath.Base(p)
		add(name)
		// 进程名取自 /proc/<pid>/comm，超过 15 字节会被内核截断
		if len(name) > commNameMax {
			add(name[:commNameMax])
		}
	}
	return names
}

// parseDNSServer 解析 DNS 描述串为 sing-box DNS server。
// 支持 tcp://、udp://、tls://、https://（可带端口与路径）与 local/system。
// detour 为空表示直连拨号；服务器是域名时自动补 dns-local 解析器
// （sing-box >= 1.12 对域名形式的 DNS 服务器强制要求 domain_resolver）。
func parseDNSServer(raw, tag, detour string) (BoxDNSServer, error) {
	s := strings.TrimSpace(raw)
	lower := strings.ToLower(s)
	if lower == "local" || lower == "system" {
		return BoxDNSServer{Type: "local", Tag: tag}, nil
	}
	idx := strings.Index(s, "://")
	if idx <= 0 {
		return BoxDNSServer{}, fmt.Errorf("格式非法: %q（示例: tcp://8.8.8.8、udp://223.5.5.5、https://dns.google/dns-query、local）", raw)
	}
	scheme := strings.ToLower(s[:idx])
	rest := s[idx+3:]
	if rest == "" {
		return BoxDNSServer{}, fmt.Errorf("缺少服务器地址: %q", raw)
	}
	switch scheme {
	case "udp", "tcp", "tls":
		defPort := 53
		if scheme == "tls" {
			defPort = 853
		}
		host, port, err := splitHostPort(rest, defPort)
		if err != nil {
			return BoxDNSServer{}, fmt.Errorf("%q: %w", raw, err)
		}
		srv := BoxDNSServer{Type: scheme, Tag: tag, Server: host, Detour: detour}
		if port != defPort {
			srv.ServerPort = port
		}
		srv.DomainResolver = domainServerResolver(host, detour)
		return srv, nil
	case "https":
		hostPart, path := rest, ""
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			hostPart, path = rest[:i], rest[i:]
		}
		host, port, err := splitHostPort(hostPart, 443)
		if err != nil {
			return BoxDNSServer{}, fmt.Errorf("%q: %w", raw, err)
		}
		srv := BoxDNSServer{Type: "https", Tag: tag, Server: host, Path: path, Detour: detour}
		if port != 443 {
			srv.ServerPort = port
		}
		srv.DomainResolver = domainServerResolver(host, detour)
		return srv, nil
	default:
		return BoxDNSServer{}, fmt.Errorf("不支持的 DNS 协议 %q（支持 tcp://、udp://、tls://、https://、local）", scheme)
	}
}

// domainServerResolver 域名形式的 DNS 服务器需要先用系统解析器解析自身地址；
// 已绑定 detour 时拨号交给出站处理，无需额外解析器。
func domainServerResolver(host, detour string) *BoxDomainResolver {
	if detour != "" {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	return &BoxDomainResolver{Server: "dns-local"}
}

// splitHostPort 拆分 host[:port]；缺省端口时使用 defPort，IPv6 字面量自动去括号。
func splitHostPort(raw string, defPort int) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, errors.New("服务器地址为空")
	}
	if host, portStr, err := net.SplitHostPort(raw); err == nil {
		port, convErr := strconv.Atoi(portStr)
		if convErr != nil || port <= 0 || port > 65535 {
			return "", 0, fmt.Errorf("端口非法: %q", portStr)
		}
		if err := validateHost(host); err != nil {
			return "", 0, err
		}
		return host, port, nil
	}
	// 无端口：可能是主机名、裸 IPv4 或裸 IPv6 字面量
	host := strings.Trim(raw, "[]")
	if err := validateHost(host); err != nil {
		return "", 0, err
	}
	return host, defPort, nil
}

// validateHost 校验主机部分：非空且不含路径分隔符等明显非法字符。
//
// 不校验主机是否可解析：DNS 服务器允许域名，具体连通性由 sing-box 处理。
func validateHost(host string) error {
	if host == "" {
		return errors.New("服务器地址为空")
	}
	if strings.ContainsAny(host, `/\`) {
		return fmt.Errorf("服务器地址非法: %q", host)
	}
	return nil
}

// splitSSHHosts 把 SSH 服务器地址拆成 IP（CIDR 形式）与域名两组。
func splitSSHHosts(hosts []string) (cidrs, domains []string) {
	for _, item := range hosts {
		for _, h := range splitList(item) {
			// 容错误传 user@host 形式
			if idx := strings.LastIndex(h, "@"); idx >= 0 {
				h = h[idx+1:]
			}
			if addr, err := netip.ParseAddr(h); err == nil {
				if addr.Is4() {
					cidrs = append(cidrs, addr.String()+"/32")
				} else {
					cidrs = append(cidrs, addr.String()+"/128")
				}
				continue
			}
			if h != "" {
				domains = append(domains, strings.ToLower(h))
			}
		}
	}
	return mergeLists(cidrs), mergeLists(domains)
}

// normalizeCIDRList 拆分、校验并规范化 CIDR 列表（裸 IP 补全掩码），非法项告警后跳过。
func normalizeCIDRList(values []string, kind string) []string {
	var out []string
	seen := make(map[string]struct{}, len(values))
	for _, item := range values {
		for _, part := range splitList(item) {
			cidr, ok := normalizeCIDR(part)
			if !ok {
				logging.Warn("tun", "忽略非法网段", "kind", kind, "value", part)
				continue
			}
			if _, dup := seen[cidr]; dup {
				continue
			}
			seen[cidr] = struct{}{}
			out = append(out, cidr)
		}
	}
	return out
}

// normalizeCIDR 把裸 IP 补全为 /32 或 /128，并把网段归一为掩码后的前缀。
//
// 掩码支持前缀长度与点分写法（如 192.168.0.0/255.255.0.0），与代理层
// direct 规则保持一致；带主机位的输入（如 10.1.2.3/8）统一掩码化。
func normalizeCIDR(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return "", false
		}
		if addr.Is4() {
			return addr.String() + "/32", true
		}
		return addr.String() + "/128", true
	}
	addr, err := netip.ParseAddr(s[:slash])
	if err != nil {
		return "", false
	}
	bits, ok := parseMaskBits(s[slash+1:], addr.BitLen())
	if !ok {
		return "", false
	}
	return netip.PrefixFrom(addr, bits).Masked().String(), true
}

// parseMaskBits 解析前缀长度：支持 24 与 255.255.255.0 两种写法。
func parseMaskBits(mask string, maxBits int) (int, bool) {
	if strings.ContainsRune(mask, '.') {
		addr, err := netip.ParseAddr(mask)
		if err != nil || !addr.Is4() || maxBits != 32 {
			return 0, false
		}
		prefix := 0
		zeroSeen := false
		for _, b := range addr.As4() {
			for i := 7; i >= 0; i-- {
				if b>>i&1 == 1 {
					if zeroSeen {
						return 0, false
					}
					prefix++
				} else {
					zeroSeen = true
				}
			}
		}
		return prefix, true
	}
	n, err := strconv.Atoi(mask)
	if err != nil || n < 0 || n > maxBits {
		return 0, false
	}
	return n, true
}

// normalizeDomains 拆分并规范化域名列表（小写、去尾点、去重）。
func normalizeDomains(values []string) []string {
	var out []string
	seen := make(map[string]struct{}, len(values))
	for _, item := range values {
		for _, part := range splitList(item) {
			lower := strings.ToLower(strings.TrimSuffix(part, "."))
			if lower == "" {
				continue
			}
			if _, dup := seen[lower]; dup {
				continue
			}
			seen[lower] = struct{}{}
			out = append(out, lower)
		}
	}
	return out
}

// splitList 拆分逗号/分号/空白分隔的列表，逐项去掉包裹引号。
func splitList(item string) []string {
	str := strings.TrimSpace(item)
	if str == "" {
		return nil
	}
	var out []string
	for _, part := range strings.FieldsFunc(str, func(c rune) bool {
		return c == ',' || c == '，' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
	}) {
		if part = strings.Trim(strings.TrimSpace(part), `"'`); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// mergeLists 按顺序合并多个列表并去重。
func mergeLists(lists ...[]string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, list := range lists {
		for _, v := range list {
			if v == "" {
				continue
			}
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// WriteConfig 把配置写入磁盘（带缩进，便于人工排障）并返回实际路径。
//
// 配置内含解密后的 SOCKS 明文凭据，权限固定为 0600；path 为空时在系统
// 临时目录以随机文件名创建（O_EXCL），避免固定路径被预置符号链接劫持。
func WriteConfig(cfg *BoxConfig, path string) (string, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化 sing-box 配置失败: %w", err)
	}
	data = append(data, '\n')
	if path == "" {
		f, err := os.CreateTemp("", defaultConfigPattern)
		if err != nil {
			return "", fmt.Errorf("创建 sing-box 配置文件失败: %w", err)
		}
		name := f.Name()
		if err := writeAndClose(f, data); err != nil {
			// 写入失败时立即清理，避免残留含明文凭据的文件
			_ = os.Remove(name)
			return "", fmt.Errorf("写入 sing-box 配置失败: %w", err)
		}
		return name, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("创建配置目录失败: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("写入 sing-box 配置失败: %w", err)
	}
	// O_CREATE 的权限仅对新建文件生效，已存在的文件需显式收紧
	_ = f.Chmod(0o600)
	if err := writeAndClose(f, data); err != nil {
		return "", fmt.Errorf("写入 sing-box 配置失败: %w", err)
	}
	return path, nil
}

// writeAndClose 写入数据并关闭文件，任一失败都会返回错误。
func writeAndClose(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
