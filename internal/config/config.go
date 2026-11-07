package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"ssh-tunnel-go/internal/console"
	"ssh-tunnel-go/internal/direct"
	"ssh-tunnel-go/internal/logging"
	"ssh-tunnel-go/internal/proxy"
)

// envLookup 便于测试替换。
var envLookup = os.LookupEnv

// SSHConfig SSH 隧道服务端配置。
type SSHConfig struct {
	Addr     string
	User     string
	Password string
	Port     int
	Pool     int
	// KnownHosts 服务端主机密钥的首次信任(TOFU)记录文件；
	// 为空表示使用工作目录下的 known_hosts
	KnownHosts string
	// HostKeys 期望的服务端主机密钥指纹（SHA256:... 或裸 base64），非空时只接受匹配项
	HostKeys []string
}

// Script 返回日志展示用的连接标识
func (s *SSHConfig) Script() string {
	return fmt.Sprintf("%s@%s:%d", s.User, s.Addr, s.Port)
}

// Config 运行配置。
type Config struct {
	SocksPort     int // -1 表示未启用
	HTTPPort      int // -1 表示未启用
	SocksUser     string
	SocksPassword string
	// BindAddr 代理端口的监听地址；空值表示监听全部网卡（默认）
	BindAddr string
	// AllowUnauthPublic 允许在非回环地址上提供无认证代理
	AllowUnauthPublic bool
	// MaxConns 代理并发连接上限；0 表示不限制。
	// 未配置时取 proxy 包内置默认值，避免两边各写一份数字后续失效
	MaxConns int
	// MaxConnsPerIP 单来源 IP 的并发连接上限；0 表示不限制
	MaxConnsPerIP int
	SSH           *SSHConfig
	Direct        *direct.Rules
}

// CheckWork 是否存在可执行任务。
func (c *Config) CheckWork() bool {
	return c.SocksPort > 0 || c.HTTPPort > 0
}

// forwardFlags 已移除的端口转发参数。
//
// ParamFormat 会静默忽略未识别的参数，若只删实现而不报错，
// 历史部署带的转发参数会变成「进程正常启动但转发不生效」，
// 比启动失败更难排查，因此这里显式拒绝启动并给出原因。
var forwardFlags = []string{"-L", "-s", "-R"}

func rejectForwardFlags(r *Resolver) error {
	var hit []string
	for _, flag := range forwardFlags {
		if r.params.Contains(flag) {
			hit = append(hit, flag)
		}
	}
	if len(hit) == 0 {
		return nil
	}
	return fmt.Errorf("本版本已移除端口转发功能，检测到 %s：代理仅保留 SOCKS5(-D) 与 HTTP(-H)，"+
		"请去掉这些参数后重启", strings.Join(hit, "、"))
}

// Load 装配配置。
func Load(r *Resolver) (*Config, error) {
	if err := rejectForwardFlags(r); err != nil {
		return nil, err
	}

	cfg := &Config{SocksPort: -1, HTTPPort: -1}

	sshPort, err := r.Int("-p", "SSH_PORT", 22)
	if err != nil {
		return nil, err
	}

	// 服务器地址：user@host，缺省账号 root；容错去掉误加的引号
	serverUser := stripQuote(r.Value("-server", "SSH_SERVER", ""))
	serverHost := ""
	if serverUser != "" {
		if idx := strings.Index(serverUser, "@"); idx >= 0 {
			serverHost = serverUser[idx+1:]
			serverUser = serverUser[:idx]
		} else {
			serverHost = serverUser
			serverUser = "root"
		}
	}
	serverPassword := r.Value("-P", "SSH_PASSWORD", "")

	if r.Has("-D", "SOCKS_PORT") {
		if cfg.SocksPort, err = r.Int("-D", "SOCKS_PORT", -1); err != nil {
			return nil, err
		}
	}
	if r.Has("-H", "HTTP_PORT") {
		if cfg.HTTPPort, err = r.Int("-H", "HTTP_PORT", -1); err != nil {
			return nil, err
		}
	}
	cfg.SocksUser = r.Value("-suser", "SOCKS_USER", "")
	cfg.SocksPassword = r.Value("-spwd", "SOCKS_PASSWORD", "")
	cfg.BindAddr = strings.TrimSpace(r.Value("-bind", "BIND_ADDR", ""))
	if cfg.AllowUnauthPublic, err = r.Bool("-allow-unauth-public", "ALLOW_UNAUTH_PUBLIC", false); err != nil {
		return nil, err
	}
	// 并发连接上限：两个维度都允许用 0 显式关闭（需自行确保内存足够）
	if cfg.MaxConns, err = r.Int("-max-conns", "MAX_CONNS", proxy.DefaultMaxConns); err != nil {
		return nil, err
	}
	if cfg.MaxConnsPerIP, err = r.Int("-max-conns-per-ip", "MAX_CONNS_PER_IP", proxy.DefaultMaxConnsPerIP); err != nil {
		return nil, err
	}
	if cfg.MaxConns < 0 || cfg.MaxConnsPerIP < 0 {
		return nil, fmt.Errorf("并发连接上限不能为负数（0 表示不限制）: MAX_CONNS=%d MAX_CONNS_PER_IP=%d",
			cfg.MaxConns, cfg.MaxConnsPerIP)
	}
	// 每 IP 上限大于全局上限时该维度失去意义，属于配置错误
	if cfg.MaxConns > 0 && cfg.MaxConnsPerIP > cfg.MaxConns {
		return nil, fmt.Errorf("单 IP 并发连接上限不能大于全局上限: MAX_CONNS=%d MAX_CONNS_PER_IP=%d",
			cfg.MaxConns, cfg.MaxConnsPerIP)
	}

	// 账号密码必须成对出现：只配一半时如果静默当作「不启用认证」，
	// 代理会变成对任何人都开放的内网跳板（巡检时实测只需 SOCKS_USER 一个变量即可绕过认证）
	authReady := cfg.SocksUser != "" && cfg.SocksPassword != ""
	if (cfg.SocksUser == "") != (cfg.SocksPassword == "") {
		return nil, fmt.Errorf("SOCKS_USER 与 SOCKS_PASSWORD 必须同时配置，当前缺少 %s；"+
			"单边配置会让代理变成完全无认证", missingAuthField(cfg.SocksUser, cfg.SocksPassword))
	}
	if cfg.SocksPort != -1 {
		if authReady {
			logging.Info("config", "socks5代理认证已启用", "user", cfg.SocksUser)
		} else {
			logging.Warn("config", "socks5代理无授权认证", "bind", bindDesc(cfg.BindAddr))
		}
	}
	if cfg.HTTPPort > 0 {
		if authReady {
			logging.Info("config", "http代理认证已启用", "user", cfg.SocksUser)
		} else {
			logging.Warn("config", "http代理无授权认证", "bind", bindDesc(cfg.BindAddr))
		}
	}
	if cfg.SocksPort > 0 || cfg.HTTPPort > 0 {
		logging.Info("config", "并发连接上限",
			"maxTotal", cfg.MaxConns, "maxPerIP", cfg.MaxConnsPerIP,
			"hint", "0 表示不限制，可用 MAX_CONNS / MAX_CONNS_PER_IP 调整")
	}

	// 无认证 + 对外监听 = 开放代理/内网跳板，默认拒绝启动；
	// 确实需要（内网受控环境）时用 ALLOW_UNAUTH_PUBLIC=true 显式放行
	if (cfg.SocksPort > 0 || cfg.HTTPPort > 0) && !authReady && !cfg.AllowUnauthPublic {
		if !isLoopbackBind(cfg.BindAddr) {
			return nil, fmt.Errorf("拒绝在 %s 上提供无认证代理（任意访问者都能把它当作代理与内网跳板）："+
				"可配置 SOCKS_USER+SOCKS_PASSWORD、或设 BIND_ADDR=127.0.0.1 仅本机使用、"+
				"或确认网络隔离后用 ALLOW_UNAUTH_PUBLIC=true 显式放行", bindDesc(cfg.BindAddr))
		}
	}

	// 直连路由：-direct-ip 支持单 IP 与网段，-direct-domain 匹配主域名，
	// -direct-cn 加载内置 geosite 列表（默认 cn）；
	// -force-domain 反向修正：命中的域名忽略一切直连规则，强制走 SSH 隧道
	directIPs := r.Values("-direct-ip", "DIRECT_IP")
	directDomains := r.Values("-direct-domain", "DIRECT_DOMAIN")
	directSites := readGeoSiteNames(r)
	forceDomains := r.Values("-force-domain", "FORCE_DOMAIN")
	if len(directIPs) > 0 || len(directDomains) > 0 || len(directSites) > 0 || len(forceDomains) > 0 {
		cfg.Direct = direct.New(directIPs, directDomains)
		cfg.Direct.SetForceDomains(forceDomains)
		if len(directSites) > 0 {
			loadGeoSite(cfg.Direct, directSites)
		}
		logging.Info("config", "直连规则已加载",
			"ipRules", cfg.Direct.IPRuleCount(), "domainRules", cfg.Direct.DomainRuleCount(),
			"forceDomains", cfg.Direct.ForceDomainCount())
	}

	// 需要 SSH 能力时，缺省信息从控制台补齐（非终端环境不阻塞）
	if serverHost != "" {
		serverHost = console.Fill("请输入服务器地址:", serverHost, false)
		serverUser = console.Fill("请输入服务器账号:", serverUser, false)
		serverPassword = console.Fill("请输入服务器密码:", serverPassword, true)
		logging.Info("config", "SSH服务器信息", "user", serverUser, "host", serverHost, "port", sshPort)
	}

	// 密码支持明文或最多 4 层 DES3 加密
	serverPassword = DecryptLayers(serverPassword, MaxCipherLayers)
	if (cfg.SocksPort > 0 || cfg.HTTPPort > 0) && authReady {
		cfg.SocksPassword = DecryptLayers(cfg.SocksPassword, MaxCipherLayers)
	}

	if serverHost != "" {
		pool, err := r.Int("-pool", "SSH_POOL", 8)
		if err != nil {
			return nil, err
		}
		cfg.SSH = &SSHConfig{
			Addr:       serverHost,
			User:       serverUser,
			Password:   serverPassword,
			Port:       sshPort,
			Pool:       pool,
			KnownHosts: strings.TrimSpace(r.Value("-known-hosts", "SSH_KNOWN_HOSTS", "")),
			HostKeys:   splitTokens(r.Values("-host-key", "SSH_HOST_KEY")),
		}
	}
	return cfg, nil
}

// missingAuthField 返回缺失的认证配置项名，用于错误提示。
func missingAuthField(user, _ string) string {
	if user == "" {
		return "SOCKS_USER"
	}
	return "SOCKS_PASSWORD"
}

// bindDesc 返回监听地址的可读描述。
func bindDesc(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return "0.0.0.0（全部网卡）"
	}
	return addr
}

// isLoopbackBind 判断监听地址是否仅限回环。
//
// 空值、0.0.0.0、:: 都是「全部网卡」，属于对外暴露；
// 只有 localhost/127.0.0.0/8/::1 才算仅本机。
func isLoopbackBind(addr string) bool {
	s := strings.TrimSpace(strings.ToLower(addr))
	if s == "" {
		return false
	}
	if s == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// splitTokens 把环境变量中用逗号/分号/空白分隔的列表拆成多个取值。
// 用于 SSH_HOST_KEY：环境变量只能传一个字符串，但可能要固定多把主机密钥
// （如轮换期间新旧指纹并存）。
func splitTokens(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.FieldsFunc(v, func(c rune) bool {
			return c == ',' || c == '，' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
		}) {
			out = append(out, part)
		}
	}
	return out
}

// readGeoSiteNames 读取 -direct-cn 的 geosite 列表名：
// 传了参数但没给值默认 cn；布尔真值（true/1/yes/on）也视为 cn；
// 显式布尔假值（false/0/no/off）表示关闭，不加载任何列表。
func readGeoSiteNames(r *Resolver) []string {
	if !r.Has("-direct-cn", "DIRECT_CN") {
		return nil
	}
	var names []string
	disabled := false
	for _, item := range r.Values("-direct-cn", "DIRECT_CN") {
		for _, part := range strings.FieldsFunc(item, func(c rune) bool {
			return c == ',' || c == '，' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
		}) {
			if part == "" {
				continue
			}
			switch {
			case isTruthy(part):
				names = append(names, "cn")
			case isFalsy(part):
				disabled = true
			default:
				names = append(names, part)
			}
		}
	}
	if len(names) > 0 {
		return names
	}
	if disabled {
		// 显式关闭（如 compose 中写 DIRECT_CN=false）不应退化成默认 cn
		return nil
	}
	return []string{"cn"}
}

func isTruthy(s string) bool {
	switch strings.ToLower(s) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func isFalsy(s string) bool {
	switch strings.ToLower(s) {
	case "false", "0", "no", "off":
		return true
	default:
		return false
	}
}

// loadGeoSite 把内置 dlc.dat 中指定列表的域名规则并入直连配置。
func loadGeoSite(rules *direct.Rules, sites []string) {
	parsed, err := direct.ParseDLC(sites)
	if err != nil {
		logging.Warn("config", "解析dlc.dat失败,忽略geosite直连规则", "err", err)
		return
	}
	seen := make(map[string]struct{}, len(sites))
	for _, site := range sites {
		name := strings.ToLower(strings.TrimSpace(site))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		list, ok := parsed[name]
		if !ok {
			logging.Warn("config", "dlc.dat中不存在该geosite列表,已忽略", "site", name)
			continue
		}
		rules.AddGeoSite(list)
		logging.Info("config", "geosite直连规则已加载", "site", name, "count", len(list))
	}
}

// stripQuote 去掉首尾空白与成对包裹的引号，容错 compose 列表写法把引号带进值里。
func stripQuote(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		break
	}
	return s
}
