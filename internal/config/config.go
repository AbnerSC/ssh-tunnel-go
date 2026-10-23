package config

import (
	"fmt"
	"os"
	"strings"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/console"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/direct"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
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
	Locals   []CopyItem
	Remotes  []CopyItem
}

// Script 返回日志展示用的连接标识，与 Java 版一致。
func (s *SSHConfig) Script() string {
	return fmt.Sprintf("%s@%s:%d", s.User, s.Addr, s.Port)
}

// Config 运行配置。
type Config struct {
	SocksPort     int // -1 表示未启用
	HTTPPort      int // -1 表示未启用
	SocksUser     string
	SocksPassword string
	SSH           *SSHConfig
	Direct        *direct.Rules
}

// CheckWork 是否存在可执行任务。
func (c *Config) CheckWork() bool {
	if c.SocksPort > 0 || c.HTTPPort > 0 {
		return true
	}
	if c.SSH != nil {
		return len(c.SSH.Locals) > 0 || len(c.SSH.Remotes) > 0
	}
	return false
}

// Load 按 Java 版 SSHCopyConfig 的顺序装配配置。
func Load(r *Resolver) (*Config, error) {
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

	authReady := cfg.SocksUser != "" && cfg.SocksPassword != ""
	if cfg.SocksPort != -1 {
		if authReady {
			logging.Info("config", "socks5代理认证已启用", "user", cfg.SocksUser)
		} else {
			logging.Info("config", "socks5代理无授权认证")
		}
	}
	if cfg.HTTPPort > 0 {
		if authReady {
			logging.Info("config", "http代理认证已启用", "user", cfg.SocksUser)
		} else {
			logging.Info("config", "http代理无授权认证")
		}
	}

	// 端口转发规则（-s/-L 为本地转发，-R 为远程转发）
	locals, err := readScript(r, "-s", "-L")
	if err != nil {
		return nil, err
	}
	remotes, err := readScript(r, "-R")
	if err != nil {
		return nil, err
	}

	// 直连路由：-direct-ip 支持单 IP 与网段，-direct-domain 匹配主域名，
	// -direct-cn 加载内置 geosite 列表（默认 cn）
	directIPs := r.Values("-direct-ip", "DIRECT_IP")
	directDomains := r.Values("-direct-domain", "DIRECT_DOMAIN")
	directSites := readGeoSiteNames(r)
	if len(directIPs) > 0 || len(directDomains) > 0 || len(directSites) > 0 {
		cfg.Direct = direct.New(directIPs, directDomains)
		if len(directSites) > 0 {
			loadGeoSite(cfg.Direct, directSites)
		}
		logging.Info("config", "直连规则已加载",
			"ipRules", cfg.Direct.IPRuleCount(), "domainRules", cfg.Direct.DomainRuleCount())
	}

	// 需要 SSH 能力时，缺省信息从控制台补齐（非终端环境不阻塞）
	if len(locals) > 0 || len(remotes) > 0 || serverHost != "" {
		serverHost = console.Fill("请输入服务器地址:", serverHost, false)
		serverUser = console.Fill("请输入服务器账号:", serverUser, false)
		serverPassword = console.Fill("请输入服务器密码:", serverPassword, true)
		logging.Info("config", "SSH服务器信息", "user", serverUser, "host", serverHost, "port", sshPort)
	}

	// 密码支持明文或最多 4 层 DES3 加密（与 Java 版一致）
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
			Addr:     serverHost,
			User:     serverUser,
			Password: serverPassword,
			Port:     sshPort,
			Pool:     pool,
			Locals:   locals,
			Remotes:  remotes,
		}
	}
	return cfg, nil
}

// readScript 读取端口转发配置；同名参数可重复传参。
func readScript(r *Resolver, flags ...string) ([]CopyItem, error) {
	var out []CopyItem
	seen := make(map[CopyItem]struct{})
	for _, flag := range flags {
		for _, value := range r.params.Values(flag) {
			item, err := ParseCopyItem(stripQuote(value))
			if err != nil {
				return nil, err
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out, nil
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
