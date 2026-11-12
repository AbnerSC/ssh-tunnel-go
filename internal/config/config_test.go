package config

import (
	"strings"
	"testing"
	"time"

	"ssh-tunnel-go/internal/proxy"
)

// clearEnv 把所有支持的环境变量置空，避免宿主环境干扰测试。
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"SOCKS_PORT", "SOCKS_USER", "SOCKS_PASSWORD", "HTTP_PORT",
		"BIND_ADDR", "ALLOW_UNAUTH_PUBLIC",
		"MAX_CONNS", "MAX_CONNS_PER_IP", "IDLE_TIMEOUT",
		"SSH_SERVER", "SSH_PORT", "SSH_PASSWORD", "SSH_POOL",
		"SSH_KNOWN_HOSTS", "SSH_HOST_KEY",
		"DIRECT_IP", "DIRECT_DOMAIN", "DIRECT_CN",
		// 主密钥同样置空，避免宿主环境注入后影响黄金向量类用例
		"CIPHER_MASTER_KEY",
	} {
		t.Setenv(key, "")
	}
}

// TestLoadProductionCompose 复刻生产 docker-compose 的环境变量，验证无缝切换。
func TestLoadProductionCompose(t *testing.T) {
	clearEnv(t)
	env := map[string]string{
		"SOCKS_PORT":     "6666",
		"HTTP_PORT":      "6667",
		"SOCKS_USER":     "user",
		"SOCKS_PASSWORD": "pwd123",
		"SSH_SERVER":     "root@172.1.2.3",
		"SSH_PORT":       "22",
		"SSH_PASSWORD":   "croot!123",
		"SSH_POOL":       "6",
		"DIRECT_IP":      "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1,119.1.2.3",
		"DIRECT_DOMAIN":  "localhost,1997.fun,openeuler.org",
		"DIRECT_CN":      "true",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}

	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if !cfg.CheckWork() {
		t.Fatal("应存在可执行任务")
	}
	if cfg.SocksPort != 6666 || cfg.HTTPPort != 6667 {
		t.Fatalf("端口解析错误: socks=%d http=%d", cfg.SocksPort, cfg.HTTPPort)
	}
	if cfg.SocksUser != "user" || cfg.SocksPassword != "pwd123" {
		t.Fatalf("代理账号解析错误: %q/%q", cfg.SocksUser, cfg.SocksPassword)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH 配置不应为空")
	}
	if cfg.SSH.Addr != "172.1.2.3" || cfg.SSH.User != "root" {
		t.Fatalf("-server 解析错误: %+v", cfg.SSH)
	}
	if cfg.SSH.Port != 22 || cfg.SSH.Pool != 6 || cfg.SSH.Password != "croot!123" {
		t.Fatalf("SSH 参数解析错误: %+v", cfg.SSH)
	}

	directIPs := []string{"192.168.1.1", "10.1.2.3", "172.16.5.5", "127.0.0.1", "119.1.2.3"}
	for _, ip := range directIPs {
		if !cfg.Direct.IsDirect(ip) {
			t.Fatalf("%s 应命中直连", ip)
		}
	}
	if cfg.Direct.IsDirect("223.5.5.5") {
		t.Fatal("223.5.5.5 不应命中直连")
	}
	for _, d := range []string{"localhost", "1997.fun", "a.1997.fun", "openeuler.org", "www.openeuler.org"} {
		if !cfg.Direct.IsDirect(d) {
			t.Fatalf("%s 应命中直连", d)
		}
	}
	if cfg.Direct.IsDirect("not1997.fun") {
		t.Fatal("not1997.fun 不应命中直连")
	}
	// geosite:cn 已内嵌加载
	if cfg.Direct.DomainRuleCount() < 6000 {
		t.Fatalf("geosite cn 规则数量异常: %d", cfg.Direct.DomainRuleCount())
	}
	if !cfg.Direct.IsDirect("baidu.com") || cfg.Direct.IsDirect("google.com") {
		t.Fatal("geosite cn 匹配结果异常")
	}
}

func TestLoadServerWithoutUser(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSH_SERVER", "1.2.3.4")
	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.SSH == nil || cfg.SSH.User != "root" || cfg.SSH.Addr != "1.2.3.4" {
		t.Fatalf("-server 缺省账号应为 root: %+v", cfg.SSH)
	}
	// 默认端口与池大小
	if cfg.SSH.Port != 22 || cfg.SSH.Pool != 8 {
		t.Fatalf("默认值错误: port=%d pool=%d", cfg.SSH.Port, cfg.SSH.Pool)
	}
}

func TestLoadEncryptedPassword(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSH_SERVER", "root@1.2.3.4")
	t.Setenv("SSH_PASSWORD", goldenLayers[3])
	t.Setenv("SOCKS_PORT", "6666")
	t.Setenv("SOCKS_USER", "u")
	t.Setenv("SOCKS_PASSWORD", goldenLayers[3])

	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.SSH.Password != "pwd123" {
		t.Fatalf("SSH 密码应解密为 pwd123: %q", cfg.SSH.Password)
	}
	if cfg.SocksPassword != "pwd123" {
		t.Fatalf("代理密码应解密为 pwd123: %q", cfg.SocksPassword)
	}
}

// TestLoadIdleTimeout 空闲回收时限：默认 30 分钟，支持 IDLE_TIMEOUT 覆盖与 0/off 关闭。
func TestLoadIdleTimeout(t *testing.T) {
	clearEnv(t)
	t.Setenv("SOCKS_PORT", "6666")
	t.Setenv("ALLOW_UNAUTH_PUBLIC", "true")

	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.IdleTimeout != proxy.DefaultIdleTimeout {
		t.Fatalf("默认空闲回收应为 %v, got %v", proxy.DefaultIdleTimeout, cfg.IdleTimeout)
	}

	t.Setenv("IDLE_TIMEOUT", "5m")
	if cfg, err = Load(NewResolver(nil)); err != nil || cfg.IdleTimeout != 5*time.Minute {
		t.Fatalf("IDLE_TIMEOUT=5m 解析错误: %v %v", cfg.IdleTimeout, err)
	}

	// 0 是合法取值（关闭回收），不能被当成「未配置」回退默认值
	t.Setenv("IDLE_TIMEOUT", "0")
	if cfg, err = Load(NewResolver(nil)); err != nil || cfg.IdleTimeout != 0 {
		t.Fatalf("IDLE_TIMEOUT=0 应关闭回收: %v %v", cfg.IdleTimeout, err)
	}
}

func TestLoadNoWork(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.CheckWork() {
		t.Fatal("空配置不应有可执行任务")
	}
	if cfg.SocksPort != -1 || cfg.HTTPPort != -1 {
		t.Fatalf("未配置端口应为 -1: %d/%d", cfg.SocksPort, cfg.HTTPPort)
	}
}

// TestLoadRejectsForwardFlags 端口转发参数必须报错而不是静默忽略。
//
// 本版本已删除 -L/-s/-R 实现，而 ParamFormat 对未识别参数不报错；
// 若不做拦截，历史部署带着这些参数仍会正常启动，运维却看不到转发已不生效。
func TestLoadRejectsForwardFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"-L", []string{"-L", "127.0.0.1:3306-13306"}, "-L"},
		{"-s 旧别名", []string{"-s", "127.0.0.1:3306-13306"}, "-s"},
		{"-R", []string{"-R", "127.0.0.1:80-8080"}, "-R"},
		{"多个同时", []string{"-L", "127.0.0.1:3306-13306", "-R", "127.0.0.1:80-8080"}, "-L、-R"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("SSH_SERVER", "root@1.2.3.4")
			_, err := Load(NewResolver(c.args))
			if err == nil {
				t.Fatalf("%s 应被拒绝", c.name)
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "端口转发") {
				t.Fatalf("报错信息应说明转发已移除并列出 %q，实际: %v", c.want, err)
			}
		})
	}

	// 对照组：不转发时同样含 -s 前缀的认证参数不能被误杀
	t.Run("认证参数不受影响", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("SOCKS_PORT", "1080")
		if _, err := Load(NewResolver([]string{"-suser", "u", "-spwd", "p"})); err != nil {
			t.Fatalf("-suser/-spwd 不应被当成转发参数: %v", err)
		}
	})
}

func TestLoadEnvPriorityOverArgs(t *testing.T) {
	clearEnv(t)
	t.Setenv("SOCKS_PORT", "6666")
	// 无认证代理默认只能在回环上开，这里显式放行以验证参数优先级
	t.Setenv("ALLOW_UNAUTH_PUBLIC", "true")
	cfg, err := Load(NewResolver([]string{"-D", "6666"}))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.SocksPort != 6666 {
		t.Fatalf("环境变量应优先: %d", cfg.SocksPort)
	}
}

func TestLoadDirectCNWithoutValue(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(NewResolver([]string{"-direct-cn"}))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Direct == nil || cfg.Direct.DomainRuleCount() < 6000 {
		t.Fatal("-direct-cn 无值时应默认加载 cn 列表")
	}
}

func TestLoadDirectCNDisabled(t *testing.T) {
	clearEnv(t)
	t.Setenv("DIRECT_CN", "false")
	t.Setenv("DIRECT_IP", "127.0.0.1")

	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Direct == nil || cfg.Direct.IPRuleCount() == 0 {
		t.Fatal("DIRECT_IP 应仍然生效")
	}
	if cfg.Direct.DomainRuleCount() != 0 {
		t.Fatalf("DIRECT_CN=false 不应加载 geosite: %d", cfg.Direct.DomainRuleCount())
	}
}

func TestLoadDirectCNExplicitWithDisable(t *testing.T) {
	clearEnv(t)
	t.Setenv("DIRECT_CN", "false,cn")

	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Direct == nil || cfg.Direct.DomainRuleCount() < 6000 {
		t.Fatal("显式指定 cn 时应加载列表")
	}
}

func TestLoadInvalidPort(t *testing.T) {
	clearEnv(t)
	if _, err := Load(NewResolver([]string{"-D", "abc"})); err == nil {
		t.Fatal("非法端口应报错")
	}
}

// TestLoadRejectsHalfAuthConfig 只配一半凭据时必须报错。
//
// 旧实现把「账号或密码为空」等同于「不启用认证」，因此只设一个环境变量
// 就能把带认证的代理降级成完全开放；这里锁定报错行为。
func TestLoadRejectsHalfAuthConfig(t *testing.T) {
	cases := []struct {
		name string
		user string
		pwd  string
	}{
		{name: "只有账号", user: "admin"},
		{name: "只有密码", pwd: "S3cret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("SOCKS_PORT", "1080")
			t.Setenv("SOCKS_USER", tc.user)
			t.Setenv("SOCKS_PASSWORD", tc.pwd)
			if _, err := Load(NewResolver(nil)); err == nil {
				t.Fatal("单边认证配置必须报错，否则代理会静默降级为无认证")
			}
		})
	}
}

// TestLoadRejectsUnauthPublicByDefault 无认证 + 对外监听必须默认拒绝启动。
func TestLoadRejectsUnauthPublicByDefault(t *testing.T) {
	for _, bind := range []string{"", "0.0.0.0", "::"} {
		clearEnv(t)
		t.Setenv("SOCKS_PORT", "1080")
		if bind != "" {
			t.Setenv("BIND_ADDR", bind)
		}
		if _, err := Load(NewResolver(nil)); err == nil {
			t.Fatalf("bind=%q 时无认证代理对外监听应被拒绝", bind)
		}
	}
}

// TestLoadAllowsUnauthOnLoopback 仅监听回环时允许无认证（本机自用场景）。
func TestLoadAllowsUnauthOnLoopback(t *testing.T) {
	for _, bind := range []string{"127.0.0.1", "::1", "localhost"} {
		clearEnv(t)
		t.Setenv("SOCKS_PORT", "1080")
		t.Setenv("BIND_ADDR", bind)
		cfg, err := Load(NewResolver(nil))
		if err != nil {
			t.Fatalf("bind=%q 时回环无认证应允许: %v", bind, err)
		}
		if cfg.BindAddr != bind {
			t.Fatalf("BIND_ADDR 解析错误: %q", cfg.BindAddr)
		}
	}
}

// TestLoadAllowsUnauthWithExplicitOptIn 显式放行后才允许对外无认证。
func TestLoadAllowsUnauthWithExplicitOptIn(t *testing.T) {
	clearEnv(t)
	t.Setenv("HTTP_PORT", "8080")
	t.Setenv("ALLOW_UNAUTH_PUBLIC", "true")
	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("显式放行后应允许: %v", err)
	}
	if !cfg.AllowUnauthPublic {
		t.Fatal("ALLOW_UNAUTH_PUBLIC 未解析")
	}
}

// TestLoadParsesHostKeyOptions 主机密钥校验相关配置应能通过参数与环境变量传入。
func TestLoadParsesHostKeyOptions(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSH_SERVER", "root@1.2.3.4")
	t.Setenv("SSH_KNOWN_HOSTS", "/etc/ssh-tunnel/known_hosts")
	t.Setenv("SSH_HOST_KEY", "SHA256:abc,def")
	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.SSH.KnownHosts != "/etc/ssh-tunnel/known_hosts" {
		t.Fatalf("SSH_KNOWN_HOSTS 未解析: %q", cfg.SSH.KnownHosts)
	}
	if len(cfg.SSH.HostKeys) != 2 {
		t.Fatalf("SSH_HOST_KEY 应支持多个值: %+v", cfg.SSH.HostKeys)
	}
}

// enableProxy 打开一个带认证的 socks5 端口，便于验证代理相关配置。
func enableProxy(t *testing.T) {
	t.Helper()
	t.Setenv("SOCKS_PORT", "1080")
	t.Setenv("SOCKS_USER", "u")
	t.Setenv("SOCKS_PASSWORD", "p")
}

// TestLoadConnectionLimitsDefault 未配置时沿用 proxy 包内置默认上限，
// 避免配置层与限制器各写一份数字、后续只改一处而失效。
func TestLoadConnectionLimitsDefault(t *testing.T) {
	clearEnv(t)
	enableProxy(t)
	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.MaxConns != proxy.DefaultMaxConns || cfg.MaxConnsPerIP != proxy.DefaultMaxConnsPerIP {
		t.Fatalf("默认上限错误: total=%d perIP=%d", cfg.MaxConns, cfg.MaxConnsPerIP)
	}
}

// TestLoadConnectionLimitsFromEnv 环境变量可覆盖并发连接上限，
// 且优先于命令行参数（与其它配置项一致）。
func TestLoadConnectionLimitsFromEnv(t *testing.T) {
	clearEnv(t)
	enableProxy(t)
	t.Setenv("MAX_CONNS", "64")
	t.Setenv("MAX_CONNS_PER_IP", "8")
	cfg, err := Load(NewResolver([]string{"-max-conns", "128", "-max-conns-per-ip", "16"}))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.MaxConns != 64 || cfg.MaxConnsPerIP != 8 {
		t.Fatalf("环境变量应优先: total=%d perIP=%d", cfg.MaxConns, cfg.MaxConnsPerIP)
	}
}

// TestLoadConnectionLimitsFromArgs 只传参数时同样生效。
func TestLoadConnectionLimitsFromArgs(t *testing.T) {
	clearEnv(t)
	enableProxy(t)
	cfg, err := Load(NewResolver([]string{"-max-conns", "128", "-max-conns-per-ip", "16"}))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.MaxConns != 128 || cfg.MaxConnsPerIP != 16 {
		t.Fatalf("参数未生效: total=%d perIP=%d", cfg.MaxConns, cfg.MaxConnsPerIP)
	}
}

// TestLoadConnectionLimitsUnlimited 0 表示不限制，不能当成非法配置拒绝启动。
func TestLoadConnectionLimitsUnlimited(t *testing.T) {
	clearEnv(t)
	enableProxy(t)
	t.Setenv("MAX_CONNS", "0")
	t.Setenv("MAX_CONNS_PER_IP", "0")
	cfg, err := Load(NewResolver(nil))
	if err != nil {
		t.Fatalf("0 应表示不限制: %v", err)
	}
	if cfg.MaxConns != 0 || cfg.MaxConnsPerIP != 0 {
		t.Fatalf("上限应为 0: total=%d perIP=%d", cfg.MaxConns, cfg.MaxConnsPerIP)
	}
}

// TestLoadRejectsInvalidConnectionLimits 非法上限在启动时就报错，
// 而不是等到运行期才发现限制没生效。
func TestLoadRejectsInvalidConnectionLimits(t *testing.T) {
	cases := []struct{ name, total, perIP string }{
		{"全局为负", "-1", "4"},
		{"每IP为负", "16", "-2"},
		{"每IP大于全局", "4", "8"},
		{"非数字", "abc", "1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			enableProxy(t)
			t.Setenv("MAX_CONNS", c.total)
			t.Setenv("MAX_CONNS_PER_IP", c.perIP)
			if _, err := Load(NewResolver(nil)); err == nil {
				t.Fatalf("应报错: MAX_CONNS=%s MAX_CONNS_PER_IP=%s", c.total, c.perIP)
			}
		})
	}
}
