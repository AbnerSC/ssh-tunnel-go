package config

import (
	"testing"
)

// clearEnv 把所有支持的环境变量置空，避免宿主环境干扰测试。
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"SOCKS_PORT", "SOCKS_USER", "SOCKS_PASSWORD", "HTTP_PORT",
		"SSH_SERVER", "SSH_PORT", "SSH_PASSWORD", "SSH_POOL",
		"DIRECT_IP", "DIRECT_DOMAIN", "DIRECT_CN",
	} {
		t.Setenv(key, "")
	}
}

// TestLoadProductionCompose 复刻生产 docker-compose 的环境变量，验证无缝切换。
func TestLoadProductionCompose(t *testing.T) {
	clearEnv(t)
	env := map[string]string{
		"SOCKS_PORT":     "11823",
		"HTTP_PORT":      "11825",
		"SOCKS_USER":     "user",
		"SOCKS_PASSWORD": "pwd123",
		"SSH_SERVER":     "root@172.81.101.123",
		"SSH_PORT":       "22",
		"SSH_PASSWORD":   "croot!123",
		"SSH_POOL":       "6",
		"DIRECT_IP":      "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1,119.6.200.182",
		"DIRECT_DOMAIN":  "localhost,mmxx.fun,05200809.xyz,openeuler.org",
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
	if cfg.SocksPort != 11823 || cfg.HTTPPort != 11825 {
		t.Fatalf("端口解析错误: socks=%d http=%d", cfg.SocksPort, cfg.HTTPPort)
	}
	if cfg.SocksUser != "user" || cfg.SocksPassword != "pwd123" {
		t.Fatalf("代理账号解析错误: %q/%q", cfg.SocksUser, cfg.SocksPassword)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH 配置不应为空")
	}
	if cfg.SSH.Addr != "172.81.101.123" || cfg.SSH.User != "root" {
		t.Fatalf("-server 解析错误: %+v", cfg.SSH)
	}
	if cfg.SSH.Port != 22 || cfg.SSH.Pool != 6 || cfg.SSH.Password != "croot!123" {
		t.Fatalf("SSH 参数解析错误: %+v", cfg.SSH)
	}

	directIPs := []string{"192.168.1.1", "10.1.2.3", "172.16.5.5", "127.0.0.1", "119.6.200.182"}
	for _, ip := range directIPs {
		if !cfg.Direct.IsDirect(ip) {
			t.Fatalf("%s 应命中直连", ip)
		}
	}
	if cfg.Direct.IsDirect("223.5.5.5") {
		t.Fatal("223.5.5.5 不应命中直连")
	}
	for _, d := range []string{"localhost", "mmxx.fun", "a.mmxx.fun", "openeuler.org", "www.openeuler.org"} {
		if !cfg.Direct.IsDirect(d) {
			t.Fatalf("%s 应命中直连", d)
		}
	}
	if cfg.Direct.IsDirect("notmmxx.fun") {
		t.Fatal("notmmxx.fun 不应命中直连")
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
	t.Setenv("SSH_PASSWORD", javaGoldenLayers[3])
	t.Setenv("SOCKS_PORT", "6666")
	t.Setenv("SOCKS_USER", "u")
	t.Setenv("SOCKS_PASSWORD", javaGoldenLayers[3])

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

func TestLoadForwardRules(t *testing.T) {
	clearEnv(t)
	t.Setenv("SSH_SERVER", "root@1.2.3.4")
	cfg, err := Load(NewResolver([]string{
		"-L", "127.0.0.1:80-8080",
		"-s", "127.0.0.1:81-8081",
		"-R", "127.0.0.1:90-9090",
		"-R", "127.0.0.1:90-9090", // 重复项应去重
	}))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if len(cfg.SSH.Locals) != 2 {
		t.Fatalf("-L/-s 应合并为 2 条: %+v", cfg.SSH.Locals)
	}
	// 解析顺序与 Java 版一致：-s 在 -L 之前
	want := map[int]CopyItem{
		8080: {Host: "127.0.0.1", Port: 80, TargetPort: 8080},
		8081: {Host: "127.0.0.1", Port: 81, TargetPort: 8081},
	}
	for _, item := range cfg.SSH.Locals {
		if item != want[item.TargetPort] {
			t.Fatalf("本地转发解析错误: %+v", item)
		}
	}
	if len(cfg.SSH.Remotes) != 1 {
		t.Fatalf("-R 去重后应为 1 条: %+v", cfg.SSH.Remotes)
	}
	if !cfg.CheckWork() {
		t.Fatal("仅端口转发也应视为有任务")
	}
}

func TestLoadEnvPriorityOverArgs(t *testing.T) {
	clearEnv(t)
	t.Setenv("SOCKS_PORT", "11823")
	cfg, err := Load(NewResolver([]string{"-D", "6666"}))
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.SocksPort != 11823 {
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
