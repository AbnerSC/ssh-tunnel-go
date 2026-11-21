package tun

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain 兼作假 sing-box：测试二进制被以 FAKE_SINGBOX_MODE=1 重新执行时，
// 模拟 version / run 子命令，而不是跑真实测试。
//
// 这样 manager.Run 的全流程（版本检查、配置落盘、子进程监控、优雅退出）
// 可以在不安装 sing-box、不需要 TUN 权限的情况下被测试。
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_SINGBOX_MODE") == "1" {
		fakeSingBoxMain(os.Args[1:])
		return
	}
	// 配置生成默认会枚举宿主网卡与 resolv.conf，测试中固定为空，
	// 保证 BuildConfig 结果与运行环境无关（集成路径由
	// TestBuildConfigLANExcludes 注入固定前缀覆盖）。
	lanRouteExcludes = func() []string { return nil }
	os.Exit(m.Run())
}

// fakeSingBoxMain 模拟 sing-box 的 version / run 子命令。
func fakeSingBoxMain(args []string) {
	if len(args) > 0 && args[0] == "version" {
		ver := os.Getenv("FAKE_SINGBOX_VERSION")
		if ver == "" {
			ver = "1.12.3"
		}
		fmt.Println("sing-box version " + ver)
		return
	}
	if len(args) >= 3 && args[0] == "run" && args[1] == "-c" {
		// 配置必须真实落盘，否则说明 Run 在启动前就出了问题
		if _, err := os.Stat(args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR fake sing-box: 配置文件不存在:", err)
			os.Exit(7)
		}
		switch os.Getenv("FAKE_SINGBOX_RUN") {
		case "crash":
			fmt.Fprintln(os.Stderr, "FATAL fake sing-box: boom")
			os.Exit(3)
		case "exit0":
			return
		default: // 挂起，等待父进程终止
			time.Sleep(30 * time.Second)
			return
		}
	}
	os.Exit(9)
}

// fakeBinPath 把测试二进制复制成名为 sing-box 的假可执行文件。
func fakeBinPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("获取测试可执行文件失败: %v", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatalf("读取测试可执行文件失败: %v", err)
	}
	name := "sing-box"
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatalf("写入假 sing-box 失败: %v", err)
	}
	return dst
}

// stubEmbeddedBinary 让 Run 使用假 sing-box，不依赖真实内置二进制。
func stubEmbeddedBinary(t *testing.T) {
	t.Helper()
	bin := fakeBinPath(t)
	binaryPathHook = func() (string, error) { return bin, nil }
	t.Cleanup(func() { binaryPathHook = nil })
}

// skipUnlessLinux 在非 Linux 平台跳过依赖 POSIX 权限位/可执行文件语义的用例。
func skipUnlessLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("TUN 模式仅支持 Linux，跳过该用例")
	}
}

// skipWithoutTunDevice 在非 Linux 或无 /dev/net/tun 环境跳过需要启动子进程的用例。
func skipWithoutTunDevice(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("TUN 模式仅支持 Linux，跳过子进程生命周期测试")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("当前环境没有 /dev/net/tun，跳过子进程生命周期测试")
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		output              string
		major, minor, patch int
		ok                  bool
	}{
		{"sing-box version 1.12.3\nEnvironment: go1.24.0", 1, 12, 3, true},
		{"sing-box version 1.13.0-beta.2", 1, 13, 0, true},
		{"sing-box version v2.0.1", 2, 0, 1, true},
		{"garbage output", 0, 0, 0, false},
	}
	for _, c := range cases {
		major, minor, patch, ok := parseVersion(c.output)
		if ok != c.ok || major != c.major || minor != c.minor || patch != c.patch {
			t.Fatalf("%q 解析异常: %d.%d.%d %v", c.output, major, minor, patch, ok)
		}
	}
}

// TestCheckVersionTooOld 假二进制输出低版本时，checkVersion 应拒绝并给出可诊断错误。
func TestCheckVersionTooOld(t *testing.T) {
	skipUnlessLinux(t)
	t.Setenv("FAKE_SINGBOX_MODE", "1")
	t.Setenv("FAKE_SINGBOX_VERSION", "1.11.9")
	err := checkVersion(context.Background(), fakeBinPath(t))
	if err == nil || !strings.Contains(err.Error(), "版本过低") {
		t.Fatalf("低版本应被拒绝且有可读错误: %v", err)
	}
}

// TestCheckVersionCanceledContext 父 ctx 已取消时版本探测应立即失败，不再拉起子进程。
func TestCheckVersionCanceledContext(t *testing.T) {
	skipUnlessLinux(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkVersion(ctx, fakeBinPath(t)); err == nil {
		t.Fatal("已取消的 ctx 应返回错误")
	}
}

func TestRunReportsChildCrash(t *testing.T) {
	skipWithoutTunDevice(t)
	t.Setenv("FAKE_SINGBOX_MODE", "1")
	t.Setenv("FAKE_SINGBOX_RUN", "crash")
	stubEmbeddedBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "box.json")
	err := Run(context.Background(), Options{
		ConfigPath: cfgPath,
		SocksPort:  6666,
		SSHHosts:   []string{"203.0.113.9"},
	})
	if err == nil || !strings.Contains(err.Error(), "异常退出") {
		t.Fatalf("子进程崩溃应返回异常退出错误: %v", err)
	}
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Fatalf("启动前配置应已落盘: %v", statErr)
	}
}

func TestRunReportsUnexpectedZeroExit(t *testing.T) {
	skipWithoutTunDevice(t)
	t.Setenv("FAKE_SINGBOX_MODE", "1")
	t.Setenv("FAKE_SINGBOX_RUN", "exit0")
	stubEmbeddedBinary(t)

	err := Run(context.Background(), Options{
		ConfigPath: filepath.Join(t.TempDir(), "box.json"),
		SocksPort:  6666,
		SSHHosts:   []string{"203.0.113.9"},
	})
	if err == nil || !strings.Contains(err.Error(), "意外退出") {
		t.Fatalf("子进程提前以 0 退出也应视为异常退出: %v", err)
	}
}

// TestRunAutoConfigCleanedUp 验证自动生成的临时配置（含明文凭据）在退出时被删除。
func TestRunAutoConfigCleanedUp(t *testing.T) {
	skipWithoutTunDevice(t)
	t.Setenv("FAKE_SINGBOX_MODE", "1")
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	stubEmbeddedBinary(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			SocksPort: 6666,
			SSHHosts:  []string{"203.0.113.9"},
		})
	}()

	// 等待随机命名的配置落盘（说明已进入子进程启动阶段）
	pattern := filepath.Join(tmp, "ssh-tunnel-tun-*.json")
	deadline := time.Now().Add(5 * time.Second)
	var matches []string
	for time.Now().Before(deadline) {
		matches, _ = filepath.Glob(pattern)
		if len(matches) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(matches) != 1 {
		t.Fatalf("应生成一份随机命名的临时配置: %v", matches)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("优雅停止应返回 nil: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run 未在超时内退出")
	}
	if left, _ := filepath.Glob(pattern); len(left) != 0 {
		t.Fatalf("退出后临时配置应被清理: %v", left)
	}
}

// TestRunAbortsBeforeStartOnCanceledContext 启动阶段已收到退出信号时，
// 不应再生成配置或建立 TUN，直接按正常收尾返回 nil。
func TestRunAbortsBeforeStartOnCanceledContext(t *testing.T) {
	skipWithoutTunDevice(t)
	t.Setenv("FAKE_SINGBOX_MODE", "1")
	stubEmbeddedBinary(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfgPath := filepath.Join(t.TempDir(), "box.json")
	err := Run(ctx, Options{
		ConfigPath: cfgPath,
		SocksPort:  6666,
		SSHHosts:   []string{"203.0.113.9"},
	})
	if err != nil {
		t.Fatalf("启动阶段取消应返回 nil（正常收尾）: %v", err)
	}
	if _, statErr := os.Stat(cfgPath); statErr == nil {
		t.Fatal("ctx 已取消时不应写配置、不应启动 sing-box")
	}
}

func TestRunGracefulStop(t *testing.T) {
	skipWithoutTunDevice(t)
	t.Setenv("FAKE_SINGBOX_MODE", "1")
	stubEmbeddedBinary(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath: filepath.Join(t.TempDir(), "box.json"),
			SocksPort:  6666,
			SSHHosts:   []string{"203.0.113.9"},
		})
	}()

	// 等待子进程启动并进入挂起状态
	time.Sleep(500 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("优雅停止应返回 nil: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run 未在超时内退出")
	}
}

func TestLineWriterSplitsPartialLines(t *testing.T) {
	w := newLineWriter("test")
	if n, err := w.Write([]byte("abc\ndef")); n != 7 || err != nil {
		t.Fatalf("写入异常: %d %v", n, err)
	}
	if string(w.buf) != "def" {
		t.Fatalf("半行应保留在缓冲: %q", w.buf)
	}
	if _, err := w.Write([]byte("ghi\n")); err != nil {
		t.Fatalf("写入异常: %v", err)
	}
	if len(w.buf) != 0 {
		t.Fatalf("完整行处理后缓冲应为空: %q", w.buf)
	}

	// 超长无换行输出必须被截断落日志，不允许缓冲无限增长
	big := make([]byte, maxLogLine+1024)
	for i := range big {
		big[i] = 'x'
	}
	if _, err := w.Write(big); err != nil {
		t.Fatalf("写入异常: %v", err)
	}
	if len(w.buf) != 0 {
		t.Fatalf("超长输出应被清空: %d", len(w.buf))
	}
}

// TestClosedNoiseClassification 校验 sing-box 输出分级的边界：
// 连接收尾噪声（下载/上传通道随 endpoint 关闭而断开）降级为调试，
// 真正的启动失败、权限问题必须保持 ERROR 以便告警。
func TestClosedNoiseClassification(t *testing.T) {
	noise := []string{
		"2026/11/21 10:00:00 +0800 ERROR [2063513061 698ms] connection: connection download closed: close tcp 172.19.0.1:49976->198.18.0.2:443: endpoint not connected",
		"ERROR connection: connection upload closed: write tcp 172.19.0.1:40001->198.18.0.3:443: endpoint not connected",
	}
	for _, line := range noise {
		if !isClosedNoise(line) {
			t.Errorf("收尾噪声未被识别: %q", line)
		}
	}

	real := []string{
		"ERROR [tun] open tun device: operation not permitted",
		"ERROR connection: connection download closed: connection refused",
		"ERROR dial tcp 172.81.101.78:32192: connect: connection refused",
		"WARN endpoint not connected",
		"",
	}
	for _, line := range real {
		if isClosedNoise(line) {
			t.Errorf("真实故障被误判为噪声: %q", line)
		}
	}
}
