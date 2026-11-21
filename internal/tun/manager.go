package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ssh-tunnel-go/internal/logging"
)

const (
	// versionTimeout sing-box version 探测超时
	versionTimeout = 10 * time.Second
	// shutdownGrace 停止 sing-box 的优雅退出等待上限
	shutdownGrace = 5 * time.Second
	// resolveTimeout SSH 服务器域名解析超时
	resolveTimeout = 3 * time.Second
	// maxLogLine 单条日志的最大缓冲，超长（无换行）输出直接截断落日志
	maxLogLine = 64 * 1024
)

// versionPattern 匹配 "sing-box version 1.12.3" 这类版本行。
var versionPattern = regexp.MustCompile(`(?i)\bversion\s+v?(\d+)\.(\d+)\.(\d+)`)

// Run 托管 sing-box 子进程实现全局接管，直到 ctx 取消或子进程退出。
//
// 启动顺序（不可颠倒）：调用方必须先完成本地 SOCKS5 监听，
// TUN 一旦建立系统流量就会立刻涌向 SOCKS 端口，端口未就绪会让首批连接失败。
//
// 子进程异常退出时返回错误，由调用方记为失败退出；
// 进程内不做重启状态机，依赖 systemd/Docker 的 restart 策略兜底。
func Run(ctx context.Context, o Options) error {
	o.applyDefaults()
	if err := o.validate(); err != nil {
		return err
	}
	// 平台检查放在最前：不支持的平台直接拒绝，避免无意义的 sing-box 定位与版本探测
	if err := checkPlatform(); err != nil {
		return err
	}

	// sing-box 与程序同目录（镜像内为 /app/singbox），统一文件名、无需按架构选择；
	// 必须在建立 TUN 前完成定位与版本检查，避免接管后才发现无法启动
	bin, err := resolveAndCheck(ctx)
	if err != nil {
		// 启动阶段收到退出信号属于正常收尾，不能记为失败退出
		if ctx.Err() != nil {
			logging.Info("tun", "启动阶段收到退出信号，取消全局接管")
			return nil
		}
		return err
	}
	// SSH 服务器是域名时先解析成 IP 并加入排除：
	// TUN 接管的瞬间隧道自身的连接也可能被路由进 TUN，必须提前排除
	o.RouteExclude = mergeResolvedExcludes(ctx, o.RouteExclude, o.SSHHosts)

	cfg, err := BuildConfig(o)
	if err != nil {
		return err
	}
	configPath, err := WriteConfig(cfg, o.ConfigPath)
	if err != nil {
		return err
	}
	if o.ConfigPath == "" {
		// 自动生成的临时配置含解密后的 SOCKS 明文凭据，退出时清除
		defer func() {
			if rmErr := os.Remove(configPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				logging.Warn("tun", "清理临时配置失败", "path", configPath, "err", rmErr)
			}
		}()
	}
	logging.Info("tun", "sing-box配置已写入", "path", configPath)

	// 停止信号在启动阶段到达时不再建立 TUN：避免刚接管就拆除，
	// 造成短暂的断网窗口与路由/网卡残留风险
	if ctx.Err() != nil {
		logging.Info("tun", "启动阶段收到退出信号，取消全局接管")
		return nil
	}
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Env = os.Environ()
	out := newLineWriter("sing-box")
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}
	logging.Info("tun", "全局接管已启动", "pid", cmd.Process.Pid, "bin", bin,
		"hint", "系统流量已进入 TUN，关闭本程序即恢复")

	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()

	select {
	case err := <-wait:
		// 退出信号已到达时子进程先退出属于正常收尾（systemd 默认向整个 cgroup
		// 发送 SIGTERM），不能误判为异常退出
		if ctx.Err() != nil {
			logging.Info("tun", "sing-box 已随退出信号停止")
			return nil
		}
		if err != nil {
			return fmt.Errorf("sing-box 异常退出: %w", err)
		}
		return errors.New("sing-box 意外退出（退出码 0）")
	case <-ctx.Done():
	}

	logging.Info("tun", "收到退出信号，正在停止 sing-box")
	stopSingBox(cmd.Process)
	select {
	case <-wait:
	case <-time.After(shutdownGrace):
		_ = cmd.Process.Kill()
		select {
		case <-wait:
		case <-time.After(shutdownGrace):
			// 孙进程继承 stdout/stderr 时 Wait 可能长时间不返回，不能无限阻塞；
			// 以错误返回让上层置非零退出码，便于 systemd 等按失败策略拉起
			return fmt.Errorf("sing-box 未能在 %s 内退出（pid=%d），可能残留路由/网卡", shutdownGrace, cmd.Process.Pid)
		}
	}
	logging.Info("tun", "sing-box 已停止")
	return nil
}

// resolveAndCheck 定位 sing-box 可执行文件并校验版本。
//
// 二进制由部署方提供（镜像内已按架构放入），版本不满足最低要求时直接
// 拒绝启动，交由部署方升级 sing-box 后重启，程序内不做替换/下载。
func resolveAndCheck(ctx context.Context) (string, error) {
	bin, err := resolveSingBox()
	if err != nil {
		return "", err
	}
	if err := checkVersion(ctx, bin); err != nil {
		return "", err
	}
	return bin, nil
}

// stopSingBox 向子进程发送 SIGTERM，让 sing-box 自行移除路由/网卡后再退出。
func stopSingBox(p *os.Process) {
	if err := p.Signal(syscall.SIGTERM); err != nil {
		logging.Warn("tun", "发送 SIGTERM 失败，强制结束 sing-box", "err", err)
		_ = p.Kill()
	}
}

// checkVersion 校验 sing-box 版本不低于最低要求。
func checkVersion(ctx context.Context, bin string) error {
	major, minor, patch, err := probeBinaryVersion(ctx, bin)
	if err != nil {
		return err
	}
	if major < MinMajorVersion || (major == MinMajorVersion && minor < MinMinorVersion) {
		return fmt.Errorf("sing-box 版本过低（%d.%d.%d）：TUN 模式需要 >= %d.%d（1.12 起 DNS 使用新语法）",
			major, minor, patch, MinMajorVersion, MinMinorVersion)
	}
	logging.Info("tun", "sing-box版本检查通过", "version", fmt.Sprintf("%d.%d.%d", major, minor, patch))
	return nil
}

// probeBinaryVersion 执行 bin version 并解析主/次/修订号。
func probeBinaryVersion(ctx context.Context, bin string) (major, minor, patch int, err error) {
	verCtx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(verCtx, bin, "version").CombinedOutput()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("执行 %s version 失败: %v（输出: %s）", bin, err, firstLine(out))
	}
	major, minor, patch, ok := parseVersion(string(out))
	if !ok {
		return 0, 0, 0, fmt.Errorf("无法识别 sing-box 版本输出: %s", firstLine(out))
	}
	return major, minor, patch, nil
}

// parseVersion 从 version 输出中提取主/次/修订号。
func parseVersion(output string) (major, minor, patch int, ok bool) {
	m := versionPattern.FindStringSubmatch(output)
	if m == nil {
		return 0, 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return major, minor, patch, true
}

// firstLine 截取输出的首行用于错误信息，避免把整段输出拼进日志。
func firstLine(out []byte) string {
	line := string(out)
	if idx := strings.IndexAny(line, "\r\n"); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "无输出"
	}
	return line
}

// checkPlatform 拒绝非 Linux 平台并检查创建 TUN 设备所需的前置条件。
func checkPlatform() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("TUN 模式仅支持 Linux（当前系统: %s）", runtime.GOOS)
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return fmt.Errorf("TUN 模式需要 /dev/net/tun，但当前不可用: %v"+
			"（请确认内核启用 tun 模块；容器内需 --device /dev/net/tun）", err)
	}
	return nil
}

// mergeResolvedExcludes 把 SSH 服务器域名解析成 IP 并入排除列表。
//
// 解析在主程序启动阶段完成（TUN 尚未建立），系统 DNS 不受接管影响；
// 解析失败只告警：此时 SSH 连接本身也会失败，路由层仍有进程级规则兜底。
func mergeResolvedExcludes(ctx context.Context, excludes, sshHosts []string) []string {
	out := append([]string{}, excludes...)
	for _, item := range sshHosts {
		// 已收到退出信号时 TUN 不会建立，不必再解析
		if ctx.Err() != nil {
			return out
		}
		for _, host := range splitList(item) {
			if idx := strings.LastIndex(host, "@"); idx >= 0 {
				host = host[idx+1:]
			}
			if host == "" {
				continue
			}
			if isIPLiteral(host) {
				// 字面量直接加入排除，让隧道连接从系统路由层就不进 TUN
				out = append(out, host)
				continue
			}
			lookupCtx, cancel := context.WithTimeout(ctx, resolveTimeout)
			ips, err := net.DefaultResolver.LookupHost(lookupCtx, host)
			cancel()
			if err != nil {
				logging.Warn("tun", "解析SSH服务器域名失败，路由排除仅依赖进程级规则", "host", host, "err", err)
				continue
			}
			logging.Info("tun", "SSH服务器域名已解析并加入排除", "host", host, "ips", strings.Join(ips, ","))
			out = append(out, ips...)
		}
	}
	return out
}

// isIPLiteral 判断字符串是否为 IP 字面量（不做 DNS 解析）。
func isIPLiteral(s string) bool {
	return net.ParseIP(strings.Trim(s, "[]")) != nil
}

// lineWriter 把子进程输出按行转发进项目日志。
type lineWriter struct {
	component string
	mu        sync.Mutex
	buf       []byte
}

func newLineWriter(component string) *lineWriter {
	return &lineWriter{component: component}
}

// Write 实现 io.Writer：按换行拆行输出，保留未完成的半行。
func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf[:idx]), "\r")
		w.buf = append(w.buf[:0], w.buf[idx+1:]...)
		w.emit(line)
	}
	// 超长且始终没有换行的输出（如异常栈），直接落日志防止缓冲无限增长
	if len(w.buf) > maxLogLine {
		w.emit(string(w.buf))
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

// emit 按行内容粗略分级输出。
//
// sing-box 的连接收尾噪声降级为 Debug：客户端提前断开 TCP 时它会把
// “对端已不在”报成 ERROR（实测每次下载中断一条）。TUN 接管下这是
// 日常生命周期而非故障，按 ERROR 落盘会淹没真实错误并把日志尺寸快速推高。
func (w *lineWriter) emit(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	switch {
	case isClosedNoise(line):
		logging.Debug(w.component, line)
	case strings.Contains(line, "ERROR"):
		logging.Error(w.component, line)
	case strings.Contains(line, "WARN"):
		logging.Warn(w.component, line)
	default:
		logging.Info(w.component, line)
	}
}

// isClosedNoise 判断是否为“连接已关闭”类的重复噪声。
func isClosedNoise(line string) bool {
	return strings.Contains(line, "endpoint not connected") &&
		(strings.Contains(line, "connection download closed") ||
			strings.Contains(line, "connection upload closed"))
}
