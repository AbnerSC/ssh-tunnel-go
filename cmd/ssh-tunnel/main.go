// 本地提供 SOCKS5 / HTTP 代理，按直连规则把流量分流到本机直连或 SSH 隧道。
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // 内嵌时区数据库：精简基础镜像不带 tzdata，TZ=Asia/Shanghai 仍可生效

	"ssh-tunnel-go/internal/config"
	"ssh-tunnel-go/internal/logging"
	"ssh-tunnel-go/internal/proxy"
	"ssh-tunnel-go/internal/sshpool"
	"ssh-tunnel-go/internal/tun"
)

// 构建时通过 -ldflags "-X main.version=..." 注入
var (
	version = "dev"
	commit  = "none"
	buildAt = "unknown"
)

func main() {
	args := os.Args[1:]
	// 一次性命令不初始化日志文件，避免健康检查在挂载卷里留下空日志
	if code, done := handleOneShot(args); done {
		os.Exit(code)
	}

	closeLog := logging.Init(os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))

	logging.Info("main", "程序启动", "version", version, "commit", commit, "buildAt", buildAt)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, args)
	// 显式收尾而不是 defer：下面要 os.Exit，defer 不会执行，
	// 跳过 closeLog 会丢掉尚未落盘的日志
	stop()
	closeLog()
	os.Exit(code)
}

// handleOneShot 处理 -encode / -health / -version 这类执行后立即退出的命令。
func handleOneShot(args []string) (int, bool) {
	params := config.ParseParams(args)

	if params.Contains("-version") {
		fmt.Printf("ssh-tunnel %s (commit %s, build %s)\n", version, commit, buildAt)
		return 0, true
	}
	if params.Contains("-health") {
		return health(args), true
	}
	if params.Contains("-encode") {
		// 明文优先从参数取；没有参数时读标准输入。
		// 直接写在命令行上会让密码进入 shell 历史与进程列表（ps 全用户可见）。
		// 主密钥与运行时解密共用同一套逻辑：设置了 CIPHER_MASTER_KEY 时，
		// -encode 与服务启动必须用同一个值，否则密文无法解开
		plain := params.ValueOr("-encode", "")
		if plain == "" {
			data, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
			if err != nil {
				fmt.Fprintln(os.Stderr, "读取标准输入失败:", err)
				return 1, true
			}
			plain = strings.TrimRight(string(data), "\r\n")
		}
		if plain == "" {
			fmt.Fprintln(os.Stderr, "用法: ssh-tunnel -encode <明文密码>（推荐: echo 密码 | ssh-tunnel -encode）")
			return 2, true
		}
		encoded, err := config.EncryptLayers(plain, config.MaxCipherLayers)
		if err != nil {
			fmt.Fprintln(os.Stderr, "加密失败:", err)
			return 1, true
		}
		fmt.Println(encoded)
		return 0, true
	}
	return 0, false
}

// health 存活探测：尝试连接本地代理端口。
//
// 优先 HTTP_PORT，其次 SOCKS_PORT；都未配置时恒健康，
// 但不依赖 bash 的 /dev/tcp，因此镜像无需额外安装 shell 工具。
// 已配置但取值非法或端口不可用时判定不健康，不静默回退到另一个端口，
// 避免掩盖配置错误。
func health(args []string) int {
	r := config.NewResolver(args)
	for _, c := range []struct{ flag, env string }{
		{"-H", "HTTP_PORT"},
		{"-D", "SOCKS_PORT"},
	} {
		if !r.Has(c.flag, c.env) {
			continue
		}
		port, err := r.Int(c.flag, c.env, 0)
		if err != nil || port <= 0 {
			return 1
		}
		// 监听地址可能被 BIND_ADDR 限定到具体网卡，探测必须跟着走，
		// 否则容器会被持续标记为不健康
		return probe(probeHost(r.Value("-bind", "BIND_ADDR", "")), port)
	}
	return 0
}

// probeHost 把监听地址翻译成可拨号的回环地址。
func probeHost(bind string) string {
	switch strings.TrimSpace(bind) {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::", "[::]":
		return "::1"
	default:
		return strings.TrimSpace(bind)
	}
}

// isPublicIP 判断探测主机是否为公网 IP 字面量（非回环、非私网、非链路本地）。
func isPublicIP(host string) bool {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// probe 探测本地端口是否可建立 TCP 连接。
func probe(host string, port int) int {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return 1
	}
	_ = conn.Close()
	return 0
}

// statsInterval 汇总统计的输出间隔。
//
// 逐连接日志改为 Debug 后，用一条周期性汇总代替：既能看出隧道是否在承载流量，
// 又不会在高并发时把日志刷满。
const statsInterval = 5 * time.Minute

// startStatsLoop 周期性输出代理运行统计。
func startStatsLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := proxy.Snapshot()
				logging.Info("main", "代理统计",
					"active", s.Active, "total", s.Total,
					"upMB", s.UpBytes/1024/1024, "downMB", s.DownBytes/1024/1024)
			}
		}
	}()
}

// tunStopWait 等待 sing-box 收尾的上限。
//
// 子进程需要先清理系统路由与虚拟网卡再退出；直接 os.Exit 会把
// sing-box 变成孤儿进程，网卡和路由残留会切断本机网络。
const tunStopWait = 15 * time.Second

// bindLogAddr 返回监听地址的日志展示值。
func bindLogAddr(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return "0.0.0.0"
	}
	return addr
}

// run 装配并运行全部代理任务，返回进程退出码（0 正常，1 启动失败，2 配置错误）。
func run(ctx context.Context, args []string) int {
	cfg, err := config.Load(config.NewResolver(args))
	if err != nil {
		logging.Error("main", "配置解析失败", "err", err)
		return 2
	}
	if !cfg.CheckWork() {
		logging.Info("main", "找不到可以工作的任务")
		return 0
	}

	// 并发连接上限必须在启动监听之前生效：Serve 只会在启动时取一次限制器
	proxy.SetConnectionLimits(cfg.MaxConns, cfg.MaxConnsPerIP)
	// 空闲回收时限同样在监听前设置：新连接进入转发时读取当前值，
	// 用于回收客户端休眠/掉线留下的僵尸连接（否则 active 只增不减）
	proxy.SetIdleTimeout(cfg.IdleTimeout)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// socks5 与 http 代理共用同一个 SSH 连接池（若配置了服务器）；
	// 未配置服务器时本机直接提供代理（全部本地直连），
	// 配置了直连规则时命中规则的请求本地直连，其余走 SSH 隧道
	var tunnel proxy.Dialer
	var pool *sshpool.Pool
	if cfg.SSH != nil {
		pool = sshpool.New(cfg.SSH)
		pool.Start(ctx)
		defer pool.Close()
		tunnel = pool
	}

	direct := proxy.LocalDialer{Timeout: 3 * time.Second}
	creds := proxy.NewCredentials(cfg.SocksUser, cfg.SocksPassword)
	startStatsLoop(ctx)

	var listeners []net.Listener
	if cfg.SocksPort > 0 {
		ln, err := proxy.ListenTCPOn(cfg.BindAddr, cfg.SocksPort)
		if err != nil {
			logging.Error("main", "socks5代理端口监听失败", "port", cfg.SocksPort, "err", err)
			return 1
		}
		listeners = append(listeners, ln)
		logging.Info("main", "socks5代理端口监听成功", "port", cfg.SocksPort, "bind", bindLogAddr(cfg.BindAddr))
		go proxy.ServeSocks5(ln, creds, &proxy.Route{
			Proto: "socks5", Direct: direct, Tunnel: tunnel, Rules: cfg.Direct,
		})
	}
	if cfg.HTTPPort > 0 {
		ln, err := proxy.ListenTCPOn(cfg.BindAddr, cfg.HTTPPort)
		if err != nil {
			logging.Error("main", "http代理端口监听失败", "port", cfg.HTTPPort, "err", err)
			return 1
		}
		listeners = append(listeners, ln)
		logging.Info("main", "http代理端口监听成功", "port", cfg.HTTPPort, "bind", bindLogAddr(cfg.BindAddr))
		go proxy.ServeHTTP(ln, creds, &proxy.Route{
			Proto: "http", Direct: direct, Tunnel: tunnel, Rules: cfg.Direct,
		})
	}

	// TUN 全局接管（可选）：托管 sing-box 把系统流量经本地 SOCKS5 转发。
	// 必须在监听成功之后启动：TUN 一旦建立，系统流量会立刻涌向 SOCKS 端口
	var tunErr chan error
	if cfg.Tun != nil {
		// TUN 的 socks 出站指向 BIND_ADDR 的实际监听地址：公网地址不会被
		// 私网直连规则命中，连接会再次进入 final proxy 形成自指回环
		if host := probeHost(cfg.BindAddr); isPublicIP(host) {
			logging.Warn("main", "BIND_ADDR 为公网地址，TUN 的 socks 出站将指向该地址并可能形成自指回环；TUN 模式建议使用 BIND_ADDR=127.0.0.1",
				"socksHost", host)
		}
		tunErr = make(chan error, 1)
		go func() {
			tunErr <- tun.Run(ctx, tun.Options{
				ConfigPath:    cfg.Tun.ConfigPath,
				SocksHost:     probeHost(cfg.BindAddr),
				SocksPort:     cfg.SocksPort,
				SocksUser:     cfg.SocksUser,
				SocksPassword: cfg.SocksPassword,
				SSHHosts:      sshHosts(cfg.SSH),
				DirectIPs:     cfg.DirectIPs,
				DirectDomains: cfg.DirectDomains,
				GeoSites:      cfg.Tun.GeoSites,
				ForceDomains:  cfg.ForceDomains,
				RouteExclude:  cfg.Tun.RouteExclude,
				UDPPolicy:     cfg.Tun.UDPPolicy,
				FakeIP:        cfg.Tun.FakeIP,
				DNSProxy:      cfg.Tun.DNSProxy,
				DNSCN:         cfg.Tun.DNSCN,
				Stack:         cfg.Tun.Stack,
				LogLevel:      cfg.Tun.LogLevel,
				AutoRedirect:  cfg.Tun.AutoRedirect,
			})
		}()
	}

	// 等待退出信号；TUN 子进程异常退出时记录错误并退出（由 restarter 兜底拉起）
	code := 0
	select {
	case <-ctx.Done():
		logging.Info("main", "收到退出信号，正在停止")
		if tunErr != nil {
			// 等 sing-box 清理路由/网卡后再退出
			select {
			case err := <-tunErr:
				if err != nil {
					logging.Error("main", "TUN全局接管停止异常", "err", err)
					code = 1
				}
			case <-time.After(tunStopWait):
				// 兜底：tun.Run 自身已有界（约 2×5s），正常不会走到这里；
				// 一旦超时说明收尾卡死，可能残留路由/网卡，不能按正常退出处理
				logging.Warn("main", "等待 sing-box 收尾超时，可能残留路由/网卡", "wait", tunStopWait)
				code = 1
			}
		}
	case err := <-tunErr:
		if err != nil {
			logging.Error("main", "TUN全局接管失败", "err", err)
			code = 1
		}
	}
	for _, ln := range listeners {
		_ = ln.Close()
	}
	return code
}

// sshHosts 提取 SSH 服务器地址，供 TUN 路由排除使用。
func sshHosts(s *config.SSHConfig) []string {
	if s == nil {
		return nil
	}
	return []string{s.Addr}
}
