// Command ssh-tunnel 是 Java 版 ssh-tunnel 的 Go 重写：
// 本地提供 SOCKS5 / HTTP 代理，按直连规则把流量分流到本机直连或 SSH 隧道，
// 并支持 -L 本地端口转发 / -R 远程端口转发。
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	_ "time/tzdata" // 内嵌时区数据库：alpine 镜像默认不带 tzdata，TZ=Asia/Shanghai 仍可生效

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/config"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/proxy"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/sshpool"
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
		plain := params.ValueOr("-encode", "")
		if plain == "" {
			fmt.Fprintln(os.Stderr, "用法: ssh-tunnel -encode <明文密码>")
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
// 与 Java 版 HEALTHCHECK 等价（优先 HTTP_PORT，其次 SOCKS_PORT；都未配置时恒健康），
// 但不依赖 bash 的 /dev/tcp，因此 alpine 镜像无需额外装 shell 工具。
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
		return probe(port)
	}
	return 0
}

// probe 探测本地端口是否可建立 TCP 连接。
func probe(port int) int {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return 1
	}
	_ = conn.Close()
	return 0
}

// run 装配并运行全部代理/转发任务，返回进程退出码（0 正常，1 启动失败，2 配置错误）。
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

	var listeners []net.Listener
	if cfg.SocksPort > 0 {
		ln, err := proxy.ListenTCP(cfg.SocksPort)
		if err != nil {
			logging.Error("main", "socks5代理端口监听失败", "port", cfg.SocksPort, "err", err)
			return 1
		}
		listeners = append(listeners, ln)
		logging.Info("main", "socks5代理端口监听成功", "port", cfg.SocksPort)
		go proxy.ServeSocks5(ln, creds, &proxy.Route{
			Proto: "socks5", Direct: direct, Tunnel: tunnel, Rules: cfg.Direct,
		})
	}
	if cfg.HTTPPort > 0 {
		ln, err := proxy.ListenTCP(cfg.HTTPPort)
		if err != nil {
			logging.Error("main", "http代理端口监听失败", "port", cfg.HTTPPort, "err", err)
			return 1
		}
		listeners = append(listeners, ln)
		logging.Info("main", "http代理端口监听成功", "port", cfg.HTTPPort)
		go proxy.ServeHTTP(ln, creds, &proxy.Route{
			Proto: "http", Direct: direct, Tunnel: tunnel, Rules: cfg.Direct,
		})
	}

	<-ctx.Done()
	logging.Info("main", "收到退出信号，正在停止")
	for _, ln := range listeners {
		_ = ln.Close()
	}
	return 0
}
