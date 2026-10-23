package sshpool

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/config"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/proxy"
)

const (
	// connectTimeout 建连 + 密钥交换 + 认证的总超时（与 Java 版 CONNECT_TIMEOUT 一致）
	connectTimeout = 10 * time.Second
	// channelConnectTimeout direct-tcpip 通道建立超时，需等对端完成到目标的 TCP 连接
	channelConnectTimeout = 10 * time.Second
	// keepAliveInterval 心跳间隔
	keepAliveInterval = 15 * time.Second
	// keepAliveTimeout 单次心跳等待应答的超时
	keepAliveTimeout = 15 * time.Second
	// keepAliveMaxFails 连续多少次心跳无响应判定会话失效
	keepAliveMaxFails = 3
	// reconnectWait 连接失败/断开后的重试间隔（与 Java 版 ERROR_WAIT_TIME 一致）
	reconnectWait = 5 * time.Second
	// dialAttempts 单次代理请求最多尝试的会话数。
	// 轮询命中的会话可能刚好断开，换一条健康会话重试，
	// 避免把偶发断连直接丢给客户端。
	dialAttempts = 2
)

// ErrNoSession 当前没有可用的 SSH 会话。
var ErrNoSession = errors.New("没有可用的SSH会话")

// cipherList 与 Java 版一致：AEAD 优先，保留 CTR/ChaCha20/CBC 兼容回退。
// 注意 sshd 必须与服务端至少有一个共同算法，否则握手失败。
var cipherList = []string{
	"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
	"chacha20-poly1305@openssh.com",
	"aes128-cbc", "aes192-cbc", "aes256-cbc",
}

// Pool SSH 连接池：维持 N 条会话，按轮询分发 direct-tcpip 通道。
type Pool struct {
	cfg   *config.SSHConfig
	local proxy.LocalDialer

	slots []atomic.Pointer[conn]
	main  atomic.Pointer[conn]
	index atomic.Uint64

	electMu sync.Mutex

	localMu sync.Mutex
	locals  []net.Listener

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New 创建连接池；-L 监听在 Start 时建立。
func New(cfg *config.SSHConfig) *Pool {
	size := cfg.Pool
	if size < 1 {
		size = 1
	}
	return &Pool{
		cfg:   cfg,
		local: proxy.LocalDialer{Timeout: 3 * time.Second},
		slots: make([]atomic.Pointer[conn], size),
	}
}

// Start 启动本地转发监听与 N 个会话维持协程。
func (p *Pool) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.startLocals()
	for i := range p.slots {
		idx := i
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.runSlot(ctx, idx)
		}()
	}
}

// Close 停止全部会话与监听。
func (p *Pool) Close() {
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		p.localMu.Lock()
		listeners := p.locals
		p.locals = nil
		p.localMu.Unlock()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		for i := range p.slots {
			if c := p.slots[i].Load(); c != nil {
				c.close()
			}
		}
		p.wg.Wait()
	})
}

// DialContext 实现 proxy.Dialer：轮询选中的会话打开 direct-tcpip 通道；
// 命中会话刚断开时自动换一条重试。
func (p *Pool) DialContext(ctx context.Context, host string, port int) (net.Conn, error) {
	size := len(p.slots)
	if size == 0 {
		return nil, ErrNoSession
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := p.nextIndex()
	var lastErr error
	tried := 0
	for i := 0; i < size && tried < dialAttempts; i++ {
		c := p.slots[(start+i)%size].Load()
		if c == nil || !c.alive() {
			continue
		}
		tried++
		dialCtx, cancel := context.WithTimeout(ctx, channelConnectTimeout)
		conn, err := c.client.DialContext(dialCtx, "tcp", addr)
		cancel()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// 超时说明请求已到达服务端但目标响应慢，换会话只会把超时叠加给客户端
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, ErrNoSession
	}
	return nil, lastErr
}

// pick 无锁轮询：从上次位置的下一个开始，找到一条存活的会话。
func (p *Pool) pick() *conn {
	size := len(p.slots)
	if size == 0 {
		return nil
	}
	start := p.nextIndex()
	for i := 0; i < size; i++ {
		if c := p.slots[(start+i)%size].Load(); c != nil && c.alive() {
			return c
		}
	}
	return nil
}

// nextIndex 推进轮询游标并返回本次起点。
func (p *Pool) nextIndex() int {
	size := len(p.slots)
	if size == 0 {
		return 0
	}
	return int((p.index.Add(1) - 1) % uint64(size))
}

// runSlot 维护单个池位的状态机：连接 → 心跳保活 → 断开 → 退避重连。
func (p *Pool) runSlot(ctx context.Context, idx int) {
	server := p.serverAddr()
	for {
		if ctx.Err() != nil {
			return
		}
		logging.Info("ssh", "尝试创建连接", "server", server, "slot", idx)
		c, err := p.connect(ctx, idx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logging.Warn("ssh", "创建连接失败", "server", server, "slot", idx, "err", err)
			if !sleepCtx(ctx, reconnectDelay(idx)) {
				return
			}
			continue
		}
		logging.Info("ssh", "创建连接成功", "server", server, "slot", idx)
		p.slots[idx].Store(c)
		p.electMain()

		p.serve(ctx, c)

		// 先把会话标记为已关闭再清空槽位：若顺序反过来，并发的 electMain
		// 可能看到「仍在槽位且 alive」的旧主会话而跳过选举，
		// 导致 -R 转发在旧主会话真正关闭后无人承担。
		c.close()
		p.slots[idx].CompareAndSwap(c, nil)
		p.electMain()
		logging.Warn("ssh", "发生异常，断开连接", "server", server, "slot", idx)
		if !sleepCtx(ctx, reconnectDelay(idx)) {
			return
		}
	}
}

// connect 建立一条已完成认证的 SSH 会话。
func (p *Pool) connect(ctx context.Context, idx int) (*conn, error) {
	addr := p.serverAddr()
	password := p.cfg.Password
	clientCfg := &ssh.ClientConfig{
		User: p.cfg.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			// keyboard-interactive 兜底：部分服务端(PAM)只接受交互式认证
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		// 对应原 JSch StrictHostKeyChecking=no
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Ciphers:         cipherList,
	}
	dialer := net.Dialer{Timeout: connectTimeout, KeepAlive: keepAliveInterval}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		// 刻意不调用 SetReadBuffer/SetWriteBuffer：
		// 显式设置 SO_RCVBUF/SO_SNDBUF 会让内核置上 SOCK_RCVBUF_LOCK，
		// 关闭接收窗口自动调优(tcp_moderate_rcvbuf)。实测公网高 RTT 链路下
		// 窗口会被钉在 64~128KB，单向吞吐被压到约 1MB/s(约 100KB/RTT)，
		// 而交给内核自动调优可随 BDP 增长到几 MB，吞吐提升一个数量级。
	}
	// 握手与认证共用同一超时，防止 auth 阶段无限阻塞
	_ = raw.SetDeadline(time.Now().Add(connectTimeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(raw, addr, clientCfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return &conn{client: ssh.NewClient(sshConn, chans, reqs), index: idx}, nil
}

// serve 会话存活期间发送心跳，连续 keepAliveMaxFails 次无响应即关闭会话触发重连。
func (p *Pool) serve(ctx context.Context, c *conn) {
	done := make(chan struct{})
	go func() {
		_ = c.client.Wait()
		close(done)
	}()

	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()
	fails := 0
	for {
		select {
		case <-ctx.Done():
			c.close()
			<-done
			return
		case <-done:
			return
		case <-ticker.C:
			if err := sendKeepAlive(c.client, keepAliveTimeout); err != nil {
				fails++
				logging.Warn("ssh", "SSH心跳无响应", "server", p.serverAddr(), "slot", c.index,
					"fails", fails, "err", err)
				if fails >= keepAliveMaxFails {
					c.close()
					<-done
					return
				}
				continue
			}
			fails = 0
		}
	}
}

// electMain 选举主会话，由其承担 -R 远程端口转发。
func (p *Pool) electMain() {
	p.electMu.Lock()
	defer p.electMu.Unlock()
	if cur := p.main.Load(); cur != nil && cur.alive() {
		return
	}
	var chosen *conn
	for i := range p.slots {
		if c := p.slots[i].Load(); c != nil && c.alive() {
			chosen = c
			break
		}
	}
	p.main.Store(chosen)
	if chosen == nil {
		return
	}
	logging.Info("ssh", "选举主会话", "slot", chosen.index)
	// 不持锁做网络请求：tcpip-forward 要等服务端应答（失败还会重试），
	// 同步执行会把其它槽位的选举一起阻塞。
	go chosen.startRemotes(p.cfg.Remotes)
}

func (p *Pool) serverAddr() string {
	return net.JoinHostPort(p.cfg.Addr, strconv.Itoa(p.cfg.Port))
}

// sendKeepAlive 发送 keepalive@openssh.com 全局请求并等待应答。
func sendKeepAlive(client *ssh.Client, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		result <- err
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		return errors.New("SSH心跳超时")
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// reconnectDelay 在固定退避上按槽位错开，避免所有会话在同一时刻集中重连
// （服务器重启后同时建连、同时超时，形成周期性的惊群）。
func reconnectDelay(idx int) time.Duration {
	return reconnectWait + time.Duration(idx%8)*250*time.Millisecond
}
