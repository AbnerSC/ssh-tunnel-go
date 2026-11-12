package sshpool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"ssh-tunnel-go/internal/config"
	"ssh-tunnel-go/internal/logging"
	"ssh-tunnel-go/internal/proxy"
)

const (
	// connectTimeout 建连 + 密钥交换 + 认证的总超时
	connectTimeout = 10 * time.Second
	// channelConnectTimeout direct-tcpip 通道建立超时，需等对端完成到目标的 TCP 连接
	channelConnectTimeout = 10 * time.Second
	// keepAliveInterval 心跳间隔
	keepAliveInterval = 15 * time.Second
	// keepAliveTimeout 单次心跳等待应答的超时
	keepAliveTimeout = 15 * time.Second
	// keepAliveMaxFails 连续多少次心跳无响应判定会话失效
	keepAliveMaxFails = 3
	// reconnectWait 连接失败/断开后的重试间隔
	reconnectWait = 5 * time.Second
	// maxReconnectWait 连续失败时的退避上限。
	// 服务器宕机/密码错误时若无上限，每个槽位每 5s 重试一次，
	// 6 条会话就是每分钟 72 次无效握手与 72 行失败日志；指数退避后降为约 6 次/分钟。
	maxReconnectWait = 60 * time.Second
	// dialAttempts 单次代理请求最多尝试的会话数。
	// 轮询命中的会话可能刚好断开，换一条健康会话重试，
	// 避免把偶发断连直接丢给客户端。
	dialAttempts = 2
)

// ErrNoSession 当前没有可用的 SSH 会话。
var ErrNoSession = errors.New("没有可用的SSH会话")

// cipherList：AEAD 优先，保留 CTR/ChaCha20/CBC 兼容回退。
// 注意 sshd 必须与服务端至少有一个共同算法，否则握手失败。
var cipherList = []string{
	"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
	"aes128-ctr", "aes192-ctr", "aes256-ctr",
	"chacha20-poly1305@openssh.com",
	"aes128-cbc", "aes192-cbc", "aes256-cbc",
}

// conn 一条已认证的 SSH 会话。
type conn struct {
	client *ssh.Client
	index  int

	closed    atomic.Bool
	closeOnce sync.Once
}

func (c *conn) alive() bool {
	return c != nil && !c.closed.Load()
}

// close 幂等关闭会话。
func (c *conn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.client.Close()
	})
}

// Pool SSH 连接池：维持 N 条会话，按轮询分发 direct-tcpip 通道。
type Pool struct {
	cfg      *config.SSHConfig
	local    proxy.LocalDialer
	hostKeys *hostKeyStore

	slots []atomic.Pointer[conn]
	index atomic.Uint64

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New 创建连接池。
func New(cfg *config.SSHConfig) *Pool {
	size := cfg.Pool
	if size < 1 {
		size = 1
	}
	return &Pool{
		cfg:      cfg,
		local:    proxy.LocalDialer{Timeout: 3 * time.Second},
		slots:    make([]atomic.Pointer[conn], size),
		hostKeys: newHostKeyStore(cfg.KnownHosts, cfg.HostKeys),
	}
}

// Start 启动 N 个会话维持协程。
func (p *Pool) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	for i := range p.slots {
		idx := i
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.runSlot(ctx, idx)
		}()
	}
}

// Close 停止全部会话。
func (p *Pool) Close() {
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
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
		// 服务端明确拒绝建通道（sshd 到目标的 TCP 连不上、或被策略禁止）：
		// 换一条会话同样失败，直接返回，避免同一次请求在两个池位上各记一条告警。
		// 日志里的 "ssh: rejected: connect failed (\"open failed\")" 就是这一类，
		// 典型目标：服务端无 IPv6 出口的 v6 域名、被服务端网络阻断的站点。
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			return nil, fmt.Errorf("服务端拒绝建通道(%s)，目标在服务端侧不可达: %w", openErr.Reason, err)
		}
		// 超时说明请求已到达服务端但目标响应慢，换会话只会把超时叠加给客户端。
		// 原始错误只有一个 context deadline exceeded，排障时看不出是哪个阶段超时，
		// 这里补上时限与目标，区分「通道建连超时」与「服务端拒绝」。
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("SSH 通道建连超过 %s 未完成，服务端到 %s 的 TCP 未建或未响应: %w",
				channelConnectTimeout, addr, err)
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
	// fails 连续失败次数，驱动指数退避；连接成功后清零
	fails := 0
	for {
		if ctx.Err() != nil {
			return
		}
		logging.Info("ssh", "尝试创建连接", "server", server, "slot", idx, "attempt", fails+1)
		c, err := p.connect(ctx, idx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fails++
			delay := reconnectDelay(idx, fails)
			logging.Warn("ssh", "创建连接失败", "server", server, "slot", idx,
				"fails", fails, "nextRetry", delay.Round(time.Second), "err", err)
			if !sleepCtx(ctx, delay) {
				return
			}
			continue
		}
		fails = 0
		logging.Info("ssh", "创建连接成功", "server", server, "slot", idx)
		p.slots[idx].Store(c)

		p.serve(ctx, c)

		c.close()
		p.slots[idx].CompareAndSwap(c, nil)
		// 断线后的首次重连沿用 5s 固定等待，
		// 若重连继续失败则转为指数退避
		fails = 1
		logging.Warn("ssh", "发生异常，断开连接", "server", server, "slot", idx)
		if !sleepCtx(ctx, reconnectDelay(idx, fails)) {
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
		// 服务端主机密钥校验：默认首次信任(TOFU)，可用 SSH_HOST_KEY 固定指纹。
		// 不校验等于把 SSH 密码和全部隧道流量交给链路上的任何中间人。
		HostKeyCallback: p.hostKeys.callback(),
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
		// 显式设置 SO_RCVBUF/SO_SNDBUF 会让内核置上 SOCK_RCVBUF_LOCK/SOCK_SNDBUF_LOCK，
		// 关闭收发缓冲的自动调优(tcp_moderate_rcvbuf)。实测公网 78ms RTT 链路下，
		// 请求值被 net.core.rmem_max 截断且不再增长：接收窗口钉在 64~128KB、
		// 发送队列卡在约 208KB，下载仅 0.8MB/s、上传仅 3MB/s；
		// 交给内核自动调优后可随 BDP 涨到 2.5~6MB，下载 16~20MB/s、上传 9~11MB/s，
		// 两者都已与同链路裸 TCP 吞吐持平。
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

// reconnectDelay 计算重连等待：按连续失败次数指数退避（5s 起，封顶 60s），
// 并在槽位维度错开 250ms，避免所有会话在同一时刻集中重连
// （服务器重启后同时建连、同时超时，形成周期性的惊群）。
func reconnectDelay(idx, fails int) time.Duration {
	if fails < 1 {
		fails = 1
	}
	d := reconnectWait
	for i := 1; i < fails && d < maxReconnectWait; i++ {
		d *= 2
	}
	if d > maxReconnectWait {
		d = maxReconnectWait
	}
	return d + time.Duration(idx%8)*250*time.Millisecond
}
