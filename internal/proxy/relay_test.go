package proxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// tcpPair 建立一对已连通的 TCP 连接（相当于代理的客户端侧与转发侧）。
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()

	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	r := <-ch
	if r.err != nil {
		_ = client.Close()
		t.Fatalf("接受连接失败: %v", r.err)
	}
	t.Cleanup(func() { _ = r.conn.Close() })
	return client, r.conn
}

// TestRelayBufferPoolReuse 池化后的缓冲长度必须固定，异常切片不得污染池。
func TestRelayBufferPoolReuse(t *testing.T) {
	buf := getRelayBuf()
	if len(buf) != relayBufSize {
		t.Fatalf("缓冲长度错误: %d", len(buf))
	}
	buf[0] = 0xAA
	putRelayBuf(buf)

	if got := getRelayBuf(); len(got) != relayBufSize {
		t.Fatalf("复用后长度错误: %d", len(got))
	}

	// 过短的切片不入池：取出仍必须是满长缓冲
	putRelayBuf(make([]byte, 16))
	if got := getRelayBuf(); len(got) != relayBufSize {
		t.Fatalf("过短切片不应入池，实际长度 %d", len(got))
	}
}

// TestRelayForwardsAndHalfCloses 验证双向转发与半关闭语义：
// 上传结束后（CloseWrite）下载通道仍然可用，且大报文跨越多个缓冲不出错。
func TestRelayForwardsAndHalfCloses(t *testing.T) {
	echoHost, echoPort := startEchoServer(t)

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(echoHost, strconv.Itoa(echoPort)), 2*time.Second)
	if err != nil {
		t.Fatalf("连接回显服务失败: %v", err)
	}
	defer upstream.Close()

	client, relaySide := tcpPair(t)
	defer client.Close()

	done := make(chan struct{})
	go func() {
		Relay(relaySide, upstream)
		close(done)
	}()

	// 80KB 需要多次读满 relayBufSize，可覆盖缓冲复用路径
	payload := bytes.Repeat([]byte("relay-buf-"), 8*1024)
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		writeErr <- err
	}()

	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("回显内容不一致: got %d bytes, want %d", len(got), len(payload))
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("双方连接结束后 Relay 应退出")
	}
}

// TestRelayIdleTimeoutReapsStuckConns 双向静默的连接必须被空闲看门狗回收。
//
// 客户端休眠/掉线/换网后本端收不到 FIN，Relay 的两个 pipe 会永久阻塞在 Read 上，
// 线上表现为 active 长期不降、SSH 通道与并发名额被幽灵连接占满。
func TestRelayIdleTimeoutReapsStuckConns(t *testing.T) {
	old := currentIdleTimeout()
	SetIdleTimeout(50 * time.Millisecond)
	t.Cleanup(func() { SetIdleTimeout(old) })

	client, relaySide := tcpPair(t)
	defer client.Close()
	target, targetSide := tcpPair(t)
	defer targetSide.Close()

	done := make(chan struct{})
	go func() {
		Relay(relaySide, target)
		close(done)
	}()

	// 双方都不发数据，也没有关闭动作：没有空闲回收时这里会一直阻塞
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("双向空闲超时后 Relay 应关闭连接并退出")
	}
}

// TestRelayIdleTimeoutDisabled 空闲回收设为 0 表示关闭：空闲连接不得被主动断开。
func TestRelayIdleTimeoutDisabled(t *testing.T) {
	old := currentIdleTimeout()
	SetIdleTimeout(0)
	t.Cleanup(func() { SetIdleTimeout(old) })

	client, relaySide := tcpPair(t)
	target, targetSide := tcpPair(t)

	done := make(chan struct{})
	go func() {
		Relay(relaySide, target)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("关闭空闲回收后不应主动断开空闲连接")
	case <-time.After(300 * time.Millisecond):
	}

	// 收尾：关闭两侧连接，Relay 应能正常退出
	_ = client.Close()
	_ = targetSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("连接关闭后 Relay 应退出")
	}
}
