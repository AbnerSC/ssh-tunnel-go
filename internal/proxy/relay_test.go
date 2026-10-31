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
