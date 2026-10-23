package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func startEcho(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动回显服务失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("端口 %d 未就绪", port)
}

func clearAllEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"LOG_FORMAT", "LOG_LEVEL",
		"SOCKS_PORT", "SOCKS_USER", "SOCKS_PASSWORD", "HTTP_PORT",
		"SSH_SERVER", "SSH_PORT", "SSH_PASSWORD", "SSH_POOL",
		"DIRECT_IP", "DIRECT_DOMAIN", "DIRECT_CN",
	} {
		t.Setenv(key, "")
	}
}

func TestHealth(t *testing.T) {
	clearAllEnv(t)
	if code := health(nil); code != 0 {
		t.Fatalf("未配置端口时应恒健康: %d", code)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	t.Setenv("HTTP_PORT", strconv.Itoa(port))
	if code := health(nil); code != 0 {
		t.Fatalf("端口可用时应健康: %d", code)
	}

	t.Setenv("HTTP_PORT", strconv.Itoa(freePort(t)))
	if code := health(nil); code != 1 {
		t.Fatalf("端口不可用时应不健康: %d", code)
	}

	// 已配置但取值非法时不得静默回退，否则会掩盖配置错误
	t.Setenv("HTTP_PORT", "abc")
	t.Setenv("SOCKS_PORT", strconv.Itoa(port))
	if code := health(nil); code != 1 {
		t.Fatalf("端口配置非法时应不健康: %d", code)
	}

	// 未配置 HTTP_PORT 时才回退到 SOCKS_PORT
	t.Setenv("HTTP_PORT", "")
	if code := health(nil); code != 0 {
		t.Fatalf("未配置 HTTP_PORT 时应探测 SOCKS_PORT: %d", code)
	}
}

func TestHandleOneShot(t *testing.T) {
	clearAllEnv(t)
	if code, done := handleOneShot(nil); done || code != 0 {
		t.Fatalf("普通启动不应被拦截: %d %v", code, done)
	}
	if code, done := handleOneShot([]string{"-version"}); !done || code != 0 {
		t.Fatalf("-version 应直接退出: %d %v", code, done)
	}
	if code, done := handleOneShot([]string{"-encode"}); !done || code != 2 {
		t.Fatalf("-encode 缺少明文应报错: %d %v", code, done)
	}
	if code, done := handleOneShot([]string{"-encode", "pwd123"}); !done || code != 0 {
		t.Fatalf("-encode 应成功: %d %v", code, done)
	}
}

// TestEndToEndDirectProxies 以生产环境变量启动完整程序（无 SSH 服务器，全部本地直连），
// 验证 SOCKS5 与 HTTP 代理的认证、转发链路。
func TestEndToEndDirectProxies(t *testing.T) {
	clearAllEnv(t)
	echoHost, echoPort := startEcho(t)
	socksPort := freePort(t)
	httpPort := freePort(t)
	t.Setenv("SOCKS_PORT", strconv.Itoa(socksPort))
	t.Setenv("HTTP_PORT", strconv.Itoa(httpPort))
	t.Setenv("SOCKS_USER", "user")
	t.Setenv("SOCKS_PASSWORD", "pwd123")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if code := run(ctx, nil); code != 0 {
			t.Errorf("run 退出码 = %d, want 0", code)
		}
	}()
	defer func() {
		cancel()
		<-done
	}()
	waitPort(t, socksPort)
	waitPort(t, httpPort)

	t.Run("socks5", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), 3*time.Second)
		if err != nil {
			t.Fatalf("连接 socks5 失败: %v", err)
		}
		defer conn.Close()

		// 认证
		if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 2 {
			t.Fatalf("认证方式选择异常: %v %v", reply, err)
		}
		auth := []byte{1, 4}
		auth = append(auth, "user"...)
		auth = append(auth, 6)
		auth = append(auth, "pwd123"...)
		if _, err := conn.Write(auth); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
			t.Fatalf("认证失败: %v %v", reply, err)
		}

		// CONNECT 请求（IPv4）
		req := []byte{5, 1, 0, 1}
		req = append(req, net.ParseIP(echoHost).To4()...)
		req = append(req, byte(echoPort>>8), byte(echoPort))
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		head := make([]byte, 10)
		if _, err := io.ReadFull(conn, head); err != nil || head[1] != 0 {
			t.Fatalf("CONNECT 失败: %v %v", head, err)
		}

		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
			t.Fatalf("回显异常: %q %v", got, err)
		}
	})

	t.Run("http", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)), 3*time.Second)
		if err != nil {
			t.Fatalf("连接 http 代理失败: %v", err)
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		auth := base64.StdEncoding.EncodeToString([]byte("user:pwd123"))
		req := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			echoHost, echoPort, echoHost, auth)
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		var head strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("读取响应头失败: %v", err)
			}
			head.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		if !strings.HasPrefix(head.String(), "HTTP/1.1 200 Connection Established") {
			t.Fatalf("CONNECT 应答异常: %q", head.String())
		}

		if _, err := conn.Write([]byte("pong")); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(br, got); err != nil || string(got) != "pong" {
			t.Fatalf("回显异常: %q %v", got, err)
		}
	})
}
