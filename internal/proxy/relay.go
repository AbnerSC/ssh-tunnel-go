package proxy

import (
	"io"
	"net"
	"sync"
)

// Relay 在两条连接之间做双向转发。
//
// 正常 EOF 时只做半关闭（CloseWrite），保留反向数据通道——上传结束不代表下载结束；
// 出错时双向关闭，避免对端 goroutine 永久阻塞。
func Relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	pipe := func(dst, src net.Conn, done chan<- struct{}) {
		defer func() { done <- struct{}{} }()
		if _, err := io.Copy(dst, src); err != nil {
			closeBoth()
			return
		}
		closeWrite(dst)
	}

	done := make(chan struct{}, 2)
	go pipe(b, a, done)
	go pipe(a, b, done)
	<-done
	<-done
	closeBoth()
}

// closeWrite 半关闭写方向，支持 *net.TCPConn 与 SSH 通道连接。
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
