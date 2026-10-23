package proxy

import (
	"io"
	"net"
	"sync"
)

// relayBufSize 单向转发缓冲大小。SSH 通道单包上限 32KB，取 4 倍可减少
// 读系统调用与写入调度次数；实测仍受对端通道窗口限制，此处只降低本地开销。
const relayBufSize = 128 * 1024

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
		// 不用 io.Copy：其内部缓冲固定 32KB，且目标为 *net.TCPConn 时会走
		// ReadFrom 而忽略自定义缓冲，导致包装后的 SSH 通道侧始终是小块读写。
		buf := make([]byte, relayBufSize)
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					closeBoth()
					return
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					closeBoth()
					return
				}
				break
			}
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
