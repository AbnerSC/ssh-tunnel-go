package proxy

import "sync/atomic"

// 运行统计。
//
// 逐连接的成功日志级别已降到 Debug（压力场景下每秒数百条会成为噪声），
// 这里用无锁计数器保留可观测性：main 每 5 分钟输出一条汇总，
// 需要排障时再把 LOG_LEVEL 调成 debug 查看逐连接日志。
var (
	// activeConns 当前处理中的客户端连接数
	activeConns atomic.Int64
	// totalConns 进程启动以来的累计客户端连接数
	totalConns atomic.Int64
	// bytesUp 客户端发往目标方向（上行）的字节数
	bytesUp atomic.Int64
	// bytesDown 目标发往客户端方向（下行）的字节数
	bytesDown atomic.Int64
)

// Stats 代理运行统计快照。
type Stats struct {
	Active    int64 // 当前连接数
	Total     int64 // 累计连接数
	UpBytes   int64 // 上行字节数
	DownBytes int64 // 下行字节数
}

// Snapshot 返回当前统计快照。
func Snapshot() Stats {
	return Stats{
		Active:    activeConns.Load(),
		Total:     totalConns.Load(),
		UpBytes:   bytesUp.Load(),
		DownBytes: bytesDown.Load(),
	}
}
