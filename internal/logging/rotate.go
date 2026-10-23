package logging

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// flushInterval 缓冲写入的落盘间隔。
//
// 文件写入改为带缓冲：高频日志（每连接多行）原来每行一次 write 系统调用，
// 压力场景下每秒数百次；缓冲后按 64KB 或 1 秒落盘，系统调用量下降两个数量级。
// 落盘靠后台 flushLoop 定时触发，而不是依赖下一次 Write：写入稀疏时
// （如高并发降噪后压测期间几乎没有日志）只靠 Write 判断会让日志长期留在
// 缓冲里，tail -f 看不到，进程异常退出还会丢失。
const flushInterval = time.Second

// Rotator 按天滚动的文件写入器，语义与 Java 版 logback 配置一致：
//   - 当前文件：logs/ssh-tunnel.log
//   - 归档文件：logs/ssh-tunnel.yyyy-MM-dd.log
//   - 保留 30 天，归档总量上限 1GB（超出时优先删除最旧的归档）
//
// 写入失败不会影响控制台输出（控制台由 fanoutWriter 在文件之后独立写出，错误被忽略）。
type Rotator struct {
	dir      string
	path     string
	maxDays  int
	maxBytes int64

	mu        sync.Mutex
	f         *os.File
	bw        *bufio.Writer
	lastFlush time.Time
	day       string

	// done 通知后台刷盘协程退出；closeOnce 保证重复 Close 不会 panic
	done      chan struct{}
	closeOnce sync.Once
}

// NewRotator 创建并打开滚动日志文件。
func NewRotator(dir string, maxDays int, maxBytes int64) (*Rotator, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	r := &Rotator{
		dir:      dir,
		path:     filepath.Join(dir, logFileName),
		maxDays:  maxDays,
		maxBytes: maxBytes,
		day:      time.Now().Format("2006-01-02"),
		done:     make(chan struct{}),
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	r.f = f
	r.bw = bufio.NewWriterSize(f, 64*1024)
	r.lastFlush = time.Now()
	// 启动时清理一次历史归档，避免只运行不跨天时长期不回收
	r.cleanupLocked(r.day)
	go r.flushLoop()
	return r, nil
}

// flushLoop 周期性把写缓冲落盘。
//
// 日志写入稀疏时只能靠它保证最新日志及时可见（tail -f）且不因异常退出而丢失。
func (r *Rotator) flushLoop() {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.mu.Lock()
			if r.bw != nil {
				_ = r.bw.Flush()
				r.lastFlush = time.Now()
			}
			r.mu.Unlock()
		}
	}
}

// Write 实现 io.Writer。
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if today != r.day {
		r.rotateLocked(today)
	}
	if r.bw == nil {
		if err := r.openLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.bw.Write(p)
	if time.Since(r.lastFlush) >= flushInterval {
		if ferr := r.bw.Flush(); ferr != nil && err == nil {
			err = ferr
		}
		r.lastFlush = time.Now()
	}
	return n, err
}

// Close 关闭当前日志文件。
func (r *Rotator) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeLocked()
}

// openLocked 打开当前日志文件并绑定写缓冲。
func (r *Rotator) openLocked() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	r.f = f
	r.bw = bufio.NewWriterSize(f, 64*1024)
	r.lastFlush = time.Now()
	return nil
}

// closeLocked 先把缓冲落盘再关闭文件。
func (r *Rotator) closeLocked() error {
	if r.f == nil {
		return nil
	}
	var err error
	if r.bw != nil {
		if ferr := r.bw.Flush(); ferr != nil {
			err = ferr
		}
		r.bw = nil
	}
	if cerr := r.f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	r.f = nil
	return err
}

// rotateLocked 把当前文件归档为 <旧日期> 并打开新文件。
func (r *Rotator) rotateLocked(today string) {
	oldDay := r.day
	// 归档前必须把缓冲落盘，否则未刷出的日志会写进新文件甚至丢失
	_ = r.closeLocked()
	if info, err := os.Stat(r.path); err == nil && info.Size() > 0 {
		archive := filepath.Join(r.dir, fmt.Sprintf("ssh-tunnel.%s.log", oldDay))
		// 同日重启后再跨天可能撞名，先删旧归档再改名（与 logback 覆盖语义一致）
		_ = os.Remove(archive)
		_ = os.Rename(r.path, archive)
	}
	r.day = today
	_ = r.openLocked()
	r.cleanupLocked(today)
}

// cleanupLocked 按天数与总大小清理归档文件。
func (r *Rotator) cleanupLocked(today string) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	todayTime, err := time.ParseInLocation("2006-01-02", today, time.Local)
	if err != nil {
		return
	}
	expire := todayTime.AddDate(0, 0, -r.maxDays)

	type archive struct {
		path string
		date time.Time
		size int64
	}
	var archives []archive
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "ssh-tunnel.") || !strings.HasSuffix(name, ".log") || name == logFileName {
			continue
		}
		dateStr := strings.TrimSuffix(strings.TrimPrefix(name, "ssh-tunnel."), ".log")
		d, err := time.ParseInLocation("2006-01-02", dateStr, time.Local)
		if err != nil {
			continue
		}
		if d.Before(expire) {
			_ = os.Remove(filepath.Join(r.dir, name))
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		archives = append(archives, archive{path: filepath.Join(r.dir, name), date: d, size: info.Size()})
	}
	if r.maxBytes <= 0 {
		return
	}
	// 按日期从旧到新累计，超出上限后继续删除最旧的归档
	sort.Slice(archives, func(i, j int) bool { return archives[i].date.Before(archives[j].date) })
	var total int64
	for _, a := range archives {
		total += a.size
	}
	for _, a := range archives {
		if total <= r.maxBytes {
			break
		}
		_ = os.Remove(a.path)
		total -= a.size
	}
}
