package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

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

	mu  sync.Mutex
	f   *os.File
	day string
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
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	r.f = f
	// 启动时清理一次历史归档，避免只运行不跨天时长期不回收
	r.cleanupLocked(r.day)
	return r, nil
}

// Write 实现 io.Writer。
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if today != r.day {
		r.rotateLocked(today)
	}
	if r.f == nil {
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return 0, err
		}
		r.f = f
	}
	return r.f.Write(p)
}

// Close 关闭当前日志文件。
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// rotateLocked 把当前文件归档为 <旧日期> 并打开新文件。
func (r *Rotator) rotateLocked(today string) {
	oldDay := r.day
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	if info, err := os.Stat(r.path); err == nil && info.Size() > 0 {
		archive := filepath.Join(r.dir, fmt.Sprintf("ssh-tunnel.%s.log", oldDay))
		// 同日重启后再跨天可能撞名，先删旧归档再改名（与 logback 覆盖语义一致）
		_ = os.Remove(archive)
		_ = os.Rename(r.path, archive)
	}
	r.day = today
	if f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		r.f = f
	}
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
