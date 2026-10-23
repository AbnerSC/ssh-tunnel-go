// Package logging 提供与 Java 版对齐的日志能力：
// 控制台 + 文件双输出、按天滚动归档、30 天/1GB 保留策略。
//
// 默认输出 JSON 结构化日志（每行一条），设置 LOG_FORMAT=text 可切换为
// Java 版同构的文本格式，便于沿用既有日志解析规则。
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// loggerName 与 Java 版一致，保证文本模式下日志行可直接被既有规则解析。
const loggerName = "org.open.scdm.common.ssh.Logf"

// 文件日志参数与 Java 版 logback.xml 保持一致。
const (
	logDirName  = "logs"
	logFileName = "ssh-tunnel.log"
	maxDays     = 30
	maxBytes    = int64(1 << 30) // 1GB
)

var (
	mu      sync.RWMutex
	logger  = slog.New(slog.NewTextHandler(io.Discard, nil))
	rotator *Rotator
)

// Init 初始化日志输出。format 支持 json（默认）与 text；
// level 支持 debug/info/warn/error（默认 info）。
// 返回的 close 函数用于关闭日志文件，可安全重复调用。
func Init(format, level string) func() {
	lv := parseLevel(level)

	// 文件排在 stdout 之前：先落盘再写控制台，避免容器 stdout 阻塞时丢掉文件记录
	var writers []io.Writer
	if r, err := NewRotator(logDirName, maxDays, maxBytes); err == nil {
		writers = append(writers, r)
		rotator = r
	} else {
		// 日志目录不可写不应阻断代理服务，降级为仅控制台输出
		fmt.Fprintf(os.Stderr, "初始化日志文件失败，仅输出到控制台: %v\n", err)
	}
	writers = append(writers, os.Stdout)

	out := fanoutWriter{writers: writers}
	var handler slog.Handler
	if strings.EqualFold(format, "text") {
		handler = &textHandler{out: out, level: lv}
	} else {
		handler = slog.NewJSONHandler(out, &slog.HandlerOptions{Level: lv})
	}

	mu.Lock()
	logger = slog.New(handler)
	r := rotator
	mu.Unlock()

	return func() {
		if r != nil {
			_ = r.Close()
		}
	}
}

// fanoutWriter 依次写入多个输出，单个输出失败不影响其它输出。
//
// 不用 io.MultiWriter：它在首个 writer 返回错误时会立即返回，
// 若容器 stdout 管道异常，文件日志会被一并跳过；日志系统不应因此丢失落盘记录。
type fanoutWriter struct{ writers []io.Writer }

func (f fanoutWriter) Write(p []byte) (int, error) {
	for _, w := range f.writers {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func current() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return logger
}

// Debug 输出调试日志。
func Debug(component, msg string, kv ...any) {
	current().Debug(msg, withComponent(component, kv)...)
}

// Info 输出信息日志。
func Info(component, msg string, kv ...any) {
	current().Info(msg, withComponent(component, kv)...)
}

// Warn 输出告警日志。
func Warn(component, msg string, kv ...any) {
	current().Warn(msg, withComponent(component, kv)...)
}

// Error 输出错误日志。
func Error(component, msg string, kv ...any) {
	current().Error(msg, withComponent(component, kv)...)
}

func withComponent(component string, kv []any) []any {
	args := make([]any, 0, len(kv)+2)
	args = append(args, "component", component)
	return append(args, kv...)
}

// textHandler 复刻 Java 版 logback 的行格式：
//
//	2026-10-23 12:00:00.123 [组件] INFO  org.open.scdm.common.ssh.Logf - 消息
//
// 线程名位置用组件名替代（Go 无线程概念）。
type textHandler struct {
	mu    sync.Mutex
	out   io.Writer
	level slog.Level
	attrs []slog.Attr
}

func (h *textHandler) Enabled(_ context.Context, lv slog.Level) bool {
	return lv >= h.level
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &textHandler{out: h.out, level: h.level, attrs: merged}
}

func (h *textHandler) WithGroup(string) slog.Handler { return h }

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	component := "main"
	var extras []slog.Attr
	collect := func(a slog.Attr) bool {
		if a.Key == "component" {
			component = a.Value.String()
			return true
		}
		extras = append(extras, a)
		return true
	}
	for _, a := range h.attrs {
		collect(a)
	}
	r.Attrs(collect)

	var b strings.Builder
	b.WriteString(r.Time.Format("2006-01-02 15:04:05.000"))
	b.WriteString(" [")
	b.WriteString(component)
	b.WriteString("] ")
	b.WriteString(fmt.Sprintf("%-5s", r.Level.String()))
	b.WriteString(" ")
	b.WriteString(loggerName)
	b.WriteString(" - ")
	b.WriteString(r.Message)
	for _, a := range extras {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
	}
	b.WriteString("\n")

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, b.String())
	return err
}
