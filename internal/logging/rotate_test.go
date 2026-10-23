package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return string(data)
}

func TestRotatorWriteAndRotate(t *testing.T) {
	dir := t.TempDir()
	// maxDays 取足够大，避免模拟跨天时归档被当作过期文件清理
	r, err := NewRotator(dir, 36500, 1<<20)
	if err != nil {
		t.Fatalf("创建 Rotator 失败: %v", err)
	}

	if _, err := r.Write([]byte("line1\n")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// 模拟跨天：把内部日期改成 2000-01-02，下一次写入应触发归档
	r.day = "2000-01-02"
	if _, err := r.Write([]byte("line2\n")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	if got := readFile(t, filepath.Join(dir, "ssh-tunnel.2000-01-02.log")); got != "line1\n" {
		t.Fatalf("归档内容错误: %q", got)
	}
	if got := readFile(t, filepath.Join(dir, logFileName)); got != "line2\n" {
		t.Fatalf("当前文件内容错误: %q", got)
	}
}

// TestRotatorFlushesWithoutFurtherWrites 验证日志不依赖后续写入也会落盘。
//
// 高并发降噪后压测期间几乎没有日志，若只在 Write 时按时间 flush，
// 启动日志会一直留在缓冲里，tail -f 看不到，异常退出即丢失。
func TestRotatorFlushesWithoutFurtherWrites(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRotator(dir, 30, 1<<30)
	if err != nil {
		t.Fatalf("创建 Rotator 失败: %v", err)
	}
	defer r.Close()

	if _, err := r.Write([]byte("startup\n")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	path := filepath.Join(dir, logFileName)
	deadline := time.Now().Add(3 * flushInterval)
	for time.Now().Before(deadline) {
		if data, _ := os.ReadFile(path); strings.Contains(string(data), "startup") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("写入后 %v 内未落盘", 3*flushInterval)
}

func TestRotatorCleansOldArchives(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "ssh-tunnel.2000-01-01.log")
	recentPath := filepath.Join(dir, "ssh-tunnel."+time.Now().AddDate(0, 0, -1).Format("2006-01-02")+".log")
	unrelatedPath := filepath.Join(dir, "other.log")
	for _, p := range []string{oldPath, recentPath, unrelatedPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("准备归档文件失败: %v", err)
		}
	}

	r, err := NewRotator(dir, 30, 1<<30)
	if err != nil {
		t.Fatalf("创建 Rotator 失败: %v", err)
	}
	defer r.Close()

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatal("超过 30 天的归档应被删除")
	}
	if _, err := os.Stat(recentPath); err != nil {
		t.Fatalf("近期归档不应被删除: %v", err)
	}
	if _, err := os.Stat(unrelatedPath); err != nil {
		t.Fatalf("非归档文件不应被删除: %v", err)
	}
}

func TestRotatorSizeCap(t *testing.T) {
	dir := t.TempDir()
	// 三个归档各 100 字节，上限 150 字节：应从最旧的开始删，只保留最新的一个
	dates := make([]string, 0, 3)
	for i := 3; i >= 1; i-- {
		date := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		dates = append(dates, date)
		if err := os.WriteFile(filepath.Join(dir, "ssh-tunnel."+date+".log"),
			bytes.Repeat([]byte("a"), 100), 0o644); err != nil {
			t.Fatalf("准备归档文件失败: %v", err)
		}
	}

	r, err := NewRotator(dir, 30, 150)
	if err != nil {
		t.Fatalf("创建 Rotator 失败: %v", err)
	}
	defer r.Close()

	for i, date := range dates {
		_, statErr := os.Stat(filepath.Join(dir, "ssh-tunnel."+date+".log"))
		if i == len(dates)-1 {
			if statErr != nil {
				t.Fatalf("最新归档应保留: %v", statErr)
			}
		} else if !os.IsNotExist(statErr) {
			t.Fatalf("超出总量上限的旧归档 %s 应被删除", date)
		}
	}
}

func TestTextHandlerFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(&textHandler{out: &buf, level: slog.LevelInfo})
	logger.Info("收到连接请求", "component", "socks5", "remote", "1.2.3.4:5678")

	line := buf.String()
	if !strings.Contains(line, " [socks5] INFO  org.open.scdm.common.ssh.Logf - 收到连接请求 remote=1.2.3.4:5678") {
		t.Fatalf("文本日志格式不符合 Java 版: %q", line)
	}
	if len(line) < 24 || line[4] != '-' || line[10] != ' ' || line[19] != '.' {
		t.Fatalf("时间戳格式错误: %q", line)
	}
}

func TestTextHandlerLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(&textHandler{out: &buf, level: slog.LevelWarn})
	logger.Info("不应输出", "component", "main")
	if buf.Len() != 0 {
		t.Fatalf("INFO 应被过滤: %q", buf.String())
	}
	logger.Warn("应输出", "component", "main")
	if buf.Len() == 0 {
		t.Fatal("WARN 应输出")
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"DEBUG":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"unknown": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Fatalf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
