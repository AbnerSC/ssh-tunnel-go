package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestSanitizeValue 控制字符必须转义，避免客户端可控内容伪造整行日志。
func TestSanitizeValue(t *testing.T) {
	cases := map[string]string{
		"normal":          "normal",
		"evil\nfake line": `evil\nfake line`,
		"cr\rcr":          `cr\rcr`,
		"tab\there":       `tab\there`,
		"nul\x00bell\x07": `nul\x00bell\x07`,
		"中文\n伪造":          `中文\n伪造`,
	}
	for in, want := range cases {
		if got := sanitizeValue(in); got != want {
			t.Fatalf("sanitizeValue(%q) = %q, want %q", in, got, want)
		}
	}

	long := strings.Repeat("A", sanitizeMaxLen+50)
	if got := sanitizeValue(long); !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("超长内容应被截断: %q", got[len(got)-20:])
	}
}

// TestTextHandlerEscapesInjectedNewline 文本模式下带换行的字段值不能新增日志行。
//
// 旧实现逐字段拼接且不清洗，认证用户名里的换行可以把一条伪造的
// 「管理员登录成功」整行塞进日志（巡检时已复现）。
func TestTextHandlerEscapesInjectedNewline(t *testing.T) {
	var buf bytes.Buffer
	h := &textHandler{out: &buf, level: slog.LevelDebug}
	rec := slog.NewRecord(time.Now(), slog.LevelWarn, "代理认证不通过", 0)
	rec.AddAttrs(
		slog.String("component", "socks5"),
		slog.String("user", "evil\n2026-10-30 00:00:00.000 [auth] INFO  fake - 管理员登录成功"),
	)
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatalf("写日志失败: %v", err)
	}

	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("只应产生一行日志（含结尾换行），实际 %d 行: %q", n, out)
	}
	if !strings.Contains(out, `user=evil\n2026`) {
		t.Fatalf("换行符应被转义为可见形式: %q", out)
	}
}
