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

// TestDurationAttrIsHumanReadable 时长字段必须输出可读字符串。
//
// time.Duration 直接交给 JSON handler 会被序列成纳秒整数
// （实测 "elapsed":2509000000），排查耗时分布与超时时几乎无法阅读。
func TestDurationAttrIsHumanReadable(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	lg.Debug("直连域名解析完成", withComponent("proxy", []any{
		"host", "www.baidu.com",
		"elapsed", 2509 * time.Millisecond,
	})...)
	out := buf.String()
	if !strings.Contains(out, `"elapsed":"2.509s"`) {
		t.Fatalf("时长应输出为 2.509s: %s", out)
	}
	if strings.Contains(out, "2509000000") {
		t.Fatalf("不应输出纳秒整数: %s", out)
	}

	buf.Reset()
	th := &textHandler{out: &buf, level: slog.LevelDebug}
	slog.New(th).Debug("耗时", withComponent("main", []any{"idleTimeout", 30 * time.Minute})...)
	if !strings.Contains(buf.String(), "idleTimeout=30m0s") {
		t.Fatalf("文本格式同样应可读: %q", buf.String())
	}
}
