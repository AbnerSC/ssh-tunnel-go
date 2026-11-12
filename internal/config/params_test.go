package config

import (
	"reflect"
	"testing"
	"time"
)

func TestParseParamsSemantics(t *testing.T) {
	p := ParseParams([]string{"-D", "6666", "-server", "root@1.2.3.4", "-direct-cn", "-a", "1", "-a", "2"})

	if !p.Contains("-D") || p.ValueOr("-D", "") != "6666" {
		t.Fatalf("-D 解析错误: %v", p.Values("-D"))
	}
	// 单值取第一个
	if got := p.ValueOr("-a", ""); got != "1" {
		t.Fatalf("-a 单值应取第一个, got %q", got)
	}
	// 同名重复累积
	if got := p.Values("-a"); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Fatalf("-a 累积取值错误: %v", got)
	}
	// 无值开关合法
	if !p.Contains("-direct-cn") || len(p.Values("-direct-cn")) != 0 {
		t.Fatalf("-direct-cn 应存在且无取值")
	}
}

func TestParseParamsKeyEatsSingleValue(t *testing.T) {
	// 一个 key 只消费紧随的一个值，多余 token 忽略（此处有意容错）
	p := ParseParams([]string{"-D", "6666", "orphan", "-p", "22"})
	if got := p.ValueOr("-D", ""); got != "6666" {
		t.Fatalf("-D = %q", got)
	}
	if got := p.ValueOr("-p", ""); got != "22" {
		t.Fatalf("-p = %q", got)
	}
}

func TestParseParamsTrailingSwitch(t *testing.T) {
	p := ParseParams([]string{"-direct-cn"})
	if !p.Contains("-direct-cn") {
		t.Fatal("末尾开关应被记录")
	}
	if _, ok := p.Value("-direct-cn"); ok {
		t.Fatal("末尾开关不应有取值")
	}
}

func TestResolverEnvFirst(t *testing.T) {
	t.Setenv("SOCKS_PORT", "11823")
	r := NewResolver([]string{"-D", "6666"})
	if got := r.Value("-D", "SOCKS_PORT", ""); got != "11823" {
		t.Fatalf("环境变量应优先, got %q", got)
	}
}

func TestResolverArgFallback(t *testing.T) {
	t.Setenv("HTTP_PORT", "") // 空值视为未配置
	r := NewResolver([]string{"-H", "11825"})
	if got := r.Value("-H", "HTTP_PORT", ""); got != "11825" {
		t.Fatalf("环境变量为空时应取命令行, got %q", got)
	}
}

func TestResolverValuesMerge(t *testing.T) {
	t.Setenv("DIRECT_IP", "10.0.0.0/8")
	r := NewResolver([]string{"-direct-ip", "192.168.0.0/16", "-direct-ip", "127.0.0.1"})
	got := r.Values("-direct-ip", "DIRECT_IP")
	want := []string{"10.0.0.0/8", "192.168.0.0/16", "127.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("列表参数应合并: got %v want %v", got, want)
	}
}

func TestResolverInt(t *testing.T) {
	r := NewResolver([]string{"-p"})
	if _, err := r.Int("-p", "SSH_PORT", 22); err == nil {
		t.Fatal("缺少取值应报错")
	}

	r = NewResolver([]string{"-p", "abc"})
	if _, err := r.Int("-p", "SSH_PORT", 22); err == nil {
		t.Fatal("非法取值应报错")
	}

	r = NewResolver(nil)
	if got, err := r.Int("-p", "SSH_PORT", 22); err != nil || got != 22 {
		t.Fatalf("默认值应为 22, got %d err %v", got, err)
	}
}

func TestResolverDuration(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want time.Duration
	}{
		{"Go 时长写法", "30m", 30 * time.Minute},
		{"纯数字按秒", "1800", 30 * time.Minute},
		{"零表示关闭", "0", 0},
		{"off 表示关闭", "off", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("IDLE_TIMEOUT", c.val)
			got, err := NewResolver(nil).Duration("-idle-timeout", "IDLE_TIMEOUT", time.Hour)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if got != c.want {
				t.Fatalf("%s 应解析为 %v, got %v", c.val, c.want, got)
			}
		})
	}

	// 未配置时取默认值
	t.Setenv("IDLE_TIMEOUT", "")
	if got, err := NewResolver(nil).Duration("-idle-timeout", "IDLE_TIMEOUT", time.Hour); err != nil || got != time.Hour {
		t.Fatalf("未配置时应取默认值, got %v err %v", got, err)
	}

	// 非法取值不能静默回退默认值，否则运维以为改了实际没生效
	for _, bad := range []string{"abc", "-5", "30x"} {
		t.Setenv("IDLE_TIMEOUT", bad)
		if _, err := NewResolver(nil).Duration("-idle-timeout", "IDLE_TIMEOUT", time.Hour); err == nil {
			t.Fatalf("%q 应报错", bad)
		}
	}

	// 参数出现但没有取值
	t.Setenv("IDLE_TIMEOUT", "")
	if _, err := NewResolver([]string{"-idle-timeout"}).Duration("-idle-timeout", "IDLE_TIMEOUT", time.Hour); err == nil {
		t.Fatal("缺取值应报错")
	}
}
