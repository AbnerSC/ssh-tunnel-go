package config

import (
	"reflect"
	"testing"
)

func TestParseParamsJavaSemantics(t *testing.T) {
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
	// 一个 key 只消费紧随的一个值，多余 token 忽略（Java 版会抛 NPE，此处有意容错）
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
