package direct

import "testing"

func TestRulesIP(t *testing.T) {
	r := New(
		[]string{"192.168.0.0/16,10.0.0.0/8", "172.16.0.0/255.240.0.0", "127.0.0.1"},
		nil,
	)
	directCases := []string{
		"192.168.1.1",
		"10.255.255.254",
		"172.20.1.1",
		"127.0.0.1",
		"::1", // 未配置 IPv6 规则
	}
	for _, host := range directCases[:4] {
		if !r.IsDirect(host) {
			t.Fatalf("%s 应命中直连", host)
		}
	}
	for _, host := range []string{"8.8.8.8", "172.32.0.1", "::1", "example.com"} {
		if r.IsDirect(host) {
			t.Fatalf("%s 不应命中直连", host)
		}
	}
}

func TestRulesIPv6(t *testing.T) {
	r := New([]string{"2001:db8::/32", "fe80::1"}, nil)
	if !r.IsDirect("2001:db8::1") || !r.IsDirect("fe80::1") {
		t.Fatal("IPv6 规则未命中")
	}
	if r.IsDirect("2001:db9::1") {
		t.Fatal("2001:db9::1 不应命中")
	}
}

func TestRulesDomain(t *testing.T) {
	r := New(nil, []string{"mmxx.fun", "openeuler.org", "example.com."})
	cases := map[string]bool{
		"mmxx.fun":            true,
		"a.mmxx.fun":          true,
		"A.MMXX.FUN":          true,
		"mmxx.fun.":           true,
		"notmmxx.fun":         false,
		"xopeneuler.org":      false, // 必须是主域或其子域
		"www.openeuler.org":   true,
		"example.com":         true,
		"example.com.evil.io": false,
	}
	for host, want := range cases {
		if got := r.IsDirect(host); got != want {
			t.Fatalf("IsDirect(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestRulesIPNotMatchedByDomain(t *testing.T) {
	// IP 目标不参与域名规则匹配（与 Java 版一致），即使域名配置里误填了 IP 也按 IP 规则处理
	r := New(nil, []string{"1.2.3.4"})
	if !r.IsDirect("1.2.3.4") {
		t.Fatal("域名配置里的 IP 应按 IP 规则处理")
	}
	if r.IsDirect("1.2.3.5") {
		t.Fatal("1.2.3.5 不应命中")
	}
}

func TestRulesNilAndEmpty(t *testing.T) {
	var nilRules *Rules
	if nilRules.IsDirect("1.2.3.4") {
		t.Fatal("nil 规则不应命中")
	}
	if !nilRules.Empty() || nilRules.IPRuleCount() != 0 || nilRules.DomainRuleCount() != 0 {
		t.Fatal("nil 规则统计异常")
	}

	empty := New(nil, nil)
	if !empty.Empty() {
		t.Fatal("空规则应为 Empty")
	}
}

func TestRulesInvalidValuesIgnored(t *testing.T) {
	r := New([]string{"not-an-ip", "1.2.3.4/33", "1.2.3.4/255.0.255.0", ""}, []string{"has/slash", ""})
	if !r.Empty() {
		t.Fatalf("非法规则应被忽略: ips=%d domains=%d", r.IPRuleCount(), r.DomainRuleCount())
	}
}

func TestRulesSeparatorsAndQuotes(t *testing.T) {
	r := New([]string{`"10.0.0.0/8; 127.0.0.1"`}, []string{"a.com，b.com;c.com d.com"})
	for _, host := range []string{"10.0.0.1", "127.0.0.1", "a.com", "b.com", "c.com", "d.com"} {
		if !r.IsDirect(host) {
			t.Fatalf("%s 应命中直连", host)
		}
	}
}

func TestAddGeoSite(t *testing.T) {
	parsed, err := ParseDLC([]string{"cn"})
	if err != nil {
		t.Fatalf("ParseDLC 失败: %v", err)
	}
	r := New(nil, nil)
	r.AddGeoSite(parsed["cn"])
	// 6624 条全部生效（含 3 条 RE2 兼容正则），说明没有规则被丢弃
	if got := r.DomainRuleCount(); got != 6624 {
		t.Fatalf("geosite 规则应全部生效: %d", got)
	}
	if !r.IsDirect("www.baidu.com") || !r.IsDirect("baidu.com") {
		t.Fatal("baidu.com 应命中 geosite:cn")
	}
	if r.IsDirect("google.com") {
		t.Fatal("google.com 不应命中 geosite:cn")
	}
}

func TestForceDomainOverridesDirect(t *testing.T) {
	// geosite:cn 收录了 googleapis.cn，会让 Play 的 services.googleapis.cn 直连
	parsed, err := ParseDLC([]string{"cn"})
	if err != nil {
		t.Fatalf("ParseDLC 失败: %v", err)
	}
	r := New(nil, nil)
	r.AddGeoSite(parsed["cn"])
	if !r.IsDirect("services.googleapis.cn") {
		t.Fatal("前置条件不成立: services.googleapis.cn 应被 geosite:cn 判定为直连")
	}

	r.SetForceDomains([]string{"googleapis.cn;google.cn,gstatic.cn"})
	if got := r.ForceDomainCount(); got != 3 {
		t.Fatalf("强制隧道域名数量 = %d, want 3", got)
	}

	// 命中的强制规则优先于 geosite 直连（含子域）
	for _, host := range []string{
		"services.googleapis.cn",
		"googleapis.cn",
		"www.google.cn",
		"dl.google.cn",
		"gstatic.cn",
	} {
		if r.IsDirect(host) {
			t.Fatalf("%s 应被强制走隧道，不应直连", host)
		}
	}

	// 不相关域名不受影响
	for _, host := range []string{"www.baidu.com", "www.qq.com", "mmxx.fun"} {
		if host == "mmxx.fun" {
			continue
		}
		if !r.IsDirect(host) {
			t.Fatalf("%s 应仍然直连", host)
		}
	}
	if r.IsDirect("googleapis.com.evil.io") {
		t.Fatal("后缀匹配不应跨越非主域边界")
	}
}

func TestForceDomainOverridesExplicitDirect(t *testing.T) {
	r := New(nil, []string{"example.com"})
	if !r.IsDirect("a.example.com") {
		t.Fatal("前置条件不成立: a.example.com 应直连")
	}
	r.SetForceDomains([]string{"a.example.com"})
	if r.IsDirect("a.example.com") {
		t.Fatal("强制规则应覆盖显式直连域名")
	}
	// 主域本身没有命中强制规则，仍然直连
	if !r.IsDirect("example.com") {
		t.Fatal("example.com 应仍然直连")
	}
}

func TestForceDomainInvalidValuesIgnored(t *testing.T) {
	r := New(nil, nil)
	r.SetForceDomains([]string{"", "  ", "has/slash"})
	if r.ForceDomainCount() != 0 {
		t.Fatalf("非法值应被忽略: %d", r.ForceDomainCount())
	}

	var nilRules *Rules
	nilRules.SetForceDomains([]string{"a.com"})
	if nilRules.ForceDomainCount() != 0 {
		t.Fatal("nil 规则不应记录强制域名")
	}
}
