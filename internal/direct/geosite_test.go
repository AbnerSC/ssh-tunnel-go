package direct

import "testing"

func TestParseEmbeddedCN(t *testing.T) {
	parsed, err := ParseDLC([]string{"cn"})
	if err != nil {
		t.Fatalf("ParseDLC 失败: %v", err)
	}
	rules, ok := parsed["cn"]
	if !ok {
		t.Fatalf("未解析出 cn 列表, 已解析列表数=%d", len(parsed))
	}
	counts := map[int]int{}
	for _, rule := range rules {
		counts[rule.Type]++
	}
	t.Logf("cn 规则总数=%d domain=%d full=%d regexp=%d keyword=%d",
		len(rules), counts[TypeDomain], counts[TypeFull], counts[TypeRegexp], counts[TypeKeyword])
	if len(rules) != 6624 {
		t.Fatalf("cn 规则数量应为 6624, got %d", len(rules))
	}
}
