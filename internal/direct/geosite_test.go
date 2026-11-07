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
	// 只锁定量级：具体条数随 dlc.dat 上游 release 变化，写死会让每次更新都打坏这个用例
	if len(rules) < 6000 {
		t.Fatalf("cn 规则数量异常偏少，怀疑内嵌数据损坏或解析丢规则: %d", len(rules))
	}
	// 分类求和必须等于总数，顺带守住规则类型集合（出现类型外的规则说明解析有问题）
	if sum := counts[TypeDomain] + counts[TypeFull] + counts[TypeRegexp] + counts[TypeKeyword]; sum != len(rules) {
		t.Fatalf("规则分类求和与总数不一致，存在未知类型: 总数=%d 求和=%d", len(rules), sum)
	}
}
