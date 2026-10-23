package config

import "testing"

func TestParseCopyItem(t *testing.T) {
	cases := []struct {
		in   string
		want CopyItem
	}{
		{"127.0.0.1:80-8080", CopyItem{Host: "127.0.0.1", Port: 80, TargetPort: 8080}},
		{"8080:127.0.0.1:80", CopyItem{Host: "127.0.0.1", Port: 80, TargetPort: 8080}},
		{"example.com:443-6666", CopyItem{Host: "example.com", Port: 443, TargetPort: 6666}},
	}
	for _, c := range cases {
		got, err := ParseCopyItem(c.in)
		if err != nil {
			t.Fatalf("%q 解析失败: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("%q -> %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseCopyItemInvalid(t *testing.T) {
	for _, in := range []string{"", "8080", "abc-8080", "127.0.0.1-8080", "127.0.0.1:abc-8080", "1:2:3:4"} {
		if _, err := ParseCopyItem(in); err == nil {
			t.Fatalf("%q 应解析失败", in)
		}
	}
}

func TestCopyItemString(t *testing.T) {
	item := CopyItem{Host: "127.0.0.1", Port: 80, TargetPort: 8080}
	if got, want := item.String(), "地址:127.0.0.1,端口:80,目标端口:8080"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
