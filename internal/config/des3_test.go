package config

import "testing"

// 黄金向量由 Java 版 DES3Util 对 "pwd123" 连续加密生成，用于保证跨语言兼容。
var javaGoldenLayers = []string{
	"fDnKijmNTEg=",
	"61acKR064/atYn3kO/4jCQ==",
	"GNed2rSe8eNAXpGhEP/PFgHrteLtdIVOiZFZ/fzo9Is=",
	"3/dxMfrDPG9PjSCuvRU2fjQscj8NmDX96ZTGpvu2kZH4aqStb+nfn5WVzAmTvTIe",
}

func TestEncryptMatchesJava(t *testing.T) {
	current := "pwd123"
	for i, want := range javaGoldenLayers {
		got, err := EncryptOnce(current, cypherKey)
		if err != nil {
			t.Fatalf("第 %d 层加密失败: %v", i+1, err)
		}
		if got != want {
			t.Fatalf("第 %d 层密文不一致: got %q want %q", i+1, got, want)
		}
		current = got
	}
}

func TestEncryptLayers(t *testing.T) {
	got, err := EncryptLayers("pwd123", MaxCipherLayers)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if want := javaGoldenLayers[MaxCipherLayers-1]; got != want {
		t.Fatalf("4 层加密结果不一致: got %q want %q", got, want)
	}
}

func TestDecryptLayers(t *testing.T) {
	if got := DecryptLayers(javaGoldenLayers[3], MaxCipherLayers); got != "pwd123" {
		t.Fatalf("4 层解密失败: %q", got)
	}
	// 部分加密（1 层）也能解开：Java 版最多解 4 层，失败即停
	if got := DecryptLayers(javaGoldenLayers[0], MaxCipherLayers); got != "pwd123" {
		t.Fatalf("1 层解密失败: %q", got)
	}
}

func TestDecryptLayersKeepsPlaintext(t *testing.T) {
	// 明文第一次解密即失败，原样保留（对应 Java 版 catch 后 return）
	if got := DecryptLayers("pwd123", MaxCipherLayers); got != "pwd123" {
		t.Fatalf("明文不应被改动: %q", got)
	}
	if got := DecryptLayers("含中文!@#$", MaxCipherLayers); got != "含中文!@#$" {
		t.Fatalf("含特殊字符的明文不应被改动: %q", got)
	}
}

func TestDecryptOnceRejectsGarbage(t *testing.T) {
	cases := []string{"", "not-base64!!", "YWJj", javaGoldenLayers[0][:8]}
	for _, c := range cases {
		if _, err := DecryptOnce(c, cypherKey); err == nil {
			t.Fatalf("%q 应解密失败", c)
		}
	}
}

func TestNormalizeKey(t *testing.T) {
	key, err := normalizeKey("short")
	if err != nil {
		t.Fatalf("短密钥应补齐: %v", err)
	}
	if len(key) != 24 || string(key[:5]) != "short" {
		t.Fatalf("补齐结果错误: %v", key)
	}
	if _, err := normalizeKey("1234567890123456789012345"); err == nil {
		t.Fatal("超长密钥应报错")
	}
}
