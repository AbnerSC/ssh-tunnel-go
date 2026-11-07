package config

import "testing"

// 黄金向量为对 "pwd123" 逐层连续 DES3 加密生成的结果，用于校验加密实现。
var goldenLayers = []string{
	"fDnKijmNTEg=",
	"61acKR064/atYn3kO/4jCQ==",
	"GNed2rSe8eNAXpGhEP/PFgHrteLtdIVOiZFZ/fzo9Is=",
	"3/dxMfrDPG9PjSCuvRU2fjQscj8NmDX96ZTGpvu2kZH4aqStb+nfn5WVzAmTvTIe",
}

func TestEncryptOnceLayers(t *testing.T) {
	current := "pwd123"
	for i, want := range goldenLayers {
		got, err := EncryptOnce(current, defaultCypherKey)
		if err != nil {
			t.Fatalf("第 %d 层加密失败: %v", i+1, err)
		}
		if got != want {
			t.Fatalf("第 %d 层密文不一致: got %q want %q", i+1, got, want)
		}
		current = got
	}
}

// TestMasterKeyDefaultFallback 未设置 CIPHER_MASTER_KEY（或只有空白）时回退到内置默认密钥。
func TestMasterKeyDefaultFallback(t *testing.T) {
	t.Setenv("CIPHER_MASTER_KEY", "")
	if got := masterKey(); got != defaultCypherKey {
		t.Fatalf("空环境变量应回退默认密钥: %q", got)
	}
	t.Setenv("CIPHER_MASTER_KEY", "   ")
	if got := masterKey(); got != defaultCypherKey {
		t.Fatalf("空白环境变量应回退默认密钥: %q", got)
	}
}

// TestMasterKeyFromEnv 设置 CIPHER_MASTER_KEY 后，加解密都应使用注入的密钥；
// 用默认密钥加密的旧密文在注入自定义密钥后解不开，明文则原样保留。
func TestMasterKeyFromEnv(t *testing.T) {
	t.Setenv("CIPHER_MASTER_KEY", "myCustomKey1234567890!")
	if got := masterKey(); got != "myCustomKey1234567890!" {
		t.Fatalf("环境变量未生效: %q", got)
	}

	enc, err := EncryptLayers("pwd123", MaxCipherLayers)
	if err != nil {
		t.Fatalf("自定义密钥加密失败: %v", err)
	}
	if got := DecryptLayers(enc, MaxCipherLayers); got != "pwd123" {
		t.Fatalf("同一自定义密钥往返失败: %q", got)
	}
	if enc == goldenLayers[MaxCipherLayers-1] {
		t.Fatal("自定义密钥的密文不应与默认密钥相同")
	}
	// 默认密钥密文在自定义密钥下解不开，解密失败即原样保留
	if got := DecryptLayers(goldenLayers[MaxCipherLayers-1], MaxCipherLayers); got != goldenLayers[MaxCipherLayers-1] {
		t.Fatalf("默认密钥密文在自定义密钥下应原样保留: %q", got)
	}
	// 首尾空白不参与密钥内容，应被修剪后使用
	t.Setenv("CIPHER_MASTER_KEY", "  myCustomKey1234567890!  ")
	if got := DecryptLayers(enc, MaxCipherLayers); got != "pwd123" {
		t.Fatalf("带空白的同一密钥应仍可解密: %q", got)
	}
}

func TestEncryptLayers(t *testing.T) {
	got, err := EncryptLayers("pwd123", MaxCipherLayers)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if want := goldenLayers[MaxCipherLayers-1]; got != want {
		t.Fatalf("4 层加密结果不一致: got %q want %q", got, want)
	}
}

func TestDecryptLayers(t *testing.T) {
	if got := DecryptLayers(goldenLayers[3], MaxCipherLayers); got != "pwd123" {
		t.Fatalf("4 层解密失败: %q", got)
	}
	// 部分加密（1 层）也能解开：最多解 4 层，失败即停
	if got := DecryptLayers(goldenLayers[0], MaxCipherLayers); got != "pwd123" {
		t.Fatalf("1 层解密失败: %q", got)
	}
}

func TestDecryptLayersKeepsPlaintext(t *testing.T) {
	// 明文第一次解密即失败，原样保留
	if got := DecryptLayers("pwd123", MaxCipherLayers); got != "pwd123" {
		t.Fatalf("明文不应被改动: %q", got)
	}
	if got := DecryptLayers("含中文!@#$", MaxCipherLayers); got != "含中文!@#$" {
		t.Fatalf("含特殊字符的明文不应被改动: %q", got)
	}
}

func TestDecryptOnceRejectsGarbage(t *testing.T) {
	cases := []string{"", "not-base64!!", "YWJj", goldenLayers[0][:8]}
	for _, c := range cases {
		if _, err := DecryptOnce(c, defaultCypherKey); err == nil {
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
