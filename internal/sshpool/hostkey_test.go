package sshpool

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestHostKey 生成一把一次性主机密钥，用于模拟服务端与中间人。
func newTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成主机密钥失败: %v", err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("封装主机公钥失败: %v", err)
	}
	return key
}

// TestHostKeyTOFU 首次信任后必须锁死指纹，密钥变更即拒绝。
//
// 旧实现用 ssh.InsecureIgnoreHostKey()，链路上的中间人换一把自签主机密钥
// 就能接管会话并拿到明文密码（巡检时用自签密钥复现成功）。
func TestHostKeyTOFU(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	store := newHostKeyStore(path, nil)
	cb := store.callback()
	remote := &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 22}

	key1 := newTestHostKey(t)
	if err := cb("10.1.2.3:22", remote, key1); err != nil {
		t.Fatalf("首次连接应信任并记录: %v", err)
	}
	if err := cb("10.1.2.3:22", remote, key1); err != nil {
		t.Fatalf("相同主机密钥应通过: %v", err)
	}

	// 服务端密钥变更（等同于中间人换密钥）必须拒绝
	err := cb("10.1.2.3:22", remote, newTestHostKey(t))
	if err == nil {
		t.Fatal("主机密钥变更必须拒绝连接")
	}
	if !strings.Contains(err.Error(), "主机密钥已变更") {
		t.Fatalf("错误信息应说明密钥变更: %v", err)
	}

	// 记录文件不能对同组用户可读：文件里是服务端指纹，泄露后便于定向伪造
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("记录文件未创建: %v", statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("记录文件权限应为 0600，实际 %o", perm)
		}
	}
}

// TestHostKeyPinnedFingerprint 显式固定指纹时只接受匹配项，且不依赖记录文件。
func TestHostKeyPinnedFingerprint(t *testing.T) {
	key1 := newTestHostKey(t)
	fp := ssh.FingerprintSHA256(key1)
	store := newHostKeyStore(filepath.Join(t.TempDir(), "known_hosts"), []string{fp})
	cb := store.callback()

	if err := cb("example.com:22", nil, key1); err != nil {
		t.Fatalf("匹配的指纹应通过: %v", err)
	}
	if err := cb("example.com:22", nil, newTestHostKey(t)); err == nil {
		t.Fatal("不匹配的指纹必须拒绝")
	}
}

// TestNormalizeFingerprint 兼容 "SHA256:xxx" 与裸 base64 两种写法。
func TestNormalizeFingerprint(t *testing.T) {
	key := newTestHostKey(t)
	withPrefix := ssh.FingerprintSHA256(key)
	bare := strings.TrimPrefix(withPrefix, "SHA256:")

	if got, want := normalizeFingerprint(withPrefix), normalizeFingerprint(bare); got != want {
		t.Fatalf("两种写法应归一化一致: %q vs %q", got, want)
	}
	for _, bad := range []string{"", "   ", "not base64!!", "SHA256:"} {
		if normalizeFingerprint(bad) != "" {
			t.Fatalf("非法指纹应返回空: %q", bad)
		}
	}
}
