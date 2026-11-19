package tun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestFile 在指定路径写入文件并设置权限。
func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
}

// TestResolveSingBoxHook 测试钩子优先于真实查找。
func TestResolveSingBoxHook(t *testing.T) {
	binaryPathHook = func() (string, error) { return "/tmp/fake-sing-box", nil }
	t.Cleanup(func() { binaryPathHook = nil })

	path, err := resolveSingBox()
	if err != nil || path != "/tmp/fake-sing-box" {
		t.Fatalf("钩子路径未生效: %q %v", path, err)
	}
}

// TestLocateSingBoxBesideExecutable 程序同目录存在可执行的 singbox 时直接使用，
// 文件名固定，不再按 CPU 架构区分。
func TestLocateSingBoxBesideExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ssh-tunnel")
	writeTestFile(t, exe, "exe", 0o755)
	want := filepath.Join(dir, binaryName)
	writeTestFile(t, want, "singbox", 0o755)

	got, err := locateSingBox(exe)
	if err != nil || got != want {
		t.Fatalf("应使用程序目录下的 %s: %q %v", binaryName, got, err)
	}
}

// TestLocateSingBoxIgnoresNonExecutable 同目录的普通文件（无执行位）不能当成 sing-box 使用。
func TestLocateSingBoxIgnoresNonExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ssh-tunnel")
	writeTestFile(t, exe, "exe", 0o755)
	writeTestFile(t, filepath.Join(dir, binaryName), "plain", 0o644)
	t.Setenv("PATH", t.TempDir())

	if _, err := locateSingBox(exe); err == nil {
		t.Fatal("无执行位的文件不应被采用")
	}
}

// TestLocateSingBoxFallsBackToPath 同目录未命中时回退 PATH 查找。
func TestLocateSingBoxFallsBackToPath(t *testing.T) {
	exeDir := t.TempDir()
	exe := filepath.Join(exeDir, "ssh-tunnel")
	writeTestFile(t, exe, "exe", 0o755)
	pathDir := t.TempDir()
	want := filepath.Join(pathDir, binaryName)
	writeTestFile(t, want, "singbox", 0o755)
	t.Setenv("PATH", pathDir)

	got, err := locateSingBox(exe)
	if err != nil || got != want {
		t.Fatalf("应回退 PATH 查找: %q %v", got, err)
	}
}

// TestLocateSingBoxNotFound 同目录与 PATH 均未命中时返回可诊断错误。
func TestLocateSingBoxNotFound(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ssh-tunnel")
	writeTestFile(t, exe, "exe", 0o755)
	t.Setenv("PATH", t.TempDir())

	_, err := locateSingBox(exe)
	if err == nil || !strings.Contains(err.Error(), binaryName) {
		t.Fatalf("未找到时应返回明确错误: %v", err)
	}
}
