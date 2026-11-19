package tun

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// binaryName 运行阶段统一的可执行文件名。
//
// Docker 镜像构建时按目标架构只把 core/sing-box-<arch> 拷入镜像并重命名为
// 该名称，程序只按固定文件名查找，不再按 CPU 架构选择二进制。
const binaryName = "singbox"

// binaryPathHook 允许测试注入假 sing-box；生产环境始终查找程序目录下的 singbox。
var binaryPathHook func() (string, error)

// resolveSingBox 返回本次运行使用的 sing-box 可执行文件路径。
func resolveSingBox() (string, error) {
	if binaryPathHook != nil {
		return binaryPathHook()
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取程序路径失败，无法定位 %s: %w", binaryName, err)
	}
	return locateSingBox(exe)
}

// locateSingBox 在程序所在目录查找统一命名的 sing-box，未命中时回退 PATH。
//
// 容器镜像把 singbox 与 ssh-tunnel 放在同一目录（/app/singbox），
// 解压后的发布包同样按同目录放置即可，常规部署无需额外配置。
func locateSingBox(exe string) (string, error) {
	// 通过软链接启动时按真实路径所在目录查找，避免链接所在目录缺少 singbox
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	path := filepath.Join(filepath.Dir(exe), binaryName)
	if isExecutableFile(path) {
		return path, nil
	}
	if found, err := exec.LookPath(binaryName); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("未找到 sing-box（%s）：请将 %s 放在程序同目录，或安装到 PATH；TUN 模式要求 sing-box >= %d.%d",
		path, binaryName, MinMajorVersion, MinMinorVersion)
}

// isExecutableFile 判断路径是否为可执行普通文件。
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}
