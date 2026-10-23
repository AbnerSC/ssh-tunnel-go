package config

import (
	"fmt"
	"strconv"
	"strings"
)

// CopyItem 端口转发项，语义与 Java 版一致：
//   - "目标端口:host:port"（三段冒号写法，目标端口在前）
//   - "host:port-目标端口"（默认写法，目标端口在后）
//
// 其中「目标端口」是本地/服务端监听端口，host:port 是通道对端地址。
type CopyItem struct {
	Host       string
	Port       int
	TargetPort int
}

// ParseCopyItem 解析单个转发配置。
func ParseCopyItem(s string) (CopyItem, error) {
	var item CopyItem
	if parts := strings.Split(s, ":"); len(parts) == 3 {
		target, err := strconv.Atoi(parts[0])
		if err != nil {
			return item, fmt.Errorf("转发配置 %q 的目标端口非法: %w", s, err)
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return item, fmt.Errorf("转发配置 %q 的端口非法: %w", s, err)
		}
		item.TargetPort, item.Host, item.Port = target, parts[1], port
		return item, nil
	}

	dash := strings.Split(s, "-")
	if len(dash) < 2 {
		return item, fmt.Errorf("转发配置 %q 格式应为 host:port-目标端口", s)
	}
	target, err := strconv.Atoi(dash[1])
	if err != nil {
		return item, fmt.Errorf("转发配置 %q 的目标端口非法: %w", s, err)
	}
	hp := strings.Split(dash[0], ":")
	if len(hp) < 2 {
		return item, fmt.Errorf("转发配置 %q 的地址格式应为 host:port", s)
	}
	port, err := strconv.Atoi(hp[1])
	if err != nil {
		return item, fmt.Errorf("转发配置 %q 的端口非法: %w", s, err)
	}
	item.TargetPort, item.Host, item.Port = target, hp[0], port
	return item, nil
}

// String 返回日志展示文本，与 Java 版 toScrpit 输出一致。
func (c CopyItem) String() string {
	return fmt.Sprintf("地址:%s,端口:%d,目标端口:%d", c.Host, c.Port, c.TargetPort)
}
