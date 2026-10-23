package console

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

var reader = bufio.NewReader(os.Stdin)

// Fill 返回已配置的值；缺省时在终端上提示输入（密码不回显）。
//
// 非终端环境（容器默认）直接返回缺省值，不读取 stdin，避免阻塞启动。
func Fill(tip, def string, hide bool) string {
	if strings.TrimSpace(def) != "" {
		return def
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return def
	}
	for {
		fmt.Print(tip)
		if hide {
			data, err := term.ReadPassword(fd)
			fmt.Println()
			if err != nil {
				return def
			}
			if line := string(data); strings.TrimSpace(line) != "" {
				return line
			}
			continue
		}
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return def
		}
		line = strings.TrimRight(line, "\r\n")
		if err == io.EOF {
			return def
		}
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
}
