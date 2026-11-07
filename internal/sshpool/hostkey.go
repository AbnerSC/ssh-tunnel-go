package sshpool

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"ssh-tunnel-go/internal/logging"
)

// defaultKnownHostsFile 未指定时的主机密钥记录文件（相对工作目录）。
//
// 与原 JSch StrictHostKeyChecking=no 的差异：默认改为首次信任(TOFU)。
// 不校验主机密钥时，链路上的中间人（恶意热点、被劫持的云主机、内网攻击者）
// 可以直接接管 SSH 会话并拿到明文密码——巡检时用一份自签主机密钥复现，
// 服务端密钥更换后客户端照旧连上并提交了密码。
const defaultKnownHostsFile = "known_hosts"

// hostKeyStore 维护服务端主机密钥：首次连接写入，之后必须一致；
// 显式配置了指纹时，只接受匹配的指纹。
type hostKeyStore struct {
	path     string
	expected []string // 归一化后的 base64 公钥指纹（SHA256 原文）
	mu       sync.Mutex
}

// newHostKeyStore 创建主机密钥校验器；path 为空表示使用默认文件。
func newHostKeyStore(path string, fingerprints []string) *hostKeyStore {
	if strings.TrimSpace(path) == "" {
		path = defaultKnownHostsFile
	}
	s := &hostKeyStore{path: path}
	for _, f := range fingerprints {
		if v := normalizeFingerprint(f); v != "" {
			s.expected = append(s.expected, v)
		} else if strings.TrimSpace(f) != "" {
			logging.Warn("ssh", "忽略非法的主机密钥指纹", "value", f)
		}
	}
	return s
}

// callback 返回可用于 ssh.ClientConfig 的主机密钥校验回调。
func (s *hostKeyStore) callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if len(s.expected) > 0 {
			for _, want := range s.expected {
				if fp == "SHA256:"+want || strings.TrimPrefix(fp, "SHA256:") == want {
					return nil
				}
			}
			return fmt.Errorf("服务端主机密钥不匹配（收到 %s），已拒绝连接："+
				"可能是中间人攻击，或服务端密钥确实发生变更，请确认后更新 SSH_HOST_KEY", fp)
		}
		return s.trustOnFirstUse(hostname, remote, fp, key)
	}
}

// trustOnFirstUse 首次连接记录指纹，之后要求一致。
func (s *hostKeyStore) trustOnFirstUse(hostname string, remote net.Addr, fp string, key ssh.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	addr := normalizeHostPort(hostname, remote)
	entries, err := s.load()
	if err != nil {
		// 文件不可读时拒绝连接，而不是静默降级为「不校验」：
		// 静默降级会让一次权限问题永久退回到可被中间人的状态
		return fmt.Errorf("读取主机密钥记录文件 %s 失败: %w", s.path, err)
	}
	for _, e := range entries {
		if e.host != addr {
			continue
		}
		if e.fingerprint == fp {
			return nil
		}
		return fmt.Errorf("服务端 %s 的主机密钥已变更（记录 %s，当前 %s），已拒绝连接："+
			"可能是中间人攻击；确认无误后删除 %s 中对应条目或改用 SSH_HOST_KEY 固定指纹",
			addr, e.fingerprint, fp, s.path)
	}

	if err := s.append(addr, fp, key); err != nil {
		return fmt.Errorf("记录主机密钥到 %s 失败: %w", s.path, err)
	}
	logging.Info("ssh", "首次连接，已记录服务端主机密钥", "server", addr, "fingerprint", fp, "file", s.path)
	return nil
}

type knownHostEntry struct {
	host        string
	fingerprint string
}

// load 读取已知主机记录（一行一个：host base64指纹）。
func (s *hostKeyStore) load() ([]knownHostEntry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []knownHostEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, knownHostEntry{host: fields[0], fingerprint: fields[1]})
	}
	return out, nil
}

// append 追加一条记录（“host 指纹”两列），文件权限 0600，便于运维直接比对。
func (s *hostKeyStore) append(host, fingerprint string, key ssh.PublicKey) error {
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s # %s %s\n", host, fingerprint, key.Type(), fingerprint)
	return err
}

// normalizeHostPort 把校验用主机名补齐端口，作为记录文件的键。
func normalizeHostPort(hostname string, remote net.Addr) string {
	if _, _, err := net.SplitHostPort(hostname); err == nil {
		return hostname
	}
	if remote != nil {
		return remote.String()
	}
	return hostname
}

// normalizeFingerprint 把 "SHA256:xxx" 或裸 base64 统一成 base64 形式。
func normalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return ""
	}
	fp = strings.TrimPrefix(fp, "SHA256:")
	// 校验是否为合法 base64（去掉 padding 差异）
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(fp, "="))
	if err != nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(raw)
}
