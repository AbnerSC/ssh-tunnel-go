package config

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// 密码支持明文或最多 4 层 DES3 加密。
// defaultCypherKey 作为未注入主密钥时的回退值，保证开箱体验可用；
// 部署时可通过环境变量 CIPHER_MASTER_KEY 注入自定义主密钥，使源码中的默认值不再参与加解密。
const (
	defaultCypherKey = "sshCopy4rfv^UGUIYOYR^UIO"
	cipherIV         = "01234567"
	// masterKeyEnv 主密钥环境变量名；-encode 与运行时解密都读取它，
	// 两侧必须使用同一个值，否则密文无法解开
	masterKeyEnv = "CIPHER_MASTER_KEY"
	// MaxCipherLayers -encode 与运行时解密的最大层数
	MaxCipherLayers = 4
)

// masterKey 返回当前生效的 DES3 主密钥。
// CIPHER_MASTER_KEY 已设置且非空白时使用注入值，否则回退到内置默认密钥。
func masterKey() string {
	if v, ok := envLookup(masterKeyEnv); ok {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return defaultCypherKey
}

var (
	errKeyLength  = errors.New("DES3 密钥长度非法")
	errCipherData = errors.New("DES3 密文非法")
)

// EncryptOnce 加密一层（DESede/CBC/PKCS5Padding + Base64）。
func EncryptOnce(plain, secretKey string) (string, error) {
	key, err := normalizeKey(secretKey)
	if err != nil {
		return "", err
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	data := pkcs7Pad([]byte(plain), block.BlockSize())
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, []byte(cipherIV)).CryptBlocks(out, data)
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptOnce 解密一层。
func DecryptOnce(encryptText, secretKey string) (string, error) {
	key, err := normalizeKey(secretKey)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encryptText)
	if err != nil {
		return "", errCipherData
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 || len(raw)%block.BlockSize() != 0 {
		return "", errCipherData
	}
	out := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, []byte(cipherIV)).CryptBlocks(out, raw)
	out, err = pkcs7Unpad(out, block.BlockSize())
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// EncryptLayers 连续加密 layers 层，用于 -encode；密钥取当前生效的主密钥。
func EncryptLayers(plain string, layers int) (string, error) {
	key := masterKey()
	var err error
	for i := 0; i < layers; i++ {
		plain, err = EncryptOnce(plain, key)
		if err != nil {
			return "", err
		}
	}
	return plain, nil
}

// DecryptLayers 最多解密 layers 层，任何一层失败即停止并返回已解密结果。
// 明文密码在第一次解密失败时原样保留。
func DecryptLayers(encryptText string, layers int) string {
	key := masterKey()
	current := encryptText
	for i := 0; i < layers; i++ {
		next, err := DecryptOnce(current, key)
		if err != nil {
			return current
		}
		current = next
	}
	return current
}

// normalizeKey 归一化密钥：不足 24 字节用 '0' 补齐，超过则报错。
func normalizeKey(secretKey string) ([]byte, error) {
	if len(secretKey) > 24 {
		return nil, errKeyLength
	}
	if len(secretKey) < 24 {
		var buf bytes.Buffer
		buf.WriteString(secretKey)
		for i := len(secretKey); i < 24; i++ {
			buf.WriteByte('0')
		}
		return buf.Bytes(), nil
	}
	return []byte(secretKey), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errCipherData
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errCipherData
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("%w: 填充字节不一致", errCipherData)
		}
	}
	return data[:len(data)-pad], nil
}
