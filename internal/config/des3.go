package config

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"errors"
	"fmt"
)

// 与 Java 版 SSHConfig 完全一致的密钥与 IV；密码支持明文或最多 4 层 DES3 加密。
const (
	cypherKey = "sshCopy4rfv^UGUIYOYR^UIO"
	cipherIV  = "01234567"
	// MaxCipherLayers -encode 与运行时解密的最大层数
	MaxCipherLayers = 4
)

var (
	errKeyLength  = errors.New("DES3 密钥长度非法")
	errCipherData = errors.New("DES3 密文非法")
)

// EncryptOnce 按 Java 版 DES3Util.encode 加密一层（DESede/CBC/PKCS5Padding + Base64）。
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

// EncryptLayers 连续加密 layers 层，用于 -encode。
func EncryptLayers(plain string, layers int) (string, error) {
	var err error
	for i := 0; i < layers; i++ {
		plain, err = EncryptOnce(plain, cypherKey)
		if err != nil {
			return "", err
		}
	}
	return plain, nil
}

// DecryptLayers 最多解密 layers 层，任何一层失败即停止并返回已解密结果。
// 与 Java 版一致：明文密码在第一次解密失败时原样保留。
func DecryptLayers(encryptText string, layers int) string {
	current := encryptText
	for i := 0; i < layers; i++ {
		next, err := DecryptOnce(current, cypherKey)
		if err != nil {
			return current
		}
		current = next
	}
	return current
}

// normalizeKey 与 Java 版 getSecretKey 一致：不足 24 字节用 '0' 补齐，超过则报错。
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
