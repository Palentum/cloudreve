package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"

	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
)

var (
	aead      cipher.AEAD
	aeadOnce  sync.Once
	ErrNotSet = errors.New("cipher: key not initialized")
	ErrBadLen = errors.New("cipher: invalid ciphertext length")
)

// Init 从应用密钥派生 AES-256-GCM 实例。
// masterKey: master 模式下使用 conf.SystemConfig.SessionSecret
//
//	slave  模式下使用 conf.SlaveConfig.Secret
func Init(keySource string) {
	aeadOnce.Do(func() {
		if keySource == "" {
			util.Log().Warning("cipher: 密钥源为空，敏感字段将不加密存储")
			return
		}
		hash := sha256.Sum256([]byte(keySource))
		block, err := aes.NewCipher(hash[:])
		if err != nil {
			util.Log().Panic("cipher: 创建 AES 分组失败: %s", err)
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			util.Log().Panic("cipher: 创建 GCM 实例失败: %s", err)
		}
		aead = a
		util.Log().Info("cipher: AES-256-GCM 加密引擎已初始化")
	})
}

// InitFromConfig 根据当前运行模式自动选择密钥源并初始化。
func InitFromConfig() {
	var keySource string
	switch conf.SystemConfig.Mode {
	case "slave":
		keySource = conf.SlaveConfig.Secret
	default:
		keySource = conf.SystemConfig.SessionSecret
	}
	Init(keySource)
}

// Encrypt 对明文进行 AES-256-GCM 加密，返回 base64 编码密文。
// 如果加密引擎未初始化则原样返回明文（兼容无密钥场景）。
func Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if aead == nil {
		return plaintext, nil
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 对 AES-256-GCM 密文进行解密。
// 如果输入不是合法 base64/AES-GCM 密文，则原样返回（兼容明文迁移场景）。
func Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if aead == nil {
		return ciphertext, nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		// 不是合法 base64，视为明文原样返回
		return ciphertext, nil
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		// 长度不足，视为明文原样返回
		return ciphertext, nil
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		// 认证失败，视为明文原样返回
		return ciphertext, nil
	}

	return string(plaintext), nil
}

// IsAvailable 返回加密引擎是否已初始化。
func IsAvailable() bool {
	return aead != nil
}

// IsEncrypted 判断输入是否是 AES-GCM 加密后的密文。
// 必须满足：合法 base64 → nonce + tag + 密文 → GCM 认证通过。
func IsEncrypted(s string) bool {
	if s == "" || aead == nil {
		return false
	}

	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize+aead.Overhead() {
		return false
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	_, err = aead.Open(nil, nonce, encrypted, nil)
	return err == nil
}
