package cipher

import (
	"sync"
	"testing"
)

func setup() {
	aead = nil
	aeadOnce = sync.Once{}
}

func TestEncryptDecrypt(t *testing.T) {
	setup()
	Init("test-secret-key-for-unit-testing-64chars-minimum-length-required")

	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty string", ""},
		{"simple text", "hello world"},
		{"access key", "AKIDabcdef123456"},
		{"secret key", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"},
		{"unicode", "你好世界"},
		{"special chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if tt.plaintext == "" {
				if encrypted != "" {
					t.Fatalf("expected empty string, got %q", encrypted)
				}
				return
			}

			if encrypted == tt.plaintext {
				t.Fatalf("ciphertext should differ from plaintext")
			}

			decrypted, err := Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Fatalf("Decrypt got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptIdempotent(t *testing.T) {
	setup()
	Init("test-secret-key-for-unit-testing-64chars-minimum-length-required")

	// 同一明文两次加密应产生不同密文（随机 nonce）
	e1, _ := Encrypt("same")
	e2, _ := Encrypt("same")
	if e1 == e2 {
		t.Fatalf("two encryptions of same plaintext should differ")
	}
}

func TestDecryptPlaintextPassthrough(t *testing.T) {
	setup()
	Init("test-secret-key-for-unit-testing-64chars-minimum-length-required")

	// 明文直接传入 Decrypt 应原样返回
	plain := "not-encrypted-data"
	result, err := Decrypt(plain)
	if err != nil {
		t.Fatalf("Decrypt of plaintext failed: %v", err)
	}
	if result != plain {
		t.Fatalf("got %q, want %q", result, plain)
	}
}

func TestNoKeyPassthrough(t *testing.T) {
	setup()
	// 不调用 Init，aead 为 nil

	enc, err := Encrypt("hello")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if enc != "hello" {
		t.Fatalf("without key, Encrypt should passthrough, got %q", enc)
	}

	dec, err := Decrypt("hello")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if dec != "hello" {
		t.Fatalf("without key, Decrypt should passthrough, got %q", dec)
	}
}

func TestIsEncrypted(t *testing.T) {
	setup()
	Init("test-secret-key-for-unit-testing-64chars-minimum-length-required")

	// 加密后的数据应被识别
	encrypted, _ := Encrypt("my-secret-key")
	if !IsEncrypted(encrypted) {
		t.Fatalf("encrypted data should be detected")
	}

	// 明文不应被识别为加密
	if IsEncrypted("my-secret-key") {
		t.Fatalf("plaintext should not be detected as encrypted")
	}

	// 长随机字符串（类似 secret_key 设置值）不应被误判
	longPlaintext := "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	if IsEncrypted(longPlaintext) {
		t.Fatalf("long random plaintext should not be detected as encrypted")
	}

	// 空字符串
	if IsEncrypted("") {
		t.Fatalf("empty string should not be detected as encrypted")
	}

	// 不同密钥加密的数据不应被当前密钥识别
	setup()
	Init("different-key-for-cross-key-testing-64chars-minimum-length-req")
	otherEncrypted, _ := Encrypt("data")
	setup()
	Init("test-secret-key-for-unit-testing-64chars-minimum-length-required")
	if IsEncrypted(otherEncrypted) {
		t.Fatalf("data encrypted with different key should not be detected")
	}

	// 无密钥时 IsEncrypted 应返回 false
	setup()
	if IsEncrypted(encrypted) {
		t.Fatalf("without key, IsEncrypted should return false")
	}
}
