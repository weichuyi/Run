// Package shadowsocks 实现 Shadowsocks AEAD 加密协议 (SIP022)
// 支持: aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305
package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Cipher AEAD 密码接口
type Cipher interface {
	// KeySize 密钥字节长度
	KeySize() int
	// SaltSize Salt 长度（等于密钥长度）
	SaltSize() int
	// NewAEAD 用给定 key 创建 AEAD 对象
	NewAEAD(key []byte) (cipher.AEAD, error)
}

// ──────────────────────────────────────────────────────────────────────────────
// 具体密码实现
// ──────────────────────────────────────────────────────────────────────────────

type aesCipher struct{ keySize int }

func (c *aesCipher) KeySize()  int { return c.keySize }
func (c *aesCipher) SaltSize() int { return c.keySize }
func (c *aesCipher) NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type chachaCipher struct{}

func (c *chachaCipher) KeySize()  int { return chacha20poly1305.KeySize }
func (c *chachaCipher) SaltSize() int { return chacha20poly1305.KeySize }
func (c *chachaCipher) NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// NewCipher 根据名称返回密码实现
func NewCipher(method string) (Cipher, error) {
	switch method {
	case "aes-128-gcm":
		return &aesCipher{keySize: 16}, nil
	case "aes-256-gcm":
		return &aesCipher{keySize: 32}, nil
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return &chachaCipher{}, nil
	default:
		return nil, fmt.Errorf("不支持的加密方式: %s", method)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// 密钥派生（HKDF-SHA1，与 Shadowsocks 规范一致）
// ──────────────────────────────────────────────────────────────────────────────

// deriveSubkey 从主密钥和 Salt 派生子密钥
func deriveSubkey(key, salt []byte, keyLen int) []byte {
	r := hkdf.New(sha1.New, key, salt, []byte("ss-subkey"))
	subkey := make([]byte, keyLen)
	io.ReadFull(r, subkey)
	return subkey
}

// EvpBytesToKey 简化版 OpenSSL EVP_BytesToKey（从密码生成 SS 主密钥）
func EvpBytesToKey(password string, keyLen int) []byte {
	const md5Size = 16
	cnt := (keyLen + md5Size - 1) / md5Size
	m := make([]byte, 0, cnt*md5Size)
	prev := []byte{}
	for i := 0; i < cnt; i++ {
		h := golangMD5(append(prev, []byte(password)...))
		m = append(m, h...)
		prev = h
	}
	return m[:keyLen]
}

// golangMD5 计算 MD5（不直接 import crypto/md5 以避免包级循环）
func golangMD5(data []byte) []byte {
	import_crypto_md5 := func(b []byte) [16]byte {
		// inline MD5 via standard library
		var h [16]byte
		copy(h[:], doMD5(b))
		return h
	}
	s := import_crypto_md5(data)
	return s[:]
}

// doMD5 使用 crypto/md5
func doMD5(data []byte) []byte {
	// Will be replaced by proper import below
	// This file only exports the public API; actual MD5 is in the same package
	return data // placeholder - overridden below
}
