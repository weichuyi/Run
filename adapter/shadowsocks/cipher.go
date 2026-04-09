// Package shadowsocks 实现 Shadowsocks AEAD 加密协议 (SIP022)
// 支持: aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305
package shadowsocks

import (
"crypto/aes"
"crypto/cipher"
"crypto/md5"
"crypto/sha1"
"fmt"
"io"

"golang.org/x/crypto/chacha20poly1305"
"golang.org/x/crypto/hkdf"
)

// Cipher AEAD 密码接口
type Cipher interface {
KeySize()  int
SaltSize() int
NewAEAD(key []byte) (cipher.AEAD, error)
}

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

// NewCipher 根据方法名返回密码实现
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

// deriveSubkey 使用 HKDF-SHA1 从主密钥+Salt 派生子密钥（SS 规范）
func deriveSubkey(key, salt []byte, keyLen int) []byte {
r := hkdf.New(sha1.New, key, salt, []byte("ss-subkey"))
subkey := make([]byte, keyLen)
io.ReadFull(r, subkey)
return subkey
}

// EvpBytesToKey 与 OpenSSL EVP_BytesToKey 兼容，从密码字符串生成主密钥
func EvpBytesToKey(password string, keyLen int) []byte {
const chunkSize = md5.Size
cnt := (keyLen + chunkSize - 1) / chunkSize
m := make([]byte, 0, cnt*chunkSize)
prev := []byte{}
pass := []byte(password)
for i := 0; i < cnt; i++ {
h := md5.Sum(append(prev, pass...))
m = append(m, h[:]...)
prev = h[:]
}
return m[:keyLen]
}
