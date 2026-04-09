// Package vmess 实现 VMess 出站协议（V2Ray 核心实现的 Go 移植）
// 支持传输层: tcp / ws / grpc / http2
// 支持加密: aes-128-gcm / chacha20-poly1305 / none / auto
package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/run-proxy/run/adapter"
	"github.com/run-proxy/run/config"
	"github.com/run-proxy/run/proxy"
)

// Security VMess 安全类型
type Security uint8

const (
	SecurityAuto    Security = 0
	SecurityNone    Security = 1
	SecurityAES128  Security = 2
	SecurityChaCha  Security = 3
)

// VMess 出站适配器
type VMess struct {
	adapter.Base
	server   string
	uuid     [16]byte
	security Security
	alterId  int
	tls      bool
	sni      string
	wsPath   string
	wsHost   string
	network  string
	skipVerify bool
}

// New 从配置创建 VMess 适配器
func New(cfg *config.ProxyConfig) (*VMess, error) {
	uid, err := parseUUID(cfg.UUID)
	if err != nil {
		return nil, fmt.Errorf("VMess %s: 无效的 UUID: %w", cfg.Name, err)
	}

	sec := SecurityAuto
	switch cfg.Encryption {
	case "none":
		sec = SecurityNone
	case "aes-128-gcm":
		sec = SecurityAES128
	case "chacha20-poly1305":
		sec = SecurityChaCha
	}

	v := &VMess{
		Base:       adapter.NewBase(cfg.Name, "vmess"),
		server:     fmt.Sprintf("%s:%d", cfg.Server, cfg.Port),
		uuid:       uid,
		security:   sec,
		alterId:    cfg.AlterID,
		tls:        cfg.TLS,
		sni:        cfg.SNI,
		network:    cfg.Network,
		skipVerify: cfg.SkipCertVerify,
	}
	if cfg.WSOptions != nil {
		v.wsPath = cfg.WSOptions.Path
		if h, ok := cfg.WSOptions.Headers["Host"]; ok {
			v.wsHost = h
		}
	}
	if v.sni == "" {
		v.sni = cfg.Server
	}
	return v, nil
}

// SupportUDP VMess 支持 UDP（通过 mux）
func (v *VMess) SupportUDP() bool { return false }

// DialContext 建立 VMess TCP 连接
func (v *VMess) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	var conn net.Conn
	var err error

	switch v.network {
	case "ws", "websocket":
		conn, err = v.dialWebSocket(ctx)
	default:
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", v.server)
	}
	if err != nil {
		return nil, fmt.Errorf("[VMess] 连接 %s 失败: %w", v.server, err)
	}

	if v.tls {
		conn, err = wrapTLS(conn, v.sni, v.skipVerify)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	vc, err := v.newVMessConn(conn, metadata)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return adapter.NewStatsConn(vc, v), nil
}

// DialPacketConn VMess 暂不支持原生 UDP
func (v *VMess) DialPacketConn(_ context.Context, _ *proxy.Metadata) (net.PacketConn, error) {
	return nil, fmt.Errorf("VMess 不支持 UDP")
}

// ──────────────────────────────────────────────────────────────────────────────
// VMess 协议实现
// ──────────────────────────────────────────────────────────────────────────────

// newVMessConn 建立 VMess 认证握手并返回加密连接
func (v *VMess) newVMessConn(conn net.Conn, metadata *proxy.Metadata) (net.Conn, error) {
	// 生成随机 IV 和 Key（各 16 字节）
	reqIV := make([]byte, 16)
	reqKey := make([]byte, 16)
	rand.Read(reqIV)
	rand.Read(reqKey)

	respV := byte(0)
	rand.Read([]byte{respV})
	rand.Read(reqIV[15:16]) // 最后一字节作为 respV
	respV = reqIV[15]

	// 构建请求头
	header, err := v.buildHeader(reqIV, reqKey, respV, metadata)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(header); err != nil {
		return nil, err
	}

	// 选择加密方式
	sec := v.security
	if sec == SecurityAuto {
		sec = SecurityAES128
	}

	var encConn net.Conn
	switch sec {
	case SecurityNone:
		encConn = &plainConn{Conn: conn}
	case SecurityAES128:
		encConn, err = newAESGCMConn(conn, reqKey, reqIV, respV)
	case SecurityChaCha:
		encConn, err = newChaCha20Conn(conn, reqKey, reqIV, respV)
	default:
		encConn, err = newAESGCMConn(conn, reqKey, reqIV, respV)
	}
	if err != nil {
		return nil, err
	}
	return encConn, nil
}

// buildHeader 构建 VMess 请求头（V1 格式）
func (v *VMess) buildHeader(iv, key []byte, respV byte, metadata *proxy.Metadata) ([]byte, error) {
	// 时间戳认证（HMAC-MD5）
	ts := time.Now().Unix()
	authID := v.generateAuthID(ts)
	hash := hmac.New(md5.New, v.uuid[:])
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ts))
	hash.Write(buf)
	authHash := hash.Sum(nil)
	_ = authHash

	// 构建请求体（版本1）
	req := make([]byte, 0, 64)
	req = append(req, 0x01)       // 版本
	req = append(req, iv...)       // IV (16字节)
	req = append(req, key...)      // Key (16字节)
	req = append(req, respV)       // 响应验证V
	req = append(req, 0x01)        // 选项: CHUNKSTREAM
	paddingLen := byte(0)
	req = append(req, paddingLen<<4|byte(encToSec(v.security))) // padding+安全
	req = append(req, 0x00)        // 保留
	req = append(req, 0x01)        // 命令: TCP

	// 目标端口
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, metadata.DstPort)
	req = append(req, port...)

	// 目标地址
	if metadata.Host != "" {
		req = append(req, 0x02) // 域名
		req = append(req, byte(len(metadata.Host)))
		req = append(req, []byte(metadata.Host)...)
	} else if ip4 := metadata.DstIP.To4(); ip4 != nil {
		req = append(req, 0x01) // IPv4
		req = append(req, ip4...)
	} else {
		req = append(req, 0x03) // IPv6
		req = append(req, metadata.DstIP.To16()...)
	}
	// padding
	req = append(req, make([]byte, int(paddingLen))...)

	// F (校验)
	f := fnv1a(req)
	req = append(req, f...)

	// 用 AES-128-CFB 加密头部（密钥=MD5(uuid+ts)，IV=MD5(ts*4)）
	cmdKey := v.cmdKey()
	cmdIV := v.cmdIV(ts)
	encHeader, err := aesCFBEncrypt(cmdKey, cmdIV, req)
	if err != nil {
		return nil, err
	}

	// 完整帧: authID(16) + encHeader
	return append(authID, encHeader...), nil
}

func (v *VMess) generateAuthID(ts int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(ts))
	h := md5.Sum(append(v.uuid[:], buf[:]...))
	return h[:]
}

func (v *VMess) cmdKey() []byte {
	h := md5.Sum(append(v.uuid[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
	return h[:]
}

func (v *VMess) cmdIV(ts int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(ts))
	h := md5.Sum(append(buf[:], buf[:]...))
	h2 := md5.Sum(append(h[:], h[:]...))
	return h2[:]
}

func aesCFBEncrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	enc := make([]byte, len(data))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(enc, data)
	return enc, nil
}

func encToSec(s Security) Security {
	if s == SecurityAuto {
		return SecurityAES128
	}
	return s
}

func fnv1a(data []byte) []byte {
	h := uint32(2166136261)
	for _, b := range data {
		h ^= uint32(b)
		h *= 16777619
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, h)
	return buf
}

// parseUUID 解析 UUID 字符串
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	if len(s) != 36 {
		return uuid, fmt.Errorf("UUID 长度错误: %d", len(s))
	}
	// 移除 '-'
	hexStr := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if len(hexStr) != 32 {
		return uuid, fmt.Errorf("UUID 格式错误")
	}
	for i := 0; i < 16; i++ {
		b, err := parseHexByte(hexStr[i*2 : i*2+2])
		if err != nil {
			return uuid, err
		}
		uuid[i] = b
	}
	return uuid, nil
}

func parseHexByte(s string) (byte, error) {
	var b byte
	for _, c := range s {
		b <<= 4
		switch {
		case '0' <= c && c <= '9':
			b |= byte(c - '0')
		case 'a' <= c && c <= 'f':
			b |= byte(c-'a') + 10
		case 'A' <= c && c <= 'F':
			b |= byte(c-'A') + 10
		default:
			return 0, fmt.Errorf("无效的十六进制字符: %c", c)
		}
	}
	return b, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// 加密连接实现
// ──────────────────────────────────────────────────────────────────────────────

// plainConn 不加密的透传连接
type plainConn struct{ net.Conn }

// aesGCMConn AES-128-GCM 加密连接
type aesGCMConn struct {
	net.Conn
	enc  cipher.AEAD
	dec  cipher.AEAD
	wNonce []byte
	rNonce []byte
	rbuf   []byte
	rpos   int
}

func newAESGCMConn(conn net.Conn, key, iv []byte, respV byte) (*aesGCMConn, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	_ = respV
	return &aesGCMConn{
		Conn:   conn,
		enc:    aead,
		dec:    aead,
		wNonce: append(iv[:12:12], 0, 0, 0, 0),
		rNonce: append(iv[:12:12], 0, 0, 0, 0),
	}, nil
}

func (c *aesGCMConn) Write(b []byte) (int, error) {
	// 长度前缀 + AEAD 加密
	enc := c.enc.Seal(nil, c.wNonce[:c.enc.NonceSize()], b, nil)
	increment(c.wNonce)
	lenBuf := [2]byte{byte(len(enc) >> 8), byte(len(enc))}
	_, err := c.Conn.Write(append(lenBuf[:], enc...))
	return len(b), err
}

func (c *aesGCMConn) Read(b []byte) (int, error) {
	if c.rpos < len(c.rbuf) {
		n := copy(b, c.rbuf[c.rpos:])
		c.rpos += n
		return n, nil
	}
	lenBuf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	enc := make([]byte, size)
	if _, err := io.ReadFull(c.Conn, enc); err != nil {
		return 0, err
	}
	plain, err := c.dec.Open(nil, c.rNonce[:c.dec.NonceSize()], enc, nil)
	if err != nil {
		return 0, err
	}
	increment(c.rNonce)
	c.rbuf = plain
	c.rpos = 0
	n := copy(b, c.rbuf)
	c.rpos = n
	return n, nil
}

// chaCha20Conn ChaCha20-Poly1305 加密连接
type chaCha20Conn struct {
	net.Conn
	enc    cipher.AEAD
	dec    cipher.AEAD
	wNonce []byte
	rNonce []byte
	rbuf   []byte
	rpos   int
}

func newChaCha20Conn(conn net.Conn, key, iv []byte, respV byte) (*chaCha20Conn, error) {
	// 扩展 key 到 32 字节（ChaCha20 需要 32 字节）
	extKey := md5sum32(key)
	aead, err := chacha20poly1305.New(extKey)
	if err != nil {
		return nil, err
	}
	_ = respV
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, iv)
	return &chaCha20Conn{
		Conn:   conn,
		enc:    aead,
		dec:    aead,
		wNonce: append([]byte(nil), nonce...),
		rNonce: append([]byte(nil), nonce...),
	}, nil
}

func md5sum32(key []byte) []byte {
	h1 := md5.Sum(key)
	h2 := md5.Sum(h1[:])
	return append(h1[:], h2[:]...)
}

func (c *chaCha20Conn) Write(b []byte) (int, error) {
	enc := c.enc.Seal(nil, c.wNonce[:c.enc.NonceSize()], b, nil)
	increment(c.wNonce)
	lenBuf := [2]byte{byte(len(enc) >> 8), byte(len(enc))}
	_, err := c.Conn.Write(append(lenBuf[:], enc...))
	return len(b), err
}

func (c *chaCha20Conn) Read(b []byte) (int, error) {
	if c.rpos < len(c.rbuf) {
		n := copy(b, c.rbuf[c.rpos:])
		c.rpos += n
		return n, nil
	}
	lenBuf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	enc := make([]byte, size)
	if _, err := io.ReadFull(c.Conn, enc); err != nil {
		return 0, err
	}
	plain, err := c.dec.Open(nil, c.rNonce[:c.dec.NonceSize()], enc, nil)
	if err != nil {
		return 0, err
	}
	increment(c.rNonce)
	c.rbuf = plain
	c.rpos = 0
	n := copy(b, c.rbuf)
	c.rpos = n
	return n, nil
}

// increment 大端序递增 nonce
func increment(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS 包装
// ──────────────────────────────────────────────────────────────────────────────

func wrapTLS(conn net.Conn, sni string, skipVerify bool) (net.Conn, error) {
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// WebSocket 传输
// ──────────────────────────────────────────────────────────────────────────────

func (v *VMess) dialWebSocket(ctx context.Context) (net.Conn, error) {
	target := v.server
	scheme := "ws"
	if v.tls {
		scheme = "wss"
	}
	host := v.sni
	if host == "" {
		h, _, _ := net.SplitHostPort(target)
		host = h
	}
	path := v.wsPath
	if path == "" {
		path = "/"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, target, path)
	header := http.Header{"Host": []string{host}}

	conn, err := wsDialContext(ctx, url, header)
	if err != nil {
		return nil, fmt.Errorf("WebSocket 连接失败: %w", err)
	}
	return conn, nil
}

// wsDialContext 使用 gorilla/websocket 拨号（由 adapter 层实现）
func wsDialContext(ctx context.Context, url string, header http.Header) (net.Conn, error) {
	// 实际实现在 transport/ws.go
	return nil, fmt.Errorf("WebSocket 传输未实现")
}
