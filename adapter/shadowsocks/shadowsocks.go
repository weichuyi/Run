// Shadowsocks AEAD TCP/UDP 连接实现
package shadowsocks

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/run-proxy/run/adapter"
	"github.com/run-proxy/run/config"
	"github.com/run-proxy/run/proxy"
)

// Shadowsocks 出站适配器
type Shadowsocks struct {
	adapter.Base
	server string
	key    []byte
	cipher Cipher
}

// New 从配置创建 Shadowsocks 适配器
func New(cfg *config.ProxyConfig) (*Shadowsocks, error) {
	c, err := NewCipher(cfg.Cipher)
	if err != nil {
		return nil, fmt.Errorf("SS %s: %w", cfg.Name, err)
	}
	key := EvpBytesToKey(cfg.Password, c.KeySize())
	return &Shadowsocks{
		Base:   adapter.NewBase(cfg.Name, "ss"),
		server: fmt.Sprintf("%s:%d", cfg.Server, cfg.Port),
		key:    key,
		cipher: c,
	}, nil
}

// SupportUDP SS 支持 UDP
func (s *Shadowsocks) SupportUDP() bool { return true }

// DialContext 建立 SS TCP 加密连接
func (s *Shadowsocks) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.server)
	if err != nil {
		return nil, fmt.Errorf("[SS] 连接服务器 %s 失败: %w", s.server, err)
	}

	sc, err := newSSConn(conn, s.cipher, s.key, metadata)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return adapter.NewStatsConn(sc, s), nil
}

// DialPacketConn 建立 SS UDP 连接
func (s *Shadowsocks) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	serverAddr, err := net.ResolveUDPAddr("udp", s.server)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return newSSPacketConn(pc, serverAddr, s.cipher, s.key), nil
}

// ──────────────────────────────────────────────────────────────────────────────
// SS AEAD TCP 连接
// ──────────────────────────────────────────────────────────────────────────────

const (
	// 每个 AEAD 数据块最大负载长度（16KB - 1）
	maxPayloadSize = 0x3FFF
	// AEAD 认证标签长度
	tagSize = 16
)

// ssConn SS AEAD 加密的 TCP 连接
type ssConn struct {
	net.Conn
	cipher  Cipher
	key     []byte
	reader  *ssReader
	writer  *ssWriter
}

func newSSConn(conn net.Conn, c Cipher, key []byte, metadata *proxy.Metadata) (*ssConn, error) {
	sc := &ssConn{Conn: conn, cipher: c, key: key}

	// 写端：先发送 Salt，再加密写目标地址
	salt := make([]byte, c.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := conn.Write(salt); err != nil {
		return nil, err
	}

	subkey := deriveSubkey(key, salt, c.KeySize())
	aead, err := c.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}
	sc.writer = &ssWriter{conn: conn, aead: aead, nonce: make([]byte, aead.NonceSize())}

	// 写入目标地址（SOCKS5 格式）
	addrBuf := encodeAddr(metadata)
	if err := sc.writer.writeChunk(addrBuf); err != nil {
		return nil, err
	}

	// 读端：先读 Salt，再解密
	readSalt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(conn, readSalt); err != nil {
		return nil, err
	}
	readSubkey := deriveSubkey(key, readSalt, c.KeySize())
	readAEAD, err := c.NewAEAD(readSubkey)
	if err != nil {
		return nil, err
	}
	sc.reader = &ssReader{conn: conn, aead: readAEAD, nonce: make([]byte, readAEAD.NonceSize())}

	return sc, nil
}

func (c *ssConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *ssConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

// ──────────────────────────────────────────────────────────────────────────────
// AEAD 写入器（length-prefix 分块加密）
// ──────────────────────────────────────────────────────────────────────────────

type ssWriter struct {
	conn  net.Conn
	aead  interface {
		Overhead() int
		NonceSize() int
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
	}
	nonce []byte
	buf   []byte
}

func (w *ssWriter) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPayloadSize {
			chunk = b[:maxPayloadSize]
		}
		if err := w.writeChunk(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (w *ssWriter) writeChunk(payload []byte) error {
	// 加密长度字段
	lenBuf := make([]byte, 2+w.aead.Overhead())
	binary.BigEndian.PutUint16(lenBuf[:2], uint16(len(payload)))
	encLen := w.aead.Seal(lenBuf[:0], w.nonce, lenBuf[:2], nil)
	increment(w.nonce)

	// 加密数据
	dataBuf := make([]byte, len(payload)+w.aead.Overhead())
	encData := w.aead.Seal(dataBuf[:0], w.nonce, payload, nil)
	increment(w.nonce)

	// 一次性写出，减少系统调用次数
	_, err := w.conn.Write(append(encLen, encData...))
	return err
}

// ──────────────────────────────────────────────────────────────────────────────
// AEAD 读取器
// ──────────────────────────────────────────────────────────────────────────────

type ssReader struct {
	conn  net.Conn
	aead  interface {
		Overhead() int
		NonceSize() int
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	nonce []byte
	buf   []byte
	pos   int
}

func (r *ssReader) Read(b []byte) (int, error) {
	if r.pos < len(r.buf) {
		n := copy(b, r.buf[r.pos:])
		r.pos += n
		return n, nil
	}

	// 解密长度字段
	encLen := make([]byte, 2+r.aead.Overhead())
	if _, err := io.ReadFull(r.conn, encLen); err != nil {
		return 0, err
	}
	lenPlain, err := r.aead.Open(encLen[:0], r.nonce, encLen, nil)
	if err != nil {
		return 0, fmt.Errorf("解密长度字段失败: %w", err)
	}
	increment(r.nonce)
	payloadLen := int(binary.BigEndian.Uint16(lenPlain))

	// 解密数据
	encData := make([]byte, payloadLen+r.aead.Overhead())
	if _, err := io.ReadFull(r.conn, encData); err != nil {
		return 0, err
	}
	plain, err := r.aead.Open(encData[:0], r.nonce, encData, nil)
	if err != nil {
		return 0, fmt.Errorf("解密数据失败: %w", err)
	}
	increment(r.nonce)

	r.buf = plain
	r.pos = 0
	n := copy(b, r.buf)
	r.pos = n
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
// 地址编码（SOCKS5 格式）
// ──────────────────────────────────────────────────────────────────────────────

// encodeAddr 将 Metadata 中的目标地址编码为 SOCKS5 地址格式
func encodeAddr(m *proxy.Metadata) []byte {
	port := m.DstPort
	if m.Host != "" {
		host := []byte(m.Host)
		buf := make([]byte, 1+1+len(host)+2)
		buf[0] = 0x03 // domain
		buf[1] = byte(len(host))
		copy(buf[2:], host)
		binary.BigEndian.PutUint16(buf[2+len(host):], port)
		return buf
	}
	if ip4 := m.DstIP.To4(); ip4 != nil {
		buf := make([]byte, 1+4+2)
		buf[0] = 0x01
		copy(buf[1:], ip4)
		binary.BigEndian.PutUint16(buf[5:], port)
		return buf
	}
	buf := make([]byte, 1+16+2)
	buf[0] = 0x04
	copy(buf[1:], m.DstIP.To16())
	binary.BigEndian.PutUint16(buf[17:], port)
	return buf
}

// ──────────────────────────────────────────────────────────────────────────────
// SS UDP PacketConn
// ──────────────────────────────────────────────────────────────────────────────

type ssPacketConn struct {
	net.PacketConn
	serverAddr *net.UDPAddr
	cipher     Cipher
	key        []byte
}

func newSSPacketConn(pc net.PacketConn, serverAddr *net.UDPAddr, c Cipher, key []byte) *ssPacketConn {
	return &ssPacketConn{PacketConn: pc, serverAddr: serverAddr, cipher: c, key: key}
}

func (pc *ssPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	// UDP 包格式：Salt (saltSize) + AEAD(addr + data) + tag
	salt := make([]byte, pc.cipher.SaltSize())
	rand.Read(salt)
	subkey := deriveSubkey(pc.key, salt, pc.cipher.KeySize())
	aead, err := pc.cipher.NewAEAD(subkey)
	if err != nil {
		return 0, err
	}
	nonce := make([]byte, aead.NonceSize())
	enc := aead.Seal(nil, nonce, b, nil)
	pkt := append(salt, enc...)
	_, err = pc.PacketConn.WriteTo(pkt, pc.serverAddr)
	return len(b), err
}

func (pc *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65536)
	n, addr, err := pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	pkt := buf[:n]
	saltSize := pc.cipher.SaltSize()
	if len(pkt) < saltSize {
		return 0, addr, fmt.Errorf("SS UDP 包太短")
	}
	salt := pkt[:saltSize]
	subkey := deriveSubkey(pc.key, salt, pc.cipher.KeySize())
	aead, err := pc.cipher.NewAEAD(subkey)
	if err != nil {
		return 0, addr, err
	}
	nonce := make([]byte, aead.NonceSize())
	plain, err := aead.Open(nil, nonce, pkt[saltSize:], nil)
	if err != nil {
		return 0, addr, fmt.Errorf("SS UDP 解密失败: %w", err)
	}
	n = copy(b, plain)
	return n, addr, nil
}
