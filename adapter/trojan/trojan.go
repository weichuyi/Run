// Package trojan 实现 Trojan 出站协议
// Trojan 通过 TLS 伪装成 HTTPS，仅需一层 TLS + 简单的密码哈希头
package trojan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/run-proxy/run/adapter"
	"github.com/run-proxy/run/config"
	"github.com/run-proxy/run/proxy"
)

// Trojan 出站适配器
type Trojan struct {
	adapter.Base
	server     string
	password   string  // 原密码
	hexPwd     []byte  // SHA256 哈希后的十六进制表示（56字节）
	sni        string
	skipVerify bool
	alpn       []string
	udp        bool
}

// New 从配置创建 Trojan 适配器
func New(cfg *config.ProxyConfig) (*Trojan, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}
	// Trojan 密码 = SHA224(password) 转十六进制 (56 字节)
	hash := sha256.Sum224([]byte(cfg.Password))
	hexPwd := []byte(hex.EncodeToString(hash[:]))

	return &Trojan{
		Base:       adapter.NewBase(cfg.Name, "trojan"),
		server:     fmt.Sprintf("%s:%d", cfg.Server, cfg.Port),
		password:   cfg.Password,
		hexPwd:     hexPwd,
		sni:        sni,
		skipVerify: cfg.SkipCertVerify,
		alpn:       cfg.ALPN,
		udp:        cfg.UDP,
	}, nil
}

// SupportUDP Trojan 支持 UDP
func (t *Trojan) SupportUDP() bool { return t.udp }

// DialContext 建立 Trojan TCP 连接
func (t *Trojan) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.server)
	if err != nil {
		return nil, fmt.Errorf("[Trojan] 连接 %s 失败: %w", t.server, err)
	}

	// TLS 握手（Trojan 必须使用 TLS）
	alpn := t.alpn
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	tlsCfg := &tls.Config{
		ServerName:         t.sni,
		InsecureSkipVerify: t.skipVerify,
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("[Trojan] TLS 握手失败: %w", err)
	}

	// 发送 Trojan 请求头
	tc := newTrojanConn(tlsConn, t.hexPwd, metadata)
	return adapter.NewStatsConn(tc, t), nil
}

// DialPacketConn Trojan UDP（通过 UDP ASSOCIATE 命令）
func (t *Trojan) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.server)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         t.sni,
		InsecureSkipVerify: t.skipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return newTrojanUDPConn(tlsConn, t.hexPwd, metadata), nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Trojan 协议头格式
// HEXPASSWD(56) + CRLF + CMD(1) + ATYP(1) + ADDR + PORT(2) + CRLF
// ──────────────────────────────────────────────────────────────────────────────

type trojanConn struct {
	net.Conn
	headerSent bool
	hexPwd     []byte
	metadata   *proxy.Metadata
}

func newTrojanConn(conn net.Conn, hexPwd []byte, metadata *proxy.Metadata) *trojanConn {
	return &trojanConn{Conn: conn, hexPwd: hexPwd, metadata: metadata}
}

func (c *trojanConn) Write(b []byte) (int, error) {
	if !c.headerSent {
		c.headerSent = true
		header := buildTrojanHeader(c.hexPwd, 0x01, c.metadata)
		payload := append(header, b...)
		_, err := c.Conn.Write(payload)
		return len(b), err
	}
	return c.Conn.Write(b)
}

// buildTrojanHeader 构建 Trojan 请求头
// cmd: 0x01=TCP CONNECT, 0x03=UDP ASSOCIATE
func buildTrojanHeader(hexPwd []byte, cmd byte, m *proxy.Metadata) []byte {
	buf := make([]byte, 0, 80)
	buf = append(buf, hexPwd...)    // 56 字节十六进制密码
	buf = append(buf, '\r', '\n')  // CRLF
	buf = append(buf, cmd)         // 命令

	// 地址
	if m.Host != "" {
		buf = append(buf, 0x03) // 域名
		buf = append(buf, byte(len(m.Host)))
		buf = append(buf, []byte(m.Host)...)
	} else if ip4 := m.DstIP.To4(); ip4 != nil {
		buf = append(buf, 0x01) // IPv4
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, 0x04) // IPv6
		buf = append(buf, m.DstIP.To16()...)
	}

	// 端口（大端）
	portBuf := [2]byte{}
	binary.BigEndian.PutUint16(portBuf[:], m.DstPort)
	buf = append(buf, portBuf[:]...)
	buf = append(buf, '\r', '\n') // CRLF
	return buf
}

// ──────────────────────────────────────────────────────────────────────────────
// Trojan UDP PacketConn
// ──────────────────────────────────────────────────────────────────────────────

type trojanUDPConn struct {
	conn     net.Conn
	hexPwd   []byte
	metadata *proxy.Metadata
	initiated bool
}

func newTrojanUDPConn(conn net.Conn, hexPwd []byte, metadata *proxy.Metadata) *trojanUDPConn {
	return &trojanUDPConn{conn: conn, hexPwd: hexPwd, metadata: metadata}
}

func (c *trojanUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.initiated {
		c.initiated = true
		// 先发 UDP ASSOCIATE 头
		header := buildTrojanHeader(c.hexPwd, 0x03, c.metadata)
		if _, err := c.conn.Write(header); err != nil {
			return 0, err
		}
	}
	// UDP 数据格式: ATYP(1) + ADDR + PORT(2) + LEN(2) + CRLF + DATA
	udpHeader := buildUDPHeader(addr)
	lenBuf := [2]byte{byte(len(b) >> 8), byte(len(b))}
	pkt := append(udpHeader, lenBuf[:]...)
	pkt = append(pkt, '\r', '\n')
	pkt = append(pkt, b...)
	_, err := c.conn.Write(pkt)
	return len(b), err
}

func (c *trojanUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// 读取 UDP 头部（简化实现）
	buf := make([]byte, 65536)
	n, err := c.conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	// 跳过头部（简化处理）
	copied := copy(b, buf[:n])
	return copied, nil, nil
}

func (c *trojanUDPConn) Close() error                       { return c.conn.Close() }
func (c *trojanUDPConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *trojanUDPConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *trojanUDPConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *trojanUDPConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func buildUDPHeader(addr net.Addr) []byte {
	var buf []byte
	switch a := addr.(type) {
	case *net.UDPAddr:
		if ip4 := a.IP.To4(); ip4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, a.IP.To16()...)
		}
		portBuf := [2]byte{byte(a.Port >> 8), byte(a.Port)}
		buf = append(buf, portBuf[:]...)
	default:
		buf = []byte{0x01, 0, 0, 0, 0, 0, 0}
	}
	return buf
}
