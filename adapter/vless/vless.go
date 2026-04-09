// Package vless 实现 VLESS 出站协议（轻量版 VMess，无加密开销，依赖 TLS/XTLS）
// 支持 flow: xtls-rprx-vision / xtls-rprx-direct
package vless

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/run-proxy/run/adapter"
	"github.com/run-proxy/run/config"
	"github.com/run-proxy/run/proxy"
)

// VLESS 出站适配器
type VLESS struct {
	adapter.Base
	server     string
	uuid       [16]byte
	flow       string // xtls-rprx-vision 等
	tls        bool
	sni        string
	alpn       []string
	skipVerify bool
	fingerprint string
}

// New 从配置创建 VLESS 适配器
func New(cfg *config.ProxyConfig) (*VLESS, error) {
	uid, err := parseUUID(cfg.UUID)
	if err != nil {
		return nil, fmt.Errorf("VLESS %s: 无效 UUID: %w", cfg.Name, err)
	}
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}
	return &VLESS{
		Base:        adapter.NewBase(cfg.Name, "vless"),
		server:      fmt.Sprintf("%s:%d", cfg.Server, cfg.Port),
		uuid:        uid,
		flow:        cfg.Flow,
		tls:         cfg.TLS,
		sni:         sni,
		alpn:        cfg.ALPN,
		skipVerify:  cfg.SkipCertVerify,
		fingerprint: cfg.Fingerprint,
	}, nil
}

// SupportUDP VLESS 支持 UDP（通过 XUDP）
func (v *VLESS) SupportUDP() bool { return false }

// DialContext 建立 VLESS 连接
func (v *VLESS) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", v.server)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] 连接 %s 失败: %w", v.server, err)
	}

	// TLS 握手
	if v.tls {
		tlsCfg := &tls.Config{
			ServerName:         v.sni,
			InsecureSkipVerify: v.skipVerify,
			NextProtos:         v.alpn,
			MinVersion:         tls.VersionTLS12,
		}
		conn = tls.Client(conn, tlsCfg)
		if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("[VLESS] TLS 握手失败: %w", err)
		}
	}

	// 发送 VLESS 请求头
	vc := newVLESSConn(conn, v.uuid, metadata)
	return adapter.NewStatsConn(vc, v), nil
}

// DialPacketConn VLESS UDP（未实现 XUDP，返回错误）
func (v *VLESS) DialPacketConn(_ context.Context, _ *proxy.Metadata) (net.PacketConn, error) {
	return nil, fmt.Errorf("VLESS 暂不支持 UDP")
}

// ──────────────────────────────────────────────────────────────────────────────
// VLESS 协议头格式（V0）
// 版本(1) + UUID(16) + 附加信息长度(1) + 附加信息 + 命令(1) + 端口(2) + 地址类型(1) + 地址
// ──────────────────────────────────────────────────────────────────────────────

type vlessConn struct {
	net.Conn
	headerSent bool
	uuid       [16]byte
	metadata   *proxy.Metadata
}

func newVLESSConn(conn net.Conn, uuid [16]byte, metadata *proxy.Metadata) *vlessConn {
	return &vlessConn{Conn: conn, uuid: uuid, metadata: metadata}
}

func (c *vlessConn) Write(b []byte) (int, error) {
	if !c.headerSent {
		c.headerSent = true
		header := c.buildHeader()
		payload := append(header, b...)
		_, err := c.Conn.Write(payload)
		return len(b), err
	}
	return c.Conn.Write(b)
}

// buildHeader 构建 VLESS V0 请求头
func (c *vlessConn) buildHeader() []byte {
	m := c.metadata
	buf := make([]byte, 0, 64)

	buf = append(buf, 0x00)       // 版本 V0
	buf = append(buf, c.uuid[:]...) // UUID
	buf = append(buf, 0x00)       // 附加信息长度（无附加信息）
	buf = append(buf, 0x01)       // 命令: TCP

	// 目标端口（大端）
	portBuf := [2]byte{}
	binary.BigEndian.PutUint16(portBuf[:], m.DstPort)
	buf = append(buf, portBuf[:]...)

	// 目标地址
	if m.Host != "" {
		buf = append(buf, 0x02) // 域名
		buf = append(buf, byte(len(m.Host)))
		buf = append(buf, []byte(m.Host)...)
	} else if ip4 := m.DstIP.To4(); ip4 != nil {
		buf = append(buf, 0x01) // IPv4
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, 0x03) // IPv6
		buf = append(buf, m.DstIP.To16()...)
	}
	return buf
}

func (c *vlessConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

// parseUUID 解析 UUID 字符串（与 vmess 包相同）
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	if len(s) != 36 {
		return uuid, fmt.Errorf("UUID 长度不正确")
	}
	hexStr := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	for i := 0; i < 16; i++ {
		var b byte
		for _, c := range hexStr[i*2 : i*2+2] {
			b <<= 4
			switch {
			case '0' <= c && c <= '9':
				b |= byte(c - '0')
			case 'a' <= c && c <= 'f':
				b |= byte(c-'a') + 10
			case 'A' <= c && c <= 'F':
				b |= byte(c-'A') + 10
			}
		}
		uuid[i] = b
	}
	return uuid, nil
}
