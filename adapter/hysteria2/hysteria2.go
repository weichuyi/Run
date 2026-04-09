// Package hysteria2 实现 Hysteria2 出站协议（基于 QUIC 的高速传输）
// Hysteria2 使用 QUIC 协议，通过伪装成 HTTP/3 流量绕过 QoS
package hysteria2

import (
	"context"
	"fmt"
	"net"

	"github.com/run-proxy/run/adapter"
	"github.com/run-proxy/run/config"
	"github.com/run-proxy/run/proxy"
)

// Hysteria2 出站适配器
type Hysteria2 struct {
	adapter.Base
	server     string
	password   string
	sni        string
	skipVerify bool
	upMbps     int
	downMbps   int
}

// New 从配置创建 Hysteria2 适配器
func New(cfg *config.ProxyConfig) (*Hysteria2, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}
	upMbps := parseBandwidth(cfg.Up)
	downMbps := parseBandwidth(cfg.Down)

	return &Hysteria2{
		Base:       adapter.NewBase(cfg.Name, "hysteria2"),
		server:     fmt.Sprintf("%s:%d", cfg.Server, cfg.Port),
		password:   cfg.Password,
		sni:        sni,
		skipVerify: cfg.SkipCertVerify,
		upMbps:     upMbps,
		downMbps:   downMbps,
	}, nil
}

// SupportUDP Hysteria2 原生支持 UDP
func (h *Hysteria2) SupportUDP() bool { return true }

// DialContext 建立 Hysteria2 TCP（实际通过 QUIC 流）连接
// 注意：完整的 QUIC 实现需要 github.com/quic-go/quic-go，此处提供架构接口
func (h *Hysteria2) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	// TODO: 集成 quic-go 实现完整的 Hysteria2 协议
	// 完整实现步骤：
	// 1. 建立 QUIC 连接到服务器（带 TLS）
	// 2. 发送 CONNECT 握手（password 认证）
	// 3. 协商带宽（BBR 拥塞控制）
	// 4. 打开 QUIC 流代替 TCP 连接
	return nil, fmt.Errorf("[Hysteria2] QUIC 支持需要 quic-go 依赖，请运行: go get github.com/quic-go/quic-go")
}

// DialPacketConn 建立 Hysteria2 UDP 连接
func (h *Hysteria2) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	return nil, fmt.Errorf("[Hysteria2] UDP 需要 QUIC 支持")
}

// ──────────────────────────────────────────────────────────────────────────────
// 工具函数
// ──────────────────────────────────────────────────────────────────────────────

// parseBandwidth 解析带宽字符串（如 "100 Mbps" → 100）
func parseBandwidth(s string) int {
	if s == "" {
		return 0
	}
	var value int
	var unit string
	fmt.Sscanf(s, "%d %s", &value, &unit)
	switch unit {
	case "Gbps", "gbps":
		return value * 1000
	case "Mbps", "mbps":
		return value
	case "Kbps", "kbps":
		return value / 1000
	}
	return value
}
