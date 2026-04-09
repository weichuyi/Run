// Package proxy 定义代理连接的核心元数据和处理接口
package proxy

import (
	"fmt"
	"net"
)

// Network 网络类型
type Network string

const (
	TCP Network = "tcp"
	UDP Network = "udp"
)

// InboundType 入站类型
type InboundType string

const (
	InboundSOCKS5 InboundType = "socks5"
	InboundHTTP   InboundType = "http"
	InboundMixed  InboundType = "mixed"
	InboundRedir  InboundType = "redir"
	InboundTProxy InboundType = "tproxy"
	InboundTUN    InboundType = "tun"
)

// Metadata 描述一次代理连接的完整上下文信息，
// 被入站、规则引擎、出站适配器共同使用。
type Metadata struct {
	// 入站信息
	InboundType InboundType
	InboundName string

	// 连接层协议
	Network Network

	// 来源地址
	SrcIP   net.IP
	SrcPort uint16

	// 目标地址（域名优先，IP 作为补充）
	Host    string // 域名（可为空）
	DstIP   net.IP // 解析后的 IP
	DstPort uint16

	// DNS 相关（fake-ip 模式下使用）
	DNSMode   string // "" / "fake-ip" / "redir-host"
	OriginDst string // 原始目标（透明代理使用）

	// 进程信息（部分平台可获取）
	ProcessName string
	ProcessPath string
}

// DestIP 返回目标 IP，如果没有则返回 nil
func (m *Metadata) DestIP() net.IP {
	return m.DstIP
}

// String 返回可读格式
func (m *Metadata) String() string {
	return fmt.Sprintf("[%s] %s → %s", m.Network, m.Source(), m.Destination())
}

// Source 返回来源地址字符串
func (m *Metadata) Source() string {
	if m.SrcIP == nil {
		return "unknown"
	}
	return fmt.Sprintf("%s:%d", m.SrcIP, m.SrcPort)
}

// Destination 返回目标地址字符串（域名优先）
func (m *Metadata) Destination() string {
	if m.Host != "" {
		return fmt.Sprintf("%s:%d", m.Host, m.DstPort)
	}
	if m.DstIP != nil {
		return fmt.Sprintf("%s:%d", m.DstIP, m.DstPort)
	}
	return fmt.Sprintf("unknown:%d", m.DstPort)
}

// RemoteAddr 返回目标的 net.Addr（域名优先解析为字符串地址）
func (m *Metadata) RemoteAddr() net.Addr {
	return &addrString{addr: m.Destination(), network: string(m.Network)}
}

// Pure 用于判断是否已解析 IP（false 代表只有域名）
func (m *Metadata) Pure() bool {
	return m.DstIP != nil
}

type addrString struct {
	addr    string
	network string
}

func (a *addrString) Network() string { return a.network }
func (a *addrString) String() string  { return a.addr }

// -----------------------------------------------------------------------------
// Handler 接口：由 Tunnel 实现，供入站组件调用
// -----------------------------------------------------------------------------

// TCPHandler 处理 TCP 连接
type TCPHandler interface {
	HandleTCP(conn net.Conn, metadata *Metadata)
}

// UDPHandler 处理 UDP 数据包
type UDPHandler interface {
	HandleUDP(conn net.PacketConn, metadata *Metadata)
}

// Handler 同时处理 TCP 和 UDP
type Handler interface {
	TCPHandler
	UDPHandler
}
