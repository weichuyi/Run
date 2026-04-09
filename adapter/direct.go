// Package adapter - Direct 直连出站适配器
package adapter

import (
	"context"
	"net"

	"github.com/run-proxy/run/proxy"
)

// Direct 直连出站（不经过任何代理）
type Direct struct {
	Base
	iface string // 绑定网卡（可选）
}

// NewDirect 创建直连适配器
func NewDirect(iface string) *Direct {
	return &Direct{
		Base:  NewBase("DIRECT", "direct"),
		iface: iface,
	}
}

// DialContext 直接拨号目标地址
func (d *Direct) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	dialer := &net.Dialer{}
	if d.iface != "" {
		iface, err := net.InterfaceByName(d.iface)
		if err == nil {
			addr, _ := iface.Addrs()
			if len(addr) == 0 {
				goto DIAL
			}
			if ipNet, ok := addr[0].(*net.IPNet); ok {
				dialer.LocalAddr = &net.TCPAddr{IP: ipNet.IP}
			}
		}
	}

	DIAL:
	conn, err := dialer.DialContext(ctx, "tcp", metadata.Destination())
	if err != nil {
		return nil, err
	}
	return NewStatsConn(conn, d), nil
}

// DialPacketConn UDP 直连
func (d *Direct) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// SupportUDP 直连支持 UDP
func (d *Direct) SupportUDP() bool { return true }
