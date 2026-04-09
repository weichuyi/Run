// Package adapter - Reject 阻断出站适配器（拦截广告/恶意域名）
package adapter

import (
	"context"
	"errors"
	"net"

	"github.com/run-proxy/run/proxy"
)

// ErrRejected 连接被规则拒绝
var ErrRejected = errors.New("connection rejected by rule")

// Reject 拒绝连接（用于广告过滤、恶意域名拦截）
type Reject struct {
	Base
}

// NewReject 创建 Reject 适配器
func NewReject() *Reject {
	return &Reject{Base: NewBase("REJECT", "reject")}
}

// DialContext 始终返回错误（拒绝连接）
func (r *Reject) DialContext(_ context.Context, _ *proxy.Metadata) (net.Conn, error) {
	return nil, ErrRejected
}

// DialPacketConn 始终返回错误
func (r *Reject) DialPacketConn(_ context.Context, _ *proxy.Metadata) (net.PacketConn, error) {
	return nil, ErrRejected
}

// SupportUDP Reject 不支持 UDP
func (r *Reject) SupportUDP() bool { return false }
