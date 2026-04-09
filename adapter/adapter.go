// Package adapter 定义出站代理适配器接口及流量统计
package adapter

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/run-proxy/run/proxy"
)

// Proxy 出站代理适配器接口（所有协议均实现此接口）
type Proxy interface {
	// Name 节点名称
	Name() string
	// Type 协议类型，如 "ss" / "vmess" / "direct"
	Type() string
	// DialContext 建立 TCP 连接（带 context 超时控制）
	DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error)
	// DialPacketConn 建立 UDP 连接
	DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error)
	// SupportUDP 是否支持 UDP 转发
	SupportUDP() bool
	// Stats 返回流量统计快照
	Stats() TrafficStats
	// AddUpload 累加上行字节
	AddUpload(n int64)
	// AddDownload 累加下行字节
	AddDownload(n int64)
	// Latency 最近一次测速延迟（0 表示未测速）
	Latency() time.Duration
	// SetLatency 设置延迟
	SetLatency(d time.Duration)
	// Alive 节点是否可用
	Alive() bool
	// SetAlive 设置节点可用性
	SetAlive(v bool)
}

// TrafficStats 流量统计快照
type TrafficStats struct {
	Upload   int64
	Download int64
	Latency  time.Duration
	Alive    bool
}

// -----------------------------------------------------------------------------
// Base 提供 Proxy 接口的通用字段实现（内嵌到具体协议结构中）
// -----------------------------------------------------------------------------

// Base 通用出站适配器基类
type Base struct {
	name    string
	typ     string
	upload  atomic.Int64
	download atomic.Int64
	latency atomic.Int64 // 纳秒
	alive   atomic.Bool
}

// NewBase 初始化基类
func NewBase(name, typ string) Base {
	b := Base{name: name, typ: typ}
	b.alive.Store(true)
	return b
}

func (b *Base) Name() string { return b.name }
func (b *Base) Type() string { return b.typ }

func (b *Base) AddUpload(n int64)   { b.upload.Add(n) }
func (b *Base) AddDownload(n int64) { b.download.Add(n) }

func (b *Base) Latency() time.Duration {
	return time.Duration(b.latency.Load())
}

func (b *Base) SetLatency(d time.Duration) {
	b.latency.Store(int64(d))
}

func (b *Base) Alive() bool       { return b.alive.Load() }
func (b *Base) SetAlive(v bool)   { b.alive.Store(v) }

func (b *Base) Stats() TrafficStats {
	return TrafficStats{
		Upload:   b.upload.Load(),
		Download: b.download.Load(),
		Latency:  b.Latency(),
		Alive:    b.alive.Load(),
	}
}

// -----------------------------------------------------------------------------
// statsConn 包装 net.Conn 并统计流量
// -----------------------------------------------------------------------------

// StatsConn 包装 net.Conn，透明地统计上下行流量
type StatsConn struct {
	net.Conn
	proxy Proxy
}

// NewStatsConn 创建统计连接
func NewStatsConn(conn net.Conn, p Proxy) *StatsConn {
	return &StatsConn{Conn: conn, proxy: p}
}

func (c *StatsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.proxy.AddDownload(int64(n))
	}
	return n, err
}

func (c *StatsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.proxy.AddUpload(int64(n))
	}
	return n, err
}
