// Package dns - Fake-IP 地址池
// Fake-IP 模式下，每个域名会被分配一个虚假 IP（来自保留地址段）
// 当流量到达虚假 IP 时，Run 通过反向查表找到真实域名，使用真实域名进行路由和代理连接
package dns

import (
	"fmt"
	"net"
	"sync"
)

// FakeIPPool Fake-IP 地址池，管理 虚假IP ↔ 真实域名 的双向映射
type FakeIPPool struct {
	mu      sync.RWMutex
	ipMap   map[string]net.IP  // domain → fake IP
	domMap  map[string]string  // fake IP string → domain
	network *net.IPNet
	next    uint32 // 下一个可分配的 IP 偏移（从子网起始 +2）
	max     uint32 // 子网最大可用地址数
}

// NewFakeIPPool 从 CIDR 创建 Fake-IP 地址池
// 建议使用 198.18.0.0/15（RFC 2544 测试专用地址，不会被路由）
func NewFakeIPPool(cidr string) (*FakeIPPool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无效的 Fake-IP CIDR %q: %w", cidr, err)
	}

	// 计算地址空间大小
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits < 8 {
		return nil, fmt.Errorf("Fake-IP 地址段至少需要 /24 或更大")
	}
	maxAddrs := uint32(1<<hostBits) - 2 // 减去网络地址和广播地址

	pool := &FakeIPPool{
		ipMap:   make(map[string]net.IP),
		domMap:  make(map[string]string),
		network: network,
		next:    1, // 从 .1 开始分配
		max:     maxAddrs,
	}
	return pool, nil
}

// GetOrAllocate 为域名获取（已有）或分配（新建）一个 Fake IP
// 返回 (ip, 是否为已有分配)
func (p *FakeIPPool) GetOrAllocate(domain string) (net.IP, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ip, ok := p.ipMap[domain]; ok {
		return ip, true
	}

	// 分配新 IP
	ip := p.allocate()
	if ip == nil {
		// 地址池已满，回滚到开始（覆盖最旧的条目）
		p.next = 1
		ip = p.allocate()
	}

	p.ipMap[domain] = ip
	p.domMap[ip.String()] = domain
	return ip, false
}

// LookupDomain 通过 Fake IP 反查域名
func (p *FakeIPPool) LookupDomain(ip net.IP) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	domain, ok := p.domMap[ip.String()]
	return domain, ok
}

// IsFakeIP 判断 IP 是否属于 Fake-IP 地址池
func (p *FakeIPPool) IsFakeIP(ip net.IP) bool {
	return p.network.Contains(ip)
}

// Release 释放某域名的 Fake IP 映射（可选清理）
func (p *FakeIPPool) Release(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip, ok := p.ipMap[domain]; ok {
		delete(p.domMap, ip.String())
		delete(p.ipMap, domain)
	}
}

// Stats 返回统计信息
func (p *FakeIPPool) Stats() (used, total int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.ipMap), int(p.max)
}

// allocate 从地址池中分配下一个可用 IP（调用者负责持锁）
func (p *FakeIPPool) allocate() net.IP {
	if p.next > p.max {
		return nil
	}
	// 计算 IP：子网基址 + next
	base := ipToUint32(p.network.IP.Mask(p.network.Mask))
	offset := base + p.next
	p.next++
	return uint32ToIP(offset)
}

// ipToUint32 将 IPv4 地址转为 uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP 将 uint32 转为 IPv4 地址
func uint32ToIP(n uint32) net.IP {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}
