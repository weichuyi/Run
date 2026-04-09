// Package net 提供网络地址相关工具函数
package net

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AddrType 地址类型
type AddrType uint8

const (
	AtypIPv4   AddrType = 1
	AtypDomain AddrType = 3
	AtypIPv6   AddrType = 4
)

// Addr 表示一个网络地址（支持 IPv4、IPv6、域名）
type Addr struct {
	Type AddrType
	IP   net.IP
	FQDN string
	Port uint16
}

// String 返回 "host:port" 格式字符串
func (a Addr) String() string {
	return net.JoinHostPort(a.Host(), strconv.Itoa(int(a.Port)))
}

// Host 返回纯主机部分
func (a Addr) Host() string {
	if a.Type == AtypDomain {
		return a.FQDN
	}
	return a.IP.String()
}

// IsIPv6 是否为 IPv6 地址
func (a Addr) IsIPv6() bool {
	return a.Type == AtypIPv6
}

// ParseAddr 解析 "host:port" 字符串为 Addr
func ParseAddr(s string) (Addr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, fmt.Errorf("解析地址失败 %q: %w", s, err)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Addr{}, fmt.Errorf("解析端口失败 %q: %w", portStr, err)
	}

	addr := Addr{Port: uint16(port)}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr.Type = AtypIPv4
			addr.IP = ip4
		} else {
			addr.Type = AtypIPv6
			addr.IP = ip
		}
	} else {
		addr.Type = AtypDomain
		addr.FQDN = strings.ToLower(host)
	}
	return addr, nil
}

// NewAddrFromIPPort 通过 IP 和端口构造 Addr
func NewAddrFromIPPort(ip net.IP, port uint16) Addr {
	if ip4 := ip.To4(); ip4 != nil {
		return Addr{Type: AtypIPv4, IP: ip4, Port: port}
	}
	return Addr{Type: AtypIPv6, IP: ip, Port: port}
}

// NewAddrFromDomainPort 通过域名和端口构造 Addr
func NewAddrFromDomainPort(domain string, port uint16) Addr {
	return Addr{Type: AtypDomain, FQDN: strings.ToLower(domain), Port: port}
}

// TCPAddr 将 Addr 转为 *net.TCPAddr（仅 IP 类型）
func (a Addr) TCPAddr() *net.TCPAddr {
	if a.Type == AtypDomain {
		return nil
	}
	return &net.TCPAddr{IP: a.IP, Port: int(a.Port)}
}

// UDPAddr 将 Addr 转为 *net.UDPAddr（仅 IP 类型）
func (a Addr) UDPAddr() *net.UDPAddr {
	if a.Type == AtypDomain {
		return nil
	}
	return &net.UDPAddr{IP: a.IP, Port: int(a.Port)}
}

// IsPrivate 是否为私有 IP 地址
func IsPrivate(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// SplitPort 将 "host:port" 安全分离
func SplitPort(addr string) (host string, port int, err error) {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return "", 0, e
	}
	pn, e := strconv.Atoi(p)
	if e != nil {
		return "", 0, e
	}
	return h, pn, nil
}
