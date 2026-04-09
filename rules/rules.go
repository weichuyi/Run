// Package rules 实现基于规则的流量路由引擎
// 规则类型：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / GEOIP / GEOSITE / IP-CIDR / MATCH
package rules

import (
	"fmt"
	"net"
	"strings"

	"github.com/run-proxy/run/proxy"
)

// Rule 规则接口
type Rule interface {
	// Match 是否命中此规则
	Match(metadata *proxy.Metadata) bool
	// Adapter 命中后使用哪个出站适配器名称
	Adapter() string
	// Payload 规则内容（如域名、CIDR）
	Payload() string
	// Type 规则类型名称
	Type() string
	// NoResolve 返回 true 表示不对域名进行 DNS 解析（IP 规则使用）
	NoResolve() bool
}

// ──────────────────────────────────────────────────────────────────────────────
// 域名规则
// ──────────────────────────────────────────────────────────────────────────────

// Domain 精确域名匹配（DOMAIN）
type Domain struct {
	payload string
	adapter string
}

func (r *Domain) Match(m *proxy.Metadata) bool {
	return m.Host == r.payload
}
func (r *Domain) Adapter() string   { return r.adapter }
func (r *Domain) Payload() string   { return r.payload }
func (r *Domain) Type() string      { return "DOMAIN" }
func (r *Domain) NoResolve() bool   { return false }

// DomainSuffix 域名后缀匹配（DOMAIN-SUFFIX）
type DomainSuffix struct {
	payload string
	adapter string
}

func (r *DomainSuffix) Match(m *proxy.Metadata) bool {
	host := m.Host
	if host == r.payload {
		return true
	}
	return strings.HasSuffix(host, "."+r.payload)
}
func (r *DomainSuffix) Adapter() string  { return r.adapter }
func (r *DomainSuffix) Payload() string  { return r.payload }
func (r *DomainSuffix) Type() string     { return "DOMAIN-SUFFIX" }
func (r *DomainSuffix) NoResolve() bool  { return false }

// DomainKeyword 域名关键字匹配（DOMAIN-KEYWORD）
type DomainKeyword struct {
	payload string
	adapter string
}

func (r *DomainKeyword) Match(m *proxy.Metadata) bool {
	return strings.Contains(m.Host, r.payload)
}
func (r *DomainKeyword) Adapter() string   { return r.adapter }
func (r *DomainKeyword) Payload() string   { return r.payload }
func (r *DomainKeyword) Type() string      { return "DOMAIN-KEYWORD" }
func (r *DomainKeyword) NoResolve() bool   { return false }

// DomainRegex 正则域名匹配（DOMAIN-REGEX）
type DomainRegex struct {
	payload string
	pattern interface{ MatchString(string) bool }
	adapter string
}

func (r *DomainRegex) Match(m *proxy.Metadata) bool {
	return r.pattern.MatchString(m.Host)
}
func (r *DomainRegex) Adapter() string  { return r.adapter }
func (r *DomainRegex) Payload() string  { return r.payload }
func (r *DomainRegex) Type() string     { return "DOMAIN-REGEX" }
func (r *DomainRegex) NoResolve() bool  { return false }

// ──────────────────────────────────────────────────────────────────────────────
// IP 规则
// ──────────────────────────────────────────────────────────────────────────────

// IPCIDR IP CIDR 块匹配（IP-CIDR / IP-CIDR6）
type IPCIDR struct {
	payload   string
	network   *net.IPNet
	adapter   string
	noResolve bool
	isIPv6    bool
}

func (r *IPCIDR) Match(m *proxy.Metadata) bool {
	if m.DstIP == nil {
		return false
	}
	return r.network.Contains(m.DstIP)
}
func (r *IPCIDR) Adapter() string  { return r.adapter }
func (r *IPCIDR) Payload() string  { return r.payload }
func (r *IPCIDR) Type() string {
	if r.isIPv6 {
		return "IP-CIDR6"
	}
	return "IP-CIDR"
}
func (r *IPCIDR) NoResolve() bool { return r.noResolve }

// SrcIPCIDR 来源 IP CIDR 匹配
type SrcIPCIDR struct {
	payload string
	network *net.IPNet
	adapter string
}

func (r *SrcIPCIDR) Match(m *proxy.Metadata) bool {
	return r.network.Contains(m.SrcIP)
}
func (r *SrcIPCIDR) Adapter() string  { return r.adapter }
func (r *SrcIPCIDR) Payload() string  { return r.payload }
func (r *SrcIPCIDR) Type() string     { return "SRC-IP-CIDR" }
func (r *SrcIPCIDR) NoResolve() bool  { return false }

// ──────────────────────────────────────────────────────────────────────────────
// 端口规则
// ──────────────────────────────────────────────────────────────────────────────

// DstPort 目标端口匹配（DST-PORT）
type DstPort struct {
	payload string
	ports   []uint16
	adapter string
}

func (r *DstPort) Match(m *proxy.Metadata) bool {
	for _, p := range r.ports {
		if m.DstPort == p {
			return true
		}
	}
	return false
}
func (r *DstPort) Adapter() string  { return r.adapter }
func (r *DstPort) Payload() string  { return r.payload }
func (r *DstPort) Type() string     { return "DST-PORT" }
func (r *DstPort) NoResolve() bool  { return false }

// SrcPort 来源端口匹配（SRC-PORT）
type SrcPort struct {
	payload string
	ports   []uint16
	adapter string
}

func (r *SrcPort) Match(m *proxy.Metadata) bool {
	for _, p := range r.ports {
		if m.SrcPort == p {
			return true
		}
	}
	return false
}
func (r *SrcPort) Adapter() string  { return r.adapter }
func (r *SrcPort) Payload() string  { return r.payload }
func (r *SrcPort) Type() string     { return "SRC-PORT" }
func (r *SrcPort) NoResolve() bool  { return false }

// ──────────────────────────────────────────────────────────────────────────────
// 进程规则
// ──────────────────────────────────────────────────────────────────────────────

// ProcessName 进程名匹配（PROCESS-NAME）
type ProcessName struct {
	payload string
	adapter string
}

func (r *ProcessName) Match(m *proxy.Metadata) bool {
	return strings.EqualFold(m.ProcessName, r.payload) ||
		strings.EqualFold(stripExt(m.ProcessName), r.payload)
}
func (r *ProcessName) Adapter() string  { return r.adapter }
func (r *ProcessName) Payload() string  { return r.payload }
func (r *ProcessName) Type() string     { return "PROCESS-NAME" }
func (r *ProcessName) NoResolve() bool  { return false }

func stripExt(name string) string {
	if idx := strings.LastIndex(name, "."); idx > 0 {
		return name[:idx]
	}
	return name
}

// ──────────────────────────────────────────────────────────────────────────────
// GeoIP 规则（需要 MaxMind GeoIP 数据库）
// ──────────────────────────────────────────────────────────────────────────────

// GeoIP 根据 IP 地理位置匹配（GEOIP）
type GeoIP struct {
	payload   string // 国家代码，如 "CN"
	adapter   string
	noResolve bool
	matcher   GeoIPMatcher
}

// GeoIPMatcher GeoIP 匹配接口（由 geo 包实现）
type GeoIPMatcher interface {
	Match(ip net.IP) (string, error)
}

func (r *GeoIP) Match(m *proxy.Metadata) bool {
	if r.matcher == nil || m.DstIP == nil {
		return false
	}
	country, err := r.matcher.Match(m.DstIP)
	if err != nil {
		return false
	}
	if r.payload == "private" {
		return isPrivate(m.DstIP)
	}
	return strings.EqualFold(country, r.payload)
}
func (r *GeoIP) Adapter() string  { return r.adapter }
func (r *GeoIP) Payload() string  { return r.payload }
func (r *GeoIP) Type() string     { return "GEOIP" }
func (r *GeoIP) NoResolve() bool  { return r.noResolve }

// ──────────────────────────────────────────────────────────────────────────────
// GeoSite 规则（需要 GeoSite 数据库）
// ──────────────────────────────────────────────────────────────────────────────

// GeoSite 根据域名分类匹配（GEOSITE）
type GeoSite struct {
	payload string // 分类名，如 "cn" / "google"
	adapter string
	matcher GeoSiteMatcher
}

// GeoSiteMatcher GeoSite 匹配接口
type GeoSiteMatcher interface {
	Match(domain, category string) bool
}

func (r *GeoSite) Match(m *proxy.Metadata) bool {
	if r.matcher == nil {
		return false
	}
	return r.matcher.Match(m.Host, r.payload)
}
func (r *GeoSite) Adapter() string  { return r.adapter }
func (r *GeoSite) Payload() string  { return r.payload }
func (r *GeoSite) Type() string     { return "GEOSITE" }
func (r *GeoSite) NoResolve() bool  { return false }

// ──────────────────────────────────────────────────────────────────────────────
// MATCH 兜底规则
// ──────────────────────────────────────────────────────────────────────────────

// Match 兜底规则，永远匹配（必须放在规则列表最后）
type Match struct {
	adapter string
}

func (r *Match) Match(_ *proxy.Metadata) bool { return true }
func (r *Match) Adapter() string              { return r.adapter }
func (r *Match) Payload() string              { return "" }
func (r *Match) Type() string                 { return "MATCH" }
func (r *Match) NoResolve() bool              { return false }

// ──────────────────────────────────────────────────────────────────────────────
// 规则解析器
// ──────────────────────────────────────────────────────────────────────────────

// ParseOptions 规则解析选项（注入 GeoIP/GeoSite 匹配器）
type ParseOptions struct {
	GeoIP   GeoIPMatcher
	GeoSite GeoSiteMatcher
}

// Parse 解析单条规则字符串
// 格式: TYPE,PAYLOAD,ADAPTER[,OPTIONS]
// 示例: DOMAIN-SUFFIX,google.com,🚀 节点选择
//        IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
func Parse(line string, opts *ParseOptions) (Rule, error) {
	parts := strings.SplitN(strings.TrimSpace(line), ",", 4)
	if len(parts) < 2 {
		return nil, fmt.Errorf("规则格式错误: %q", line)
	}

	ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))

	// MATCH 规则只有两段
	if ruleType == "MATCH" {
		if len(parts) < 2 {
			return nil, fmt.Errorf("MATCH 规则缺少适配器名称")
		}
		return &Match{adapter: strings.TrimSpace(parts[1])}, nil
	}

	if len(parts) < 3 {
		return nil, fmt.Errorf("规则 %q 缺少适配器字段", line)
	}
	payload := strings.TrimSpace(parts[1])
	adapterName := strings.TrimSpace(parts[2])

	noResolve := false
	if len(parts) == 4 && strings.ToLower(strings.TrimSpace(parts[3])) == "no-resolve" {
		noResolve = true
	}

	switch ruleType {
	case "DOMAIN":
		return &Domain{payload: strings.ToLower(payload), adapter: adapterName}, nil

	case "DOMAIN-SUFFIX":
		return &DomainSuffix{payload: strings.ToLower(payload), adapter: adapterName}, nil

	case "DOMAIN-KEYWORD":
		return &DomainKeyword{payload: strings.ToLower(payload), adapter: adapterName}, nil

	case "IP-CIDR", "IP-CIDR6":
		_, network, err := net.ParseCIDR(payload)
		if err != nil {
			return nil, fmt.Errorf("无效的 CIDR %q: %w", payload, err)
		}
		return &IPCIDR{
			payload:   payload,
			network:   network,
			adapter:   adapterName,
			noResolve: noResolve,
			isIPv6:    ruleType == "IP-CIDR6",
		}, nil

	case "SRC-IP-CIDR":
		_, network, err := net.ParseCIDR(payload)
		if err != nil {
			return nil, fmt.Errorf("无效的 SRC CIDR %q: %w", payload, err)
		}
		return &SrcIPCIDR{payload: payload, network: network, adapter: adapterName}, nil

	case "GEOIP":
		geo := &GeoIP{payload: strings.ToUpper(payload), adapter: adapterName, noResolve: noResolve}
		if opts != nil {
			geo.matcher = opts.GeoIP
		}
		return geo, nil

	case "GEOSITE":
		gs := &GeoSite{payload: strings.ToLower(payload), adapter: adapterName}
		if opts != nil {
			gs.matcher = opts.GeoSite
		}
		return gs, nil

	case "PROCESS-NAME":
		return &ProcessName{payload: payload, adapter: adapterName}, nil

	case "DST-PORT":
		ports, err := parsePorts(payload)
		if err != nil {
			return nil, err
		}
		return &DstPort{payload: payload, ports: ports, adapter: adapterName}, nil

	case "SRC-PORT":
		ports, err := parsePorts(payload)
		if err != nil {
			return nil, err
		}
		return &SrcPort{payload: payload, ports: ports, adapter: adapterName}, nil

	default:
		return nil, fmt.Errorf("未知规则类型: %s", ruleType)
	}
}

// ParseAll 批量解析规则列表
func ParseAll(lines []string, opts *ParseOptions) ([]Rule, error) {
	result := make([]Rule, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := Parse(line, opts)
		if err != nil {
			return nil, fmt.Errorf("解析规则 %q 失败: %w", line, err)
		}
		result = append(result, r)
	}
	return result, nil
}

// parsePorts 解析端口列表（支持单个端口和范围，如 "80,443,8080-8090"）
func parsePorts(s string) ([]uint16, error) {
	var ports []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			var start, end int
			if _, err := fmt.Sscanf(part, "%d-%d", &start, &end); err != nil {
				return nil, fmt.Errorf("无效的端口范围: %s", part)
			}
			for p := start; p <= end; p++ {
				ports = append(ports, uint16(p))
			}
		} else {
			var p int
			if _, err := fmt.Sscanf(part, "%d", &p); err != nil {
				return nil, fmt.Errorf("无效的端口: %s", part)
			}
			ports = append(ports, uint16(p))
		}
	}
	return ports, nil
}

// isPrivate 判断是否为私有 IP
func isPrivate(ip net.IP) bool {
	privateRanges := []*net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
