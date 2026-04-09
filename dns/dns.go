// Package dns 实现 Run 的 DNS 模块
// 特性：
//   - 支持 DoH (DNS-over-HTTPS)、DoT (DNS-over-TLS)、UDP/TCP DNS
//   - Fake-IP 模式：返回虚假 IP，实际域名保留以便路由
//   - 域名路由：不同域名使用不同上游 DNS（防止污染）
//   - TTL 缓存
//   - Hosts 文件映射
package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	miekgdns "github.com/miekg/dns"
	log "github.com/run-proxy/run/common/log"
	"github.com/run-proxy/run/config"
)

// Resolver DNS 解析器接口
type Resolver interface {
	ResolveIP(ctx context.Context, host string) (net.IP, error)
	ResolveIPv4(ctx context.Context, host string) (net.IP, error)
	ResolveIPv6(ctx context.Context, host string) (net.IP, error)
	Exchange(ctx context.Context, msg *miekgdns.Msg) (*miekgdns.Msg, error)
	FakeIPEnabled() bool
	FakeIPForDomain(ctx context.Context, domain string) (net.IP, error)
	RealDomainFromFakeIP(ip net.IP) (string, bool)
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS 客户端
// ──────────────────────────────────────────────────────────────────────────────

// DNSResolver 完整 DNS 解析器实现
type DNSResolver struct {
	cfg      *config.DNS
	hosts    map[string]net.IP
	cache    *dnsCache
	fakeIP   *FakeIPPool
	upstream []*upstreamClient
	fallback []*upstreamClient
	policy   map[string]*upstreamClient // 域名策略路由
	mu       sync.RWMutex
}

// New 从配置创建 DNS 解析器
func New(cfg *config.DNS, hosts map[string]string) (*DNSResolver, error) {
	r := &DNSResolver{
		cfg:    cfg,
		hosts:  make(map[string]net.IP),
		cache:  newDNSCache(),
		policy: make(map[string]*upstreamClient),
	}

	// 解析 hosts
	for domain, ip := range hosts {
		if parsed := net.ParseIP(ip); parsed != nil {
			r.hosts[strings.ToLower(domain)] = parsed
		}
	}

	// 创建主上游
	for _, server := range cfg.Nameservers {
		client, err := newUpstream(server)
		if err != nil {
			log.Warnf("[DNS] 忽略无效上游 %s: %v", server, err)
			continue
		}
		r.upstream = append(r.upstream, client)
	}

	// 创建备用上游
	for _, server := range cfg.Fallback {
		client, err := newUpstream(server)
		if err != nil {
			log.Warnf("[DNS] 忽略无效备用上游 %s: %v", server, err)
			continue
		}
		r.fallback = append(r.fallback, client)
	}

	// 域名路由策略
	for domain, server := range cfg.NameserverPolicy {
		client, err := newUpstream(server)
		if err != nil {
			continue
		}
		r.policy[strings.ToLower(domain)] = client
	}

	// Fake-IP 池
	if cfg.EnhancedMode == "fake-ip" {
		pool, err := NewFakeIPPool(cfg.FakeIPRange)
		if err != nil {
			return nil, fmt.Errorf("创建 Fake-IP 池失败: %w", err)
		}
		r.fakeIP = pool
		log.Infof("[DNS] Fake-IP 模式已启用，地址段: %s", cfg.FakeIPRange)
	}

	if len(r.upstream) == 0 {
		return nil, fmt.Errorf("至少需要配置一个 DNS 上游服务器")
	}

	log.Infof("[DNS] 解析器初始化完成，主上游: %d 个，备用: %d 个",
		len(r.upstream), len(r.fallback))
	return r, nil
}

// FakeIPEnabled 是否启用了 Fake-IP 模式
func (r *DNSResolver) FakeIPEnabled() bool { return r.fakeIP != nil }

// FakeIPForDomain 为域名分配/获取 Fake IP 地址
func (r *DNSResolver) FakeIPForDomain(ctx context.Context, domain string) (net.IP, error) {
	if r.fakeIP == nil {
		return nil, fmt.Errorf("Fake-IP 模式未启用")
	}

	// 检查是否在过滤列表
	if r.isFakeIPFiltered(domain) {
		// 过滤的域名使用真实解析
		return r.ResolveIPv4(ctx, domain)
	}

	ip, exists := r.fakeIP.GetOrAllocate(domain)
	if !exists {
		log.Debugf("[DNS] Fake-IP 分配 %s → %s", domain, ip)
	}
	return ip, nil
}

// RealDomainFromFakeIP 通过 Fake IP 反查真实域名
func (r *DNSResolver) RealDomainFromFakeIP(ip net.IP) (string, bool) {
	if r.fakeIP == nil {
		return "", false
	}
	return r.fakeIP.LookupDomain(ip)
}

// ResolveIP 解析域名为 IP（IPv4 优先，IPv6 回退）
func (r *DNSResolver) ResolveIP(ctx context.Context, host string) (net.IP, error) {
	ip, err := r.ResolveIPv4(ctx, host)
	if err == nil {
		return ip, nil
	}
	return r.ResolveIPv6(ctx, host)
}

// ResolveIPv4 解析域名为 IPv4
func (r *DNSResolver) ResolveIPv4(ctx context.Context, host string) (net.IP, error) {
	return r.resolve(ctx, host, miekgdns.TypeA)
}

// ResolveIPv6 解析域名为 IPv6
func (r *DNSResolver) ResolveIPv6(ctx context.Context, host string) (net.IP, error) {
	return r.resolve(ctx, host, miekgdns.TypeAAAA)
}

// resolve 核心解析逻辑
func (r *DNSResolver) resolve(ctx context.Context, host string, qtype uint16) (net.IP, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// 1. 检查 hosts 映射
	if ip, ok := r.hosts[host]; ok {
		return ip, nil
	}

	// 2. 检查缓存
	if cached := r.cache.Get(host, qtype); cached != nil {
		return cached, nil
	}

	// 3. 发起查询
	msg := newQuery(host, qtype)
	resp, err := r.Exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	// 4. 提取 IP
	ip := extractIP(resp, qtype)
	if ip == nil {
		return nil, fmt.Errorf("域名 %s 解析无结果", host)
	}

	// 5. 缓存结果
	ttl := extractTTL(resp)
	if ttl > 0 {
		r.cache.Set(host, qtype, ip, time.Duration(ttl)*time.Second)
	}

	return ip, nil
}

// Exchange 发送 DNS 查询并返回应答
func (r *DNSResolver) Exchange(ctx context.Context, msg *miekgdns.Msg) (*miekgdns.Msg, error) {
	// 确定使用哪个上游
	client := r.selectUpstream(questionDomain(msg))

	resp, err := client.exchange(ctx, msg)
	if err != nil && len(r.fallback) > 0 {
		// 主上游失败，尝试备用
		for _, fb := range r.fallback {
			resp, err = fb.exchange(ctx, msg)
			if err == nil {
				return resp, nil
			}
		}
	}
	return resp, err
}

// selectUpstream 根据域名路由策略选择上游
func (r *DNSResolver) selectUpstream(domain string) *upstreamClient {
	if domain == "" {
		return r.upstream[0]
	}
	// 检查策略路由（最长匹配优先）
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestMatch string
	var bestClient *upstreamClient
	for pattern, client := range r.policy {
		if matchDomainPolicy(domain, pattern) {
			if len(pattern) > len(bestMatch) {
				bestMatch = pattern
				bestClient = client
			}
		}
	}
	if bestClient != nil {
		return bestClient
	}
	return r.upstream[0]
}

// isFakeIPFiltered 检查域名是否在 Fake-IP 过滤列表
func (r *DNSResolver) isFakeIPFiltered(domain string) bool {
	for _, pattern := range r.cfg.FakeIPFilter {
		if matchDomainPattern(domain, pattern) {
			return true
		}
	}
	return false
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS 上游客户端
// ──────────────────────────────────────────────────────────────────────────────

type upstreamType uint8

const (
	upstreamUDP upstreamType = iota
	upstreamTCP
	upstreamDoT
	upstreamDoH
)

type upstreamClient struct {
	addr    string
	typ     upstreamType
	client  *miekgdns.Client
	dohURL  string
	httpCli *http.Client
}

func newUpstream(server string) (*upstreamClient, error) {
	switch {
	case strings.HasPrefix(server, "https://"):
		return &upstreamClient{
			addr:   server,
			typ:    upstreamDoH,
			dohURL: server,
			httpCli: &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				},
			},
		}, nil

	case strings.HasPrefix(server, "tls://"):
		addr := strings.TrimPrefix(server, "tls://")
		if !strings.Contains(addr, ":") {
			addr += ":853"
		}
		return &upstreamClient{
			addr: addr,
			typ:  upstreamDoT,
			client: &miekgdns.Client{
				Net:     "tcp-tls",
				Timeout: 5 * time.Second,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		}, nil

	case strings.HasPrefix(server, "tcp://"):
		addr := strings.TrimPrefix(server, "tcp://")
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		return &upstreamClient{
			addr:   addr,
			typ:    upstreamTCP,
			client: &miekgdns.Client{Net: "tcp", Timeout: 5 * time.Second},
		}, nil

	default:
		// UDP（默认）
		if !strings.Contains(server, ":") {
			server += ":53"
		}
		return &upstreamClient{
			addr:   server,
			typ:    upstreamUDP,
			client: &miekgdns.Client{Net: "udp", Timeout: 5 * time.Second},
		}, nil
	}
}

func (u *upstreamClient) exchange(ctx context.Context, msg *miekgdns.Msg) (*miekgdns.Msg, error) {
	switch u.typ {
	case upstreamDoH:
		return u.dohExchange(ctx, msg)
	default:
		resp, _, err := u.client.ExchangeContext(ctx, msg, u.addr)
		return resp, err
	}
}

func (u *upstreamClient) dohExchange(ctx context.Context, msg *miekgdns.Msg) (*miekgdns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.dohURL, strings.NewReader(string(packed)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := u.httpCli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 服务器返回 %d", resp.StatusCode)
	}

	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	ans := new(miekgdns.Msg)
	if err := ans.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return ans, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS 缓存
// ──────────────────────────────────────────────────────────────────────────────

type cacheEntry struct {
	ip      net.IP
	expires time.Time
}

type dnsCache struct {
	mu    sync.RWMutex
	store map[string]*cacheEntry
}

func newDNSCache() *dnsCache {
	c := &dnsCache{store: make(map[string]*cacheEntry)}
	go c.janitor()
	return c
}

func (c *dnsCache) Get(domain string, qtype uint16) net.IP {
	key := fmt.Sprintf("%s:%d", domain, qtype)
	c.mu.RLock()
	e, ok := c.store[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return nil
	}
	return e.ip
}

func (c *dnsCache) Set(domain string, qtype uint16, ip net.IP, ttl time.Duration) {
	key := fmt.Sprintf("%s:%d", domain, qtype)
	c.mu.Lock()
	c.store[key] = &cacheEntry{ip: ip, expires: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// janitor 定期清理过期缓存
func (c *dnsCache) janitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for k, v := range c.store {
			if now.After(v.expires) {
				delete(c.store, k)
			}
		}
		c.mu.Unlock()
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// DNS 服务器（监听本地 53 端口）
// ──────────────────────────────────────────────────────────────────────────────

// Server DNS 服务器，将本地 DNS 请求转由 Resolver 处理
type Server struct {
	resolver Resolver
	server   *miekgdns.Server
	udpServer *miekgdns.Server
}

// StartServer 启动 DNS 服务器
func StartServer(addr string, resolver Resolver) (*Server, error) {
	s := &Server{resolver: resolver}
	mux := miekgdns.NewServeMux()
	mux.HandleFunc(".", s.handleRequest)

	s.server = &miekgdns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}
	s.udpServer = &miekgdns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: mux,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			log.Warnf("[DNS] UDP 服务器停止: %v", err)
		}
	}()
	go func() {
		if err := s.udpServer.ListenAndServe(); err != nil {
			log.Warnf("[DNS] TCP 服务器停止: %v", err)
		}
	}()

	log.Infof("[DNS] 服务器监听 %s", addr)
	return s, nil
}

// Close 停止 DNS 服务器
func (s *Server) Close() {
	s.server.Shutdown()
	s.udpServer.Shutdown()
}

func (s *Server) handleRequest(w miekgdns.ResponseWriter, req *miekgdns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.resolver.Exchange(ctx, req)
	if err != nil {
		// 返回 SERVFAIL
		m := new(miekgdns.Msg)
		m.SetReply(req)
		m.Rcode = miekgdns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	w.WriteMsg(resp)
}

// ──────────────────────────────────────────────────────────────────────────────
// 工具函数
// ──────────────────────────────────────────────────────────────────────────────

func newQuery(domain string, qtype uint16) *miekgdns.Msg {
	msg := new(miekgdns.Msg)
	msg.SetQuestion(miekgdns.Fqdn(domain), qtype)
	msg.RecursionDesired = true
	return msg
}

func extractIP(resp *miekgdns.Msg, qtype uint16) net.IP {
	for _, rr := range resp.Answer {
		switch qtype {
		case miekgdns.TypeA:
			if a, ok := rr.(*miekgdns.A); ok {
				return a.A.To4()
			}
		case miekgdns.TypeAAAA:
			if aaaa, ok := rr.(*miekgdns.AAAA); ok {
				return aaaa.AAAA
			}
		}
	}
	return nil
}

func extractTTL(resp *miekgdns.Msg) uint32 {
	for _, rr := range resp.Answer {
		return rr.Header().Ttl
	}
	return 0
}

func questionDomain(msg *miekgdns.Msg) string {
	if len(msg.Question) > 0 {
		return strings.ToLower(strings.TrimSuffix(msg.Question[0].Name, "."))
	}
	return ""
}

// matchDomainPattern 通配符域名匹配（支持 *.example.com 和 +.example.com）
func matchDomainPattern(domain, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return domain == suffix || strings.HasSuffix(domain, "."+suffix)
	}
	if strings.HasPrefix(pattern, "+.") {
		suffix := pattern[2:]
		return domain == suffix || strings.HasSuffix(domain, "."+suffix)
	}
	return domain == pattern
}

// matchDomainPolicy 策略路由域名匹配
func matchDomainPolicy(domain, pattern string) bool {
	if strings.HasPrefix(pattern, "geosite:") {
		// geosite 规则由 GeoSite 数据库处理，此处简单跳过
		return false
	}
	return matchDomainPattern(domain, pattern)
}
