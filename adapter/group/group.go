// Package group 实现代理分组：手动选择 / 自动测速 / 负载均衡
package group

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/run-proxy/run/adapter"
	"github.com/run-proxy/run/proxy"
)

// ──────────────────────────────────────────────────────────────────────────────
// Selector 手动选择分组
// ──────────────────────────────────────────────────────────────────────────────

// Selector 允许用户通过 Dashboard 手动选择当前激活的代理节点
type Selector struct {
	adapter.Base
	proxies []adapter.Proxy
	mu      sync.RWMutex
	now     adapter.Proxy
}

// NewSelector 创建 Selector 分组
func NewSelector(name string, proxies []adapter.Proxy) *Selector {
	s := &Selector{
		Base:    adapter.NewBase(name, "selector"),
		proxies: proxies,
	}
	if len(proxies) > 0 {
		s.now = proxies[0]
	}
	return s
}

// Current 返回当前选中的代理
func (s *Selector) Current() adapter.Proxy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.now
}

// Select 切换到指定名称的节点（由 Dashboard API 调用）
func (s *Selector) Select(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.proxies {
		if p.Name() == name {
			s.now = p
			return true
		}
	}
	return false
}

// Proxies 返回所有节点列表
func (s *Selector) Proxies() []adapter.Proxy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]adapter.Proxy, len(s.proxies))
	copy(result, s.proxies)
	return result
}

func (s *Selector) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	return s.Current().DialContext(ctx, metadata)
}

func (s *Selector) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	return s.Current().DialPacketConn(ctx, metadata)
}

func (s *Selector) SupportUDP() bool {
	return s.Current().SupportUDP()
}

// ──────────────────────────────────────────────────────────────────────────────
// URLTest 自动选速分组（选延迟最低的节点）
// ──────────────────────────────────────────────────────────────────────────────

// URLTest 定期对所有节点测速，自动选择延迟最低的节点
type URLTest struct {
	adapter.Base
	proxies   []adapter.Proxy
	testURL   string
	interval  time.Duration
	tolerance time.Duration // 切换容差：新节点延迟必须低于当前延迟 - tolerance 才切换
	timeout   time.Duration
	lazy      bool

	mu       sync.RWMutex
	best     adapter.Proxy
	stopCh   chan struct{}
	testOnce sync.Once
}

// NewURLTest 创建 URLTest 分组
func NewURLTest(name string, proxies []adapter.Proxy, testURL string, interval, timeout time.Duration, tolerance int, lazy bool) *URLTest {
	ut := &URLTest{
		Base:      adapter.NewBase(name, "url-test"),
		proxies:   proxies,
		testURL:   testURL,
		interval:  interval,
		timeout:   timeout,
		tolerance: time.Duration(tolerance) * time.Millisecond,
		lazy:      lazy,
		stopCh:    make(chan struct{}),
	}
	if len(proxies) > 0 {
		ut.best = proxies[0]
	}
	return ut
}

// Start 启动后台测速
func (ut *URLTest) Start() {
	go ut.testLoop()
}

// Stop 停止后台测速
func (ut *URLTest) Stop() {
	close(ut.stopCh)
}

func (ut *URLTest) testLoop() {
	// 立即执行一次测速（非 lazy 模式）
	if !ut.lazy {
		ut.test()
	}
	ticker := time.NewTicker(ut.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ut.test()
		case <-ut.stopCh:
			return
		}
	}
}

// test 对所有节点并发测速
func (ut *URLTest) test() {
	ctx, cancel := context.WithTimeout(context.Background(), ut.timeout)
	defer cancel()

	type result struct {
		proxy   adapter.Proxy
		latency time.Duration
	}

	ch := make(chan result, len(ut.proxies))
	for _, p := range ut.proxies {
		go func(px adapter.Proxy) {
			lat, err := testLatency(ctx, px, ut.testURL)
			if err != nil {
				px.SetAlive(false)
				ch <- result{px, 0}
				return
			}
			px.SetAlive(true)
			px.SetLatency(lat)
			ch <- result{px, lat}
		}(p)
	}

	var best adapter.Proxy
	var bestLat time.Duration
	for i := 0; i < len(ut.proxies); i++ {
		r := <-ch
		if r.latency == 0 {
			continue
		}
		if best == nil || r.latency < bestLat {
			best = r.proxy
			bestLat = r.latency
		}
	}

	if best == nil {
		return
	}

	ut.mu.Lock()
	defer ut.mu.Unlock()

	// 仅在延迟低于当前最优 - 容差时才切换
	if ut.best == nil || !ut.best.Alive() {
		ut.best = best
		return
	}
	currentLat := ut.best.Latency()
	if bestLat < currentLat-ut.tolerance {
		ut.best = best
	}
}

// Best 返回当前最优节点
func (ut *URLTest) Best() adapter.Proxy {
	ut.mu.RLock()
	defer ut.mu.RUnlock()
	if ut.best != nil {
		return ut.best
	}
	if len(ut.proxies) > 0 {
		return ut.proxies[0]
	}
	return nil
}

func (ut *URLTest) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	// lazy 模式：首次使用时触发测速
	ut.testOnce.Do(func() {
		if ut.lazy {
			go ut.test()
		}
	})
	return ut.Best().DialContext(ctx, metadata)
}

func (ut *URLTest) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	return ut.Best().DialPacketConn(ctx, metadata)
}

func (ut *URLTest) SupportUDP() bool {
	if b := ut.Best(); b != nil {
		return b.SupportUDP()
	}
	return false
}

// ──────────────────────────────────────────────────────────────────────────────
// LoadBalance 负载均衡分组
// ──────────────────────────────────────────────────────────────────────────────

// LBStrategy 负载均衡策略
type LBStrategy uint8

const (
	StrategyRoundRobin       LBStrategy = iota // 轮询
	StrategyConsistentHashing                  // 一致性哈希（同一目标总分到同一节点）
	StrategyStickySession                      // 粘性会话
)

// LoadBalance 在多个节点间分散流量
type LoadBalance struct {
	adapter.Base
	proxies  []adapter.Proxy
	strategy LBStrategy
	mu       sync.Mutex
	counter  int
	cache    map[string]adapter.Proxy // 一致性哈希缓存
}

// NewLoadBalance 创建负载均衡分组
func NewLoadBalance(name string, proxies []adapter.Proxy, strategy string) *LoadBalance {
	var s LBStrategy
	switch strategy {
	case "consistent-hashing":
		s = StrategyConsistentHashing
	case "sticky-sessions":
		s = StrategyStickySession
	default:
		s = StrategyRoundRobin
	}
	return &LoadBalance{
		Base:     adapter.NewBase(name, "load-balance"),
		proxies:  proxies,
		strategy: s,
		cache:    make(map[string]adapter.Proxy),
	}
}

func (lb *LoadBalance) pick(metadata *proxy.Metadata) adapter.Proxy {
	alive := lb.aliveProxies()
	if len(alive) == 0 {
		return lb.proxies[0] // 兜底
	}

	switch lb.strategy {
	case StrategyConsistentHashing, StrategyStickySession:
		key := metadata.Destination()
		lb.mu.Lock()
		if p, ok := lb.cache[key]; ok && p.Alive() {
			lb.mu.Unlock()
			return p
		}
		// 哈希选择
		h := fnv32(key)
		p := alive[int(h)%len(alive)]
		lb.cache[key] = p
		lb.mu.Unlock()
		return p
	default: // RoundRobin
		lb.mu.Lock()
		p := alive[lb.counter%len(alive)]
		lb.counter++
		lb.mu.Unlock()
		return p
	}
}

func (lb *LoadBalance) aliveProxies() []adapter.Proxy {
	result := make([]adapter.Proxy, 0, len(lb.proxies))
	for _, p := range lb.proxies {
		if p.Alive() {
			result = append(result, p)
		}
	}
	return result
}

func (lb *LoadBalance) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	return lb.pick(metadata).DialContext(ctx, metadata)
}

func (lb *LoadBalance) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	return lb.pick(metadata).DialPacketConn(ctx, metadata)
}

func (lb *LoadBalance) SupportUDP() bool { return false }

// ──────────────────────────────────────────────────────────────────────────────
// Fallback 故障转移分组
// ──────────────────────────────────────────────────────────────────────────────

// Fallback 总是使用第一个可用节点，当前节点故障后切换到下一个
type Fallback struct {
	adapter.Base
	proxies  []adapter.Proxy
	testURL  string
	interval time.Duration
	timeout  time.Duration
	stopCh   chan struct{}
}

// NewFallback 创建故障转移分组
func NewFallback(name string, proxies []adapter.Proxy, testURL string, interval, timeout time.Duration) *Fallback {
	f := &Fallback{
		Base:     adapter.NewBase(name, "fallback"),
		proxies:  proxies,
		testURL:  testURL,
		interval: interval,
		timeout:  timeout,
		stopCh:   make(chan struct{}),
	}
	return f
}

// Start 启动健康检查
func (f *Fallback) Start() {
	f.healthCheck()
	go func() {
		ticker := time.NewTicker(f.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				f.healthCheck()
			case <-f.stopCh:
				return
			}
		}
	}()
}

// Stop 停止健康检查
func (f *Fallback) Stop() { close(f.stopCh) }

func (f *Fallback) healthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	for _, p := range f.proxies {
		_, err := testLatency(ctx, p, f.testURL)
		p.SetAlive(err == nil)
	}
}

func (f *Fallback) first() adapter.Proxy {
	for _, p := range f.proxies {
		if p.Alive() {
			return p
		}
	}
	return f.proxies[0]
}

func (f *Fallback) DialContext(ctx context.Context, metadata *proxy.Metadata) (net.Conn, error) {
	return f.first().DialContext(ctx, metadata)
}

func (f *Fallback) DialPacketConn(ctx context.Context, metadata *proxy.Metadata) (net.PacketConn, error) {
	return f.first().DialPacketConn(ctx, metadata)
}

func (f *Fallback) SupportUDP() bool { return false }

// ──────────────────────────────────────────────────────────────────────────────
// 工具函数
// ──────────────────────────────────────────────────────────────────────────────

// testLatency 测试节点到测速 URL 的延迟
func testLatency(ctx context.Context, p adapter.Proxy, testURL string) (time.Duration, error) {
	u, err := url.Parse(testURL)
	if err != nil || u.Hostname() == "" {
		return 0, fmt.Errorf("测速 URL 无效: %s", testURL)
	}
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	start := time.Now()
	m := &proxy.Metadata{
		Network: proxy.TCP,
		Host:    u.Hostname(),
		DstPort: port,
	}
	conn, err := p.DialContext(ctx, m)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// fnv32 FNV-1a 哈希（用于一致性哈希）
func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for _, c := range s {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}
