// Package config 负责加载和解析 Run 的配置文件（YAML 格式，与 Clash/Mihomo 低级别兼容）
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------
// 顶层配置结构
// -----------------------------------------------------------------------------

// Config 是整个配置文件的根结构
type Config struct {
	General     General            `yaml:"general"`
	DNS         DNS                `yaml:"dns"`
	TUN         TUN                `yaml:"tun"`
	Hosts       map[string]string  `yaml:"hosts"`
	Proxies     []map[string]any   `yaml:"proxies"`
	Groups      []map[string]any   `yaml:"proxy-groups"`
	Rules       []string           `yaml:"rules"`
	Subscribers []Subscriber       `yaml:"subscribers"`
}

// General 通用设置
type General struct {
	// 日志级别: silent / error / warning / info / debug
	LogLevel string `yaml:"log-level"`
	// 运行模式: rule（规则）/ global（全局）/ direct（直连）
	Mode string `yaml:"mode"`

	// 本地 HTTP 代理端口，0 表示不启用
	Port int `yaml:"port"`
	// 本地 SOCKS5 代理端口，0 表示不启用
	SocksPort int `yaml:"socks-port"`
	// 混合端口（同时支持 HTTP/SOCKS5）
	MixedPort int `yaml:"mixed-port"`
	// 透明代理端口（redirect，Linux/macOS）
	RedirPort int `yaml:"redir-port"`
	// 透明代理端口（tproxy，仅 Linux）
	TProxyPort int `yaml:"tproxy-port"`

	// 是否允许局域网连接
	AllowLan bool `yaml:"allow-lan"`
	// 监听地址，"*" 表示所有接口
	BindAddress string `yaml:"bind-address"`

	// REST API 监听地址，如 "127.0.0.1:9090"
	ExternalController string `yaml:"external-controller"`
	// Dashboard 静态文件目录
	ExternalUI string `yaml:"external-ui"`
	// REST API 认证密钥
	Secret string `yaml:"secret"`

	// 指定出站网络接口名称
	Interface string `yaml:"interface-name"`
	// 是否启用 IPv6
	IPv6 bool `yaml:"ipv6"`

	// 测速 URL
	TestURL string `yaml:"test-url"`
	// 测速超时
	TestTimeout time.Duration `yaml:"test-timeout"`
}

// -----------------------------------------------------------------------------
// DNS 配置
// -----------------------------------------------------------------------------

// DNS 域名解析配置
type DNS struct {
	Enable bool   `yaml:"enable"`
	Listen string `yaml:"listen"` // e.g. "0.0.0.0:53"
	IPv6   bool   `yaml:"ipv6"`

	// DNS 增强模式: "" / "fake-ip" / "redir-host"
	EnhancedMode string `yaml:"enhanced-mode"`
	// Fake-IP 地址池 CIDR
	FakeIPRange string `yaml:"fake-ip-range"`
	// 不使用 fake-ip 的域名列表
	FakeIPFilter []string `yaml:"fake-ip-filter"`
	// 是否使用 hosts
	UseHosts bool `yaml:"use-hosts"`

	// 主 DNS 服务器列表
	Nameservers []string `yaml:"nameserver"`
	// 备用 DNS 服务器列表（可选，通常用于对抗 DNS 污染）
	Fallback []string `yaml:"fallback"`
	// 备用 DNS 过滤规则
	FallbackFilter FallbackFilter `yaml:"fallback-filter"`
	// 按 domain 路由到不同的 DNS 服务器
	NameserverPolicy map[string]string `yaml:"nameserver-policy"`
	// 默认 DNS 服务器（用于解析其他 DNS 服务器的域名）
	DefaultNameserver []string `yaml:"default-nameserver"`
}

// FallbackFilter 备用 DNS 过滤规则
type FallbackFilter struct {
	GeoIP    bool     `yaml:"geoip"`
	GeoIPCode string  `yaml:"geoip-code"`
	IPCIDRs  []string `yaml:"ipcidr"`
	Domains  []string `yaml:"domain"`
}

// -----------------------------------------------------------------------------
// TUN 配置
// -----------------------------------------------------------------------------

// TUN 虚拟网卡模式配置（系统级代理）
type TUN struct {
	Enable    bool     `yaml:"enable"`
	// 网络栈实现: "gvisor" / "system" / "mixed"
	Stack     string   `yaml:"stack"`
	// 需要劫持的 DNS 地址
	DNSHijack []string `yaml:"dns-hijack"`
	// 自动添加路由
	AutoRoute bool     `yaml:"auto-route"`
	// 自动检测出站接口
	AutoDetectInterface bool `yaml:"auto-detect-interface"`
	// TUN 设备名称
	Device    string   `yaml:"device"`
	// TUN IP 地址段
	Inet4Address []string `yaml:"inet4-address"`
	Inet6Address []string `yaml:"inet6-address"`
	// 严格路由（防泄漏）
	StrictRoute bool `yaml:"strict-route"`
}

// -----------------------------------------------------------------------------
// 代理节点配置
// -----------------------------------------------------------------------------

// ProxyConfig 单个代理节点的配置（支持多协议）
type ProxyConfig struct {
	// 节点名称
	Name string `yaml:"name"`
	// 节点类型: ss / vmess / vless / trojan / hysteria2 / socks5 / http
	Type string `yaml:"type"`
	// 服务器地址
	Server string `yaml:"server"`
	// 服务器端口
	Port int `yaml:"port"`

	// ── Shadowsocks ──────────────────────────────────────────────────
	Cipher   string `yaml:"cipher"`
	Password string `yaml:"password"`
	// ShadowTLS / obfs
	Plugin     string            `yaml:"plugin"`
	PluginOpts map[string]string `yaml:"plugin-opts"`

	// ── VMess ────────────────────────────────────────────────────────
	UUID           string `yaml:"uuid"`
	AlterID        int    `yaml:"alterId"`
	// 加密方式: auto / none / aes-128-gcm / chacha20-poly1305
	Encryption     string `yaml:"encryption"`

	// ── VLESS ────────────────────────────────────────────────────────
	Flow string `yaml:"flow"`

	// ── Trojan ───────────────────────────────────────────────────────
	// Password 复用

	// ── Hysteria2 ────────────────────────────────────────────────────
	// Password 复用
	// 上下行带宽
	Up   string `yaml:"up"`
	Down string `yaml:"down"`

	// ── 传输层配置 ───────────────────────────────────────────────────
	// 传输协议: tcp / ws / grpc / http / h2 / quic
	Network   string         `yaml:"network"`
	WSOptions *WSOptions     `yaml:"ws-opts"`
	GRPCOpts  *GRPCOptions   `yaml:"grpc-opts"`
	H2Opts    *H2Options     `yaml:"h2-opts"`
	HTTPOpts  *HTTPOptions   `yaml:"http-opts"`

	// ── TLS 配置 ─────────────────────────────────────────────────────
	TLS            bool     `yaml:"tls"`
	SNI            string   `yaml:"sni"`
	Fingerprint    string   `yaml:"fingerprint"`
	ALPN           []string `yaml:"alpn"`
	SkipCertVerify bool     `yaml:"skip-cert-verify"`
	ClientCert     string   `yaml:"client-cert"`
	ClientKey      string   `yaml:"client-key"`

	// ── 通用选项 ─────────────────────────────────────────────────────
	// 强制使用 UDP
	UDP bool `yaml:"udp"`
	// 指定出站接口
	Interface string `yaml:"interface-name"`
	// 节点备注
	Comments string `yaml:"comments"`
}

// WSOptions WebSocket 传输选项
type WSOptions struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	// 是否开启 v2ray-plugin 兼容
	MaxEarlyData        int    `yaml:"max-early-data"`
	EarlyDataHeaderName string `yaml:"early-data-header-name"`
}

// GRPCOptions gRPC 传输选项
type GRPCOptions struct {
	ServiceName string `yaml:"grpc-service-name"`
}

// H2Options HTTP/2 传输选项
type H2Options struct {
	Host []string `yaml:"host"`
	Path string   `yaml:"path"`
}

// HTTPOptions HTTP 传输选项
type HTTPOptions struct {
	Method  string              `yaml:"method"`
	Path    []string            `yaml:"path"`
	Headers map[string][]string `yaml:"headers"`
}

// -----------------------------------------------------------------------------
// 代理组配置
// -----------------------------------------------------------------------------

// ProxyGroupConfig 代理分组配置
type ProxyGroupConfig struct {
	Name     string   `yaml:"name"`
	// 分组类型: select / url-test / fallback / load-balance / relay
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`

	// URLTest / Fallback 测速配置
	URL      string        `yaml:"url"`
	Interval time.Duration `yaml:"interval"`
	Lazy     bool          `yaml:"lazy"`
	Timeout  time.Duration `yaml:"timeout"`
	Tolerance int          `yaml:"tolerance"`

	// LoadBalance 策略: consistent-hashing / round-robin / sticky-sessions
	Strategy string `yaml:"strategy"`

	// 过滤正则（用于从订阅中筛选节点）
	Filter string `yaml:"filter"`
}

// -----------------------------------------------------------------------------
// 订阅配置
// -----------------------------------------------------------------------------

// Subscriber 订阅源配置
type Subscriber struct {
	Name     string        `yaml:"name"`
	URL      string        `yaml:"url"`
	Interval time.Duration `yaml:"interval"`
	// 自定义 User-Agent
	UserAgent string `yaml:"user-agent"`
	// 代理下载（使用哪个出站下载）
	Proxy     string `yaml:"proxy"`
}

// -----------------------------------------------------------------------------
// 配置加载
// -----------------------------------------------------------------------------

// defaults 设置默认值
func defaults(cfg *Config) {
	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "info"
	}
	if cfg.General.Mode == "" {
		cfg.General.Mode = "rule"
	}
	if cfg.General.BindAddress == "" {
		cfg.General.BindAddress = "127.0.0.1"
	}
	if cfg.General.TestURL == "" {
		cfg.General.TestURL = "https://www.gstatic.com/generate_204"
	}
	if cfg.General.TestTimeout == 0 {
		cfg.General.TestTimeout = 5 * time.Second
	}
	if cfg.DNS.FakeIPRange == "" {
		cfg.DNS.FakeIPRange = "198.18.0.0/15"
	}
	if cfg.TUN.Stack == "" {
		cfg.TUN.Stack = "mixed"
	}
	if cfg.TUN.Device == "" {
		cfg.TUN.Device = "run0"
	}
}

// validate 验证配置合法性
func validate(cfg *Config) error {
	mode := cfg.General.Mode
	if mode != "rule" && mode != "global" && mode != "direct" {
		return fmt.Errorf("mode 必须是 rule / global / direct，当前: %s", mode)
	}
	if cfg.General.Port < 0 || cfg.General.Port > 65535 {
		return fmt.Errorf("port 超出范围: %d", cfg.General.Port)
	}
	if cfg.General.SocksPort < 0 || cfg.General.SocksPort > 65535 {
		return fmt.Errorf("socks-port 超出范围: %d", cfg.General.SocksPort)
	}
	if cfg.General.MixedPort < 0 || cfg.General.MixedPort > 65535 {
		return fmt.Errorf("mixed-port 超出范围: %d", cfg.General.MixedPort)
	}
	return nil
}

// Load 从文件加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}
	return Parse(data)
}

// Parse 从 YAML 字节解析配置
func Parse(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析 YAML 失败: %w", err)
	}
	defaults(cfg)
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("配置校验失败: %w", err)
	}
	return cfg, nil
}

// ParseProxy 将 map 解析为 ProxyConfig
func ParseProxy(raw map[string]any) (*ProxyConfig, error) {
	data, err := yaml.Marshal(raw)
	if err != nil {
		return nil, err
	}
	p := &ProxyConfig{}
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		return nil, fmt.Errorf("代理节点缺少 name 字段")
	}
	if p.Type == "" {
		return nil, fmt.Errorf("代理节点 %s 缺少 type 字段", p.Name)
	}
	return p, nil
}

// ParseGroup 将 map 解析为 ProxyGroupConfig
func ParseGroup(raw map[string]any) (*ProxyGroupConfig, error) {
	data, err := yaml.Marshal(raw)
	if err != nil {
		return nil, err
	}
	g := &ProxyGroupConfig{}
	if err := yaml.Unmarshal(data, g); err != nil {
		return nil, err
	}
	if g.Name == "" {
		return nil, fmt.Errorf("代理组缺少 name 字段")
	}
	return g, nil
}
