package core

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/run-proxy/run/adapter"
	adaptergroup "github.com/run-proxy/run/adapter/group"
	"github.com/run-proxy/run/adapter/hysteria2"
	"github.com/run-proxy/run/adapter/shadowsocks"
	"github.com/run-proxy/run/adapter/trojan"
	"github.com/run-proxy/run/adapter/vless"
	"github.com/run-proxy/run/adapter/vmess"
	"github.com/run-proxy/run/api"
	log "github.com/run-proxy/run/common/log"
	"github.com/run-proxy/run/config"
	"github.com/run-proxy/run/dns"
	"github.com/run-proxy/run/proxy/inbound"
	"github.com/run-proxy/run/rules"
	"github.com/run-proxy/run/subscription"
)

const version = "1.0.0"

type Engine struct {
	cfg *config.Config

	resolver *dns.DNSResolver
	dnsSrv   *dns.Server
	tunnel   *Tunnel
	router   *Router

	httpIn  *inbound.HTTPServer
	socksIn *inbound.SOCKS5Server
	apiSrv  *api.Server
	subs    *subscription.Manager

	adapters  map[string]adapter.Proxy
	selectors map[string]*adaptergroup.Selector

	mu sync.RWMutex
}

func New(cfg *config.Config) (*Engine, error) {
	e := &Engine{cfg: cfg, adapters: map[string]adapter.Proxy{}, selectors: map[string]*adaptergroup.Selector{}}

	res, err := dns.New(&cfg.DNS, cfg.Hosts)
	if err != nil && cfg.DNS.Enable {
		return nil, err
	}
	e.resolver = res

	if err := e.buildAdapters(); err != nil {
		return nil, err
	}

	ruleset, err := rules.ParseAll(cfg.Rules, &rules.ParseOptions{})
	if err != nil {
		return nil, err
	}
	if len(ruleset) == 0 {
		r, _ := rules.Parse("MATCH,DIRECT", nil)
		ruleset = []rules.Rule{r}
	}
	e.router = NewRouter(cfg.General.Mode, ruleset, e.adapters)
	e.tunnel = NewTunnel(e.router, e.resolver)
	return e, nil
}

func (e *Engine) Start() error {
	if e.cfg.DNS.Enable && e.resolver != nil {
		srv, err := dns.StartServer(e.cfg.DNS.Listen, e.resolver)
		if err != nil {
			return err
		}
		e.dnsSrv = srv
	}

	if e.cfg.General.SocksPort > 0 {
		addr := fmt.Sprintf("%s:%d", e.cfg.General.BindAddress, e.cfg.General.SocksPort)
		s, err := inbound.NewSOCKS5Server(addr, e.tunnel, "", "")
		if err != nil {
			return err
		}
		e.socksIn = s
		go s.Serve()
	}

	if e.cfg.General.Port > 0 {
		addr := fmt.Sprintf("%s:%d", e.cfg.General.BindAddress, e.cfg.General.Port)
		h, err := inbound.NewHTTPServer(addr, e.tunnel, "", "")
		if err != nil {
			return err
		}
		e.httpIn = h
		go h.Serve()
	}

	if e.cfg.General.ExternalController != "" {
		e.apiSrv = api.New(e.cfg.General.ExternalController, e.cfg.General.Secret, e)
		_ = e.apiSrv.Start()
		log.Infof("[API] listening on %s", e.cfg.General.ExternalController)
	}

	if len(e.cfg.Subscribers) > 0 {
		e.subs = subscription.New(e.cfg.Subscribers)
		e.subs.Start()
	}

	for _, p := range e.adapters {
		switch g := p.(type) {
		case *adaptergroup.URLTest:
			g.Start()
		case *adaptergroup.Fallback:
			g.Start()
		}
	}
	return nil
}

func (e *Engine) Stop() {
	if e.socksIn != nil {
		_ = e.socksIn.Close()
	}
	if e.httpIn != nil {
		_ = e.httpIn.Close()
	}
	if e.dnsSrv != nil {
		e.dnsSrv.Close()
	}
	if e.apiSrv != nil {
		_ = e.apiSrv.Stop()
	}
	if e.subs != nil {
		e.subs.Stop()
	}
	for _, p := range e.adapters {
		switch g := p.(type) {
		case *adaptergroup.URLTest:
			g.Stop()
		case *adaptergroup.Fallback:
			g.Stop()
		}
	}
}

func (e *Engine) buildAdapters() error {
	e.adapters["DIRECT"] = adapter.NewDirect(e.cfg.General.Interface)
	e.adapters["REJECT"] = adapter.NewReject()

	for _, raw := range e.cfg.Proxies {
		pc, err := config.ParseProxy(raw)
		if err != nil {
			return err
		}
		p, err := e.newAdapter(pc)
		if err != nil {
			return err
		}
		e.adapters[pc.Name] = p
	}

	for _, raw := range e.cfg.Groups {
		gc, err := config.ParseGroup(raw)
		if err != nil {
			return err
		}
		members := make([]adapter.Proxy, 0, len(gc.Proxies))
		for _, name := range gc.Proxies {
			p, ok := e.adapters[name]
			if !ok {
				log.Warnf("[Group] skip unknown proxy: %s", name)
				continue
			}
			members = append(members, p)
		}
		if len(members) == 0 {
			return fmt.Errorf("group %s has no valid proxies", gc.Name)
		}

		var gp adapter.Proxy
		switch strings.ToLower(gc.Type) {
		case "select":
			s := adaptergroup.NewSelector(gc.Name, members)
			e.selectors[gc.Name] = s
			gp = s
		case "url-test":
			interval := gc.Interval
			if interval <= 0 {
				interval = 300 * time.Second
			}
			timeout := gc.Timeout
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			gp = adaptergroup.NewURLTest(gc.Name, members, gc.URL, interval, timeout, gc.Tolerance, gc.Lazy)
		case "fallback":
			interval := gc.Interval
			if interval <= 0 {
				interval = 180 * time.Second
			}
			timeout := gc.Timeout
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			gp = adaptergroup.NewFallback(gc.Name, members, gc.URL, interval, timeout)
		case "load-balance":
			gp = adaptergroup.NewLoadBalance(gc.Name, members, gc.Strategy)
		default:
			return fmt.Errorf("unsupported group type: %s", gc.Type)
		}
		e.adapters[gc.Name] = gp
	}
	return nil
}

func (e *Engine) newAdapter(pc *config.ProxyConfig) (adapter.Proxy, error) {
	switch strings.ToLower(pc.Type) {
	case "ss", "shadowsocks":
		return shadowsocks.New(pc)
	case "vmess":
		return vmess.New(pc)
	case "vless":
		return vless.New(pc)
	case "trojan":
		return trojan.New(pc)
	case "hysteria2", "hy2":
		return hysteria2.New(pc)
	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", pc.Type)
	}
}

func (e *Engine) Version() string { return version }

func (e *Engine) Mode() string {
	return e.router.Mode()
}

func (e *Engine) SetMode(mode string) error {
	return e.router.SetMode(mode)
}

func (e *Engine) Proxies() map[string]adapter.Proxy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]adapter.Proxy, len(e.adapters))
	for k, v := range e.adapters {
		out[k] = v
	}
	return out
}

func (e *Engine) SelectProxy(groupName, proxyName string) error {
	e.mu.RLock()
	s, ok := e.selectors[groupName]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("group not found or not selector: %s", groupName)
	}
	if !s.Select(proxyName) {
		return fmt.Errorf("proxy not found in group: %s", proxyName)
	}
	return nil
}
