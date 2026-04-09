package core

import (
	"fmt"
	"strings"
	"sync"

	"github.com/run-proxy/run/adapter"
	"github.com/run-proxy/run/proxy"
	"github.com/run-proxy/run/rules"
)

// Router 按模式+规则选择最终出站节点。
type Router struct {
	mu       sync.RWMutex
	mode     string
	rules    []rules.Rule
	adapters map[string]adapter.Proxy
	global   string
}

func NewRouter(mode string, rs []rules.Rule, adapters map[string]adapter.Proxy) *Router {
	r := &Router{
		mode:     strings.ToLower(mode),
		rules:    rs,
		adapters: adapters,
	}
	if _, ok := adapters["🚀 节点选择"]; ok {
		r.global = "🚀 节点选择"
	} else {
		for k := range adapters {
			if k != "DIRECT" && k != "REJECT" {
				r.global = k
				break
			}
		}
	}
	return r
}

func (r *Router) Pick(m *proxy.Metadata) adapter.Proxy {
	r.mu.RLock()
	defer r.mu.RUnlock()

	switch r.mode {
	case "direct":
		if p, ok := r.adapters["DIRECT"]; ok {
			return p
		}
	case "global":
		if p, ok := r.adapters[r.global]; ok {
			return p
		}
	}

	for _, rule := range r.rules {
		if rule.Match(m) {
			if p, ok := r.adapters[rule.Adapter()]; ok {
				return p
			}
		}
	}

	if p, ok := r.adapters["DIRECT"]; ok {
		return p
	}
	for _, p := range r.adapters {
		return p
	}
	return nil
}

func (r *Router) SetMode(mode string) error {
	mode = strings.ToLower(mode)
	if mode != "rule" && mode != "global" && mode != "direct" {
		return fmt.Errorf("unsupported mode: %s", mode)
	}
	r.mu.Lock()
	r.mode = mode
	r.mu.Unlock()
	return nil
}

func (r *Router) Mode() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mode
}

func (r *Router) Rules() []rules.Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]rules.Rule, len(r.rules))
	copy(out, r.rules)
	return out
}
