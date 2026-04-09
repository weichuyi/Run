package subscription

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/run-proxy/run/common/log"
	"github.com/run-proxy/run/config"
)

// Manager 定时拉取订阅原文，供后续解析器使用。
type Manager struct {
	mu     sync.RWMutex
	subs   []config.Subscriber
	raw    map[string]string
	stopCh chan struct{}
}

func New(subs []config.Subscriber) *Manager {
	return &Manager{subs: subs, raw: make(map[string]string), stopCh: make(chan struct{})}
}

func (m *Manager) Start() {
	for _, s := range m.subs {
		sub := s
		if sub.Interval <= 0 {
			sub.Interval = 24 * time.Hour
		}
		go m.loop(sub)
	}
}

func (m *Manager) Stop() { close(m.stopCh) }

func (m *Manager) loop(sub config.Subscriber) {
	_ = m.refresh(sub)
	ticker := time.NewTicker(sub.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = m.refresh(sub)
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) refresh(sub config.Subscriber) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return err
	}
	if sub.UserAgent != "" {
		req.Header.Set("User-Agent", sub.UserAgent)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("bad status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	text := string(body)

	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text)); err == nil {
		text = string(decoded)
	}

	m.mu.Lock()
	m.raw[sub.Name] = text
	m.mu.Unlock()

	log.Infof("[Sub] 刷新完成: %s", sub.Name)
	return nil
}

func (m *Manager) Snapshot() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.raw))
	for k, v := range m.raw {
		out[k] = v
	}
	return out
}
