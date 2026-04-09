package core

import (
	"context"
	"io"
	"net"
	"time"

	log "github.com/run-proxy/run/common/log"
	"github.com/run-proxy/run/dns"
	"github.com/run-proxy/run/proxy"
)

// Tunnel 实现入站处理并转发到路由选出的出站。
type Tunnel struct {
	router   *Router
	resolver *dns.DNSResolver
}

func NewTunnel(router *Router, resolver *dns.DNSResolver) *Tunnel {
	return &Tunnel{router: router, resolver: resolver}
}

func (t *Tunnel) HandleTCP(in net.Conn, m *proxy.Metadata) {
	defer in.Close()

	if m.DstIP != nil && t.resolver != nil && t.resolver.FakeIPEnabled() {
		if domain, ok := t.resolver.RealDomainFromFakeIP(m.DstIP); ok {
			m.Host = domain
		}
	}

	outbound := t.router.Pick(m)
	if outbound == nil {
		log.Warnf("[Tunnel] 无可用出站: %s", m.Destination())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	out, err := outbound.DialContext(ctx, m)
	cancel()
	if err != nil {
		log.Warnf("[Tunnel] 出站 %s 拨号失败 %s: %v", outbound.Name(), m.Destination(), err)
		return
	}
	defer out.Close()

	log.Debugf("[Tunnel] %s -> %s via %s", m.Source(), m.Destination(), outbound.Name())

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(out, in)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(in, out)
		errCh <- err
	}()
	<-errCh
}

func (t *Tunnel) HandleUDP(_ net.PacketConn, m *proxy.Metadata) {
	log.Debugf("[Tunnel] UDP not implemented yet: %s", m.Destination())
}
