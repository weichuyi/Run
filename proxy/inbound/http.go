// Package inbound 实现 HTTP/HTTPS CONNECT 入站代理
package inbound

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/run-proxy/run/common/log"
	"github.com/run-proxy/run/proxy"
)

// HTTPServer HTTP 代理入站（支持 CONNECT 隧道和普通 HTTP 转发）
type HTTPServer struct {
	listener net.Listener
	handler  proxy.Handler
	username string
	password string
}

// NewHTTPServer 创建 HTTP 代理服务器
func NewHTTPServer(addr string, handler proxy.Handler, username, password string) (*HTTPServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("HTTP 代理监听 %s 失败: %w", addr, err)
	}
	log.Infof("[HTTP] 监听 %s", addr)
	return &HTTPServer{
		listener: ln,
		handler:  handler,
		username: username,
		password: password,
	}, nil
}

// Serve 开始接受连接
func (s *HTTPServer) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

// Close 关闭服务器
func (s *HTTPServer) Close() error {
	return s.listener.Close()
}

func (s *HTTPServer) handleConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("[HTTP] panic: %v", r)
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		conn.Close()
		return
	}

	// 认证检查
	if s.username != "" {
		if !s.checkAuth(req) {
			resp := &http.Response{
				StatusCode: http.StatusProxyAuthRequired,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     http.Header{"Proxy-Authenticate": []string{`Basic realm="Run"`}},
			}
			resp.Write(conn)
			conn.Close()
			return
		}
	}

	_ = conn.SetDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		s.handleCONNECT(conn, req)
	} else {
		s.handleHTTP(conn, br, req)
	}
}

// handleCONNECT 处理 HTTPS CONNECT 隧道
func (s *HTTPServer) handleCONNECT(conn net.Conn, req *http.Request) {
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		// 没有端口，默认 443
		host = req.Host
		portStr = "443"
	}

	port, err := parsePort(portStr)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.Close()
		return
	}

	metadata := buildMetadata(conn, host, uint16(port))
	metadata.InboundType = proxy.InboundHTTP

	// 回复 200 Connection Established
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	log.Debugf("[HTTP] CONNECT %s → %s", conn.RemoteAddr(), metadata.Destination())
	s.handler.HandleTCP(conn, metadata)
}

// handleHTTP 处理普通 HTTP 请求（非 CONNECT）
func (s *HTTPServer) handleHTTP(conn net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.URL.Hostname()
	portStr := req.URL.Port()
	if portStr == "" {
		portStr = "80"
	}

	port, err := parsePort(portStr)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.Close()
		return
	}

	metadata := buildMetadata(conn, host, uint16(port))
	metadata.InboundType = proxy.InboundHTTP

	// 将原始请求重新写入管道，以便出站可以转发
	pr, pw := net.Pipe()
	go func() {
		defer pw.Close()
		// 移除 Proxy-* 头并写入请求
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")
		req.RequestURI = req.URL.RequestURI()
		req.WriteProxy(pw)
	}()

	// 用管道 + 原始连接组合为一个双向连接
	wrapped := &httpConn{Conn: conn, reader: pr}

	log.Debugf("[HTTP] %s %s → %s", req.Method, req.URL, metadata.Destination())
	s.handler.HandleTCP(wrapped, metadata)
}

// checkAuth 验证 Proxy-Authorization 头
func (s *HTTPServer) checkAuth(req *http.Request) bool {
	auth := req.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[0] == s.username && parts[1] == s.password
}

// httpConn 将普通 HTTP 请求包装为 net.Conn（用于 HTTP 代理转发）
type httpConn struct {
	net.Conn
	reader net.Conn
}

func (c *httpConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *httpConn) Write(b []byte) (int, error) { return c.Conn.Write(b) }

func buildMetadata(conn net.Conn, host string, port uint16) *proxy.Metadata {
	m := &proxy.Metadata{
		Network: proxy.TCP,
		DstPort: port,
	}
	if ip := net.ParseIP(host); ip != nil {
		m.DstIP = ip
	} else {
		m.Host = host
	}
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		m.SrcIP = tcpAddr.IP
		m.SrcPort = uint16(tcpAddr.Port)
	}
	return m
}

func parsePort(s string) (int, error) {
	var port int
	_, err := fmt.Sscanf(s, "%d", &port)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("无效端口: %s", s)
	}
	return port, nil
}
