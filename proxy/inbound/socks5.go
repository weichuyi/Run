// Package inbound 实现 SOCKS5 入站代理协议
package inbound

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	log "github.com/run-proxy/run/common/log"
	"github.com/run-proxy/run/proxy"
)

// SOCKS5 协议常量
const (
	socks5Version = 0x05

	// 认证方式
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	// 命令
	cmdConnect   = 0x01
	cmdBind      = 0x02
	cmdUDPAssoc  = 0x03

	// 地址类型
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// 应答码
	repSuccess            = 0x00
	repGeneralFailure     = 0x01
	repRulesetFailure     = 0x02
	repNetworkUnreachable = 0x03
	repHostUnreachable    = 0x04
	repConnRefused        = 0x05
	repTTLExpired         = 0x06
	repCmdNotSupported    = 0x07
	repAtypNotSupported   = 0x08
)

// SOCKS5Server SOCKS5 入站服务器
type SOCKS5Server struct {
	listener  net.Listener
	handler   proxy.Handler
	username  string
	password  string
	udpEnable bool
}

// NewSOCKS5Server 创建 SOCKS5 服务器
func NewSOCKS5Server(addr string, handler proxy.Handler, username, password string) (*SOCKS5Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 监听 %s 失败: %w", addr, err)
	}
	log.Infof("[SOCKS5] 监听 %s", addr)
	return &SOCKS5Server{
		listener:  ln,
		handler:   handler,
		username:  username,
		password:  password,
		udpEnable: true,
	}, nil
}

// Serve 开始接受连接
func (s *SOCKS5Server) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

// Close 关闭服务器
func (s *SOCKS5Server) Close() error {
	return s.listener.Close()
}

func (s *SOCKS5Server) handleConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("[SOCKS5] panic: %v", r)
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. 握手：协商认证方式
	if err := s.handshake(conn); err != nil {
		log.Debugf("[SOCKS5] 握手失败 %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	// 2. 读取请求
	metadata, err := s.readRequest(conn)
	if err != nil {
		log.Debugf("[SOCKS5] 读取请求失败: %v", err)
		conn.Close()
		return
	}

	// 设置来源信息
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		metadata.SrcIP = tcpAddr.IP
		metadata.SrcPort = uint16(tcpAddr.Port)
	}
	metadata.InboundType = proxy.InboundSOCKS5

	// 清除超时
	_ = conn.SetDeadline(time.Time{})

	// 3. 发送成功应答
	reply := []byte{socks5Version, repSuccess, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		conn.Close()
		return
	}

	log.Debugf("[SOCKS5] %s → %s", conn.RemoteAddr(), metadata.Destination())

	// 4. 交给 Tunnel 处理
	s.handler.HandleTCP(conn, metadata)
}

// handshake 进行 SOCKS5 握手（认证协商）
func (s *SOCKS5Server) handshake(conn net.Conn) error {
	// 读取版本和方法数
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("不支持的 SOCKS 版本: %d", header[0])
	}

	// 读取方法列表
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// 选择认证方式
	if s.username != "" {
		// 需要密码认证
		hasPassword := false
		for _, m := range methods {
			if m == authPassword {
				hasPassword = true
				break
			}
		}
		if !hasPassword {
			conn.Write([]byte{socks5Version, authNoAccept})
			return fmt.Errorf("客户端不支持密码认证")
		}
		conn.Write([]byte{socks5Version, authPassword})
		return s.authenticate(conn)
	}

	// 无需认证
	conn.Write([]byte{socks5Version, authNone})
	return nil
}

// authenticate 执行用户名/密码认证（RFC 1929）
func (s *SOCKS5Server) authenticate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	// header[0] = 0x01 (sub-negotiation version), header[1] = username length
	ulen := int(header[1])
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}
	password := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	if string(username) == s.username && string(password) == s.password {
		conn.Write([]byte{0x01, 0x00}) // 成功
		return nil
	}
	conn.Write([]byte{0x01, 0x01}) // 失败
	return fmt.Errorf("认证失败")
}

// readRequest 读取 SOCKS5 请求，返回连接元数据
func (s *SOCKS5Server) readRequest(conn net.Conn) (*proxy.Metadata, error) {
	// VER CMD RSV ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("无效的 SOCKS5 版本")
	}
	if header[1] != cmdConnect {
		// 仅支持 CONNECT
		conn.Write([]byte{socks5Version, repCmdNotSupported, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("不支持的命令: %d", header[1])
	}

	metadata := &proxy.Metadata{Network: proxy.TCP}

	// 解析目标地址
	switch header[3] {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		metadata.DstIP = net.IP(ip)

	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		metadata.DstIP = net.IP(ip)

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		metadata.Host = string(domain)

	default:
		conn.Write([]byte{socks5Version, repAtypNotSupported, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("不支持的地址类型: %d", header[3])
	}

	// 端口（2字节大端）
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	metadata.DstPort = binary.BigEndian.Uint16(portBuf)

	return metadata, nil
}

// WriteSOCKS5Address 将地址写入 SOCKS5 格式
func WriteSOCKS5Address(w io.Writer, host string, port int) error {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			_, err := w.Write(append([]byte{atypIPv4}, append(ip4, byte(port>>8), byte(port))...))
			return err
		}
		ip6 := ip.To16()
		_, err := w.Write(append([]byte{atypIPv6}, append(ip6, byte(port>>8), byte(port))...))
		return err
	}
	// 域名
	hostBytes := []byte(host)
	buf := make([]byte, 0, 1+1+len(hostBytes)+2)
	buf = append(buf, atypDomain, byte(len(hostBytes)))
	buf = append(buf, hostBytes...)
	buf = append(buf, byte(port>>8), byte(port))
	_, err := w.Write(buf)
	return err
}

// PortToString 端口转字符串
func PortToString(port uint16) string {
	return strconv.Itoa(int(port))
}
