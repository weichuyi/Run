// Package buf 提供高性能的缓冲池，减少 GC 压力
package buf

import (
	"io"
	"sync"
)

const (
	// DefaultSize 默认缓冲区大小（16KB，适合大多数网络传输）
	DefaultSize = 16 * 1024
	// UDPSize UDP 分片最大缓冲区大小
	UDPSize = 64 * 1024
)

// pool16k 是 16KB 缓冲区的对象池
var pool16k = sync.Pool{
	New: func() any {
		b := make([]byte, DefaultSize)
		return &b
	},
}

// poolUDP 是 UDP 专用大缓冲区对象池
var poolUDP = sync.Pool{
	New: func() any {
		b := make([]byte, UDPSize)
		return &b
	},
}

// Get 从池中获取一个 16KB 缓冲区
func Get() []byte {
	return *pool16k.Get().(*[]byte)
}

// Put 将缓冲区归还到池中
func Put(b []byte) {
	if cap(b) >= DefaultSize {
		b = b[:cap(b)]
		pool16k.Put(&b)
	}
}

// GetUDP 从池中获取 UDP 专用大缓冲区
func GetUDP() []byte {
	return *poolUDP.Get().(*[]byte)
}

// PutUDP 将 UDP 缓冲区归还
func PutUDP(b []byte) {
	if cap(b) >= UDPSize {
		b = b[:cap(b)]
		poolUDP.Put(&b)
	}
}

// Relay 进行双向数据中继，直到任一端关闭。
// 返回 (上行字节数, 下行字节数)
func Relay(dst io.Writer, src io.Reader) (int64, error) {
	buf := Get()
	defer Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

// BiRelay 同时在两个 ReadWriter 之间进行全双工数据中继。
// 返回的两个 int64 分别代表 a→b 和 b→a 的字节数。
func BiRelay(a, b io.ReadWriter) (int64, int64) {
	type result struct {
		n   int64
		err error
	}
	ch := make(chan result, 1)

	go func() {
		n, err := Relay(b, a)
		ch <- result{n, err}
	}()

	n2, _ := Relay(a, b)
	r := <-ch
	return r.n, n2
}
