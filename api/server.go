package api

import (
	_ "embed"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/run-proxy/run/adapter"
)

//go:embed ui/index.html
var dashboardHTML []byte

// ProxyGroupInfo 代理组信息
type ProxyGroupInfo struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now"`
	Members []string `json:"members"`
}

// Runtime 是 API 与核心引擎交互的最小接口。
type Runtime interface {
	Version() string
	Mode() string
	SetMode(string) error
	Proxies() map[string]adapter.Proxy
	SelectProxy(groupName, proxyName string) error
	Groups() []ProxyGroupInfo
	Shutdown()
}

type Server struct {
	engine Runtime
	http   *http.Server
}

func New(addr, secret string, engine Runtime) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{engine: engine}

	// 公开路由（无需认证）
	r.GET("/ui", s.serveUI)

	// API 路由（可选认证）
	api := r.Group("/")
	if secret != "" {
		api.Use(func(c *gin.Context) {
			if c.GetHeader("Authorization") != "Bearer "+secret {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Next()
		})
	}
	api.GET("/version", s.version)
	api.GET("/configs", s.getConfig)
	api.PATCH("/configs", s.patchConfig)
	api.GET("/proxies", s.getProxies)
	api.PUT("/proxies/:name", s.putProxy)
	api.GET("/groups", s.getGroups)
	api.POST("/shutdown", s.shutdown)

	s.http = &http.Server{Addr: addr, Handler: r}
	return s
}

func (s *Server) Start() error {
	go func() {
		_ = s.http.ListenAndServe()
	}()
	return nil
}

func (s *Server) Stop() error {
	return s.http.Close()
}

func (s *Server) version(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": s.engine.Version()})
}

func (s *Server) getConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"mode": s.engine.Mode()})
}

func (s *Server) patchConfig(c *gin.Context) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.engine.SetMode(req.Mode); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) getProxies(c *gin.Context) {
	m := s.engine.Proxies()
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)

	out := make(map[string]any, len(m))
	for _, name := range names {
		p := m[name]
		st := p.Stats()
		out[name] = gin.H{
			"name":     p.Name(),
			"type":     p.Type(),
			"alive":    st.Alive,
			"latency":  st.Latency.Milliseconds(),
			"upload":   st.Upload,
			"download": st.Download,
		}
	}
	c.JSON(http.StatusOK, gin.H{"proxies": out})
}

func (s *Server) putProxy(c *gin.Context) {
	groupName := c.Param("name")
	var req struct {
		Proxy string `json:"proxy"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.engine.SelectProxy(groupName, req.Proxy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) serveUI(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", dashboardHTML)
}

func (s *Server) getGroups(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"groups": s.engine.Groups()})
}

func (s *Server) shutdown(c *gin.Context) {
	c.Status(http.StatusOK)
	go func() {
		time.Sleep(200 * time.Millisecond)
		s.engine.Shutdown()
	}()
}
