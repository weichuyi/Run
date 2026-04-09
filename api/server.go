package api

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/run-proxy/run/adapter"
)

// Runtime 是 API 与核心引擎交互的最小接口。
type Runtime interface {
	Version() string
	Mode() string
	SetMode(string) error
	Proxies() map[string]adapter.Proxy
	SelectProxy(groupName, proxyName string) error
}

type Server struct {
	engine Runtime
	http   *http.Server
}

func New(addr, secret string, engine Runtime) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	if secret != "" {
		r.Use(func(c *gin.Context) {
			auth := c.GetHeader("Authorization")
			if auth != "Bearer "+secret {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Next()
		})
	}

	s := &Server{engine: engine}
	r.GET("/version", s.version)
	r.GET("/configs", s.getConfig)
	r.PATCH("/configs", s.patchConfig)
	r.GET("/proxies", s.getProxies)
	r.PUT("/proxies/:name", s.putProxy)

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
