package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ServerConfig 是 HTTP 服务生命周期参数。
type ServerConfig struct {
	Addr            string
	Handler         http.Handler
	Logger          *slog.Logger
	ShutdownTimeout time.Duration
}

// Server 封装带超时防护与优雅停机的 http.Server。
type Server struct {
	srv    *http.Server
	log    *slog.Logger
	ln     net.Listener
	shutTO time.Duration
}

// NewServer 构造服务；ReadHeaderTimeout 等超时用于抵御慢速攻击。
func NewServer(c ServerConfig) *Server {
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = 15 * time.Second
	}
	return &Server{
		srv: &http.Server{
			Addr:              c.Addr,
			Handler:           c.Handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    1 << 20,
			ErrorLog:          nil,
		},
		log:    c.Logger,
		shutTO: c.ShutdownTimeout,
	}
}

// Listen 提前绑定端口，让"端口占用"在启动阶段就失败。
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Addr 返回实际监听地址。
func (s *Server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.srv.Addr
}

// Serve 阻塞运行（在 goroutine 中调用）。
func (s *Server) Serve() error {
	var err error
	if s.ln != nil {
		err = s.srv.Serve(s.ln)
	} else {
		err = s.srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown 优雅停机：停止接收新连接，等待在途请求完成。
func (s *Server) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.shutTO)
	defer cancel()
	if s.log != nil {
		s.log.Info("http_server_shutting_down", "addr", s.Addr())
	}
	return s.srv.Shutdown(ctx)
}
