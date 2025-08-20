package http

import (
	"context"
	"log"
	"net"
	"net/http"

	"github.com/dvjn/knight/internal/config"
)

type server struct {
	cfg    *config.Config
	server *http.Server
}

func Server(cfg *config.Config, h *handler) *server {
	return &server{
		cfg: cfg,
		server: &http.Server{
			Addr:    net.JoinHostPort(cfg.HTTPHost, cfg.HTTPPort),
			Handler: h.Handler(),
		},
	}
}

func (s *server) ListenAndServe() error {
	log.Println("starting http server on port", s.cfg.HTTPPort)
	err := s.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *server) Shutdown(ctx context.Context) error {
	log.Println("stopping http server")
	return s.server.Shutdown(ctx)
}
