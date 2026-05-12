package ssh

import (
	"context"
	"log"
	"net"

	"github.com/gliderlabs/ssh"

	"github.com/dvjn/knight/internal/config"
)

type server struct {
	cfg    *config.Config
	server *ssh.Server
}

func Server(cfg *config.Config, h *handler) *server {
	return &server{
		cfg: cfg,
		server: &ssh.Server{
			Addr:        net.JoinHostPort(cfg.SSHHost, cfg.SSHPort),
			Banner:      "Welcome to knight!\n",
			HostSigners: []ssh.Signer{cfg.SSHSigner},
			IdleTimeout: cfg.SSHIdleTimeout,
			MaxTimeout:  cfg.SSHMaxTimeout,
			ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
				log.Println("ssh connection", conn.RemoteAddr())
				return conn
			},
			PublicKeyHandler: h.PublicKeyHandler,
			Handler:          h.Handler,
		},
	}
}

func (s *server) ListenAndServe() error {
	log.Println("starting ssh server on port", s.cfg.SSHPort)
	err := s.server.ListenAndServe()
	if err != nil && err != ssh.ErrServerClosed {
		return err
	}
	return nil
}

func (s *server) Shutdown(ctx context.Context) error {
	log.Println("stopping ssh server")
	return s.server.Shutdown(ctx)
}
