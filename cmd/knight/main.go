package main

import (
	"log"
	"time"

	"github.com/dvjn/knight/internal/config"
	"github.com/dvjn/knight/internal/git"
	"github.com/dvjn/knight/internal/http"
	"github.com/dvjn/knight/internal/shutdown"
	"github.com/dvjn/knight/internal/ssh"
)

func main() {
	log.Println("starting knight")

	cfg, err := config.Initialize()
	if err != nil {
		log.Fatal(err)
	}

	git := git.New(cfg)

	shutdown := shutdown.New(10 * time.Second)

	if cfg.EnableHTTP {
		handler := http.Handler(cfg, git)
		server := http.Server(cfg, handler)
		go func() {
			err := server.ListenAndServe()
			if err != nil {
				log.Fatal("http server error", err)
			}
			log.Println("http server stopped")
		}()
		shutdown.Register(server.Shutdown)
	}

	if cfg.EnableSSH {
		handler := ssh.Handler(cfg, git)
		server := ssh.Server(cfg, handler)
		go func() {
			err := server.ListenAndServe()
			if err != nil {
				log.Fatal("ssh server error", err)
			}
			log.Println("ssh server stopped")
		}()
		shutdown.Register(server.Shutdown)
	}

	shutdown.GracefulShutdown()
}
