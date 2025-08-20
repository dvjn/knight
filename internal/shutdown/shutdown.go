package shutdown

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type ShutdownFunc func(context.Context) error

type Manager struct {
	shutdownFuncs []ShutdownFunc
	timeout       time.Duration
}

func New(timeout time.Duration) *Manager {
	return &Manager{
		shutdownFuncs: make([]ShutdownFunc, 0),
		timeout:       timeout,
	}
}

func (m *Manager) Register(fn ShutdownFunc) {
	m.shutdownFuncs = append(m.shutdownFuncs, fn)
}

func (m *Manager) WaitForSignal() context.Context {
	sigCtx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer stop()

	<-sigCtx.Done()
	log.Println("shutting down")

	return sigCtx
}

func (m *Manager) Shutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	for _, shutdownFunc := range m.shutdownFuncs {
		if err := shutdownFunc(shutdownCtx); err != nil {
			log.Println("failed to shutdown server", err)
		}
	}

	log.Println("shutdown complete")
	os.Exit(0)
}

func (m *Manager) GracefulShutdown() {
	m.WaitForSignal()
	m.Shutdown()
}
