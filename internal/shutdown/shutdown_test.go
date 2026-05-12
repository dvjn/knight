package shutdown

import (
	"context"
	"testing"
	"time"
)

func TestNewAndRegister(t *testing.T) {
	manager := New(5 * time.Second)

	if manager.timeout != 5*time.Second {
		t.Fatalf("timeout = %v, want 5s", manager.timeout)
	}
	if len(manager.shutdownFuncs) != 0 {
		t.Fatalf("len(shutdownFuncs) = %d, want 0", len(manager.shutdownFuncs))
	}

	manager.Register(func(context.Context) error { return nil })
	manager.Register(func(context.Context) error { return nil })

	if len(manager.shutdownFuncs) != 2 {
		t.Fatalf("len(shutdownFuncs) = %d, want 2", len(manager.shutdownFuncs))
	}
}
