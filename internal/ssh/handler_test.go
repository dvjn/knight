package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dvjn/knight/internal/config"
	"github.com/dvjn/knight/internal/git"
	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func TestPublicKeyHandler(t *testing.T) {
	authorized := testAuthorizedPublicKey(t)
	unauthorized := testAuthorizedPublicKey(t)
	h := Handler(&config.Config{AuthorizedKeys: []gossh.PublicKey{authorized}}, nil)

	if !h.PublicKeyHandler(nil, authorized) {
		t.Fatal("PublicKeyHandler() = false for authorized key, want true")
	}
	if h.PublicKeyHandler(nil, unauthorized) {
		t.Fatal("PublicKeyHandler() = true for unauthorized key, want false")
	}
}

func TestHandlerInvalidCommand(t *testing.T) {
	h := Handler(&config.Config{}, git.New(&config.Config{ReposPath: t.TempDir()}))
	sess := newFakeSession([]string{"git-upload-pack"})

	h.Handler(sess)

	if !sess.exited || sess.exitCode != 1 {
		t.Fatalf("exit = (%v, %d), want (true, 1)", sess.exited, sess.exitCode)
	}
	if !strings.Contains(sess.stderr.String(), "invalid command") {
		t.Fatalf("stderr = %q, want invalid command", sess.stderr.String())
	}
}

func TestHandlerInvalidRepoName(t *testing.T) {
	cfg := &config.Config{ReposPath: t.TempDir()}
	h := Handler(cfg, git.New(cfg))
	sess := newFakeSession([]string{"git-upload-pack", "/invalid"})

	h.Handler(sess)

	if !sess.exited || sess.exitCode != 1 {
		t.Fatalf("exit = (%v, %d), want (true, 1)", sess.exited, sess.exitCode)
	}
	if !strings.Contains(sess.stderr.String(), "invalid repo name") {
		t.Fatalf("stderr = %q, want invalid repo name", sess.stderr.String())
	}
}

func TestHandlerUnsupportedOperation(t *testing.T) {
	cfg := &config.Config{ReposPath: t.TempDir()}
	h := Handler(cfg, git.New(cfg))
	sess := newFakeSession([]string{"git-unknown", "/repo.git"})

	h.Handler(sess)

	if !sess.exited || sess.exitCode != 1 {
		t.Fatalf("exit = (%v, %d), want (true, 1)", sess.exited, sess.exitCode)
	}
	if !strings.Contains(sess.stderr.String(), "unsupported git operation") {
		t.Fatalf("stderr = %q, want unsupported operation", sess.stderr.String())
	}
}

func TestHandlerUploadPackRepoNotFound(t *testing.T) {
	cfg := &config.Config{ReposPath: t.TempDir()}
	h := Handler(cfg, git.New(cfg))
	sess := newFakeSession([]string{"git-upload-pack", "/repo.git"})

	h.Handler(sess)

	if !sess.exited || sess.exitCode != 1 {
		t.Fatalf("exit = (%v, %d), want (true, 1)", sess.exited, sess.exitCode)
	}
	if !strings.Contains(sess.stderr.String(), "repo does not exist") {
		t.Fatalf("stderr = %q, want repo does not exist", sess.stderr.String())
	}
}

func TestServerConstructor(t *testing.T) {
	cfg := &config.Config{
		SSHHost:   "127.0.0.1",
		SSHPort:   "2222",
		SSHSigner: testSigner(t),
	}
	h := Handler(cfg, git.New(&config.Config{ReposPath: filepath.Join(t.TempDir(), "repos")}))

	s := Server(cfg, h)

	if s.server.Addr != "127.0.0.1:2222" {
		t.Fatalf("server.Addr = %q, want 127.0.0.1:2222", s.server.Addr)
	}
	if s.server.Banner != "Welcome to knight!\n" {
		t.Fatalf("server.Banner = %q, want welcome banner", s.server.Banner)
	}
	if len(s.server.HostSigners) != 1 {
		t.Fatalf("len(server.HostSigners) = %d, want 1", len(s.server.HostSigners))
	}
	if s.server.PublicKeyHandler == nil || s.server.Handler == nil {
		t.Fatal("server handlers were not configured")
	}
}

type fakeSession struct {
	command  []string
	stdin    *bytes.Reader
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	exitCode int
	exited   bool
	ctx      gliderssh.Context
}

func newFakeSession(command []string) *fakeSession {
	return &fakeSession{
		command: command,
		stdin:   bytes.NewReader(nil),
		ctx:     &fakeContext{Context: context.Background()},
	}
}

func (s *fakeSession) Read(p []byte) (int, error)                     { return s.stdin.Read(p) }
func (s *fakeSession) Write(p []byte) (int, error)                    { return s.stdout.Write(p) }
func (s *fakeSession) Close() error                                   { return nil }
func (s *fakeSession) CloseWrite() error                              { return nil }
func (s *fakeSession) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (s *fakeSession) Stderr() io.ReadWriter                          { return &s.stderr }
func (s *fakeSession) User() string                                   { return "" }
func (s *fakeSession) RemoteAddr() net.Addr                           { return dummyAddr("remote") }
func (s *fakeSession) LocalAddr() net.Addr                            { return dummyAddr("local") }
func (s *fakeSession) Environ() []string                              { return nil }
func (s *fakeSession) Exit(code int) error {
	s.exited = true
	s.exitCode = code
	return nil
}
func (s *fakeSession) Command() []string                          { return append([]string(nil), s.command...) }
func (s *fakeSession) RawCommand() string                         { return strings.Join(s.command, " ") }
func (s *fakeSession) Subsystem() string                          { return "" }
func (s *fakeSession) PublicKey() gliderssh.PublicKey             { return nil }
func (s *fakeSession) Context() gliderssh.Context                 { return s.ctx }
func (s *fakeSession) Permissions() gliderssh.Permissions         { return gliderssh.Permissions{} }
func (s *fakeSession) Pty() (gliderssh.Pty, <-chan gliderssh.Window, bool) {
	return gliderssh.Pty{}, nil, false
}
func (s *fakeSession) Signals(chan<- gliderssh.Signal) {}
func (s *fakeSession) Break(chan<- bool)               {}

type fakeContext struct {
	context.Context
	sync.Mutex
}

func (c *fakeContext) User() string                         { return "" }
func (c *fakeContext) SessionID() string                    { return "" }
func (c *fakeContext) ClientVersion() string                { return "" }
func (c *fakeContext) ServerVersion() string                { return "" }
func (c *fakeContext) RemoteAddr() net.Addr                 { return dummyAddr("remote") }
func (c *fakeContext) LocalAddr() net.Addr                  { return dummyAddr("local") }
func (c *fakeContext) Permissions() *gliderssh.Permissions  { return &gliderssh.Permissions{} }
func (c *fakeContext) SetValue(key, value interface{}) {}

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func testAuthorizedPublicKey(t *testing.T) gossh.PublicKey {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	key, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}

	return key
}

func testSigner(t *testing.T) gossh.Signer {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}

	return signer
}
