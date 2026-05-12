package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dvjn/knight/internal/config"
	"github.com/dvjn/knight/internal/git"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/bcrypt"
)

func TestHandlerUnauthorized(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/repo.git/info/refs?service=git-upload-pack", nil)
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="Git"` {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, `Basic realm="Git"`)
	}
}

func TestHandleInfoRefsMissingService(t *testing.T) {
	h := newTestHandler(t)

	req := newAuthedRequest(http.MethodGet, "/repo.git/info/refs", nil)
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "Please upgrade your git client.") {
		t.Fatalf("body = %q, want upgrade message", rec.Body.String())
	}
}

func TestHandleInfoRefsInvalidRepo(t *testing.T) {
	h := newTestHandler(t)

	req := newAuthedRequest(http.MethodGet, "/repo/info/refs?service=git-upload-pack", nil)
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleInfoRefsUploadPackRepoNotFound(t *testing.T) {
	h := newTestHandler(t)

	req := newAuthedRequest(http.MethodGet, "/repo.git/info/refs?service=git-upload-pack", nil)
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleInfoRefsUploadPackSuccess(t *testing.T) {
	h := newTestHandler(t)
	repo, err := h.git.Repo("repo.git")
	if err != nil {
		t.Fatalf("Repo() error = %v", err)
	}
	if err := repo.Create(h.cfg.InitialBranch); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	req := newAuthedRequest(http.MethodGet, "/repo.git/info/refs?service=git-upload-pack", nil)
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-git-upload-pack-advertisement" {
		t.Fatalf("Content-Type = %q, want upload-pack advertisement", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", got)
	}
	if !strings.HasPrefix(rec.Body.String(), "001e# service=git-upload-pack\n0000") {
		t.Fatalf("body prefix = %q, want upload-pack advertisement preamble", rec.Body.String())
	}
}

func TestHandleInfoRefsReceivePackCreatesRepo(t *testing.T) {
	h := newTestHandler(t)
	repo, err := h.git.Repo("repo.git")
	if err != nil {
		t.Fatalf("Repo() error = %v", err)
	}

	req := newAuthedRequest(http.MethodGet, "/repo.git/info/refs?service=git-receive-pack", nil)
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !repo.Exists() {
		t.Fatal("repo was not created")
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-git-receive-pack-advertisement" {
		t.Fatalf("Content-Type = %q, want receive-pack advertisement", got)
	}
	if !strings.HasPrefix(rec.Body.String(), "001f# service=git-receive-pack\n0000") {
		t.Fatalf("body prefix = %q, want receive-pack advertisement preamble", rec.Body.String())
	}
}

func TestHandleUploadPackValidation(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name        string
		contentType string
		wantStatus  int
		wantBody    string
	}{
		{name: "missing content type", wantStatus: http.StatusBadRequest, wantBody: "content type is required"},
		{name: "unsupported content type", contentType: "text/plain", wantStatus: http.StatusBadRequest, wantBody: "unsupported content type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newAuthedRequest(http.MethodPost, "/repo.git/git-upload-pack", strings.NewReader("body"))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()

			h.Handler().ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want substring %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestHandleUploadPackInvalidRepo(t *testing.T) {
	h := newTestHandler(t)

	req := newAuthedRequest(http.MethodPost, "/repo/git-upload-pack", strings.NewReader("body"))
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleUploadPackInvalidGzip(t *testing.T) {
	h := newTestHandler(t)

	req := newAuthedRequest(http.MethodPost, "/repo.git/git-upload-pack", strings.NewReader("not-gzip"))
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), "failed to create gzip reader") {
		t.Fatalf("body = %q, want gzip reader error", rec.Body.String())
	}
}

func TestHandleReceivePackValidation(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name        string
		contentType string
		wantStatus  int
		wantBody    string
	}{
		{name: "missing content type", wantStatus: http.StatusBadRequest, wantBody: "content type is required"},
		{name: "unsupported content type", contentType: "text/plain", wantStatus: http.StatusBadRequest, wantBody: "unsupported content type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newAuthedRequest(http.MethodPost, "/repo.git/git-receive-pack", strings.NewReader("body"))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()

			h.Handler().ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want substring %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestHandleReceivePackInvalidRepo(t *testing.T) {
	h := newTestHandler(t)

	req := newAuthedRequest(http.MethodPost, "/repo/git-receive-pack", strings.NewReader("body"))
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleReceivePackInvalidGzipCreatesRepo(t *testing.T) {
	h := newTestHandler(t)
	repoPath := filepath.Join(h.cfg.ReposPath, "repo.git")

	req := newAuthedRequest(http.MethodPost, "/repo.git/git-receive-pack", strings.NewReader("not-gzip"))
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()

	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if _, err := os.Stat(repoPath); err != nil {
		t.Fatalf("repo was not created before gzip failure: %v", err)
	}
}

func TestServerConstructor(t *testing.T) {
	h := newTestHandler(t)
	s := Server(h.cfg, h)

	if s.server.Addr != "127.0.0.1:8080" {
		t.Fatalf("server.Addr = %q, want 127.0.0.1:8080", s.server.Addr)
	}
	if s.server.Handler == nil {
		t.Fatal("server.Handler = nil")
	}
}

func newTestHandler(t *testing.T) *handler {
	t.Helper()

	reposPath := filepath.Join(t.TempDir(), "repos")
	if err := os.MkdirAll(reposPath, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	cfg := &config.Config{
		ReposPath:     reposPath,
		InitialBranch: "main",
		HTTPHost:      "127.0.0.1",
		HTTPPort:      "8080",
		HTPasswd:      testHTPasswdFile(t, "dev", "secret"),
	}

	return Handler(cfg, git.New(cfg))
}

func newAuthedRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.SetBasicAuth("dev", "secret")
	return req
}

func testHTPasswdFile(t *testing.T, username, password string) *htpasswd.File {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}

	file, err := htpasswd.NewFromReader(
		strings.NewReader(username+":"+string(hash)+"\n"),
		htpasswd.DefaultSystems,
		nil,
	)
	if err != nil {
		t.Fatalf("NewFromReader() error = %v", err)
	}

	return file
}
