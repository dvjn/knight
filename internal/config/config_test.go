package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/bcrypt"
	gossh "golang.org/x/crypto/ssh"
)

func TestGetEnv(t *testing.T) {
	t.Setenv("TEST_ENV_VALUE", "configured")

	if got := getEnv("TEST_ENV_VALUE", "default"); got != "configured" {
		t.Fatalf("getEnv() = %q, want configured", got)
	}

	if got := getEnv("TEST_ENV_MISSING", "default"); got != "default" {
		t.Fatalf("getEnv() = %q, want default", got)
	}
}

func TestGetBoolEnv(t *testing.T) {
	t.Setenv("BOOL_TRUE", "true")
	t.Setenv("BOOL_ONE", "1")
	t.Setenv("BOOL_FALSE", "false")
	t.Setenv("BOOL_ZERO", "0")
	t.Setenv("BOOL_OTHER", "anything")

	tests := []struct {
		name         string
		key          string
		defaultValue bool
		want         bool
	}{
		{name: "default true", key: "BOOL_MISSING", defaultValue: true, want: true},
		{name: "default false", key: "BOOL_MISSING_2", defaultValue: false, want: false},
		{name: "true string", key: "BOOL_TRUE", defaultValue: false, want: true},
		{name: "one string", key: "BOOL_ONE", defaultValue: false, want: true},
		{name: "false string", key: "BOOL_FALSE", defaultValue: true, want: false},
		{name: "zero string", key: "BOOL_ZERO", defaultValue: true, want: false},
		{name: "other string", key: "BOOL_OTHER", defaultValue: false, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getBoolEnv(tt.key, tt.defaultValue); got != tt.want {
				t.Fatalf("getBoolEnv(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestParseDurationEnv(t *testing.T) {
	key := "KNIGHT_TEST_PARSE_DURATION_48291"
	t.Cleanup(func() { os.Unsetenv(key) })

	t.Run("unset uses default", func(t *testing.T) {
		os.Unsetenv(key)
		d, err := parseDurationEnv(key, "90s")
		if err != nil {
			t.Fatalf("parseDurationEnv() error = %v", err)
		}
		if d != 90*time.Second {
			t.Fatalf("parseDurationEnv() = %v, want 90s", d)
		}
	})

	t.Run("blank uses default", func(t *testing.T) {
		t.Setenv(key, "  ")
		d, err := parseDurationEnv(key, "3m")
		if err != nil {
			t.Fatalf("parseDurationEnv() error = %v", err)
		}
		if d != 3*time.Minute {
			t.Fatalf("parseDurationEnv() = %v, want 3m", d)
		}
	})

	t.Run("zero literal", func(t *testing.T) {
		t.Setenv(key, "0")
		d, err := parseDurationEnv(key, "9h")
		if err != nil {
			t.Fatalf("parseDurationEnv() error = %v", err)
		}
		if d != 0 {
			t.Fatalf("parseDurationEnv() = %v, want 0", d)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv(key, "not-a-duration")
		if _, err := parseDurationEnv(key, "1s"); err == nil {
			t.Fatal("parseDurationEnv() error = nil, want error")
		}
	})
}

func TestEnsureReposDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repos")

	ensureReposDir(dir)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%q was not created as a directory", dir)
	}

	ensureReposDir(dir)
}

func TestGetSSHSigner(t *testing.T) {
	privateKey := testPrivateKeyPEM(t)

	t.Run("inline", func(t *testing.T) {
		t.Setenv("SSH_SIGNER_KEY", privateKey)

		signer, err := getSSHSigner("SSH_SIGNER_KEY", "")
		if err != nil {
			t.Fatalf("getSSHSigner() error = %v", err)
		}
		if signer == nil {
			t.Fatal("getSSHSigner() returned nil signer")
		}
	})

	t.Run("from file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "id_ed25519")
		if err := os.WriteFile(path, []byte(privateKey), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		t.Setenv("SSH_SIGNER_KEY", "@"+path)

		signer, err := getSSHSigner("SSH_SIGNER_KEY", "")
		if err != nil {
			t.Fatalf("getSSHSigner() error = %v", err)
		}
		if signer == nil {
			t.Fatal("getSSHSigner() returned nil signer")
		}
	})
}

func TestGetSSHSignerInvalid(t *testing.T) {
	t.Setenv("SSH_SIGNER_KEY", "not-a-private-key")

	if _, err := getSSHSigner("SSH_SIGNER_KEY", ""); err == nil {
		t.Fatal("getSSHSigner() error = nil, want error")
	}
}

func TestGetAuthorizedKeys(t *testing.T) {
	pub1 := testAuthorizedKey(t)
	pub2 := testAuthorizedKey(t)

	t.Run("inline", func(t *testing.T) {
		t.Setenv("AUTHORIZED_KEYS", pub1+"\n\n"+pub2+"\n")

		keys, err := getAuthorizedKeys("AUTHORIZED_KEYS", "")
		if err != nil {
			t.Fatalf("getAuthorizedKeys() error = %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("len(keys) = %d, want 2", len(keys))
		}
	})

	t.Run("from file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(path, []byte(pub1+"\n"+pub2+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		t.Setenv("AUTHORIZED_KEYS", "@"+path)

		keys, err := getAuthorizedKeys("AUTHORIZED_KEYS", "")
		if err != nil {
			t.Fatalf("getAuthorizedKeys() error = %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("len(keys) = %d, want 2", len(keys))
		}
	})
}

func TestGetAuthorizedKeysInvalid(t *testing.T) {
	t.Setenv("AUTHORIZED_KEYS", "not-a-public-key")

	if _, err := getAuthorizedKeys("AUTHORIZED_KEYS", ""); err == nil {
		t.Fatal("getAuthorizedKeys() error = nil, want error")
	}
}

func TestGetHtpasswd(t *testing.T) {
	content := testHTPasswdContent(t, "dev", "secret")

	t.Run("inline", func(t *testing.T) {
		t.Setenv("HTTP_HTPASSWD", content)

		file, err := getHtpasswd("HTTP_HTPASSWD", "")
		if err != nil {
			t.Fatalf("getHtpasswd() error = %v", err)
		}
		if !file.Match("dev", "secret") {
			t.Fatal("htpasswd did not match expected credentials")
		}
	})

	t.Run("from file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "htpasswd")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		t.Setenv("HTTP_HTPASSWD", "@"+path)

		file, err := getHtpasswd("HTTP_HTPASSWD", "")
		if err != nil {
			t.Fatalf("getHtpasswd() error = %v", err)
		}
		if !file.Match("dev", "secret") {
			t.Fatal("htpasswd did not match expected credentials")
		}
	})
}

func TestGetHtpasswdInvalid(t *testing.T) {
	t.Setenv("HTTP_HTPASSWD", "@"+filepath.Join(t.TempDir(), "missing"))

	if _, err := getHtpasswd("HTTP_HTPASSWD", ""); err == nil {
		t.Fatal("getHtpasswd() error = nil, want error")
	}
}

func TestInitializeHTTPOnly(t *testing.T) {
	reposPath := filepath.Join(t.TempDir(), "repos")

	t.Setenv("REPOS_PATH", reposPath)
	t.Setenv("INITIAL_BRANCH", "trunk")
	t.Setenv("ENABLE_SSH", "false")
	t.Setenv("ENABLE_HTTP", "true")
	t.Setenv("HTTP_HOST", "127.0.0.1")
	t.Setenv("HTTP_PORT", "9000")
	t.Setenv("HTTP_HTPASSWD", testHTPasswdContent(t, "dev", "secret"))

	cfg, err := Initialize()
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	if cfg.ReposPath != reposPath {
		t.Fatalf("ReposPath = %q, want %q", cfg.ReposPath, reposPath)
	}
	if cfg.InitialBranch != "trunk" {
		t.Fatalf("InitialBranch = %q, want trunk", cfg.InitialBranch)
	}
	if cfg.EnableSSH {
		t.Fatal("EnableSSH = true, want false")
	}
	if !cfg.EnableHTTP {
		t.Fatal("EnableHTTP = false, want true")
	}
	if cfg.HTTPHost != "127.0.0.1" || cfg.HTTPPort != "9000" {
		t.Fatalf("HTTP address = %s:%s, want 127.0.0.1:9000", cfg.HTTPHost, cfg.HTTPPort)
	}
	if cfg.HTPasswd == nil || !cfg.HTPasswd.Match("dev", "secret") {
		t.Fatal("HTPasswd not initialized correctly")
	}
	if cfg.HTTPReadHeaderTimeout != 30*time.Second {
		t.Fatalf("HTTPReadHeaderTimeout = %v, want 30s", cfg.HTTPReadHeaderTimeout)
	}
	if cfg.HTTPIdleTimeout != 5*time.Minute {
		t.Fatalf("HTTPIdleTimeout = %v, want 5m", cfg.HTTPIdleTimeout)
	}
	if cfg.HTTPReadTimeout != 0 || cfg.HTTPWriteTimeout != 0 {
		t.Fatalf("HTTPReadTimeout = %v, HTTPWriteTimeout = %v, want 0", cfg.HTTPReadTimeout, cfg.HTTPWriteTimeout)
	}
}

func TestInitializeSSHOnly(t *testing.T) {
	reposPath := filepath.Join(t.TempDir(), "repos")
	privateKey := testPrivateKeyPEM(t)
	publicKey := testAuthorizedKey(t)

	t.Setenv("REPOS_PATH", reposPath)
	t.Setenv("ENABLE_SSH", "true")
	t.Setenv("ENABLE_HTTP", "false")
	t.Setenv("SSH_HOST", "127.0.0.1")
	t.Setenv("SSH_PORT", "2222")
	t.Setenv("SSH_SIGNER_KEY", privateKey)
	t.Setenv("AUTHORIZED_KEYS", publicKey)

	cfg, err := Initialize()
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	if !cfg.EnableSSH {
		t.Fatal("EnableSSH = false, want true")
	}
	if cfg.EnableHTTP {
		t.Fatal("EnableHTTP = true, want false")
	}
	if cfg.SSHHost != "127.0.0.1" || cfg.SSHPort != "2222" {
		t.Fatalf("SSH address = %s:%s, want 127.0.0.1:2222", cfg.SSHHost, cfg.SSHPort)
	}
	if cfg.SSHSigner == nil {
		t.Fatal("SSHSigner = nil")
	}
	if len(cfg.AuthorizedKeys) != 1 {
		t.Fatalf("len(AuthorizedKeys) = %d, want 1", len(cfg.AuthorizedKeys))
	}
	if cfg.SSHIdleTimeout != 10*time.Minute {
		t.Fatalf("SSHIdleTimeout = %v, want 10m", cfg.SSHIdleTimeout)
	}
	if cfg.SSHMaxTimeout != 0 {
		t.Fatalf("SSHMaxTimeout = %v, want 0", cfg.SSHMaxTimeout)
	}
}

func TestInitializeReturnsParseError(t *testing.T) {
	t.Setenv("REPOS_PATH", filepath.Join(t.TempDir(), "repos"))
	t.Setenv("ENABLE_SSH", "true")
	t.Setenv("ENABLE_HTTP", "false")
	t.Setenv("SSH_SIGNER_KEY", "invalid")
	t.Setenv("AUTHORIZED_KEYS", testAuthorizedKey(t))

	if _, err := Initialize(); err == nil {
		t.Fatal("Initialize() error = nil, want error")
	}
}

func TestInitializeInvalidHTTPReadHeaderTimeout(t *testing.T) {
	t.Setenv("REPOS_PATH", filepath.Join(t.TempDir(), "repos"))
	t.Setenv("ENABLE_SSH", "false")
	t.Setenv("ENABLE_HTTP", "true")
	t.Setenv("HTTP_HTPASSWD", testHTPasswdContent(t, "dev", "secret"))
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "not-a-duration")

	if _, err := Initialize(); err == nil {
		t.Fatal("Initialize() error = nil, want error")
	}
}

func TestValidateReposPath(t *testing.T) {
	if err := validateReposPath(t.TempDir()); err != nil {
		t.Fatalf("validateReposPath() error = %v", err)
	}

	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := validateReposPath(f); err == nil {
		t.Fatal("validateReposPath() error = nil for non-directory, want error")
	}
}

func TestValidateGitBinaryMissingFromPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := validateGitBinary(); err == nil {
		t.Fatal("validateGitBinary() error = nil, want error")
	}
}

func TestValidateGitBinary(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not in PATH:", err)
	}
	if err := validateGitBinary(); err != nil {
		t.Fatalf("validateGitBinary() error = %v", err)
	}
}

func TestValidateRuntime(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not in PATH:", err)
	}
	if err := ValidateRuntime(&Config{ReposPath: t.TempDir()}); err != nil {
		t.Fatalf("ValidateRuntime() error = %v", err)
	}
}

func testPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}))
}

func testAuthorizedKey(t *testing.T) string {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	sshPublicKey, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}

	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPublicKey)))
}

func testHTPasswdContent(t *testing.T, username, password string) string {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}

	content := username + ":" + string(hash) + "\n"
	if _, err := htpasswd.NewFromReader(strings.NewReader(content), htpasswd.DefaultSystems, nil); err != nil {
		t.Fatalf("NewFromReader() error = %v", err)
	}

	return content
}
