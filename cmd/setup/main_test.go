package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")

	if exists(path) {
		t.Fatal("exists() = true for missing file, want false")
	}

	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if !exists(path) {
		t.Fatal("exists() = false for existing file, want true")
	}
}

func TestEnsurePrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")

	created, err := ensurePrivateKey(path)
	if err != nil {
		t.Fatalf("ensurePrivateKey() error = %v", err)
	}
	if !created {
		t.Fatal("ensurePrivateKey() created = false, want true")
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(bytes), "PRIVATE KEY") {
		t.Fatalf("private key file = %q, want PEM private key", string(bytes))
	}

	created, err = ensurePrivateKey(path)
	if err != nil {
		t.Fatalf("ensurePrivateKey() second call error = %v", err)
	}
	if created {
		t.Fatal("ensurePrivateKey() created = true on second call, want false")
	}
}

func TestEnsureClientKeypair(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "dev_client_ed25519")
	publicPath := filepath.Join(dir, "dev_client_ed25519.pub")

	returnedPrivatePath, publicKey, created, err := ensureClientKeypair(privatePath, publicPath)
	if err != nil {
		t.Fatalf("ensureClientKeypair() error = %v", err)
	}
	if !created {
		t.Fatal("ensureClientKeypair() created = false, want true")
	}
	if returnedPrivatePath != privatePath {
		t.Fatalf("privatePath = %q, want %q", returnedPrivatePath, privatePath)
	}
	if !strings.HasPrefix(publicKey, "ssh-ed25519 ") {
		t.Fatalf("publicKey = %q, want ssh-ed25519 key", publicKey)
	}

	storedPublicKey, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("ReadFile(public) error = %v", err)
	}
	if string(storedPublicKey) != publicKey {
		t.Fatalf("stored public key = %q, want %q", string(storedPublicKey), publicKey)
	}

	returnedPrivatePath, publicKeyAgain, created, err := ensureClientKeypair(privatePath, publicPath)
	if err != nil {
		t.Fatalf("ensureClientKeypair() second call error = %v", err)
	}
	if created {
		t.Fatal("ensureClientKeypair() created = true on second call, want false")
	}
	if returnedPrivatePath != privatePath {
		t.Fatalf("privatePath second call = %q, want %q", returnedPrivatePath, privatePath)
	}
	if publicKeyAgain != publicKey {
		t.Fatalf("publicKey second call = %q, want %q", publicKeyAgain, publicKey)
	}
}

func TestEnsureAuthorizedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	content := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"

	created, err := ensureAuthorizedKeys(path, content)
	if err != nil {
		t.Fatalf("ensureAuthorizedKeys() error = %v", err)
	}
	if !created {
		t.Fatal("ensureAuthorizedKeys() created = false, want true")
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(stored) != content {
		t.Fatalf("authorized_keys = %q, want %q", string(stored), content)
	}

	created, err = ensureAuthorizedKeys(path, "different")
	if err != nil {
		t.Fatalf("ensureAuthorizedKeys() second call error = %v", err)
	}
	if created {
		t.Fatal("ensureAuthorizedKeys() created = true on second call, want false")
	}
}

func TestEnsureHTPasswd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "htpasswd")

	created, err := ensureHTPasswd(path, "dev", "secret")
	if err != nil {
		t.Fatalf("ensureHTPasswd() error = %v", err)
	}
	if !created {
		t.Fatal("ensureHTPasswd() created = false, want true")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(content)), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("htpasswd content = %q, want username:hash", string(content))
	}
	if parts[0] != "dev" {
		t.Fatalf("username = %q, want dev", parts[0])
	}
	if err := bcrypt.CompareHashAndPassword([]byte(parts[1]), []byte("secret")); err != nil {
		t.Fatalf("CompareHashAndPassword() error = %v", err)
	}

	created, err = ensureHTPasswd(path, "dev", "different")
	if err != nil {
		t.Fatalf("ensureHTPasswd() second call error = %v", err)
	}
	if created {
		t.Fatal("ensureHTPasswd() created = true on second call, want false")
	}
}

func TestPrintStatus(t *testing.T) {
	output := captureStdout(t, func() {
		printStatus("some/path", true)
		printStatus("some/path", false)
	})

	if !strings.Contains(output, "created:") {
		t.Fatalf("output = %q, want created status", output)
	}
	if !strings.Contains(output, "exists:") {
		t.Fatalf("output = %q, want exists status", output)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe() error = %v", err)
	}

	os.Stdout = writer
	defer func() { os.Stdout = original }()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("Close(writer) error = %v", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(reader); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}

	return buf.String()
}
