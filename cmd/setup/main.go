package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

const (
	configDir          = "config"
	hostKeyPath        = "config/id_ed25519"
	clientKeyPath      = "config/dev_client_ed25519"
	clientPubKeyPath   = "config/dev_client_ed25519.pub"
	authorizedKeysPath = "config/authorized_keys"
	htpasswdPath       = "config/htpasswd"
	defaultUser        = "dev"
	defaultPassword    = "dev"
)

func main() {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		fatalf("create config directory: %v", err)
	}

	createdHostKey, err := ensurePrivateKey(hostKeyPath)
	if err != nil {
		fatalf("create host key: %v", err)
	}

	clientPrivateKey, clientPublicKey, createdClientKey, err := ensureClientKeypair(clientKeyPath, clientPubKeyPath)
	if err != nil {
		fatalf("create client keypair: %v", err)
	}

	createdAuthorizedKeys, err := ensureAuthorizedKeys(authorizedKeysPath, clientPublicKey)
	if err != nil {
		fatalf("create authorized_keys: %v", err)
	}

	createdHTPasswd, err := ensureHTPasswd(htpasswdPath, defaultUser, defaultPassword)
	if err != nil {
		fatalf("create htpasswd: %v", err)
	}

	fmt.Printf("setup complete\n")
	printStatus(hostKeyPath, createdHostKey)
	printStatus(clientKeyPath, createdClientKey)
	printStatus(clientPubKeyPath, createdClientKey)
	printStatus(authorizedKeysPath, createdAuthorizedKeys)
	printStatus(htpasswdPath, createdHTPasswd)
	fmt.Printf("http basic auth: %s / %s\n", defaultUser, defaultPassword)
	fmt.Printf("ssh client key: %s\n", clientPrivateKey)
}

func ensurePrivateKey(path string) (bool, error) {
	if exists(path) {
		return false, nil
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, err
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return false, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return false, err
	}

	return true, nil
}

func ensureClientKeypair(privatePath, publicPath string) (string, string, bool, error) {
	if exists(privatePath) && exists(publicPath) {
		bytes, err := os.ReadFile(publicPath)
		if err != nil {
			return "", "", false, err
		}
		return privatePath, string(bytes), false, nil
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", false, err
	}

	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", false, err
	}

	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateBytes,
	}

	if err := os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0o600); err != nil {
		return "", "", false, err
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", "", false, err
	}

	authorizedKey := string(ssh.MarshalAuthorizedKey(sshPublicKey))
	if err := os.WriteFile(publicPath, []byte(authorizedKey), 0o644); err != nil {
		return "", "", false, err
	}

	return privatePath, authorizedKey, true, nil
}

func ensureAuthorizedKeys(path, publicKey string) (bool, error) {
	if exists(path) {
		return false, nil
	}

	if err := os.WriteFile(path, []byte(publicKey), 0o600); err != nil {
		return false, err
	}

	return true, nil
}

func ensureHTPasswd(path, username, password string) (bool, error) {
	if exists(path) {
		return false, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}

	content := fmt.Sprintf("%s:%s\n", username, hash)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return false, err
	}

	return true, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func printStatus(path string, created bool) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	status := "exists"
	if created {
		status = "created"
	}

	fmt.Printf("%s: %s\n", status, absPath)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
