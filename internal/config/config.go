package config

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/tg123/go-htpasswd"
	gossh "golang.org/x/crypto/ssh"
)

type Config struct {
	ReposPath     string
	InitialBranch string

	EnableSSH      bool
	SSHHost        string
	SSHPort        string
	SSHSigner      gossh.Signer
	AuthorizedKeys []gossh.PublicKey

	EnableHTTP bool
	HTTPHost   string
	HTTPPort   string
	HTPasswd   *htpasswd.File

	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration

	SSHIdleTimeout time.Duration
	SSHMaxTimeout  time.Duration
}

func Initialize() (*Config, error) {
	log.Println("initializing config")

	cfg := &Config{}
	var err error

	log.Println("initializing repos")
	cfg.ReposPath = getEnv("REPOS_PATH", "./data/repos")
	ensureReposDir(cfg.ReposPath)

	cfg.InitialBranch = getEnv("INITIAL_BRANCH", "main")

	cfg.EnableSSH = getBoolEnv("ENABLE_SSH", true)
	if cfg.EnableSSH {
		cfg.SSHHost = getEnv("SSH_HOST", "0.0.0.0")
		cfg.SSHPort = getEnv("SSH_PORT", "2222")

		log.Println("initializing ssh signing key")
		cfg.SSHSigner, err = getSSHSigner("SSH_SIGNER_KEY", "@config/id_ed25519")
		if err != nil {
			return nil, err
		}

		log.Println("initializing ssh authorized keys")
		cfg.AuthorizedKeys, err = getAuthorizedKeys("AUTHORIZED_KEYS", "@config/authorized_keys")
		if err != nil {
			return nil, err
		}

		cfg.SSHIdleTimeout, err = parseDurationEnv("SSH_IDLE_TIMEOUT", "10m")
		if err != nil {
			return nil, err
		}
		cfg.SSHMaxTimeout, err = parseDurationEnv("SSH_MAX_TIMEOUT", "0")
		if err != nil {
			return nil, err
		}
	}

	cfg.EnableHTTP = getBoolEnv("ENABLE_HTTP", true)
	if cfg.EnableHTTP {
		cfg.HTTPHost = getEnv("HTTP_HOST", "0.0.0.0")
		cfg.HTTPPort = getEnv("HTTP_PORT", "8080")

		log.Println("initializing http htpasswd file")
		cfg.HTPasswd, err = getHtpasswd("HTTP_HTPASSWD", "@config/htpasswd")
		if err != nil {
			return nil, err
		}

		cfg.HTTPReadHeaderTimeout, err = parseDurationEnv("HTTP_READ_HEADER_TIMEOUT", "30s")
		if err != nil {
			return nil, err
		}
		cfg.HTTPReadTimeout, err = parseDurationEnv("HTTP_READ_TIMEOUT", "0")
		if err != nil {
			return nil, err
		}
		cfg.HTTPWriteTimeout, err = parseDurationEnv("HTTP_WRITE_TIMEOUT", "0")
		if err != nil {
			return nil, err
		}
		cfg.HTTPIdleTimeout, err = parseDurationEnv("HTTP_IDLE_TIMEOUT", "5m")
		if err != nil {
			return nil, err
		}
	}

	if !cfg.EnableSSH && !cfg.EnableHTTP {
		log.Fatal("both ssh and http are disabled")
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		return value != "false" && value != "0"
	}
	return defaultValue
}

func parseDurationEnv(key, defaultLiteral string) (time.Duration, error) {
	s, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(s) == "" {
		s = defaultLiteral
	}
	if s == "0" || s == "-1" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return d, nil
}

func ensureReposDir(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Println("creating repos directory at", path)
		os.MkdirAll(path, 0o755)
	}
}

func getSSHSigner(env, defaultValue string) (gossh.Signer, error) {
	value := getEnv(env, defaultValue)

	var bytes []byte
	var err error
	if strings.HasPrefix(value, "@") {
		bytes, err = os.ReadFile(strings.TrimPrefix(value, "@"))
		if err != nil {
			return nil, err
		}
	} else {
		bytes = []byte(value)
	}

	key, err := gossh.ParseRawPrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func getAuthorizedKeys(env, defaultValue string) ([]gossh.PublicKey, error) {
	value := getEnv(env, defaultValue)

	if strings.HasPrefix(value, "@") {
		bytes, err := os.ReadFile(strings.TrimPrefix(value, "@"))
		if err != nil {
			return nil, err
		}
		value = string(bytes)
	}

	authorizedKeys := []gossh.PublicKey{}
	for _, line := range strings.Split(value, "\n") {
		if line == "" {
			continue
		}
		pubKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, err
		}
		authorizedKeys = append(authorizedKeys, pubKey)
	}

	return authorizedKeys, nil
}

func getHtpasswd(env, defaultValue string) (*htpasswd.File, error) {
	value := getEnv(env, defaultValue)

	if strings.HasPrefix(value, "@") {
		bytes, err := os.ReadFile(strings.TrimPrefix(value, "@"))
		if err != nil {
			return nil, err
		}
		value = string(bytes)
	}

	htpasswd, err := htpasswd.NewFromReader(strings.NewReader(value), htpasswd.DefaultSystems, nil)
	if err != nil {
		return nil, err
	}

	return htpasswd, nil
}
