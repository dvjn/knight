package git

import (
	"fmt"
	"regexp"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/dvjn/knight/internal/config"
)

type Service struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Service {
	return &Service{cfg: cfg}
}

func (g *Service) Repo(name string) (*Repo, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+\.git$`).MatchString(name) {
		return nil, fmt.Errorf("invalid repo name (must end with .git): %s", name)
	}

	path, err := securejoin.SecureJoin(g.cfg.ReposPath, name)
	if err != nil {
		return nil, fmt.Errorf("invalid repo path: %s", err)
	}

	return &Repo{path: path}, nil
}
