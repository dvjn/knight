package ssh

import (
	"fmt"
	"log"
	"strings"

	"github.com/gliderlabs/ssh"

	"github.com/dvjn/knight/internal/config"
	"github.com/dvjn/knight/internal/git"
)

type handler struct {
	cfg *config.Config
	git *git.Service
}

func Handler(cfg *config.Config, git *git.Service) *handler {
	return &handler{cfg: cfg, git: git}
}

func (h *handler) PublicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	for _, authKey := range h.cfg.AuthorizedKeys {
		if ssh.KeysEqual(authKey, key) {
			return true
		}
	}
	return false
}

func (h *handler) Handler(s ssh.Session) {
	log.Println("ssh session", s.Command())

	command := s.Command()
	if len(command) != 2 {
		log.Println("invalid command", command)
		fmt.Fprintf(s.Stderr(), "invalid command: %s\n\n", command)
		s.Exit(1)
		return
	}

	gitOperation := command[0]
	repoName := strings.TrimPrefix(command[1], "/")

	repo, err := h.git.Repo(repoName)
	if err != nil {
		log.Println("invalid repo name", repoName, err)
		fmt.Fprintf(s.Stderr(), "invalid repo name: %s\n\n", repoName)
		s.Exit(1)
		return
	}

	switch gitOperation {
	case "git-upload-pack":
		if !repo.Exists() {
			log.Println("repo does not exist", repoName)
			fmt.Fprintf(s.Stderr(), "repo does not exist: %s\n\n", repoName)
			s.Exit(1)
			return
		}
		err = repo.UploadPack(s, s, s.Stderr())
	case "git-receive-pack":
		err = repo.Ensure(h.cfg.InitialBranch)
		if err != nil {
			log.Println("failed to create repo", err)
			fmt.Fprintf(s.Stderr(), "failed to create repo: %s\n\n", err)
			s.Exit(1)
			return
		}
		err = repo.ReceivePack(s, s, s.Stderr())
	default:
		log.Println("unsupported git operation", gitOperation)
		fmt.Fprintf(s.Stderr(), "unsupported git operation: %s\n\n", gitOperation)
		s.Exit(1)
		return
	}
	if err != nil {
		log.Println("failed to run git command", err)
		s.Exit(1)
		return
	}

	s.Exit(0)
}
