package git

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dvjn/knight/internal/config"
)

func TestServiceRepo(t *testing.T) {
	svc := New(&config.Config{ReposPath: t.TempDir()})

	valid := []string{"repo.git", "repo-name.git", "repo_name.git", "REPO.git"}
	for _, name := range valid {
		t.Run("valid/"+name, func(t *testing.T) {
			repo, err := svc.Repo(name)
			if err != nil {
				t.Fatalf("Repo(%q) error = %v", name, err)
			}
			wantPath := filepath.Join(svc.cfg.ReposPath, name)
			if repo.path != wantPath {
				t.Fatalf("repo.path = %q, want %q", repo.path, wantPath)
			}
		})
	}

	invalid := []string{"repo", "../repo.git", "nested/repo.git", ".git", "repo.git/extra", "repo space.git"}
	for _, name := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			if _, err := svc.Repo(name); err == nil {
				t.Fatalf("Repo(%q) error = nil, want error", name)
			}
		})
	}
}

func TestRepoCreateEnsureExists(t *testing.T) {
	repo := &Repo{path: filepath.Join(t.TempDir(), "example.git")}

	if repo.Exists() {
		t.Fatal("Exists() = true before creation, want false")
	}

	if err := repo.Create("main"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !repo.Exists() {
		t.Fatal("Exists() = false after creation, want true")
	}

	headBytes, err := os.ReadFile(filepath.Join(repo.path, "HEAD"))
	if err != nil {
		t.Fatalf("ReadFile(HEAD) error = %v", err)
	}
	if !strings.Contains(string(headBytes), "refs/heads/main") {
		t.Fatalf("HEAD = %q, want refs/heads/main", string(headBytes))
	}

	if err := repo.Ensure("main"); err != nil {
		t.Fatalf("Ensure() on existing repo error = %v", err)
	}
}

func TestRepoCreateFailsWhenAlreadyExists(t *testing.T) {
	repo := &Repo{path: filepath.Join(t.TempDir(), "example.git")}
	if err := repo.Create("main"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := repo.Create("main"); err == nil {
		t.Fatal("Create() error = nil, want error")
	}
}

func TestRepoCreateCleansUpOnGitInitFailure(t *testing.T) {
	repo := &Repo{path: filepath.Join(t.TempDir(), "example.git")}
	t.Setenv("PATH", t.TempDir())

	err := repo.Create("main")
	if err == nil {
		t.Fatal("Create() error = nil, want error")
	}

	if _, statErr := os.Stat(repo.path); !os.IsNotExist(statErr) {
		t.Fatalf("repo path still exists after Create() failure, stat error = %v", statErr)
	}
}

func TestRepoInfoRefs(t *testing.T) {
	repo := &Repo{path: filepath.Join(t.TempDir(), "example.git")}
	if err := repo.Create("main"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := repo.InfoRefs(stdout, stderr); err != nil {
		t.Fatalf("InfoRefs() error = %v, stderr = %q", err, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("InfoRefs() wrote no output")
	}
}
