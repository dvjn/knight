package git

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

type Repo struct {
	path string
}

func (r *Repo) Exists() bool {
	_, err := os.Stat(r.path)
	return err == nil || os.IsExist(err)
}

func (r *Repo) Create(initialBranch string) error {
	if _, err := os.Stat(r.path); err == nil {
		return fmt.Errorf("repository already exists: %s", r.path)
	}

	if err := os.MkdirAll(r.path, 0o755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	cmd := exec.Command("git", "init", "--initial-branch", initialBranch, "--bare")
	cmd.Dir = r.path
	if err := cmd.Run(); err != nil {
		os.RemoveAll(r.path)
		return fmt.Errorf("failed to initialize git repository: %w", err)
	}

	return nil
}

func (r *Repo) Ensure(initialBranch string) error {
	if r.Exists() {
		return nil
	}

	return r.Create(initialBranch)
}

func (r *Repo) UploadPack(stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	cmd := exec.Command("git", "upload-pack", ".")
	cmd.Dir = r.path
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (r *Repo) ReceivePack(stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	cmd := exec.Command("git", "receive-pack", ".")
	cmd.Dir = r.path
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (r *Repo) InfoRefs(stdout io.Writer, stderr io.Writer) error {
	cmd := exec.Command("git", "upload-pack", "--http-backend-info-refs", ".")
	cmd.Dir = r.path
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (r *Repo) UploadPackHTTP(stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	cmd := exec.Command("git", "upload-pack", "--stateless-rpc", ".")
	cmd.Dir = r.path
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (r *Repo) ReceivePackHTTP(stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	cmd := exec.Command("git", "receive-pack", "--stateless-rpc", ".")
	cmd.Dir = r.path
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
