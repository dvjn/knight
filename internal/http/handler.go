package http

import (
	"bytes"
	"compress/gzip"
	"io"
	"log"
	"net/http"

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

func (h *handler) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{repo}/info/refs", h.authMiddleware(h.handleInfoRefs))
	mux.HandleFunc("POST /{repo}/git-upload-pack", h.authMiddleware(h.handleUploadPack))
	mux.HandleFunc("POST /{repo}/git-receive-pack", h.authMiddleware(h.handleReceivePack))

	return h.logMiddleware(mux.ServeHTTP)
}

func (h *handler) logMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("http request", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	}
}

func (h *handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || !h.cfg.HTPasswd.Match(username, password) {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Git\"")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			log.Println("unauthorized request", r.URL.String())
			return
		}
		log.Println("authorized request", r.URL.String())
		next.ServeHTTP(w, r)
	}
}

func (h *handler) handleInfoRefs(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	if service == "" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Please upgrade your git client."))
		return
	}

	repo, err := h.git.Repo(r.PathValue("repo"))
	if err != nil {
		log.Println("invalid repo name", r.URL.String(), err)
		http.Error(w, "invalid repo name", http.StatusBadRequest)
		return
	}

	switch service {
	case "git-upload-pack":
		if !repo.Exists() {
			log.Println("repo does not exist", r.URL.String())
			http.Error(w, "repo does not exist", http.StatusNotFound)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("001e"))
		w.Write([]byte("# service=git-upload-pack\n"))
		w.Write([]byte("0000"))
	case "git-receive-pack":
		if err := repo.Ensure(h.cfg.InitialBranch); err != nil {
			log.Println("failed to create repo", r.URL.String(), err)
			http.Error(w, "failed to create repo", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("001f"))
		w.Write([]byte("# service=git-receive-pack\n"))
		w.Write([]byte("0000"))
	default:
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("service not supported: " + service))
		return
	}

	stderr := &bytes.Buffer{}
	err = repo.InfoRefs(w, stderr)
	if err != nil {
		log.Println("failed to get info refs", r.URL.String(), err, stderr.String())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (h *handler) handleUploadPack(w http.ResponseWriter, r *http.Request) {
	repo, err := h.git.Repo(r.PathValue("repo"))
	if err != nil {
		log.Println("invalid repo name", r.URL.String(), err)
		http.Error(w, "invalid repo name", http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		http.Error(w, "content type is required", http.StatusBadRequest)
		return
	}
	if contentType != "application/x-git-upload-pack-request" {
		http.Error(w, "unsupported content type", http.StatusBadRequest)
		return
	}

	var reader io.ReadCloser = r.Body
	contentEncoding := r.Header.Get("Content-Encoding")
	if contentEncoding == "gzip" {
		var err error
		reader, err = gzip.NewReader(r.Body)
		if err != nil {
			log.Println("failed to create gzip reader", err)
			http.Error(w, "failed to create gzip reader", http.StatusInternalServerError)
			return
		}
	}
	defer reader.Close()

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.WriteHeader(http.StatusOK)

	err = repo.UploadPackHTTP(reader, w, w)
	if err != nil {
		log.Println("failed to run git command", r.URL.String(), err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (h *handler) handleReceivePack(w http.ResponseWriter, r *http.Request) {
	repo, err := h.git.Repo(r.PathValue("repo"))
	if err != nil {
		log.Println("invalid repo name", r.URL.String(), err)
		http.Error(w, "invalid repo name", http.StatusBadRequest)
		return
	}

	if err := repo.Ensure(h.cfg.InitialBranch); err != nil {
		log.Println("failed to create repo", r.URL.String(), err)
		http.Error(w, "failed to create repo", http.StatusInternalServerError)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		http.Error(w, "content type is required", http.StatusBadRequest)
		return
	}
	if contentType != "application/x-git-receive-pack-request" {
		http.Error(w, "unsupported content type", http.StatusBadRequest)
		return
	}

	var reader io.ReadCloser = r.Body
	contentEncoding := r.Header.Get("Content-Encoding")
	if contentEncoding == "gzip" {
		var err error
		reader, err = gzip.NewReader(r.Body)
		if err != nil {
			log.Println("failed to create gzip reader", err)
			http.Error(w, "failed to create gzip reader", http.StatusInternalServerError)
			return
		}
	}
	defer reader.Close()

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	w.WriteHeader(http.StatusOK)

	err = repo.ReceivePackHTTP(reader, w, w)
	if err != nil {
		log.Println("failed to run git command", r.URL.String(), err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
