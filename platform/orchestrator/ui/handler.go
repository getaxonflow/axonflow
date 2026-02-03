// Package ui serves the embedded execution viewer web UI.
package ui

import (
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

//go:embed static/*
var staticFiles embed.FS

// Handler serves the embedded UI static files.
type Handler struct {
	fileServer http.Handler
}

// NewHandler creates a new UI handler.
func NewHandler() *Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("failed to create sub filesystem for UI: %v", err)
	}

	return &Handler{
		fileServer: http.FileServer(http.FS(sub)),
	}
}

// RegisterRoutes registers the UI routes on the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Serve index.html for the base path
	r.HandleFunc("/ui/executions/", h.serveIndex).Methods("GET")
	r.HandleFunc("/ui/executions", h.redirectToSlash).Methods("GET")

	// Serve static files (app.js, styles.css, detail.html)
	r.PathPrefix("/ui/executions/").Handler(
		http.StripPrefix("/ui/executions/", h.fileServer),
	).Methods("GET")
}

// serveIndex serves the main index.html page.
func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

// redirectToSlash redirects /ui/executions to /ui/executions/.
func (h *Handler) redirectToSlash(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/ui/executions/", http.StatusMovedPermanently)
}

