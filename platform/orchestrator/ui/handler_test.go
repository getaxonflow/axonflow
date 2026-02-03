package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func setupRouter() *mux.Router {
	r := mux.NewRouter()
	h := NewHandler()
	h.RegisterRoutes(r)
	return r
}

func TestServeIndex(t *testing.T) {
	r := setupRouter()

	req := httptest.NewRequest("GET", "/ui/executions/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content type, got %s", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "AxonFlow Execution Viewer") {
		t.Error("index.html should contain 'AxonFlow Execution Viewer'")
	}
}

func TestRedirectToSlash(t *testing.T) {
	r := setupRouter()

	req := httptest.NewRequest("GET", "/ui/executions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	if loc != "/ui/executions/" {
		t.Errorf("expected redirect to /ui/executions/, got %s", loc)
	}
}

func TestServeDetailHTML(t *testing.T) {
	r := setupRouter()

	req := httptest.NewRequest("GET", "/ui/executions/detail.html", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Execution Detail") {
		t.Error("detail.html should contain 'Execution Detail'")
	}
}

func TestServeAppJS(t *testing.T) {
	r := setupRouter()

	req := httptest.NewRequest("GET", "/ui/executions/app.js", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "App") {
		t.Error("app.js should contain 'App'")
	}
}

func TestServeStylesCSS(t *testing.T) {
	r := setupRouter()

	req := httptest.NewRequest("GET", "/ui/executions/styles.css", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "status-badge") {
		t.Error("styles.css should contain 'status-badge'")
	}
}

func TestServe404(t *testing.T) {
	r := setupRouter()

	req := httptest.NewRequest("GET", "/ui/executions/nonexistent.html", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing file, got %d", w.Code)
	}
}

