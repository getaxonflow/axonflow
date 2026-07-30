// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/tenantscope"
)

// Handler provides HTTP handlers for webhook management.
type Handler struct {
	service *Service
}

// NewHandler creates a new webhook handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes registers webhook management routes on the router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/webhooks", h.createWebhook).Methods("POST")
	r.HandleFunc("/api/v1/webhooks", h.listWebhooks).Methods("GET")
	r.HandleFunc("/api/v1/webhooks/{id}", h.getWebhook).Methods("GET")
	r.HandleFunc("/api/v1/webhooks/{id}", h.updateWebhook).Methods("PUT")
	r.HandleFunc("/api/v1/webhooks/{id}", h.deleteWebhook).Methods("DELETE")
}

func (h *Handler) createWebhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	scope, ok := requireScope(w, r)
	if !ok {
		return
	}
	tenantID, orgID := scope.TenantID, scope.OrgID

	var req CreateSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sub, err := h.service.Create(r.Context(), &req, tenantID, orgID)
	if err != nil {
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(sub); err != nil {
		log.Printf("[Webhooks] Failed to encode create response: %v", err)
	}
}

func (h *Handler) getWebhook(w http.ResponseWriter, r *http.Request) {
	scope, ok := requireScope(w, r)
	if !ok {
		return
	}
	tenantID, orgID := scope.TenantID, scope.OrgID
	id := mux.Vars(r)["id"]

	sub, err := h.service.Get(r.Context(), id, tenantID, orgID)
	if err != nil {
		sendError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sub); err != nil {
		log.Printf("[Webhooks] Failed to encode get response: %v", err)
	}
}

func (h *Handler) updateWebhook(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	scope, ok := requireScope(w, r)
	if !ok {
		return
	}
	tenantID, orgID := scope.TenantID, scope.OrgID
	id := mux.Vars(r)["id"]

	var req UpdateSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sub, err := h.service.Update(r.Context(), id, &req, tenantID, orgID)
	if err != nil {
		sendError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sub); err != nil {
		log.Printf("[Webhooks] Failed to encode update response: %v", err)
	}
}

func (h *Handler) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	scope, ok := requireScope(w, r)
	if !ok {
		return
	}
	tenantID, orgID := scope.TenantID, scope.OrgID
	id := mux.Vars(r)["id"]

	if err := h.service.Delete(r.Context(), id, tenantID, orgID); err != nil {
		sendError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listWebhooks(w http.ResponseWriter, r *http.Request) {
	scope, ok := requireScope(w, r)
	if !ok {
		return
	}
	tenantID, orgID := scope.TenantID, scope.OrgID

	resp, err := h.service.List(r.Context(), tenantID, orgID)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[Webhooks] Failed to encode list response: %v", err)
	}
}

// requireScope resolves the caller's authenticated tenancy, writing a 401 and
// returning ok=false when the request carries none.
//
// #3065 (F6): extractContext used to hand the raw headers straight through,
// so a caller who sent neither reached a repository whose by-id read had no
// predicate at all — and whose projection included the subscription's HMAC
// signing secret. Nothing legitimate is affected: the agent gateway and the
// customer portal proxy both Set these headers from a validated credential.
func requireScope(w http.ResponseWriter, r *http.Request) (tenantscope.Scope, bool) {
	scope, err := tenantscope.Bind(r)
	if err != nil {
		sendError(w, "Missing tenant or org identity", http.StatusUnauthorized)
		return tenantscope.Scope{}, false
	}
	return scope, true
}

func sendError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		log.Printf("[Webhooks] Failed to encode error response: %v", err)
	}
}
