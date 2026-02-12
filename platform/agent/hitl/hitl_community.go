// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

// Package hitl provides Human-in-the-Loop (HITL) queue functionality for
// AI governance and EU AI Act Article 14 compliance.
//
// This is the Community Edition stub - HITL functionality is an Enterprise feature.
// Upgrade to Enterprise at https://getaxonflow.com/enterprise for:
//   - Human oversight queue for high-risk AI decisions
//   - Approval/rejection workflow with audit trail
//   - EU AI Act Article 14 compliance
//   - Override capability with justification tracking
package hitl

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// Handler provides HTTP handlers for HITL queue operations.
// Community Edition: No-op implementation.
type Handler struct{}

// NewHandler creates a new HITL handler.
// Community Edition: Returns a no-op handler.
func NewHandler(service *Service) *Handler {
	return &Handler{}
}

// RegisterRoutes registers HITL routes with a mux router.
// Community Edition: Registers only the status endpoint.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/hitl/status", h.getStatus).Methods("GET")
}

// getStatus returns the HITL feature status for community edition.
func (h *Handler) getStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled": false,
		"mode":    "community",
		"message": "HITL queue is an Enterprise feature. Upgrade at https://getaxonflow.com/enterprise",
	}); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// Service provides business logic for HITL queue operations.
// Community Edition: No-op implementation.
type Service struct{}

// ServiceConfig contains configuration for the HITL service.
type ServiceConfig struct {
	DefaultExpiry time.Duration
	MaxExpiry     time.Duration
}

// NewService creates a new HITL service.
// Community Edition: Returns a no-op service.
func NewService(repo *Repository, config ServiceConfig) *Service {
	return &Service{}
}

// Repository provides data access for HITL approval requests.
// Community Edition: No-op implementation.
type Repository struct{}

// ExpireStaleRequests expires stale pending approval requests.
// Community Edition: No-op, returns 0.
func (s *Service) ExpireStaleRequests(ctx context.Context) (int, error) {
	return 0, nil
}

// NewRepository creates a new HITL repository.
// Community Edition: Returns a no-op repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{}
}
