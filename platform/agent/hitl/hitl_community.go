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
	"database/sql"
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
// Community Edition: Does not register any routes (feature not available).
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// HITL queue is an Enterprise feature
	// Routes are registered in enterprise builds
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

// NewRepository creates a new HITL repository.
// Community Edition: Returns a no-op repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{}
}
