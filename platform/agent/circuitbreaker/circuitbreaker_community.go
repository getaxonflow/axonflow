// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

// Package circuitbreaker provides emergency stop functionality for
// AI governance and EU AI Act Article 14 compliance.
//
// This is the Community Edition stub - Circuit Breaker functionality is an Enterprise feature.
// Upgrade to Enterprise at https://getaxonflow.com/enterprise for:
//   - Emergency stop/interrupt capability for AI operations
//   - Scope-based circuit tripping (global, tenant, client, policy)
//   - EU AI Act Article 14 compliance
//   - Audit trail with two-person deactivation
package circuitbreaker

import (
	"context"
	"database/sql"
	"time"

	"github.com/gorilla/mux"
)

// Handler provides HTTP handlers for circuit breaker operations.
// Community Edition: No-op implementation.
type Handler struct{}

// NewHandler creates a new circuit breaker handler.
// Community Edition: Returns a no-op handler.
func NewHandler(cb *CircuitBreaker) *Handler {
	return &Handler{}
}

// RegisterRoutes registers circuit breaker routes with a mux router.
// Community Edition: Does not register any routes (feature not available).
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Circuit breaker is an Enterprise feature
	// Routes are registered in enterprise builds
}

// CircuitBreaker manages emergency stop functionality.
// Community Edition: No-op implementation.
type CircuitBreaker struct{}

// Config contains circuit breaker configuration.
type Config struct {
	DefaultTimeout           time.Duration
	MaxTimeout               time.Duration
	ErrorThreshold           int
	PolicyViolationThreshold int
	PolicyViolationWindow    time.Duration
	EnableAutoRecovery       bool
}

// New creates a new circuit breaker.
// Community Edition: Returns a no-op circuit breaker.
func New(repo *Repository, config Config) *CircuitBreaker {
	return &CircuitBreaker{}
}

// CheckInput contains input for checking circuit state.
// Community Edition: Defined for compilation compatibility.
type CheckInput struct {
	OrgID    string
	TenantID string
	ClientID string
	PolicyID string
}

// CheckResult is the result of checking if a request should proceed.
// Community Edition: Always returns Allowed=true.
type CheckResult struct {
	Allowed   bool
	CircuitID string
	Scope     string
	ScopeID   string
	Reason    string
	TrippedBy string
	TrippedAt *time.Time
	ExpiresAt *time.Time
	Comment   string
}

// Check determines if a request should be allowed based on circuit state.
// Community Edition: Always allows requests.
func (cb *CircuitBreaker) Check(ctx context.Context, input CheckInput) (*CheckResult, error) {
	return &CheckResult{Allowed: true}, nil
}

// IsAllowed is a convenience method for quick checks.
// Community Edition: Always returns true.
func (cb *CircuitBreaker) IsAllowed(ctx context.Context, orgID, tenantID, clientID string) bool {
	return true
}

// RecordError records an error for automatic circuit tripping.
// Community Edition: No-op.
func (cb *CircuitBreaker) RecordError(ctx context.Context, orgID, tenantID, clientID string) error {
	return nil
}

// RecordPolicyViolation records a policy violation for automatic tripping.
// Community Edition: No-op.
func (cb *CircuitBreaker) RecordPolicyViolation(ctx context.Context, orgID, tenantID, clientID, policyID string) error {
	return nil
}

// LoadCircuits loads active circuits from the database into memory.
// Community Edition: No-op.
func (cb *CircuitBreaker) LoadCircuits(ctx context.Context, orgID string) error {
	return nil
}

// ExpireCircuits closes circuits that have passed their expiry time.
// Community Edition: No-op.
func (cb *CircuitBreaker) ExpireCircuits(ctx context.Context) error {
	return nil
}

// Repository provides data access for circuit breaker state.
// Community Edition: No-op implementation.
type Repository struct{}

// NewRepository creates a new circuit breaker repository.
// Community Edition: Returns a no-op repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{}
}
