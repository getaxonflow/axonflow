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
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// ErrHITLApprovalDisabledByTier is the sentinel returned by community
// builds whenever an in-process caller (such as the V1 Plugin Pro MCP
// tool `axonflow_request_approval`) tries to create an approval. The
// agent's community build doesn't ship the HITL queue at all — every
// caller is rejected at this gate so the same error can be translated
// to user-facing wording at the call site, identical to the
// enterprise-build's tier rejection on Community-tier processes.
var ErrHITLApprovalDisabledByTier = errors.New("HITL approvals require an Evaluation or higher license tier; current tier is Community")

// ErrPendingApprovalLimitExceeded is exposed for symbol parity with the
// enterprise build. Community build never returns it because no rows
// can be created in the first place.
var ErrPendingApprovalLimitExceeded = errors.New("pending approval limit exceeded")

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
	DefaultExpiry       time.Duration
	MaxExpiry           time.Duration
	MaxPendingApprovals int // Ignored in Community edition
}

// NewService creates a new HITL service.
// Community Edition: Returns a no-op service.
func NewService(repo *Repository, config ServiceConfig) *Service {
	return &Service{}
}

// Repository provides data access for HITL approval requests.
// Community Edition: No-op implementation.
type Repository struct{}

// SetCrossOrgDB is a no-op in Community Edition (mirrors the Enterprise
// repository's BYPASSRLS lookup-pool setter, #3048, so run.go wires it
// unconditionally).
func (r *Repository) SetCrossOrgDB(_ *sql.DB) {}

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

// CreateApprovalInput is the input shape for Service.CreateApprovalRequest.
// Mirrors the enterprise-build struct field-for-field so callers in
// agent/mcp_v1_pro_tools.go (no build tag) compile under both builds.
type CreateApprovalInput struct {
	OrgID               string
	TenantID            string
	ClientID            string
	UserID              string
	OriginalQuery       string
	RequestType         string
	RequestContext      map[string]interface{}
	TriggeredPolicyID   string
	TriggeredPolicyName string
	TriggerReason       string
	Severity            string
	EUAIActArticle      string
	ComplianceFramework string
	RiskClassification  string
	ExpiresIn           time.Duration
	NotifyURL           string
}

// WebhookDispatcher is the community stub. No-op constructor + no-op
// setter so agent/run.go's enterprise wiring compiles under both builds.
type WebhookDispatcher struct{}

// NewWebhookDispatcher returns a no-op dispatcher for community builds.
func NewWebhookDispatcher() *WebhookDispatcher { return &WebhookDispatcher{} }

// SetWebhookDispatcher is a no-op on community builds.
func (s *Service) SetWebhookDispatcher(_ *WebhookDispatcher) {}

// IdempotencyWrapFn matches the enterprise signature so run.go's
// SetIdempotencyWrap call compiles under both builds.
type IdempotencyWrapFn func(w http.ResponseWriter, r *http.Request, orgID, tenantID, endpoint string, handler func(http.ResponseWriter, *http.Request))

// SetIdempotencyWrap is a no-op on community builds (HITL is enterprise-only
// so there is no handler to wrap).
func SetIdempotencyWrap(_ IdempotencyWrapFn) {}

// ExpireStaleAcrossTenants is the FORCE-RLS-safe expire path on community
// builds — a no-op returning zero.
func (s *Service) ExpireStaleAcrossTenants(_ context.Context, _ *sql.DB) (int, error) {
	return 0, nil
}

// ApprovalRequest is the return shape for Service.CreateApprovalRequest.
// Field-for-field match with the enterprise build so call sites in
// agent/ compile in both. Community build never populates a real one
// because CreateApprovalRequest always rejects.
type ApprovalRequest struct {
	RequestID           uuid.UUID
	OrgID               string
	TenantID            string
	ClientID            string
	UserID              string
	OriginalQuery       string
	RequestType         string
	RequestContext      map[string]interface{}
	TriggeredPolicyID   string
	TriggeredPolicyName string
	TriggerReason       string
	Severity            string
	EUAIActArticle      string
	ComplianceFramework string
	RiskClassification  string
	Status              string
	ExpiresAt           time.Time
}

// CreateApprovalRequest is the in-process entry point used by the MCP
// tool path. Community build always rejects with
// ErrHITLApprovalDisabledByTier — the call site translates this into a
// user-visible message pointing at the Evaluation license URL. The
// enterprise build implementation in service.go enforces the same gate
// for Community-tier processes plus does the real DB write for
// Evaluation+ tiers.
func (s *Service) CreateApprovalRequest(_ context.Context, _ CreateApprovalInput) (*ApprovalRequest, error) {
	return nil, ErrHITLApprovalDisabledByTier
}
