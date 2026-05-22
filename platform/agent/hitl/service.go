// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL Queue Service
// EU AI Act Article 14 - Human Oversight Business Logic

//go:build enterprise

package hitl

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"axonflow/platform/agent/license"
	logutil "axonflow/platform/shared/logger"

	"github.com/google/uuid"
)

// ErrPendingApprovalLimitExceeded is returned when the pending approval limit is reached.
var ErrPendingApprovalLimitExceeded = fmt.Errorf("pending approval limit exceeded")

// ErrHITLApprovalDisabledByTier is returned when the running process is on a
// tier that does not enable HITL approvals (Community). The platform's tier
// matrix in `license/tier.go` defines `HITLApprovalEnabled: false` for
// Community-tier; we surface that as an explicit error so callers (HTTP
// handlers, in-process callers like the MCP tool path) can map to a clear
// "requires Evaluation+ license" response.
//
// Mirrors the orchestrator's existing WCP HITL gate at
// `platform/orchestrator/hitl_wcp_community.go` so a self-hosted process
// blocks user-initiated approvals at every entry point uniformly.
var ErrHITLApprovalDisabledByTier = errors.New("HITL approvals require an Evaluation or higher license tier; current tier is Community")

// tierProvider lets tests override the tier source. In production this
// resolves to the binary's effective license tier via
// `license.GetCurrentTier`. Defaults to that on Service construction.
type tierProvider func(ctx context.Context) license.Tier

// Service provides business logic for HITL queue operations.
type Service struct {
	repo                *Repository
	defaultExpiry       time.Duration
	maxExpiry           time.Duration
	maxPendingApprovals atomic.Int64 // 0 or negative = unlimited
	// currentTier resolves the running process's tier on every call so the
	// gate reflects hot-reloaded license state (the license validator caches
	// internally; tier flips take effect on next call).
	currentTier tierProvider
}

// ServiceConfig contains configuration for the HITL service.
type ServiceConfig struct {
	DefaultExpiry       time.Duration // Default request expiry (e.g., 24h)
	MaxExpiry           time.Duration // Maximum request expiry (e.g., 168h/7 days)
	MaxPendingApprovals int           // Max pending approvals per tenant (0 = unlimited)
}

// NewService creates a new HITL service.
func NewService(repo *Repository, config ServiceConfig) *Service {
	if config.DefaultExpiry == 0 {
		config.DefaultExpiry = 24 * time.Hour
	}
	if config.MaxExpiry == 0 {
		config.MaxExpiry = 168 * time.Hour // 7 days
	}
	svc := &Service{
		repo:          repo,
		defaultExpiry: config.DefaultExpiry,
		maxExpiry:     config.MaxExpiry,
		currentTier:   license.GetCurrentTier,
	}
	svc.maxPendingApprovals.Store(int64(config.MaxPendingApprovals))
	return svc
}

// SetTierProviderForTest overrides the tier source. Test-only; production
// callers must not invoke this (the default `license.GetCurrentTier` is
// the production source of truth).
func (s *Service) SetTierProviderForTest(p tierProvider) {
	s.currentTier = p
}

// SetMaxPendingApprovals updates the max pending approvals limit (for hot-reload via license changes).
func (s *Service) SetMaxPendingApprovals(limit int) {
	s.maxPendingApprovals.Store(int64(limit))
}

// CreateApprovalRequest validates and creates a new approval request.
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
}

// CreateApprovalRequest creates a new approval request in the queue.
func (s *Service) CreateApprovalRequest(ctx context.Context, input CreateApprovalInput) (*ApprovalRequest, error) {
	// Validate required fields first (before any DB queries)
	if input.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	if input.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if input.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if input.OriginalQuery == "" {
		return nil, fmt.Errorf("original_query is required")
	}
	if input.RequestType == "" {
		return nil, fmt.Errorf("request_type is required")
	}
	if input.TriggeredPolicyID == "" {
		return nil, fmt.Errorf("triggered_policy_id is required")
	}
	if input.TriggeredPolicyName == "" {
		return nil, fmt.Errorf("triggered_policy_name is required")
	}
	if input.TriggerReason == "" {
		return nil, fmt.Errorf("trigger_reason is required")
	}

	// Validate severity
	validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if input.Severity == "" {
		input.Severity = "high"
	}
	if !validSeverities[input.Severity] {
		return nil, fmt.Errorf("invalid severity: %s", input.Severity)
	}

	// License-tier gate. Community-tier processes (no AXONFLOW_LICENSE_KEY,
	// or invalid/expired license) reject HITL-approval creation here so the
	// `hitl_approval_queue` row is never written. Mirrors the WCP gate at
	// `platform/orchestrator/hitl_wcp_community.go` so the same call from
	// the HTTP handler path AND the in-process MCP-tool path both fail at
	// this single chokepoint.
	//
	// Eval-or-higher tiers fall through to the existing flow.
	if s.currentTier != nil {
		tier := s.currentTier(ctx)
		if !license.IsEvaluationOrHigher(tier) {
			return nil, ErrHITLApprovalDisabledByTier
		}
	}

	// Check pending approval limit per tenant (after validation, before DB writes)
	maxPending := int(s.maxPendingApprovals.Load())
	if maxPending > 0 {
		pendingCount, err := s.repo.CountPendingByTenant(ctx, input.TenantID)
		if err != nil {
			log.Printf("[HITL] Failed to check pending approval count for tenant %s: %v", logutil.Sanitize(input.TenantID), err)
			return nil, fmt.Errorf("failed to verify pending approval limit: %w", err)
		}
		if pendingCount >= maxPending {
			return nil, fmt.Errorf("%w: tenant %s has %d pending approvals (limit: %d). Upgrade your license for higher limits: https://getaxonflow.com/enterprise",
				ErrPendingApprovalLimitExceeded, input.TenantID, pendingCount, maxPending)
		}
	}

	// Calculate expiry
	expiresIn := input.ExpiresIn
	if expiresIn == 0 {
		expiresIn = s.defaultExpiry
	}
	if expiresIn > s.maxExpiry {
		expiresIn = s.maxExpiry
	}

	req := &ApprovalRequest{
		RequestID:           uuid.New(),
		OrgID:               input.OrgID,
		TenantID:            input.TenantID,
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		OriginalQuery:       input.OriginalQuery,
		RequestType:         input.RequestType,
		RequestContext:      input.RequestContext,
		TriggeredPolicyID:   input.TriggeredPolicyID,
		TriggeredPolicyName: input.TriggeredPolicyName,
		TriggerReason:       input.TriggerReason,
		Severity:            input.Severity,
		EUAIActArticle:      input.EUAIActArticle,
		ComplianceFramework: input.ComplianceFramework,
		RiskClassification:  input.RiskClassification,
		Status:              "pending",
		ExpiresAt:           time.Now().Add(expiresIn),
	}

	if err := s.repo.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create approval request: %w", err)
	}

	// Add creation history entry
	history := &ApprovalHistory{
		RequestID:  req.RequestID,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		Action:     "created",
		NewStatus:  "pending",
	}
	if err := s.repo.AddHistory(ctx, history); err != nil {
		// Log but don't fail - history is supplementary
		fmt.Printf("[HITL] Warning: failed to add creation history: %v\n", err)
	}

	return req, nil
}

// GetApprovalRequest retrieves an approval request by ID.
func (s *Service) GetApprovalRequest(ctx context.Context, requestID uuid.UUID) (*ApprovalRequest, error) {
	req, err := s.repo.GetByRequestID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get approval request: %w", err)
	}
	if req == nil {
		return nil, fmt.Errorf("approval request not found: %s", requestID)
	}
	return req, nil
}

// ListApprovalRequests lists approval requests with filters.
func (s *Service) ListApprovalRequests(ctx context.Context, filter ListFilter) ([]*ApprovalRequest, int64, error) {
	return s.repo.List(ctx, filter)
}

// ApproveRequest approves a pending request.
func (s *Service) ApproveRequest(ctx context.Context, requestID uuid.UUID, reviewer *Reviewer, comment string) error {
	// Get current request
	req, err := s.repo.GetByRequestID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get request: %w", err)
	}
	if req == nil {
		return fmt.Errorf("approval request not found")
	}

	// Validate state transition
	if req.Status != "pending" {
		return fmt.Errorf("cannot approve request with status: %s", req.Status)
	}

	// Check expiry
	if time.Now().After(req.ExpiresAt) {
		return fmt.Errorf("request has expired")
	}

	// Update status. v9 Phase 8 #2384 PR-C1: req.OrgID required for RLS scope.
	if err := s.repo.UpdateStatus(ctx, req.OrgID, requestID, "approved", reviewer, comment); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	// Add history
	history := &ApprovalHistory{
		RequestID:      requestID,
		OrgID:          req.OrgID,
		TenantID:       req.TenantID,
		Action:         "approved",
		ActorID:        reviewer.ID,
		ActorEmail:     reviewer.Email,
		ActorRole:      reviewer.Role,
		ActorIP:        reviewer.IP,
		Comment:        comment,
		PreviousStatus: "pending",
		NewStatus:      "approved",
	}
	if err := s.repo.AddHistory(ctx, history); err != nil {
		fmt.Printf("[HITL] Warning: failed to add approval history: %v\n", err)
	}

	return nil
}

// RejectRequest rejects a pending request.
func (s *Service) RejectRequest(ctx context.Context, requestID uuid.UUID, reviewer *Reviewer, comment string) error {
	// Get current request
	req, err := s.repo.GetByRequestID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get request: %w", err)
	}
	if req == nil {
		return fmt.Errorf("approval request not found")
	}

	// Validate state transition
	if req.Status != "pending" {
		return fmt.Errorf("cannot reject request with status: %s", req.Status)
	}

	// Update status. v9 Phase 8 #2384 PR-C1: req.OrgID required for RLS scope.
	if err := s.repo.UpdateStatus(ctx, req.OrgID, requestID, "rejected", reviewer, comment); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	// Add history
	history := &ApprovalHistory{
		RequestID:      requestID,
		OrgID:          req.OrgID,
		TenantID:       req.TenantID,
		Action:         "rejected",
		ActorID:        reviewer.ID,
		ActorEmail:     reviewer.Email,
		ActorRole:      reviewer.Role,
		ActorIP:        reviewer.IP,
		Comment:        comment,
		PreviousStatus: "pending",
		NewStatus:      "rejected",
	}
	if err := s.repo.AddHistory(ctx, history); err != nil {
		fmt.Printf("[HITL] Warning: failed to add rejection history: %v\n", err)
	}

	return nil
}

// OverrideRequest overrides a request with justification (bypasses normal approval).
func (s *Service) OverrideRequest(ctx context.Context, requestID uuid.UUID, justification string, authorizedBy *Reviewer) error {
	if justification == "" {
		return fmt.Errorf("justification is required for override")
	}
	if authorizedBy == nil || authorizedBy.ID == "" {
		return fmt.Errorf("authorized_by is required for override")
	}

	// Get current request
	req, err := s.repo.GetByRequestID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get request: %w", err)
	}
	if req == nil {
		return fmt.Errorf("approval request not found")
	}

	// Can only override pending requests
	if req.Status != "pending" {
		return fmt.Errorf("cannot override request with status: %s", req.Status)
	}

	// Perform override. v9 Phase 8 #2384 PR-C1: req.OrgID required for RLS scope.
	if err := s.repo.Override(ctx, req.OrgID, requestID, justification, authorizedBy.ID); err != nil {
		return fmt.Errorf("override request: %w", err)
	}

	// Add history
	history := &ApprovalHistory{
		RequestID:      requestID,
		OrgID:          req.OrgID,
		TenantID:       req.TenantID,
		Action:         "overridden",
		ActorID:        authorizedBy.ID,
		ActorEmail:     authorizedBy.Email,
		ActorRole:      authorizedBy.Role,
		ActorIP:        authorizedBy.IP,
		Justification:  justification,
		PreviousStatus: "pending",
		NewStatus:      "overridden",
	}
	if err := s.repo.AddHistory(ctx, history); err != nil {
		fmt.Printf("[HITL] Warning: failed to add override history: %v\n", err)
	}

	return nil
}

// GetPendingStats returns dashboard metrics for pending approvals.
func (s *Service) GetPendingStats(ctx context.Context, orgID string) (*PendingStats, error) {
	return s.repo.GetPendingStats(ctx, orgID)
}

// GetRequestHistory returns the audit trail for a request.
func (s *Service) GetRequestHistory(ctx context.Context, requestID uuid.UUID) ([]*ApprovalHistory, error) {
	return s.repo.GetHistory(ctx, requestID)
}

// ExpireStaleRequests expires all stale pending requests.
func (s *Service) ExpireStaleRequests(ctx context.Context) (int, error) {
	return s.repo.ExpireStale(ctx)
}
