// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/tenantscope"
)

// PlanAuditLogger interface for audit logging plan operations
// This avoids a circular dependency with the orchestrator package
type PlanAuditLogger interface {
	LogPlanOperation(ctx context.Context, entry *PlanAuditEntry)
}

// PlanAuditEntry represents an audit entry for plan operations
type PlanAuditEntry struct {
	PlanID    string
	Query     string
	Domain    string
	Operation string // created, execution_started, completed, failed, expired, cancelled
	Status    string // pending, executing, completed, failed, expired
	StepCount int
	ErrorMsg  string
	TenantID  string
	OrgID     string
	ClientID  string
	UserID    string
	Metadata  map[string]interface{}
}

// ServiceConfig holds configuration for the planning service
type ServiceConfig struct {
	MaxPlansWithVersioning int // Max plans that can have versions (community limit)
	MaxVersionsPerPlan     int // Max versions per plan (community limit)
}

// Service handles plan storage and retrieval for two-step MAP execution
type Service struct {
	repo        Repository
	auditLogger PlanAuditLogger
	config      ServiceConfig
}

// NewService creates a new planning service
func NewService(repo Repository) *Service {
	return &Service{
		repo: repo,
		config: ServiceConfig{
			MaxPlansWithVersioning: MaxCommunityPlans,
			MaxVersionsPerPlan:     MaxCommunityVersionsPerPlan,
		},
	}
}

// NewServiceWithConfig creates a new planning service with custom configuration
func NewServiceWithConfig(repo Repository, config ServiceConfig) *Service {
	svc := NewService(repo)
	if config.MaxPlansWithVersioning > 0 {
		svc.config.MaxPlansWithVersioning = config.MaxPlansWithVersioning
	}
	if config.MaxVersionsPerPlan > 0 {
		svc.config.MaxVersionsPerPlan = config.MaxVersionsPerPlan
	}
	return svc
}

// SetAuditLogger sets the audit logger for the service
func (s *Service) SetAuditLogger(auditLogger PlanAuditLogger) {
	s.auditLogger = auditLogger
}

// logAudit logs a plan audit entry if an audit logger is configured
func (s *Service) logAudit(ctx context.Context, entry *PlanAuditEntry) {
	if s.auditLogger != nil {
		s.auditLogger.LogPlanOperation(ctx, entry)
	}
}

// StorePlan saves a generated plan for later execution
func (s *Service) StorePlan(ctx context.Context, req *CreatePlanRequest) (*Plan, error) {
	if req.PlanID == "" {
		return nil, ErrInvalidPlanID
	}
	if len(req.WorkflowDefinition) == 0 {
		return nil, ErrInvalidWorkflow
	}

	// #3065 (F2): make the empty state unrepresentable. `plans` has NO RLS at
	// all, so the org key on the row IS the entire tenancy boundary — and
	// SavePlan writes it through nullString(), which turned an absent header
	// into a permanent NULL. A NULL-org plan was reachable by every tenant
	// (the old `plan.OrgID != "" && ...` compare skipped the check) and can
	// never be re-authorized now that the compare fails closed, so persisting
	// one only manufactures orphans. Migration core/156 enforces the same
	// invariant in the database.
	if err := tenantscope.ValidateRowKeys(req.OrgID, req.TenantID); err != nil {
		return nil, fmt.Errorf("cannot store plan without an authenticated org and tenant: %w", err)
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultPlanTTL
	}

	plan := &Plan{
		PlanID:             req.PlanID,
		Query:              req.Query,
		Domain:             req.Domain,
		ExecutionMode:      req.ExecutionMode,
		Version:            1,
		WorkflowDefinition: req.WorkflowDefinition,
		Complexity:         req.Complexity,
		Parallel:           req.Parallel,
		EstimatedDuration:  req.EstimatedDuration,
		StepCount:          req.StepCount,
		Status:             PlanStatusPending,
		OrgID:              req.OrgID,
		TenantID:           req.TenantID,
		UserID:             req.UserID,
		ClientID:           req.ClientID,
		ExpiresAt:          time.Now().Add(ttl),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	if err := s.repo.SavePlan(ctx, plan); err != nil {
		return nil, fmt.Errorf("failed to store plan: %w", err)
	}

	log.Printf("[PlanService] Stored plan %s (domain: %s, steps: %d, expires: %v)",
		logutil.Sanitize(plan.PlanID), logutil.Sanitize(plan.Domain), plan.StepCount, plan.ExpiresAt)

	// Audit log: plan created
	s.logAudit(ctx, &PlanAuditEntry{
		PlanID:    plan.PlanID,
		Query:     plan.Query,
		Domain:    plan.Domain,
		Operation: "created",
		Status:    string(plan.Status),
		StepCount: plan.StepCount,
		TenantID:  plan.TenantID,
		OrgID:     plan.OrgID,
		ClientID:  plan.ClientID,
		UserID:    plan.UserID,
		Metadata: map[string]interface{}{
			"complexity":         plan.Complexity,
			"parallel":           plan.Parallel,
			"estimated_duration": plan.EstimatedDuration,
			"execution_mode":     plan.ExecutionMode,
			"expires_at":         plan.ExpiresAt,
		},
	})

	return plan, nil
}

// GetPlanForExecution retrieves a plan and validates it can be executed.
// It uses atomic status update to prevent race conditions when multiple
// ExecutePlan requests arrive for the same plan.
func (s *Service) GetPlanForExecution(ctx context.Context, planID string, orgID string) (*Plan, error) {
	plan, err := s.repo.GetPlan(ctx, planID)
	if err != nil {
		return nil, err
	}

	// Authorization: the requesting org must match the plan's org.
	// #3065 (F2): this was `orgID != "" && plan.OrgID != "" && plan.OrgID != orgID`
	// — omitting X-Org-ID skipped it entirely and let any caller execute any
	// tenant's plan. authorizePlan fails closed on an empty value on either
	// side.
	if err := authorizePlan(plan, orgID); err != nil {
		log.Printf("[PlanService] Authorization failed for plan %s requested by org %q: %v",
			logutil.Sanitize(planID), logutil.Sanitize(orgID), err)
		return nil, ErrPlanNotFound // Return not found to avoid leaking plan existence
	}

	// Check if plan is expired
	if plan.IsExpired() {
		// Mark as expired in DB
		_ = s.repo.UpdatePlanStatus(ctx, planID, PlanStatusExpired, nil, "Plan expired")
		return nil, ErrPlanExpired
	}

	// Check if plan can be executed
	if plan.Status != PlanStatusPending {
		if plan.Status == PlanStatusCompleted || plan.Status == PlanStatusFailed {
			return nil, ErrPlanAlreadyRun
		}
		if plan.Status == PlanStatusExecuting {
			return nil, ErrPlanAlreadyRun // Already being executed by another request
		}
		if plan.Status == PlanStatusCancelled {
			return nil, ErrPlanCancelled
		}
		return nil, fmt.Errorf("plan is in %s status, cannot execute", plan.Status)
	}

	// Atomically mark as executing - this prevents race conditions
	// If another request already marked it as executing, this will fail
	if err := s.repo.UpdatePlanStatusAtomic(ctx, planID, PlanStatusPending, PlanStatusExecuting); err != nil {
		if err == ErrPlanAlreadyRun {
			return nil, ErrPlanAlreadyRun
		}
		return nil, fmt.Errorf("failed to mark plan as executing: %w", err)
	}

	// Audit log: execution started
	s.logAudit(ctx, &PlanAuditEntry{
		PlanID:    plan.PlanID,
		Query:     plan.Query,
		Domain:    plan.Domain,
		Operation: "execution_started",
		Status:    string(PlanStatusExecuting),
		StepCount: plan.StepCount,
		TenantID:  plan.TenantID,
		OrgID:     plan.OrgID,
		ClientID:  plan.ClientID,
		UserID:    plan.UserID,
		Metadata: map[string]interface{}{
			"requested_by_org": orgID,
		},
	})

	return plan, nil
}

// MarkPlanCompleted marks a plan as completed with the execution result
func (s *Service) MarkPlanCompleted(ctx context.Context, planID string, result interface{}) error {
	// Get plan details for audit logging
	plan, _ := s.repo.GetPlan(ctx, planID)

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := s.repo.UpdatePlanStatus(ctx, planID, PlanStatusCompleted, resultJSON, ""); err != nil {
		return fmt.Errorf("failed to mark plan completed: %w", err)
	}

	log.Printf("[PlanService] Plan %s completed", logutil.Sanitize(planID))

	// Audit log: plan completed
	if plan != nil {
		s.logAudit(ctx, &PlanAuditEntry{
			PlanID:    planID,
			Query:     plan.Query,
			Domain:    plan.Domain,
			Operation: "completed",
			Status:    string(PlanStatusCompleted),
			StepCount: plan.StepCount,
			TenantID:  plan.TenantID,
			OrgID:     plan.OrgID,
			ClientID:  plan.ClientID,
			UserID:    plan.UserID,
		})
	}

	return nil
}

// MarkPlanFailed marks a plan as failed with an error message
func (s *Service) MarkPlanFailed(ctx context.Context, planID string, errMsg string) error {
	// Get plan details for audit logging
	plan, _ := s.repo.GetPlan(ctx, planID)

	if err := s.repo.UpdatePlanStatus(ctx, planID, PlanStatusFailed, nil, errMsg); err != nil {
		return fmt.Errorf("failed to mark plan failed: %w", err)
	}

	log.Printf("[PlanService] Plan %s failed: %s", logutil.Sanitize(planID), logutil.Sanitize(errMsg))

	// Audit log: plan failed
	if plan != nil {
		s.logAudit(ctx, &PlanAuditEntry{
			PlanID:    planID,
			Query:     plan.Query,
			Domain:    plan.Domain,
			Operation: "failed",
			Status:    string(PlanStatusFailed),
			StepCount: plan.StepCount,
			ErrorMsg:  errMsg,
			TenantID:  plan.TenantID,
			OrgID:     plan.OrgID,
			ClientID:  plan.ClientID,
			UserID:    plan.UserID,
		})
	}

	return nil
}

// CancelPlan cancels a pending or executing plan.
// If orgID is non-empty, it validates cross-tenant authorization.
func (s *Service) CancelPlan(ctx context.Context, planID string, orgID string, reason string) error {
	// Get plan details for validation and audit logging
	plan, err := s.repo.GetPlan(ctx, planID)
	if err != nil {
		return fmt.Errorf("failed to get plan: %w", err)
	}

	// Authorization: the requesting org must match the plan's org (#3065 F2).
	if err := authorizePlan(plan, orgID); err != nil {
		log.Printf("[PlanService] Cancel authorization failed for plan %s requested by org %q: %v",
			logutil.Sanitize(planID), logutil.Sanitize(orgID), err)
		return ErrPlanNotFound // Return not found to avoid leaking plan existence
	}

	// Only pending or executing plans can be cancelled
	if plan.Status != PlanStatusPending && plan.Status != PlanStatusExecuting {
		return fmt.Errorf("plan is in %s status, cannot cancel", plan.Status)
	}

	if err := s.repo.UpdatePlanStatus(ctx, planID, PlanStatusCancelled, nil, reason); err != nil {
		return fmt.Errorf("failed to cancel plan: %w", err)
	}

	log.Printf("[PlanService] Plan %s cancelled: %s", logutil.Sanitize(planID), logutil.Sanitize(reason))

	// Audit log: plan cancelled
	s.logAudit(ctx, &PlanAuditEntry{
		PlanID:    planID,
		Query:     plan.Query,
		Domain:    plan.Domain,
		Operation: "cancelled",
		Status:    string(PlanStatusCancelled),
		StepCount: plan.StepCount,
		ErrorMsg:  reason,
		TenantID:  plan.TenantID,
		OrgID:     plan.OrgID,
		ClientID:  plan.ClientID,
		UserID:    plan.UserID,
	})

	return nil
}

// GetPlan retrieves a plan by ID (for status checks), scoped to the caller's
// org.
//
// #3065 (F3): this method had NO authorization check at all. Its callers —
// the plan-status handler, the cost-estimation handler, the plan-resume
// handler — each re-implemented (or, in the resume handler's case, omitted)
// the fail-open compare afterwards. The check now lives here, once, so a
// fourth caller inherits it instead of forgetting it. Callers that hold no
// request scope use GetPlanUnscoped.
func (s *Service) GetPlan(ctx context.Context, planID, orgID string) (*Plan, error) {
	plan, err := s.repo.GetPlan(ctx, planID)
	if err != nil {
		return nil, err
	}
	if err := authorizePlan(plan, orgID); err != nil {
		log.Printf("[PlanService] GetPlan authorization failed for plan %s requested by org %q: %v",
			logutil.Sanitize(planID), logutil.Sanitize(orgID), err)
		return nil, ErrPlanNotFound // not-found, never 403 — no existence oracle
	}
	return plan, nil
}

// GetPlanUnscoped fetches a plan WITHOUT tenancy authorization.
//
// #3065: the named replacement for calling the old unscoped GetPlan. Exactly
// one caller is legitimate — MAPExecutionTracker.GetPlanStatus, in-process
// reconciliation whose result is authorized by the HTTP layer
// (UnifiedExecutionHandler.checkTenantOwnership) before any byte reaches a
// client. Never call this from a request handler.
func (s *Service) GetPlanUnscoped(ctx context.Context, planID string) (*Plan, error) {
	return s.repo.GetPlan(ctx, planID)
}

// authorizePlan is the single by-id authorization for `plans` (#3065 F2/F3).
//
// It is AuthorizeOrgOnly rather than the two-dimension Authorize because the
// plan by-id call sites thread a bare orgID string: GetPlanForExecution's
// signature is fixed by a call site in a region of run.go owned by another
// workstream, and having half the plan surface check both keys while the
// other half checks one is precisely the kind of per-door divergence this
// issue exists to end. `plans.org_id` has always been the plan tenancy key.
func authorizePlan(plan *Plan, callerOrgID string) error {
	if plan == nil {
		return ErrPlanNotFound
	}
	return tenantscope.NewOrgOnly(callerOrgID).AuthorizeOrgOnly(plan.OrgID)
}

// UpdatePlan updates a plan with optimistic locking and version history
func (s *Service) UpdatePlan(ctx context.Context, req *UpdatePlanRequest) (*Plan, error) {
	if req.PlanID == "" {
		return nil, ErrInvalidPlanID
	}
	if req.ExpectedVersion < 1 {
		return nil, fmt.Errorf("expected_version must be >= 1")
	}

	// Get current plan for validation
	plan, err := s.repo.GetPlan(ctx, req.PlanID)
	if err != nil {
		return nil, err
	}

	// Authorization check (#3065 F2 — fail closed on an empty value either side)
	if err := authorizePlan(plan, req.OrgID); err != nil {
		return nil, ErrPlanNotFound
	}

	// Only pending plans can be updated
	if plan.Status != PlanStatusPending {
		return nil, fmt.Errorf("plan is in %s status, only pending plans can be updated", plan.Status)
	}

	// Community limits: max plans with versioning
	if s.config.MaxPlansWithVersioning > 0 && plan.Version == 1 {
		count, err := s.repo.CountPlansWithVersioning(ctx, plan.OrgID)
		if err != nil {
			log.Printf("[PlanService] Warning: failed to count versioned plans: %v", err)
		} else if count >= s.config.MaxPlansWithVersioning {
			return nil, ErrMaxPlans
		}
	}

	// Community limits: max versions per plan
	if s.config.MaxVersionsPerPlan > 0 {
		count, err := s.repo.CountVersions(ctx, req.PlanID)
		if err != nil {
			log.Printf("[PlanService] Warning: failed to count versions: %v", err)
		} else if count >= s.config.MaxVersionsPerPlan {
			return nil, ErrMaxVersions
		}
	}

	// Save snapshot of current state before update
	snapshot, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("failed to create version snapshot: %w", err)
	}

	// Build change summary
	changes := []string{}
	updates := map[string]interface{}{}
	if req.ExecutionMode != "" && req.ExecutionMode != plan.ExecutionMode {
		updates["execution_mode"] = req.ExecutionMode
		changes = append(changes, fmt.Sprintf("execution_mode: %s → %s", plan.ExecutionMode, req.ExecutionMode))
	}
	if req.Domain != "" && req.Domain != plan.Domain {
		updates["domain"] = req.Domain
		changes = append(changes, fmt.Sprintf("domain: %s → %s", plan.Domain, req.Domain))
	}

	if len(updates) == 0 {
		return plan, nil // No changes
	}

	// Perform optimistic update
	updatedPlan, err := s.repo.UpdatePlanWithVersion(ctx, req.PlanID, req.ExpectedVersion, updates)
	if err != nil {
		return nil, err
	}

	// Save version snapshot
	changeSummary := ""
	for i, c := range changes {
		if i > 0 {
			changeSummary += "; "
		}
		changeSummary += c
	}

	if err := s.repo.SavePlanVersion(ctx, &PlanVersion{
		PlanID:        req.PlanID,
		Version:       req.ExpectedVersion, // Snapshot of the version before update
		OrgID:         plan.OrgID,
		Snapshot:      snapshot,
		ChangedBy:     req.ChangedBy,
		ChangeType:    "update",
		ChangeSummary: changeSummary,
	}); err != nil {
		log.Printf("[PlanService] Warning: failed to save plan version: %v", err)
	}

	log.Printf("[PlanService] Plan %s updated: v%d → v%d (%s)", logutil.Sanitize(req.PlanID), req.ExpectedVersion, updatedPlan.Version, logutil.Sanitize(changeSummary))

	// Audit log
	s.logAudit(ctx, &PlanAuditEntry{
		PlanID:    req.PlanID,
		Operation: "updated",
		Status:    string(updatedPlan.Status),
		TenantID:  plan.TenantID,
		OrgID:     plan.OrgID,
		ClientID:  plan.ClientID,
		UserID:    plan.UserID,
		Metadata: map[string]interface{}{
			"from_version": req.ExpectedVersion,
			"to_version":   updatedPlan.Version,
			"changes":      changeSummary,
		},
	})

	return updatedPlan, nil
}

// GetPlanVersions retrieves version history for a plan
func (s *Service) GetPlanVersions(ctx context.Context, planID string, orgID string) ([]PlanVersion, error) {
	// Verify plan exists and check authorization
	plan, err := s.repo.GetPlan(ctx, planID)
	if err != nil {
		return nil, err
	}
	if err := authorizePlan(plan, orgID); err != nil {
		return nil, ErrPlanNotFound
	}

	return s.repo.GetPlanVersions(ctx, planID)
}

// RollbackPlan rolls back a plan to a previous version.
// It creates a pre-rollback snapshot, restores the target version, and increments the version.
func (s *Service) RollbackPlan(ctx context.Context, req *RollbackPlanRequest) (*Plan, error) {
	if req.PlanID == "" {
		return nil, ErrInvalidPlanID
	}
	if req.TargetVersion < 1 {
		return nil, fmt.Errorf("target_version must be >= 1")
	}

	// Get current plan for validation
	plan, err := s.repo.GetPlan(ctx, req.PlanID)
	if err != nil {
		return nil, err
	}

	// Authorization check (#3065 F2 — fail closed on an empty value either side)
	if err := authorizePlan(plan, req.OrgID); err != nil {
		return nil, ErrPlanNotFound
	}

	// Only pending plans can be rolled back
	if plan.Status != PlanStatusPending {
		return nil, fmt.Errorf("plan is in %s status, only pending plans can be rolled back", plan.Status)
	}

	// Can't rollback to current or future version
	if req.TargetVersion >= plan.Version {
		return nil, fmt.Errorf("target version %d must be less than current version %d", req.TargetVersion, plan.Version)
	}

	// Community limits: max versions per plan (rollback creates a new version)
	if s.config.MaxVersionsPerPlan > 0 {
		count, err := s.repo.CountVersions(ctx, req.PlanID)
		if err != nil {
			log.Printf("[PlanService] Warning: failed to count versions: %v", err)
		} else if count >= s.config.MaxVersionsPerPlan {
			return nil, ErrMaxVersions
		}
	}

	// Fetch the target version snapshot
	targetVersion, err := s.repo.GetPlanVersion(ctx, req.PlanID, req.TargetVersion)
	if err != nil {
		return nil, err
	}

	// Save pre-rollback snapshot (current state)
	preRollbackSnapshot, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-rollback snapshot: %w", err)
	}
	if err := s.repo.SavePlanVersion(ctx, &PlanVersion{
		PlanID:        req.PlanID,
		Version:       plan.Version,
		OrgID:         plan.OrgID,
		Snapshot:      preRollbackSnapshot,
		ChangedBy:     req.RolledBackBy,
		ChangeType:    "rollback",
		ChangeSummary: fmt.Sprintf("rollback to v%d (pre-rollback state)", req.TargetVersion),
	}); err != nil {
		log.Printf("[PlanService] Warning: failed to save pre-rollback version: %v", err)
	}

	// Restore plan from target snapshot
	restoredPlan, err := s.repo.RollbackPlan(ctx, req.PlanID, plan.Version, targetVersion.Snapshot)
	if err != nil {
		return nil, err
	}

	log.Printf("[PlanService] Plan %s rolled back: v%d → v%d (restored from v%d snapshot)",
		logutil.Sanitize(req.PlanID), plan.Version, restoredPlan.Version, req.TargetVersion)

	// Audit log
	s.logAudit(ctx, &PlanAuditEntry{
		PlanID:    req.PlanID,
		Operation: "rollback",
		Status:    string(restoredPlan.Status),
		TenantID:  plan.TenantID,
		OrgID:     plan.OrgID,
		ClientID:  plan.ClientID,
		UserID:    plan.UserID,
		Metadata: map[string]interface{}{
			"from_version":   plan.Version,
			"to_version":     restoredPlan.Version,
			"target_version": req.TargetVersion,
			"rolled_back_by": req.RolledBackBy,
		},
	})

	return restoredPlan, nil
}

// CleanupExpiredPlans removes expired plans
func (s *Service) CleanupExpiredPlans(ctx context.Context) (int, error) {
	count, err := s.repo.CleanupExpiredPlans(ctx)
	if err != nil {
		return 0, err
	}
	if count > 0 {
		log.Printf("[PlanService] Cleaned up %d expired plans", count)
	}
	return count, nil
}

// CleanupMetricsCallback is called after each cleanup run with metrics
type CleanupMetricsCallback func(cleaned int, err error, duration time.Duration)

// StartCleanupWorker starts a background goroutine to clean up expired plans
func (s *Service) StartCleanupWorker(ctx context.Context, interval time.Duration) {
	s.StartCleanupWorkerWithMetrics(ctx, interval, nil)
}

// StartCleanupWorkerWithMetrics starts a cleanup worker that reports metrics via callback
func (s *Service) StartCleanupWorkerWithMetrics(ctx context.Context, interval time.Duration, onCleanup CleanupMetricsCallback) {
	if interval == 0 {
		interval = 15 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[PlanService] Cleanup worker stopped")
				return
			case <-ticker.C:
				start := time.Now()
				count, err := s.CleanupExpiredPlans(ctx)
				elapsed := time.Since(start)
				if err != nil {
					log.Printf("[PlanService] Cleanup error: %v", err)
				}
				if onCleanup != nil {
					onCleanup(count, err, elapsed)
				}
			}
		}
	}()

	log.Printf("[PlanService] Started cleanup worker (interval: %v)", interval)
}
