// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// PlanAuditLogger interface for audit logging plan operations
// This avoids a circular dependency with the orchestrator package
type PlanAuditLogger interface {
	LogPlanOperation(ctx context.Context, entry *PlanAuditEntry)
}

// PlanAuditEntry represents an audit entry for plan operations
type PlanAuditEntry struct {
	PlanID     string
	Query      string
	Domain     string
	Operation  string // created, execution_started, completed, failed, expired, cancelled
	Status     string // pending, executing, completed, failed, expired
	StepCount  int
	ErrorMsg   string
	TenantID   string
	OrgID      string
	ClientID   string
	UserID     string
	Metadata   map[string]interface{}
}

// Service handles plan storage and retrieval for two-step MAP execution
type Service struct {
	repo        Repository
	auditLogger PlanAuditLogger
}

// NewService creates a new planning service
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
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

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultPlanTTL
	}

	plan := &Plan{
		PlanID:             req.PlanID,
		Query:              req.Query,
		Domain:             req.Domain,
		ExecutionMode:      req.ExecutionMode,
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
		plan.PlanID, plan.Domain, plan.StepCount, plan.ExpiresAt)

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

	// Authorization: verify the requesting org matches the plan's org
	// This prevents cross-tenant plan execution
	if orgID != "" && plan.OrgID != "" && plan.OrgID != orgID {
		log.Printf("[PlanService] Authorization failed: plan %s belongs to org %s, requested by org %s",
			planID, plan.OrgID, orgID)
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
		return nil, fmt.Errorf("plan is in %s status, cannot execute", plan.Status)
	}

	// Atomically mark as executing - this prevents race conditions
	// If another request already marked it as executing, this will fail
	if err := s.repo.UpdatePlanStatusAtomic(ctx, planID, PlanStatusPending, PlanStatusExecuting); err != nil {
		if err == ErrPlanAlreadyRun {
			return nil, ErrPlanAlreadyRun
		}
		log.Printf("[PlanService] Warning: failed to mark plan %s as executing: %v", planID, err)
		// Continue anyway - the plan was retrieved successfully
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

	log.Printf("[PlanService] Plan %s completed", planID)

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

	log.Printf("[PlanService] Plan %s failed: %s", planID, errMsg)

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

// CancelPlan cancels a pending or executing plan
func (s *Service) CancelPlan(ctx context.Context, planID string, reason string) error {
	// Get plan details for validation and audit logging
	plan, err := s.repo.GetPlan(ctx, planID)
	if err != nil {
		return fmt.Errorf("failed to get plan: %w", err)
	}

	// Only pending or executing plans can be cancelled
	if plan.Status != PlanStatusPending && plan.Status != PlanStatusExecuting {
		return fmt.Errorf("plan is in %s status, cannot cancel", plan.Status)
	}

	if err := s.repo.UpdatePlanStatus(ctx, planID, PlanStatusCancelled, nil, reason); err != nil {
		return fmt.Errorf("failed to cancel plan: %w", err)
	}

	log.Printf("[PlanService] Plan %s cancelled: %s", planID, reason)

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

// GetPlan retrieves a plan by ID (for status checks)
func (s *Service) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	return s.repo.GetPlan(ctx, planID)
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

// StartCleanupWorker starts a background goroutine to clean up expired plans
func (s *Service) StartCleanupWorker(ctx context.Context, interval time.Duration) {
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
				if _, err := s.CleanupExpiredPlans(ctx); err != nil {
					log.Printf("[PlanService] Cleanup error: %v", err)
				}
			}
		}
	}()

	log.Printf("[PlanService] Started cleanup worker (interval: %v)", interval)
}
