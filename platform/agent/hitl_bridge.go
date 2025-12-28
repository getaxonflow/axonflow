// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// HITL Bridge - Policy Engine to HITL Queue Integration
// Enables require_approval action for human oversight (EU AI Act Article 14)

package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// HITLBridge provides integration between policy evaluation and HITL queue.
// When a policy returns ActionRequireApproval, the bridge creates an approval
// request and returns the request ID for tracking.
type HITLBridge struct {
	service HITLService
}

// HITLService defines the interface for HITL queue operations.
// This interface allows for both enterprise (database-backed) and
// community (stub) implementations.
type HITLService interface {
	CreateApprovalRequest(ctx context.Context, input HITLCreateInput) (*HITLApprovalRequest, error)
	GetApprovalRequest(ctx context.Context, requestID uuid.UUID) (*HITLApprovalRequest, error)
}

// HITLCreateInput contains the data needed to create an approval request.
type HITLCreateInput struct {
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

// HITLApprovalRequest represents an approval request in the HITL queue.
type HITLApprovalRequest struct {
	RequestID  uuid.UUID
	OrgID      string
	TenantID   string
	Status     string // pending, approved, rejected, expired, overridden
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ReviewedAt *time.Time
	ReviewerID string
	Comment    string
}

// HITLPolicyResult extends StaticPolicyResult with HITL-specific fields.
type HITLPolicyResult struct {
	*StaticPolicyResult

	// RequiresApproval indicates the request needs human approval before proceeding.
	RequiresApproval bool

	// ApprovalID is the UUID of the created HITL request (if RequiresApproval is true).
	ApprovalID uuid.UUID

	// ApprovalStatus is the current status of the approval request.
	ApprovalStatus string

	// Message provides user-friendly explanation of the pause.
	Message string
}

// NewHITLBridge creates a new HITL bridge with the given service.
func NewHITLBridge(service HITLService) *HITLBridge {
	return &HITLBridge{service: service}
}

// DefaultApprovalExpiration is the default expiration time for HITL approval requests.
const DefaultApprovalExpiration = 24 * time.Hour

// CreateApprovalFromPolicy creates an HITL approval request from a policy trigger.
// This is called when a policy evaluation returns ActionRequireApproval.
func (b *HITLBridge) CreateApprovalFromPolicy(
	ctx context.Context,
	orgID, tenantID, clientID, userID string,
	query string,
	requestType string,
	policyID, policyName string,
	triggerReason string,
	severity string,
	complianceFramework string, // e.g., "EU AI Act", "SEBI AI/ML", "RBI FREE-AI"
	complianceArticle string, // e.g., "Article 14", "Section 2.4"
) (*HITLApprovalRequest, error) {
	if b.service == nil {
		return nil, fmt.Errorf("HITL service not configured")
	}

	// Use defaults if not specified
	if complianceFramework == "" {
		complianceFramework = "EU AI Act"
	}
	if complianceArticle == "" {
		complianceArticle = "Article 14"
	}

	input := HITLCreateInput{
		OrgID:               orgID,
		TenantID:            tenantID,
		ClientID:            clientID,
		UserID:              userID,
		OriginalQuery:       query,
		RequestType:         requestType,
		TriggeredPolicyID:   policyID,
		TriggeredPolicyName: policyName,
		TriggerReason:       triggerReason,
		Severity:            severity,
		EUAIActArticle:      complianceArticle,
		ComplianceFramework: complianceFramework,
		RiskClassification:  mapSeverityToRisk(severity),
		ExpiresIn:           DefaultApprovalExpiration,
	}

	return b.service.CreateApprovalRequest(ctx, input)
}

// GetApprovalStatus checks the current status of an approval request.
func (b *HITLBridge) GetApprovalStatus(ctx context.Context, approvalID uuid.UUID) (string, error) {
	if b.service == nil {
		return "", fmt.Errorf("HITL service not configured")
	}

	req, err := b.service.GetApprovalRequest(ctx, approvalID)
	if err != nil {
		return "", err
	}

	return req.Status, nil
}

// IsApproved returns true if the request has been approved.
func (b *HITLBridge) IsApproved(ctx context.Context, approvalID uuid.UUID) (bool, error) {
	status, err := b.GetApprovalStatus(ctx, approvalID)
	if err != nil {
		return false, err
	}
	return status == "approved" || status == "overridden", nil
}

// IsRejected returns true if the request has been rejected.
func (b *HITLBridge) IsRejected(ctx context.Context, approvalID uuid.UUID) (bool, error) {
	status, err := b.GetApprovalStatus(ctx, approvalID)
	if err != nil {
		return false, err
	}
	return status == "rejected", nil
}

// IsPending returns true if the request is still pending approval.
func (b *HITLBridge) IsPending(ctx context.Context, approvalID uuid.UUID) (bool, error) {
	status, err := b.GetApprovalStatus(ctx, approvalID)
	if err != nil {
		return false, err
	}
	return status == "pending", nil
}

// mapSeverityToRisk maps policy severity to EU AI Act risk classification.
func mapSeverityToRisk(severity string) string {
	switch severity {
	case "critical":
		return "high-risk"
	case "high":
		return "high-risk"
	case "medium":
		return "limited-risk"
	case "low":
		return "minimal-risk"
	default:
		return "high-risk" // Default to high-risk for unknown severities
	}
}

// NoOpHITLService is a stub implementation for Community Edition.
// It allows require_approval to be used but always returns immediately
// without actual human oversight (upgrade path to Enterprise).
type NoOpHITLService struct{}

// CreateApprovalRequest in NoOp mode creates a dummy request that's immediately approved.
func (s *NoOpHITLService) CreateApprovalRequest(ctx context.Context, input HITLCreateInput) (*HITLApprovalRequest, error) {
	return &HITLApprovalRequest{
		RequestID: uuid.New(),
		OrgID:     input.OrgID,
		TenantID:  input.TenantID,
		Status:    "approved", // Auto-approved in Community Edition
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil
}

// GetApprovalRequest in NoOp mode returns a dummy approved request.
func (s *NoOpHITLService) GetApprovalRequest(ctx context.Context, requestID uuid.UUID) (*HITLApprovalRequest, error) {
	return &HITLApprovalRequest{
		RequestID: requestID,
		Status:    "approved",
		CreatedAt: time.Now(),
	}, nil
}
