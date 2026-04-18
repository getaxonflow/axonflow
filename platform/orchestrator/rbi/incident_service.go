// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// AIIncidentService provides business logic for AI incident operations.
type AIIncidentService interface {
	CreateIncident(ctx context.Context, orgID string, req *CreateIncidentRequest) (*AIIncident, error)
	GetIncident(ctx context.Context, orgID, id string) (*AIIncident, error)
	GetIncidentByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error)
	ListIncidents(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error)
	UpdateIncident(ctx context.Context, orgID, id string, req *UpdateIncidentRequest) (*AIIncident, error)
	DeleteIncident(ctx context.Context, orgID, id string) error
	UpdateStatus(ctx context.Context, orgID, id string, status IncidentStatus, resolution string) (*AIIncident, error)
	AddRemediationAction(ctx context.Context, orgID, id string, action *RemediationAction) (*AIIncident, error)
	UpdateRemediationAction(ctx context.Context, orgID, id, actionID string, req *UpdateRemediationActionRequest) (*AIIncident, error)
	RecordBoardNotification(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error)
	RecordRBINotification(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error)
	GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error)
	GetPendingBoardNotifications(ctx context.Context, orgID string) ([]*AIIncident, error)
	GetPendingRBINotifications(ctx context.Context, orgID string) ([]*AIIncident, error)
}

// CreateIncidentRequest is the request to create an incident.
type CreateIncidentRequest struct {
	SystemID                  string              `json:"system_id,omitempty"`
	IncidentType              string              `json:"incident_type" validate:"required"`
	Severity                  string              `json:"severity" validate:"required"`
	DetectedAt                *time.Time          `json:"detected_at,omitempty"`
	DetectedBy                string              `json:"detected_by" validate:"required"`
	DetectionDetails          string              `json:"detection_details,omitempty"`
	Title                     string              `json:"title" validate:"required"`
	Description               string              `json:"description" validate:"required"`
	RootCause                 string              `json:"root_cause,omitempty"`
	AffectedCustomersCount    *int                `json:"affected_customers_count,omitempty"`
	AffectedTransactionsCount *int                `json:"affected_transactions_count,omitempty"`
	FinancialImpactINR        *float64            `json:"financial_impact_inr,omitempty"`
	ReputationalImpact        string              `json:"reputational_impact,omitempty"`
	ImmediateActionTaken      string              `json:"immediate_action_taken,omitempty"`
	RemediationActions        []RemediationAction `json:"remediation_actions,omitempty"`
	BoardNotificationRequired bool                `json:"board_notification_required"`
	RBINotificationRequired   bool                `json:"rbi_notification_required"`
	EvidenceFiles             []string            `json:"evidence_files,omitempty"`
	Tags                      []string            `json:"tags,omitempty"`
	Metadata                  map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateIncidentRequest is the request to update an incident.
type UpdateIncidentRequest struct {
	IncidentType              *string                 `json:"incident_type,omitempty"`
	Severity                  *string                 `json:"severity,omitempty"`
	RootCause                 *string                 `json:"root_cause,omitempty"`
	AffectedCustomersCount    *int                    `json:"affected_customers_count,omitempty"`
	AffectedTransactionsCount *int                    `json:"affected_transactions_count,omitempty"`
	FinancialImpactINR        *float64                `json:"financial_impact_inr,omitempty"`
	ReputationalImpact        *string                 `json:"reputational_impact,omitempty"`
	ImmediateActionTaken      *string                 `json:"immediate_action_taken,omitempty"`
	LongTermFix               *string                 `json:"long_term_fix,omitempty"`
	LessonsLearned            *string                 `json:"lessons_learned,omitempty"`
	BoardNotificationRequired *bool                   `json:"board_notification_required,omitempty"`
	RBINotificationRequired   *bool                   `json:"rbi_notification_required,omitempty"`
	EvidenceFiles             []string                `json:"evidence_files,omitempty"`
	Tags                      []string                `json:"tags,omitempty"`
	Metadata                  map[string]interface{}  `json:"metadata,omitempty"`
}

// UpdateRemediationActionRequest is the request to update a remediation action.
type UpdateRemediationActionRequest struct {
	Status      *string    `json:"status,omitempty"`
	Notes       *string    `json:"notes,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// RecordNotificationRequest is the request to record a notification.
type RecordNotificationRequest struct {
	NotificationDate time.Time `json:"notification_date" validate:"required"`
	Reference        string    `json:"reference,omitempty"`
	Response         string    `json:"response,omitempty"`
}

// AIIncidentServiceImpl implements AIIncidentService.
type AIIncidentServiceImpl struct {
	repo       AIIncidentRepository
	systemRepo AISystemRepository
}

// NewAIIncidentService creates a new incident service.
func NewAIIncidentService(repo AIIncidentRepository, systemRepo AISystemRepository) *AIIncidentServiceImpl {
	return &AIIncidentServiceImpl{
		repo:       repo,
		systemRepo: systemRepo,
	}
}

// CreateIncident creates a new incident record.
func (s *AIIncidentServiceImpl) CreateIncident(ctx context.Context, orgID string, req *CreateIncidentRequest) (*AIIncident, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	// Validate required fields
	if req.IncidentType == "" {
		return nil, fmt.Errorf("%w: incident_type is required", ErrInvalidInput)
	}
	if req.Severity == "" {
		return nil, fmt.Errorf("%w: severity is required", ErrInvalidInput)
	}
	if req.DetectedBy == "" {
		return nil, fmt.Errorf("%w: detected_by is required", ErrInvalidInput)
	}
	if req.Title == "" {
		return nil, fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	if req.Description == "" {
		return nil, fmt.Errorf("%w: description is required", ErrInvalidInput)
	}

	// Validate enums
	incidentType := IncidentType(req.IncidentType)
	if !incidentType.Valid() {
		return nil, fmt.Errorf("%w: invalid incident_type", ErrInvalidInput)
	}
	severity := IncidentSeverity(req.Severity)
	if !severity.Valid() {
		return nil, fmt.Errorf("%w: invalid severity", ErrInvalidInput)
	}
	detectedBy := DetectionMethod(req.DetectedBy)
	if !detectedBy.Valid() {
		return nil, fmt.Errorf("%w: invalid detected_by", ErrInvalidInput)
	}

	// Verify system exists if specified
	if req.SystemID != "" && s.systemRepo != nil {
		_, err := s.systemRepo.GetBySystemID(ctx, orgID, req.SystemID)
		if err != nil {
			return nil, fmt.Errorf("system not found: %w", err)
		}
	}

	// Build incident
	detectedAt := time.Now().UTC()
	if req.DetectedAt != nil {
		detectedAt = *req.DetectedAt
	}

	// Generate IDs for remediation actions
	for i := range req.RemediationActions {
		if req.RemediationActions[i].ID == "" {
			req.RemediationActions[i].ID = uuid.New().String()
		}
		if req.RemediationActions[i].Status == "" {
			req.RemediationActions[i].Status = "pending"
		}
	}

	incident := &AIIncident{
		OrgID:                     orgID,
		SystemID:                  req.SystemID,
		IncidentType:              incidentType,
		Severity:                  severity,
		DetectedAt:                detectedAt,
		DetectedBy:                detectedBy,
		DetectionDetails:          req.DetectionDetails,
		Title:                     req.Title,
		Description:               req.Description,
		RootCause:                 req.RootCause,
		AffectedCustomersCount:    req.AffectedCustomersCount,
		AffectedTransactionsCount: req.AffectedTransactionsCount,
		FinancialImpactINR:        req.FinancialImpactINR,
		ReputationalImpact:        req.ReputationalImpact,
		RemediationActions:        req.RemediationActions,
		ImmediateActionTaken:      req.ImmediateActionTaken,
		Status:                    IncidentStatusOpen,
		BoardNotificationRequired: req.BoardNotificationRequired,
		RBINotificationRequired:   req.RBINotificationRequired,
		EvidenceFiles:             req.EvidenceFiles,
		Tags:                      req.Tags,
		Metadata:                  req.Metadata,
	}

	// Auto-determine notification requirements based on severity
	if severity == IncidentSeverityCritical {
		incident.BoardNotificationRequired = true
		incident.RBINotificationRequired = true
	} else if severity == IncidentSeverityHigh {
		incident.BoardNotificationRequired = true
	}

	if err := s.repo.Create(ctx, incident); err != nil {
		return nil, err
	}

	log.Printf("[RBI Incident] Created incident %s (%s) - type=%s, severity=%s",
		incident.ID, incident.IncidentID, incidentType, severity)

	return incident, nil
}

// GetIncident retrieves an incident by ID.
func (s *AIIncidentServiceImpl) GetIncident(ctx context.Context, orgID, id string) (*AIIncident, error) {
	return s.repo.Get(ctx, orgID, id)
}

// GetIncidentByIncidentID retrieves an incident by its incident ID.
func (s *AIIncidentServiceImpl) GetIncidentByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error) {
	return s.repo.GetByIncidentID(ctx, orgID, incidentID)
}

// ListIncidents retrieves incidents with optional filtering.
func (s *AIIncidentServiceImpl) ListIncidents(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error) {
	return s.repo.List(ctx, orgID, params)
}

// UpdateIncident updates an incident record.
func (s *AIIncidentServiceImpl) UpdateIncident(ctx context.Context, orgID, id string, req *UpdateIncidentRequest) (*AIIncident, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	incident, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.IncidentType != nil {
		incidentType := IncidentType(*req.IncidentType)
		if !incidentType.Valid() {
			return nil, fmt.Errorf("%w: invalid incident_type", ErrInvalidInput)
		}
		incident.IncidentType = incidentType
	}
	if req.Severity != nil {
		severity := IncidentSeverity(*req.Severity)
		if !severity.Valid() {
			return nil, fmt.Errorf("%w: invalid severity", ErrInvalidInput)
		}
		incident.Severity = severity
	}
	if req.RootCause != nil {
		incident.RootCause = *req.RootCause
	}
	if req.AffectedCustomersCount != nil {
		incident.AffectedCustomersCount = req.AffectedCustomersCount
	}
	if req.AffectedTransactionsCount != nil {
		incident.AffectedTransactionsCount = req.AffectedTransactionsCount
	}
	if req.FinancialImpactINR != nil {
		incident.FinancialImpactINR = req.FinancialImpactINR
	}
	if req.ReputationalImpact != nil {
		incident.ReputationalImpact = *req.ReputationalImpact
	}
	if req.ImmediateActionTaken != nil {
		incident.ImmediateActionTaken = *req.ImmediateActionTaken
	}
	if req.LongTermFix != nil {
		incident.LongTermFix = *req.LongTermFix
	}
	if req.LessonsLearned != nil {
		incident.LessonsLearned = *req.LessonsLearned
	}
	if req.BoardNotificationRequired != nil {
		incident.BoardNotificationRequired = *req.BoardNotificationRequired
	}
	if req.RBINotificationRequired != nil {
		incident.RBINotificationRequired = *req.RBINotificationRequired
	}
	if req.EvidenceFiles != nil {
		incident.EvidenceFiles = req.EvidenceFiles
	}
	if req.Tags != nil {
		incident.Tags = req.Tags
	}
	if req.Metadata != nil {
		incident.Metadata = req.Metadata
	}

	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}

	log.Printf("[RBI Incident] Updated incident %s (%s)", id, incident.IncidentID)

	return incident, nil
}

// DeleteIncident deletes an incident record.
func (s *AIIncidentServiceImpl) DeleteIncident(ctx context.Context, orgID, id string) error {
	if err := s.repo.Delete(ctx, orgID, id); err != nil {
		return err
	}
	log.Printf("[RBI Incident] Deleted incident %s", id)
	return nil
}

// UpdateStatus updates the status of an incident.
func (s *AIIncidentServiceImpl) UpdateStatus(ctx context.Context, orgID, id string, status IncidentStatus, resolution string) (*AIIncident, error) {
	if !status.Valid() {
		return nil, fmt.Errorf("%w: invalid status", ErrInvalidInput)
	}

	incident, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	incident.Status = status
	if resolution != "" {
		incident.ResolutionSummary = resolution
	}

	if status == IncidentStatusResolved || status == IncidentStatusClosed {
		now := time.Now().UTC()
		incident.ResolvedAt = &now
	}

	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}

	log.Printf("[RBI Incident] Updated status of incident %s to %s", id, status)

	return incident, nil
}

// AddRemediationAction adds a remediation action to an incident.
func (s *AIIncidentServiceImpl) AddRemediationAction(ctx context.Context, orgID, id string, action *RemediationAction) (*AIIncident, error) {
	if action == nil {
		return nil, ErrInvalidInput
	}

	incident, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Generate ID if not provided
	if action.ID == "" {
		action.ID = uuid.New().String()
	}
	if action.Status == "" {
		action.Status = "pending"
	}

	incident.RemediationActions = append(incident.RemediationActions, *action)

	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}

	log.Printf("[RBI Incident] Added remediation action %s to incident %s", action.ID, id)

	return incident, nil
}

// UpdateRemediationAction updates a remediation action.
func (s *AIIncidentServiceImpl) UpdateRemediationAction(ctx context.Context, orgID, id, actionID string, req *UpdateRemediationActionRequest) (*AIIncident, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	incident, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Find and update the action
	found := false
	for i := range incident.RemediationActions {
		if incident.RemediationActions[i].ID == actionID {
			if req.Status != nil {
				incident.RemediationActions[i].Status = *req.Status
			}
			if req.Notes != nil {
				incident.RemediationActions[i].Notes = *req.Notes
			}
			if req.CompletedAt != nil {
				incident.RemediationActions[i].CompletedAt = req.CompletedAt
			}
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("%w: remediation action not found", ErrInvalidInput)
	}

	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}

	log.Printf("[RBI Incident] Updated remediation action %s for incident %s", actionID, id)

	return incident, nil
}

// RecordBoardNotification records that the board has been notified.
func (s *AIIncidentServiceImpl) RecordBoardNotification(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	incident, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	incident.BoardNotified = true
	incident.BoardNotificationDate = &req.NotificationDate
	incident.BoardNotificationReference = req.Reference

	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}

	log.Printf("[RBI Incident] Recorded board notification for incident %s on %s",
		id, req.NotificationDate.Format(time.RFC3339))

	return incident, nil
}

// RecordRBINotification records that RBI has been notified.
func (s *AIIncidentServiceImpl) RecordRBINotification(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	incident, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	incident.RBINotified = true
	incident.RBINotificationDate = &req.NotificationDate
	incident.RBINotificationReference = req.Reference
	if req.Response != "" {
		incident.RBIResponse = req.Response
	}

	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}

	log.Printf("[RBI Incident] Recorded RBI notification for incident %s on %s",
		id, req.NotificationDate.Format(time.RFC3339))

	return incident, nil
}

// GetOpenIncidents retrieves all open incidents.
func (s *AIIncidentServiceImpl) GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error) {
	return s.repo.GetOpenIncidents(ctx, orgID)
}

// GetPendingBoardNotifications retrieves incidents pending board notification.
func (s *AIIncidentServiceImpl) GetPendingBoardNotifications(ctx context.Context, orgID string) ([]*AIIncident, error) {
	return s.repo.GetPendingNotifications(ctx, orgID, "board")
}

// GetPendingRBINotifications retrieves incidents pending RBI notification.
func (s *AIIncidentServiceImpl) GetPendingRBINotifications(ctx context.Context, orgID string) ([]*AIIncident, error) {
	return s.repo.GetPendingNotifications(ctx, orgID, "rbi")
}
