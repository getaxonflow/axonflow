// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"fmt"
	"log"
	"time"
)

// BoardReportService provides business logic for board report operations.
type BoardReportService interface {
	GenerateReport(ctx context.Context, orgID string, req *GenerateReportRequest) (*BoardReport, error)
	GetReport(ctx context.Context, orgID, id string) (*BoardReport, error)
	ListReports(ctx context.Context, orgID string, params *ListBoardReportsParams) ([]*BoardReport, int, error)
	SubmitForApproval(ctx context.Context, orgID, id string, req *SubmitForApprovalRequest) (*BoardReport, error)
	ApproveReport(ctx context.Context, orgID, id string, req *ApproveReportRequest) (*BoardReport, error)
	RejectReport(ctx context.Context, orgID, id string, req *RejectReportRequest) (*BoardReport, error)
	DeleteReport(ctx context.Context, orgID, id string) error
	GetLatestReport(ctx context.Context, orgID string, reportType ReportType) (*BoardReport, error)
	GetPendingApproval(ctx context.Context, orgID string) ([]*BoardReport, error)
	AddCorrectiveAction(ctx context.Context, orgID, reportID string, action *CorrectiveAction) (*BoardReport, error)
	UpdateCorrectiveAction(ctx context.Context, orgID, reportID, actionID string, update *UpdateCorrectiveActionRequest) (*BoardReport, error)
}

// GenerateReportRequest is the request to generate a board report.
type GenerateReportRequest struct {
	ReportType        string     `json:"report_type" validate:"required"`
	ReportPeriodStart *time.Time `json:"report_period_start,omitempty"`
	ReportPeriodEnd   *time.Time `json:"report_period_end,omitempty"`
	ReportQuarter     string     `json:"report_quarter,omitempty"`
	GeneratedBy       string     `json:"generated_by,omitempty"`
	GeneratedByEmail  string     `json:"generated_by_email,omitempty"`
}

// SubmitForApprovalRequest is the request to submit a report for approval.
type SubmitForApprovalRequest struct {
	SubmittedBy      string `json:"submitted_by" validate:"required"`
	SubmittedByEmail string `json:"submitted_by_email,omitempty"`
}

// ApproveReportRequest is the request to approve a board report.
type ApproveReportRequest struct {
	ApprovedBy      string `json:"approved_by" validate:"required"`
	ApprovedByEmail string `json:"approved_by_email,omitempty"`
	ApprovalNotes   string `json:"approval_notes,omitempty"`
}

// RejectReportRequest is the request to reject a board report.
type RejectReportRequest struct {
	RejectedBy      string `json:"rejected_by" validate:"required"`
	RejectedByEmail string `json:"rejected_by_email,omitempty"`
	RejectionReason string `json:"rejection_reason" validate:"required"`
}

// UpdateCorrectiveActionRequest is the request to update a corrective action.
type UpdateCorrectiveActionRequest struct {
	Status      string     `json:"status,omitempty"`
	AssignedTo  string     `json:"assigned_to,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// BoardReportServiceImpl implements BoardReportService.
type BoardReportServiceImpl struct {
	repo             BoardReportRepository
	systemRepo       AISystemRepository
	validationRepo   ModelValidationRepository
	incidentRepo     AIIncidentRepository
	killSwitchRepo   KillSwitchRepository
}

// NewBoardReportService creates a new board report service.
func NewBoardReportService(
	repo BoardReportRepository,
	systemRepo AISystemRepository,
	validationRepo ModelValidationRepository,
	incidentRepo AIIncidentRepository,
	killSwitchRepo KillSwitchRepository,
) *BoardReportServiceImpl {
	return &BoardReportServiceImpl{
		repo:           repo,
		systemRepo:     systemRepo,
		validationRepo: validationRepo,
		incidentRepo:   incidentRepo,
		killSwitchRepo: killSwitchRepo,
	}
}

// GenerateReport generates a new board report with aggregated data.
func (s *BoardReportServiceImpl) GenerateReport(ctx context.Context, orgID string, req *GenerateReportRequest) (*BoardReport, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	// Validate report type
	reportType := ReportType(req.ReportType)
	if !reportType.Valid() {
		return nil, fmt.Errorf("%w: invalid report_type", ErrInvalidInput)
	}

	// Create report with basic info
	report := &BoardReport{
		OrgID:             orgID,
		ReportType:        reportType,
		ReportPeriodStart: req.ReportPeriodStart,
		ReportPeriodEnd:   req.ReportPeriodEnd,
		ReportQuarter:     req.ReportQuarter,
		GeneratedBy:       req.GeneratedBy,
		GeneratedByEmail:  req.GeneratedByEmail,
		GeneratedAt:       time.Now().UTC(),
		GenerationMethod:  "automated",
		ApprovalStatus:    ReportApprovalDraft,
	}

	// Aggregate AI Systems data if repository available
	if s.systemRepo != nil {
		systems, total, err := s.systemRepo.List(ctx, orgID, nil)
		if err == nil {
			report.TotalAISystems = total
			report.SystemsByRisk = s.aggregateByRisk(systems)
			report.SystemsByStatus = s.aggregateByStatus(systems)

			// Count new and deprecated (simplified - in real impl, filter by date range)
			if req.ReportPeriodStart != nil {
				for _, sys := range systems {
					if sys.CreatedAt.After(*req.ReportPeriodStart) {
						report.NewSystemsDeployed++
					}
					if sys.DeploymentStatus == DeploymentStatusDeprecated {
						report.SystemsDeprecated++
					}
				}
			}
		}
	}

	// Aggregate Validation data if repository available
	if s.validationRepo != nil {
		validations, total, err := s.validationRepo.List(ctx, orgID, nil)
		if err == nil {
			report.TotalValidations = total
			report.ValidationsByType = s.aggregateValidationsByType(validations)
			report.ValidationsByRecommendation = s.aggregateValidationsByRecommendation(validations)
		}
	}

	// Count overdue validations from AI Systems (NextValidationDue is on AISystem)
	if s.systemRepo != nil {
		systems, _, err := s.systemRepo.List(ctx, orgID, nil)
		if err == nil {
			for _, sys := range systems {
				if sys.NextValidationDue != nil && sys.NextValidationDue.Before(time.Now()) {
					report.OverdueValidations++
				}
			}
		}
	}

	// Aggregate Incident data if repository available
	if s.incidentRepo != nil {
		incidents, total, err := s.incidentRepo.List(ctx, orgID, nil)
		if err == nil {
			report.TotalIncidents = total
			report.IncidentsBySeverity = s.aggregateIncidentsBySeverity(incidents)
			report.IncidentsByType = s.aggregateIncidentsByType(incidents)

			var totalResolutionHours float64
			resolvedCount := 0
			for _, inc := range incidents {
				if inc.Status == IncidentStatusResolved || inc.Status == IncidentStatusClosed {
					report.IncidentsResolved++
					if inc.ResolvedAt != nil {
						duration := inc.ResolvedAt.Sub(inc.DetectedAt).Hours()
						totalResolutionHours += duration
						resolvedCount++
					}
				} else {
					report.IncidentsOpen++
				}
			}
			if resolvedCount > 0 {
				report.AverageResolutionTimeHours = totalResolutionHours / float64(resolvedCount)
			}
		}
	}

	// Aggregate Kill Switch data if repository available
	if s.killSwitchRepo != nil {
		activeSwitches, err := s.killSwitchRepo.ListActive(ctx, orgID)
		if err == nil {
			report.KillSwitchActivations = len(activeSwitches)
			if len(activeSwitches) > 0 {
				details := make(map[string]interface{})
				for _, ks := range activeSwitches {
					details[ks.ID] = map[string]interface{}{
						"scope":             ks.Scope,
						"system_id":         ks.SystemID,
						"activated_by":      ks.ActivatedBy,
						"activation_reason": ks.ActivationReason,
					}
				}
				report.KillSwitchDetails = details
			}
		}
	}

	// Calculate compliance score (simplified algorithm)
	report.ComplianceScore = s.calculateComplianceScore(report)
	report.ComplianceIssues = s.identifyComplianceIssues(report)

	// Save the report
	if err := s.repo.Create(ctx, report); err != nil {
		return nil, err
	}

	log.Printf("[RBI BoardReport] Generated report %s type=%s quarter=%s",
		report.ID, report.ReportType, report.ReportQuarter)

	return report, nil
}

// GetReport retrieves a board report by ID.
func (s *BoardReportServiceImpl) GetReport(ctx context.Context, orgID, id string) (*BoardReport, error) {
	return s.repo.Get(ctx, orgID, id)
}

// ListReports retrieves board reports with optional filtering.
func (s *BoardReportServiceImpl) ListReports(ctx context.Context, orgID string, params *ListBoardReportsParams) ([]*BoardReport, int, error) {
	return s.repo.List(ctx, orgID, params)
}

// SubmitForApproval submits a report for board approval.
func (s *BoardReportServiceImpl) SubmitForApproval(ctx context.Context, orgID, id string, req *SubmitForApprovalRequest) (*BoardReport, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}
	if req.SubmittedBy == "" {
		return nil, fmt.Errorf("%w: submitted_by is required", ErrInvalidInput)
	}

	report, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	if report.ApprovalStatus != ReportApprovalDraft {
		return nil, fmt.Errorf("%w: report is not in draft status", ErrInvalidInput)
	}

	report.ApprovalStatus = ReportApprovalPendingReview

	if err := s.repo.Update(ctx, report); err != nil {
		return nil, err
	}

	log.Printf("[RBI BoardReport] Submitted report %s for approval by %s",
		id, req.SubmittedBy)

	return report, nil
}

// ApproveReport approves a board report.
func (s *BoardReportServiceImpl) ApproveReport(ctx context.Context, orgID, id string, req *ApproveReportRequest) (*BoardReport, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}
	if req.ApprovedBy == "" {
		return nil, fmt.Errorf("%w: approved_by is required", ErrInvalidInput)
	}

	report, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	if report.ApprovalStatus != ReportApprovalPendingReview {
		return nil, fmt.Errorf("%w: report is not pending review", ErrInvalidInput)
	}

	now := time.Now().UTC()
	report.ApprovalStatus = ReportApprovalApproved
	report.ApprovedBy = req.ApprovedBy
	report.ApprovedByEmail = req.ApprovedByEmail
	report.ApprovedAt = &now
	report.ApprovalNotes = req.ApprovalNotes

	if err := s.repo.Update(ctx, report); err != nil {
		return nil, err
	}

	log.Printf("[RBI BoardReport] APPROVED report %s by %s",
		id, req.ApprovedBy)

	return report, nil
}

// RejectReport rejects a board report.
func (s *BoardReportServiceImpl) RejectReport(ctx context.Context, orgID, id string, req *RejectReportRequest) (*BoardReport, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}
	if req.RejectedBy == "" {
		return nil, fmt.Errorf("%w: rejected_by is required", ErrInvalidInput)
	}
	if req.RejectionReason == "" {
		return nil, fmt.Errorf("%w: rejection_reason is required", ErrInvalidInput)
	}

	report, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	if report.ApprovalStatus != ReportApprovalPendingReview {
		return nil, fmt.Errorf("%w: report is not pending review", ErrInvalidInput)
	}

	report.ApprovalStatus = ReportApprovalRejected
	report.ApprovalNotes = req.RejectionReason

	if err := s.repo.Update(ctx, report); err != nil {
		return nil, err
	}

	log.Printf("[RBI BoardReport] REJECTED report %s by %s - reason: %s",
		id, req.RejectedBy, req.RejectionReason)

	return report, nil
}

// DeleteReport deletes a board report.
func (s *BoardReportServiceImpl) DeleteReport(ctx context.Context, orgID, id string) error {
	report, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return err
	}

	if report.ApprovalStatus == ReportApprovalApproved {
		return fmt.Errorf("%w: cannot delete approved reports", ErrInvalidInput)
	}

	if err := s.repo.Delete(ctx, orgID, id); err != nil {
		return err
	}

	log.Printf("[RBI BoardReport] Deleted report %s", id)
	return nil
}

// GetLatestReport retrieves the most recent report of a given type.
func (s *BoardReportServiceImpl) GetLatestReport(ctx context.Context, orgID string, reportType ReportType) (*BoardReport, error) {
	return s.repo.GetLatest(ctx, orgID, reportType)
}

// GetPendingApproval retrieves reports pending board approval.
func (s *BoardReportServiceImpl) GetPendingApproval(ctx context.Context, orgID string) ([]*BoardReport, error) {
	return s.repo.GetPendingApproval(ctx, orgID)
}

// AddCorrectiveAction adds a corrective action to a report.
func (s *BoardReportServiceImpl) AddCorrectiveAction(ctx context.Context, orgID, reportID string, action *CorrectiveAction) (*BoardReport, error) {
	if action == nil {
		return nil, ErrInvalidInput
	}

	report, err := s.repo.Get(ctx, orgID, reportID)
	if err != nil {
		return nil, err
	}

	// Generate ID if not provided
	if action.ID == "" {
		action.ID = fmt.Sprintf("ca-%d", len(report.CorrectiveActions)+1)
	}
	if action.Status == "" {
		action.Status = "pending"
	}

	report.CorrectiveActions = append(report.CorrectiveActions, *action)

	if err := s.repo.Update(ctx, report); err != nil {
		return nil, err
	}

	log.Printf("[RBI BoardReport] Added corrective action %s to report %s",
		action.ID, reportID)

	return report, nil
}

// UpdateCorrectiveAction updates a corrective action in a report.
func (s *BoardReportServiceImpl) UpdateCorrectiveAction(ctx context.Context, orgID, reportID, actionID string, update *UpdateCorrectiveActionRequest) (*BoardReport, error) {
	if update == nil {
		return nil, ErrInvalidInput
	}

	report, err := s.repo.Get(ctx, orgID, reportID)
	if err != nil {
		return nil, err
	}

	found := false
	for i := range report.CorrectiveActions {
		if report.CorrectiveActions[i].ID == actionID {
			if update.Status != "" {
				report.CorrectiveActions[i].Status = update.Status
			}
			if update.AssignedTo != "" {
				report.CorrectiveActions[i].AssignedTo = update.AssignedTo
			}
			if update.CompletedAt != nil {
				report.CorrectiveActions[i].CompletedAt = update.CompletedAt
			}
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("%w: corrective action not found", ErrInvalidInput)
	}

	if err := s.repo.Update(ctx, report); err != nil {
		return nil, err
	}

	log.Printf("[RBI BoardReport] Updated corrective action %s in report %s",
		actionID, reportID)

	return report, nil
}

// Helper functions for aggregation

func (s *BoardReportServiceImpl) aggregateByRisk(systems []*AISystem) map[string]int {
	result := make(map[string]int)
	for _, sys := range systems {
		result[string(sys.RiskCategory)]++
	}
	return result
}

func (s *BoardReportServiceImpl) aggregateByStatus(systems []*AISystem) map[string]int {
	result := make(map[string]int)
	for _, sys := range systems {
		result[string(sys.DeploymentStatus)]++
	}
	return result
}

func (s *BoardReportServiceImpl) aggregateValidationsByType(validations []*ModelValidation) map[string]int {
	result := make(map[string]int)
	for _, val := range validations {
		result[string(val.ValidationType)]++
	}
	return result
}

func (s *BoardReportServiceImpl) aggregateValidationsByRecommendation(validations []*ModelValidation) map[string]int {
	result := make(map[string]int)
	for _, val := range validations {
		result[string(val.Recommendation)]++
	}
	return result
}

func (s *BoardReportServiceImpl) aggregateIncidentsBySeverity(incidents []*AIIncident) map[string]int {
	result := make(map[string]int)
	for _, inc := range incidents {
		result[string(inc.Severity)]++
	}
	return result
}

func (s *BoardReportServiceImpl) aggregateIncidentsByType(incidents []*AIIncident) map[string]int {
	result := make(map[string]int)
	for _, inc := range incidents {
		result[string(inc.IncidentType)]++
	}
	return result
}

func (s *BoardReportServiceImpl) calculateComplianceScore(report *BoardReport) float64 {
	// Simple compliance score algorithm
	// Start with 100 and deduct points for issues

	score := 100.0

	// Deduct for overdue validations (5 points each, max 25)
	overdueDeduction := float64(report.OverdueValidations) * 5
	if overdueDeduction > 25 {
		overdueDeduction = 25
	}
	score -= overdueDeduction

	// Deduct for open incidents based on severity
	if report.IncidentsBySeverity != nil {
		if critical, ok := report.IncidentsBySeverity["critical"]; ok {
			score -= float64(critical) * 10
		}
		if high, ok := report.IncidentsBySeverity["high"]; ok {
			score -= float64(high) * 5
		}
	}

	// Deduct for active kill switches (10 points each)
	score -= float64(report.KillSwitchActivations) * 10

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

func (s *BoardReportServiceImpl) identifyComplianceIssues(report *BoardReport) []ComplianceIssue {
	var issues []ComplianceIssue

	// Check for overdue validations
	if report.OverdueValidations > 0 {
		issues = append(issues, ComplianceIssue{
			Category:    "validation",
			Description: fmt.Sprintf("%d AI systems have overdue validation assessments", report.OverdueValidations),
			Severity:    "medium",
			Remediation: "Schedule validation assessments for overdue systems",
		})
	}

	// Check for critical incidents
	if report.IncidentsBySeverity != nil {
		if critical, ok := report.IncidentsBySeverity["critical"]; ok && critical > 0 {
			issues = append(issues, ComplianceIssue{
				Category:    "incidents",
				Description: fmt.Sprintf("%d critical AI incidents require board attention", critical),
				Severity:    "high",
				Remediation: "Review and resolve critical incidents immediately",
			})
		}
	}

	// Check for active kill switches
	if report.KillSwitchActivations > 0 {
		issues = append(issues, ComplianceIssue{
			Category:    "operations",
			Description: fmt.Sprintf("%d AI systems have active kill switches", report.KillSwitchActivations),
			Severity:    "high",
			Remediation: "Review kill switch activations and resolve underlying issues",
		})
	}

	// Check for high-risk systems without recent validation
	if report.SystemsByRisk != nil {
		if high, ok := report.SystemsByRisk["high"]; ok && high > 0 {
			issues = append(issues, ComplianceIssue{
				Category:    "governance",
				Description: fmt.Sprintf("%d high-risk AI systems require enhanced monitoring", high),
				Severity:    "medium",
				Remediation: "Ensure high-risk systems have current validation and monitoring",
			})
		}
	}

	return issues
}
