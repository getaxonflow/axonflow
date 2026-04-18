// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AssessmentService provides business logic for FEAT assessment operations.
type AssessmentService struct {
	repo                   AssessmentRepository
	registryRepo           RegistryRepository
	validityMonths         int
}

// NewAssessmentService creates a new assessment service.
func NewAssessmentService(repo AssessmentRepository, registryRepo RegistryRepository, validityMonths int) *AssessmentService {
	return &AssessmentService{
		repo:           repo,
		registryRepo:   registryRepo,
		validityMonths: validityMonths,
	}
}

// CreateAssessment creates a new FEAT assessment.
func (s *AssessmentService) CreateAssessment(ctx context.Context, orgID string, req *CreateAssessmentRequest, createdBy string) (*FEATAssessment, error) {
	// Validate request
	if req.SystemID == "" {
		return nil, errors.New("system_id is required")
	}
	if req.AssessmentType == "" {
		req.AssessmentType = "periodic"
	}
	if req.AssessmentType != "initial" && req.AssessmentType != "periodic" && req.AssessmentType != "ad_hoc" {
		return nil, errors.New("assessment_type must be 'initial', 'periodic', or 'ad_hoc'")
	}

	// Verify system exists
	system, err := s.registryRepo.GetBySystemID(ctx, orgID, req.SystemID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify system: %w", err)
	}
	if system == nil {
		return nil, errors.New("system not found in registry")
	}

	// Calculate validity period
	now := time.Now().UTC()
	validUntil := now.AddDate(0, s.validityMonths, 0)

	assessment := &FEATAssessment{
		OrgID:          orgID,
		SystemID:       req.SystemID,
		AssessmentType: req.AssessmentType,
		Status:         FEATStatusPending,
		AssessmentDate: now,
		ValidUntil:     &validUntil,
		Assessors:      req.Assessors,
		CreatedBy:      createdBy,
	}

	if err := s.repo.Create(ctx, assessment); err != nil {
		return nil, fmt.Errorf("failed to create assessment: %w", err)
	}

	return assessment, nil
}

// GetAssessment retrieves a FEAT assessment by ID.
func (s *AssessmentService) GetAssessment(ctx context.Context, orgID, id string) (*FEATAssessment, error) {
	assessment, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get assessment: %w", err)
	}
	if assessment == nil {
		return nil, errors.New("assessment not found")
	}
	return assessment, nil
}

// ListAssessments lists FEAT assessments for an organization.
func (s *AssessmentService) ListAssessments(ctx context.Context, orgID string, params ListParams) ([]*FEATAssessment, error) {
	return s.repo.List(ctx, orgID, params)
}

// UpdateAssessment updates a FEAT assessment.
func (s *AssessmentService) UpdateAssessment(ctx context.Context, orgID, id string, req *UpdateAssessmentRequest) (*FEATAssessment, error) {
	assessment, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get assessment: %w", err)
	}
	if assessment == nil {
		return nil, errors.New("assessment not found")
	}

	// Only allow updates to pending or in_progress assessments
	if assessment.Status != FEATStatusPending && assessment.Status != FEATStatusInProgress {
		return nil, errors.New("cannot update assessment in current status")
	}

	// Apply updates
	if req.FairnessScore != nil {
		assessment.FairnessScore = req.FairnessScore
	}
	if req.EthicsScore != nil {
		assessment.EthicsScore = req.EthicsScore
	}
	if req.AccountabilityScore != nil {
		assessment.AccountabilityScore = req.AccountabilityScore
	}
	if req.TransparencyScore != nil {
		assessment.TransparencyScore = req.TransparencyScore
	}
	if req.FairnessDetails != nil {
		assessment.FairnessDetails = req.FairnessDetails
	}
	if req.EthicsDetails != nil {
		assessment.EthicsDetails = req.EthicsDetails
	}
	if req.AccountabilityDetails != nil {
		assessment.AccountabilityDetails = req.AccountabilityDetails
	}
	if req.TransparencyDetails != nil {
		assessment.TransparencyDetails = req.TransparencyDetails
	}
	if req.Findings != nil {
		assessment.Findings = req.Findings
	}
	if req.Recommendations != nil {
		assessment.Recommendations = req.Recommendations
	}
	if req.Assessors != nil {
		assessment.Assessors = req.Assessors
	}

	// Calculate overall score if all pillar scores are present
	if assessment.FairnessScore != nil && assessment.EthicsScore != nil &&
		assessment.AccountabilityScore != nil && assessment.TransparencyScore != nil {
		overall := (*assessment.FairnessScore + *assessment.EthicsScore +
			*assessment.AccountabilityScore + *assessment.TransparencyScore) / 4
		assessment.OverallScore = &overall
	}

	// Auto-transition to in_progress if scores are being recorded
	if assessment.Status == FEATStatusPending && (req.FairnessScore != nil || req.EthicsScore != nil ||
		req.AccountabilityScore != nil || req.TransparencyScore != nil) {
		assessment.Status = FEATStatusInProgress
	}

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("failed to update assessment: %w", err)
	}

	return assessment, nil
}

// SubmitAssessment submits an assessment for review.
func (s *AssessmentService) SubmitAssessment(ctx context.Context, orgID, id, submittedBy string) (*FEATAssessment, error) {
	assessment, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get assessment: %w", err)
	}
	if assessment == nil {
		return nil, errors.New("assessment not found")
	}

	if assessment.Status != FEATStatusInProgress && assessment.Status != FEATStatusPending {
		return nil, errors.New("can only submit pending or in-progress assessments")
	}

	// Validate that all pillar scores are present
	if assessment.FairnessScore == nil || assessment.EthicsScore == nil ||
		assessment.AccountabilityScore == nil || assessment.TransparencyScore == nil {
		return nil, errors.New("all four FEAT pillar scores are required before submission")
	}

	now := time.Now().UTC()
	assessment.Status = FEATStatusCompleted
	assessment.SubmittedAt = &now
	assessment.SubmittedBy = submittedBy

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("failed to submit assessment: %w", err)
	}

	return assessment, nil
}

// ApproveAssessment approves a submitted assessment.
func (s *AssessmentService) ApproveAssessment(ctx context.Context, orgID, id, approvedBy string) (*FEATAssessment, error) {
	assessment, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get assessment: %w", err)
	}
	if assessment == nil {
		return nil, errors.New("assessment not found")
	}

	if assessment.Status != FEATStatusCompleted {
		return nil, errors.New("can only approve completed assessments")
	}

	now := time.Now().UTC()
	assessment.Status = FEATStatusApproved
	assessment.ApprovedAt = &now
	assessment.ApprovedBy = approvedBy

	// Update the registry with last assessment date
	if s.registryRepo != nil {
		system, _ := s.registryRepo.GetBySystemID(ctx, orgID, assessment.SystemID)
		if system != nil {
			system.LastAssessmentDate = &now
			// Set next assessment due based on materiality
			var nextDue time.Time
			switch system.MaterialityClassification {
			case MaterialityHigh:
				nextDue = now.AddDate(0, 6, 0) // 6 months for high materiality
			case MaterialityMedium:
				nextDue = now.AddDate(1, 0, 0) // 1 year for medium
			default:
				nextDue = now.AddDate(2, 0, 0) // 2 years for low
			}
			system.NextAssessmentDue = &nextDue
			s.registryRepo.Update(ctx, system)
		}
	}

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("failed to approve assessment: %w", err)
	}

	return assessment, nil
}

// RejectAssessment rejects a submitted assessment.
func (s *AssessmentService) RejectAssessment(ctx context.Context, orgID, id, rejectedBy, reason string) (*FEATAssessment, error) {
	assessment, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get assessment: %w", err)
	}
	if assessment == nil {
		return nil, errors.New("assessment not found")
	}

	if assessment.Status != FEATStatusCompleted {
		return nil, errors.New("can only reject completed assessments")
	}

	if reason == "" {
		return nil, errors.New("rejection reason is required")
	}

	now := time.Now().UTC()
	assessment.Status = FEATStatusRejected
	assessment.RejectedAt = &now
	assessment.RejectedBy = rejectedBy
	assessment.RejectionReason = reason

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("failed to reject assessment: %w", err)
	}

	return assessment, nil
}
