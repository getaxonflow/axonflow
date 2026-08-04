// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ConformityService provides business logic for conformity assessments.
type ConformityService struct {
	repo ConformityRepository
}

// NewConformityService creates a new conformity service.
func NewConformityService(repo ConformityRepository) *ConformityService {
	return &ConformityService{repo: repo}
}

// loadOwned fetches an assessment that the given organization owns.
//
// One helper for all five by-id entry points so a new mutator cannot be added
// with the scope check accidentally omitted. ErrAssessmentNotFound is returned
// unwrapped for BOTH "no such id" and "belongs to another organization" - the
// handler maps it to 404, so the two are indistinguishable on the wire and the
// endpoint cannot be used as a cross-organization existence oracle.
func (s *ConformityService) loadOwned(ctx context.Context, orgID, id string) (*ConformityAssessment, error) {
	assessment, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		if errors.Is(err, ErrAssessmentNotFound) {
			return nil, ErrAssessmentNotFound
		}
		return nil, fmt.Errorf("get assessment: %w", err)
	}
	if assessment == nil {
		return nil, ErrAssessmentNotFound
	}
	return assessment, nil
}

// CreateAssessmentInput contains input for creating an assessment.
type CreateAssessmentInput struct {
	OrgID        string
	SystemID     string
	SystemName   string
	RiskCategory RiskCategory
	Assessors    []string
	CreatedBy    string
}

// CreateAssessment creates a new conformity assessment.
func (s *ConformityService) CreateAssessment(ctx context.Context, input CreateAssessmentInput) (*ConformityAssessment, error) {
	if input.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	if input.SystemID == "" {
		return nil, fmt.Errorf("system_id is required")
	}
	if input.SystemName == "" {
		return nil, fmt.Errorf("system_name is required")
	}
	if !input.RiskCategory.Valid() {
		return nil, fmt.Errorf("invalid risk_category: %s", input.RiskCategory)
	}

	// Get latest version for this system
	existing, err := s.repo.GetBySystemID(ctx, input.OrgID, input.SystemID)
	if err != nil {
		return nil, fmt.Errorf("check existing assessments: %w", err)
	}
	version := 1
	if len(existing) > 0 {
		version = existing[0].Version + 1
	}

	now := time.Now().UTC()
	assessment := &ConformityAssessment{
		ID:             "assess-" + uuid.New().String()[:8],
		OrgID:          input.OrgID,
		SystemID:       input.SystemID,
		SystemName:     input.SystemName,
		RiskCategory:   input.RiskCategory,
		Status:         AssessmentStatusDraft,
		Version:        version,
		AssessmentDate: now,
		Assessors:      input.Assessors,
		Requirements:   []RequirementStatus{},
		Evidence:       []EvidenceItem{},
		Findings:       []Finding{},
		CreatedBy:      input.CreatedBy,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.Create(ctx, assessment); err != nil {
		return nil, fmt.Errorf("create assessment: %w", err)
	}

	return assessment, nil
}

// GetAssessment retrieves an assessment by ID within an organization.
//
// orgID is REQUIRED (#3241). Every method on this service used to take an id
// alone, so an authenticated caller of organization B could read - and, via the
// mutators below, rewrite, submit, approve and reject - organization A's
// Article 43 conformity assessments. RBI and MAS FEAT were hardened for this
// class in #3103/#3141; euaiact was missed.
func (s *ConformityService) GetAssessment(ctx context.Context, orgID, id string) (*ConformityAssessment, error) {
	return s.repo.GetByID(ctx, orgID, id)
}

// ListAssessments retrieves assessments for an organization.
func (s *ConformityService) ListAssessments(ctx context.Context, orgID string, status AssessmentStatus, limit, offset int) ([]*ConformityAssessment, int64, error) {
	return s.repo.List(ctx, orgID, status, limit, offset)
}

// UpdateAssessmentInput contains input for updating an assessment.
type UpdateAssessmentInput struct {
	SystemName      string
	RiskCategory    RiskCategory
	Assessors       []string
	Requirements    []RequirementStatus
	Evidence        []EvidenceItem
	Findings        []Finding
	RiskMitigation  map[string]interface{}
	Recommendations []string
}

// UpdateAssessment updates an assessment.
func (s *ConformityService) UpdateAssessment(ctx context.Context, orgID, id string, input UpdateAssessmentInput) (*ConformityAssessment, error) {
	assessment, err := s.loadOwned(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Only allow updates in draft or in_progress status
	if assessment.Status != AssessmentStatusDraft && assessment.Status != AssessmentStatusInProgress {
		return nil, fmt.Errorf("cannot update assessment in %s status", assessment.Status)
	}

	// Apply updates
	if input.SystemName != "" {
		assessment.SystemName = input.SystemName
	}
	if input.RiskCategory != "" && input.RiskCategory.Valid() {
		assessment.RiskCategory = input.RiskCategory
	}
	if input.Assessors != nil {
		assessment.Assessors = input.Assessors
	}
	if input.Requirements != nil {
		assessment.Requirements = input.Requirements
	}
	if input.Evidence != nil {
		assessment.Evidence = input.Evidence
	}
	if input.Findings != nil {
		assessment.Findings = input.Findings
	}
	if input.RiskMitigation != nil {
		assessment.RiskMitigation = input.RiskMitigation
	}
	if input.Recommendations != nil {
		assessment.Recommendations = input.Recommendations
	}

	// Mark as in progress if it was draft
	if assessment.Status == AssessmentStatusDraft {
		assessment.Status = AssessmentStatusInProgress
	}

	assessment.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("update assessment: %w", err)
	}

	return assessment, nil
}

// SubmitAssessment submits an assessment for review.
func (s *ConformityService) SubmitAssessment(ctx context.Context, orgID, id, userID string) (*ConformityAssessment, error) {
	assessment, err := s.loadOwned(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Validate status transition
	if assessment.Status != AssessmentStatusDraft && assessment.Status != AssessmentStatusInProgress {
		return nil, fmt.Errorf("cannot submit assessment in %s status", assessment.Status)
	}

	// Validate required fields
	if len(assessment.Requirements) == 0 {
		return nil, fmt.Errorf("assessment must have at least one requirement")
	}

	now := time.Now().UTC()
	assessment.Status = AssessmentStatusSubmitted
	assessment.SubmittedAt = &now
	assessment.SubmittedBy = userID
	assessment.UpdatedAt = now

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("update assessment: %w", err)
	}

	return assessment, nil
}

// ApproveAssessment approves a submitted assessment.
func (s *ConformityService) ApproveAssessment(ctx context.Context, orgID, id, userID string, validityYears int) (*ConformityAssessment, error) {
	assessment, err := s.loadOwned(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Validate status
	if assessment.Status != AssessmentStatusSubmitted {
		return nil, fmt.Errorf("can only approve submitted assessments")
	}

	now := time.Now().UTC()
	validUntil := now.AddDate(validityYears, 0, 0)

	assessment.Status = AssessmentStatusApproved
	assessment.ApprovedAt = &now
	assessment.ApprovedBy = userID
	assessment.ValidUntil = &validUntil
	assessment.UpdatedAt = now

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("update assessment: %w", err)
	}

	return assessment, nil
}

// RejectAssessment rejects a submitted assessment.
func (s *ConformityService) RejectAssessment(ctx context.Context, orgID, id, userID, reason string) (*ConformityAssessment, error) {
	assessment, err := s.loadOwned(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Validate status
	if assessment.Status != AssessmentStatusSubmitted {
		return nil, fmt.Errorf("can only reject submitted assessments")
	}

	if reason == "" {
		return nil, fmt.Errorf("rejection reason is required")
	}

	now := time.Now().UTC()
	assessment.Status = AssessmentStatusRejected
	assessment.RejectedAt = &now
	assessment.RejectedBy = userID
	assessment.RejectionReason = reason
	assessment.UpdatedAt = now

	if err := s.repo.Update(ctx, assessment); err != nil {
		return nil, fmt.Errorf("update assessment: %w", err)
	}

	return assessment, nil
}
