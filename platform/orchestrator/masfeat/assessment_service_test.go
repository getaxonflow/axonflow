// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// mockAssessmentRepository is a mock implementation of AssessmentRepository for testing.
type mockAssessmentRepository struct {
	assessments map[string]*FEATAssessment
}

func newMockAssessmentRepository() *mockAssessmentRepository {
	return &mockAssessmentRepository{
		assessments: make(map[string]*FEATAssessment),
	}
}

func (m *mockAssessmentRepository) Create(ctx context.Context, assessment *FEATAssessment) error {
	// Generate ID if not set (simulating database auto-generation)
	if assessment.ID == "" {
		assessment.ID = fmt.Sprintf("assess-%d", len(m.assessments)+1)
	}
	m.assessments[assessment.ID] = assessment
	return nil
}

func (m *mockAssessmentRepository) GetByID(ctx context.Context, orgID, id string) (*FEATAssessment, error) {
	for _, a := range m.assessments {
		if a.OrgID == orgID && a.ID == id {
			return a, nil
		}
	}
	return nil, nil
}

func (m *mockAssessmentRepository) List(ctx context.Context, orgID string, params ListParams) ([]*FEATAssessment, error) {
	var result []*FEATAssessment
	for _, a := range m.assessments {
		if a.OrgID == orgID {
			if params.Status != "" && string(a.Status) != params.Status {
				continue
			}
			if params.SystemID != "" && a.SystemID != params.SystemID {
				continue
			}
			result = append(result, a)
		}
	}
	return result, nil
}

func (m *mockAssessmentRepository) Update(ctx context.Context, assessment *FEATAssessment) error {
	m.assessments[assessment.ID] = assessment
	return nil
}

func (m *mockAssessmentRepository) GetLatestForSystem(ctx context.Context, orgID, systemID string) (*FEATAssessment, error) {
	var latest *FEATAssessment
	for _, a := range m.assessments {
		if a.OrgID == orgID && a.SystemID == systemID {
			if latest == nil || a.CreatedAt.After(latest.CreatedAt) {
				latest = a
			}
		}
	}
	return latest, nil
}

func TestAssessmentService_CreateAssessment(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	// Create a system first
	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	tests := []struct {
		name    string
		orgID   string
		req     *CreateAssessmentRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:  "Valid assessment",
			orgID: "org-123",
			req: &CreateAssessmentRequest{
				SystemID:       "sys-001",
				AssessmentType: "initial",
				Assessors:      []string{"user@example.com"},
			},
			wantErr: false,
		},
		{
			name:  "Missing system_id",
			orgID: "org-123",
			req: &CreateAssessmentRequest{
				AssessmentType: "initial",
			},
			wantErr: true,
			errMsg:  "system_id is required",
		},
		{
			name:  "Invalid assessment_type",
			orgID: "org-123",
			req: &CreateAssessmentRequest{
				SystemID:       "sys-001",
				AssessmentType: "invalid",
			},
			wantErr: true,
			errMsg:  "assessment_type must be 'initial', 'periodic', or 'ad_hoc'",
		},
		{
			name:  "System not found",
			orgID: "org-123",
			req: &CreateAssessmentRequest{
				SystemID:       "non-existent",
				AssessmentType: "initial",
			},
			wantErr: true,
			errMsg:  "system not found in registry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment, err := service.CreateAssessment(context.Background(), tt.orgID, tt.req, "test-user")

			if tt.wantErr {
				if err == nil {
					t.Errorf("CreateAssessment() expected error, got nil")
				} else if err.Error() != tt.errMsg {
					t.Errorf("CreateAssessment() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("CreateAssessment() unexpected error: %v", err)
				}
				if assessment == nil {
					t.Errorf("CreateAssessment() returned nil assessment")
				} else {
					if assessment.Status != FEATStatusPending {
						t.Errorf("CreateAssessment() Status = %v, want %v", assessment.Status, FEATStatusPending)
					}
					if assessment.ValidUntil == nil {
						t.Errorf("CreateAssessment() ValidUntil should not be nil")
					}
				}
			}
		})
	}
}

func TestAssessmentService_UpdateAssessment(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	assessment, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	// Update with scores
	fairnessScore := 85.0
	ethicsScore := 90.0
	updateReq := &UpdateAssessmentRequest{
		FairnessScore: &fairnessScore,
		EthicsScore:   &ethicsScore,
	}

	updated, err := service.UpdateAssessment(context.Background(), "org-123", assessment.ID, updateReq)
	if err != nil {
		t.Fatalf("UpdateAssessment() unexpected error: %v", err)
	}

	if updated.FairnessScore == nil || *updated.FairnessScore != fairnessScore {
		t.Errorf("UpdateAssessment() FairnessScore = %v, want %v", updated.FairnessScore, fairnessScore)
	}

	// Status should auto-transition to in_progress when scores are recorded
	if updated.Status != FEATStatusInProgress {
		t.Errorf("UpdateAssessment() Status = %v, want %v", updated.Status, FEATStatusInProgress)
	}
}

func TestAssessmentService_SubmitAssessment(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	assessment, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	// Try to submit without all scores - should fail
	_, err := service.SubmitAssessment(context.Background(), "org-123", assessment.ID, "test-user")
	if err == nil {
		t.Errorf("SubmitAssessment() expected error for incomplete assessment")
	}

	// Add all four pillar scores
	fairnessScore := 85.0
	ethicsScore := 90.0
	accountabilityScore := 88.0
	transparencyScore := 92.0
	updateReq := &UpdateAssessmentRequest{
		FairnessScore:       &fairnessScore,
		EthicsScore:         &ethicsScore,
		AccountabilityScore: &accountabilityScore,
		TransparencyScore:   &transparencyScore,
	}
	service.UpdateAssessment(context.Background(), "org-123", assessment.ID, updateReq)

	// Now submit should succeed
	submitted, err := service.SubmitAssessment(context.Background(), "org-123", assessment.ID, "test-user")
	if err != nil {
		t.Fatalf("SubmitAssessment() unexpected error: %v", err)
	}

	if submitted.Status != FEATStatusCompleted {
		t.Errorf("SubmitAssessment() Status = %v, want %v", submitted.Status, FEATStatusCompleted)
	}
	if submitted.SubmittedAt == nil {
		t.Errorf("SubmitAssessment() SubmittedAt should not be nil")
	}
	if submitted.SubmittedBy != "test-user" {
		t.Errorf("SubmitAssessment() SubmittedBy = %v, want test-user", submitted.SubmittedBy)
	}
}

func TestAssessmentService_ApproveAssessment(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:                        "reg-001",
		OrgID:                     "org-123",
		SystemID:                  "sys-001",
		Status:                    SystemStatusActive,
		MaterialityClassification: MaterialityHigh,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create and submit an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	assessment, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	fairnessScore := 85.0
	ethicsScore := 90.0
	accountabilityScore := 88.0
	transparencyScore := 92.0
	updateReq := &UpdateAssessmentRequest{
		FairnessScore:       &fairnessScore,
		EthicsScore:         &ethicsScore,
		AccountabilityScore: &accountabilityScore,
		TransparencyScore:   &transparencyScore,
	}
	service.UpdateAssessment(context.Background(), "org-123", assessment.ID, updateReq)
	service.SubmitAssessment(context.Background(), "org-123", assessment.ID, "test-user")

	// Approve the assessment
	approved, err := service.ApproveAssessment(context.Background(), "org-123", assessment.ID, "approver@example.com")
	if err != nil {
		t.Fatalf("ApproveAssessment() unexpected error: %v", err)
	}

	if approved.Status != FEATStatusApproved {
		t.Errorf("ApproveAssessment() Status = %v, want %v", approved.Status, FEATStatusApproved)
	}
	if approved.ApprovedAt == nil {
		t.Errorf("ApproveAssessment() ApprovedAt should not be nil")
	}
	if approved.ApprovedBy != "approver@example.com" {
		t.Errorf("ApproveAssessment() ApprovedBy = %v, want approver@example.com", approved.ApprovedBy)
	}
}

func TestAssessmentService_RejectAssessment(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create and submit an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	assessment, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	fairnessScore := 85.0
	ethicsScore := 90.0
	accountabilityScore := 88.0
	transparencyScore := 92.0
	updateReq := &UpdateAssessmentRequest{
		FairnessScore:       &fairnessScore,
		EthicsScore:         &ethicsScore,
		AccountabilityScore: &accountabilityScore,
		TransparencyScore:   &transparencyScore,
	}
	service.UpdateAssessment(context.Background(), "org-123", assessment.ID, updateReq)
	service.SubmitAssessment(context.Background(), "org-123", assessment.ID, "test-user")

	// Try to reject without reason - should fail
	_, err := service.RejectAssessment(context.Background(), "org-123", assessment.ID, "reviewer@example.com", "")
	if err == nil {
		t.Errorf("RejectAssessment() expected error for missing reason")
	}

	// Reject with reason
	rejected, err := service.RejectAssessment(context.Background(), "org-123", assessment.ID, "reviewer@example.com", "Insufficient evidence")
	if err != nil {
		t.Fatalf("RejectAssessment() unexpected error: %v", err)
	}

	if rejected.Status != FEATStatusRejected {
		t.Errorf("RejectAssessment() Status = %v, want %v", rejected.Status, FEATStatusRejected)
	}
	if rejected.RejectedAt == nil {
		t.Errorf("RejectAssessment() RejectedAt should not be nil")
	}
	if rejected.RejectionReason != "Insufficient evidence" {
		t.Errorf("RejectAssessment() RejectionReason = %v, want 'Insufficient evidence'", rejected.RejectionReason)
	}
}

func TestAssessmentService_OverallScoreCalculation(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	assessment, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	// Add all four pillar scores
	fairnessScore := 80.0
	ethicsScore := 90.0
	accountabilityScore := 85.0
	transparencyScore := 95.0
	expectedOverall := (fairnessScore + ethicsScore + accountabilityScore + transparencyScore) / 4

	updateReq := &UpdateAssessmentRequest{
		FairnessScore:       &fairnessScore,
		EthicsScore:         &ethicsScore,
		AccountabilityScore: &accountabilityScore,
		TransparencyScore:   &transparencyScore,
	}

	updated, err := service.UpdateAssessment(context.Background(), "org-123", assessment.ID, updateReq)
	if err != nil {
		t.Fatalf("UpdateAssessment() unexpected error: %v", err)
	}

	if updated.OverallScore == nil {
		t.Errorf("UpdateAssessment() OverallScore should be calculated")
	} else if *updated.OverallScore != expectedOverall {
		t.Errorf("UpdateAssessment() OverallScore = %v, want %v", *updated.OverallScore, expectedOverall)
	}
}

func TestAssessmentService_CannotUpdateCompletedAssessment(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create and submit an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	assessment, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	fairnessScore := 85.0
	ethicsScore := 90.0
	accountabilityScore := 88.0
	transparencyScore := 92.0
	updateReq := &UpdateAssessmentRequest{
		FairnessScore:       &fairnessScore,
		EthicsScore:         &ethicsScore,
		AccountabilityScore: &accountabilityScore,
		TransparencyScore:   &transparencyScore,
	}
	service.UpdateAssessment(context.Background(), "org-123", assessment.ID, updateReq)
	service.SubmitAssessment(context.Background(), "org-123", assessment.ID, "test-user")

	// Try to update after submission - should fail
	newScore := 95.0
	_, err := service.UpdateAssessment(context.Background(), "org-123", assessment.ID, &UpdateAssessmentRequest{
		FairnessScore: &newScore,
	})
	if err == nil {
		t.Errorf("UpdateAssessment() expected error for completed assessment")
	}
}

func TestAssessmentService_GetAssessment(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	created, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	// Get the assessment
	assessment, err := service.GetAssessment(context.Background(), "org-123", created.ID)
	if err != nil {
		t.Fatalf("GetAssessment() unexpected error: %v", err)
	}
	if assessment.ID != created.ID {
		t.Errorf("GetAssessment() ID = %v, want %v", assessment.ID, created.ID)
	}

	// Try to get non-existent assessment
	_, err = service.GetAssessment(context.Background(), "org-123", "non-existent")
	if err == nil {
		t.Errorf("GetAssessment() expected error for non-existent assessment")
	}
}

func TestAssessmentService_ListAssessments(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}
	registryRepo.systems["sys-002"] = &AISystemRegistry{
		ID:       "reg-002",
		OrgID:    "org-123",
		SystemID: "sys-002",
		Status:   SystemStatusActive,
	}

	service := NewAssessmentService(assessmentRepo, registryRepo, 12)

	// Create assessments for different systems
	service.CreateAssessment(context.Background(), "org-123", &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}, "test-user")
	service.CreateAssessment(context.Background(), "org-123", &CreateAssessmentRequest{
		SystemID:       "sys-002",
		AssessmentType: "periodic",
	}, "test-user")

	// List all
	all, err := service.ListAssessments(context.Background(), "org-123", ListParams{})
	if err != nil {
		t.Fatalf("ListAssessments() unexpected error: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListAssessments() count = %v, want 2", len(all))
	}

	// Filter by system_id
	filtered, err := service.ListAssessments(context.Background(), "org-123", ListParams{SystemID: "sys-001"})
	if err != nil {
		t.Fatalf("ListAssessments() unexpected error: %v", err)
	}
	if len(filtered) != 1 {
		t.Errorf("ListAssessments() filtered count = %v, want 1", len(filtered))
	}
}

func TestAssessmentService_ValidUntilCalculation(t *testing.T) {
	assessmentRepo := newMockAssessmentRepository()
	registryRepo := newMockRegistryRepository()

	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:       "reg-001",
		OrgID:    "org-123",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}

	validityMonths := 6
	service := NewAssessmentService(assessmentRepo, registryRepo, validityMonths)

	// Create an assessment
	req := &CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
	}
	assessment, _ := service.CreateAssessment(context.Background(), "org-123", req, "test-user")

	if assessment.ValidUntil == nil {
		t.Fatalf("CreateAssessment() ValidUntil should not be nil")
	}

	// ValidUntil should be approximately 6 months from now
	expectedValidUntil := time.Now().UTC().AddDate(0, validityMonths, 0)
	diff := assessment.ValidUntil.Sub(expectedValidUntil)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("CreateAssessment() ValidUntil = %v, expected approximately %v", assessment.ValidUntil, expectedValidUntil)
	}
}
