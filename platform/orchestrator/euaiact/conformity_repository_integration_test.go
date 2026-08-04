// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Integration tests for ConformityRepository
// These tests require DATABASE_URL to be set

func cleanupTestConformityAssessments(t *testing.T, db *sql.DB, orgID string) {
	_, err := db.Exec("DELETE FROM euaiact_conformity_assessments WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup conformity assessments: %v", err)
	}
}

func TestConformityRepository_Integration_NewPostgresConformityRepository(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to have the provided database connection")
	}
}

func TestConformityRepository_Integration_Create(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-create-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	assessment := &ConformityAssessment{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		SystemID:       "ai-system-001",
		SystemName:     "Customer Service AI",
		RiskCategory:   RiskCategoryHighRisk,
		Status:         AssessmentStatusDraft,
		Version:        1,
		AssessmentDate: time.Now().UTC(),
		Assessors:      []string{"assessor1@example.com", "assessor2@example.com"},
		Requirements: []RequirementStatus{
			{RequirementID: "req-1", Article: "Article 9", Description: "Risk Management", Status: "compliant"},
			{RequirementID: "req-2", Article: "Article 10", Description: "Data Governance", Status: "partial"},
		},
		Evidence: []EvidenceItem{
			{ID: "ev-1", Type: "document", Title: "Risk Assessment Report", UploadedAt: time.Now().UTC(), UploadedBy: "test-user"},
		},
		Findings: []Finding{
			{ID: "find-1", Severity: "minor", Category: "documentation", Description: "Missing data governance policy", Status: "open"},
		},
		RiskMitigation: map[string]interface{}{
			"strategy": "continuous_monitoring",
			"controls": []string{"access_control", "audit_logging"},
		},
		Recommendations: []string{"Implement comprehensive data governance policy", "Enhance audit logging"},
		CreatedBy:       "test-user",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	err := repo.Create(ctx, assessment)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify by retrieving
	retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected assessment to be found")
	}
	if retrieved.ID != assessment.ID {
		t.Errorf("Expected ID %s, got %s", assessment.ID, retrieved.ID)
	}
	if retrieved.SystemID != "ai-system-001" {
		t.Errorf("Expected SystemID 'ai-system-001', got %s", retrieved.SystemID)
	}
	if retrieved.SystemName != "Customer Service AI" {
		t.Errorf("Expected SystemName 'Customer Service AI', got %s", retrieved.SystemName)
	}
	if retrieved.RiskCategory != RiskCategoryHighRisk {
		t.Errorf("Expected RiskCategory %s, got %s", RiskCategoryHighRisk, retrieved.RiskCategory)
	}
	if retrieved.Status != AssessmentStatusDraft {
		t.Errorf("Expected Status %s, got %s", AssessmentStatusDraft, retrieved.Status)
	}
	if len(retrieved.Assessors) != 2 {
		t.Errorf("Expected 2 assessors, got %d", len(retrieved.Assessors))
	}
	if len(retrieved.Requirements) != 2 {
		t.Errorf("Expected 2 requirements, got %d", len(retrieved.Requirements))
	}
	if len(retrieved.Evidence) != 1 {
		t.Errorf("Expected 1 evidence item, got %d", len(retrieved.Evidence))
	}
	if len(retrieved.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(retrieved.Findings))
	}
	if len(retrieved.Recommendations) != 2 {
		t.Errorf("Expected 2 recommendations, got %d", len(retrieved.Recommendations))
	}
}

func TestConformityRepository_Integration_GetByID_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	// #3241: a miss now returns ErrAssessmentNotFound rather than (nil, nil) - the
	// handler needs a value it can map to 404, and "no such id" must be
	// indistinguishable from "belongs to another organization".
	retrieved, err := repo.GetByID(ctx, "test-org-nonexistent-lookup", "non-existent-assessment-id")
	if !errors.Is(err, ErrAssessmentNotFound) {
		t.Fatalf("GetByID() error = %v, want ErrAssessmentNotFound", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent ID")
	}
}

func TestConformityRepository_Integration_List(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-list-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Create multiple assessments
	statuses := []AssessmentStatus{AssessmentStatusDraft, AssessmentStatusInProgress, AssessmentStatusSubmitted}
	for i, status := range statuses {
		assessment := &ConformityAssessment{
			ID:             uuid.New().String(),
			OrgID:          orgID,
			SystemID:       "system-" + string(rune('A'+i)),
			SystemName:     "System " + string(rune('A'+i)),
			RiskCategory:   RiskCategoryHighRisk,
			Status:         status,
			Version:        1,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC().Add(time.Duration(i) * time.Minute),
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// List all assessments (no status filter)
	assessments, total, err := repo.List(ctx, orgID, "", 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 3 {
		t.Errorf("Expected total 3, got %d", total)
	}
	if len(assessments) != 3 {
		t.Errorf("Expected 3 assessments, got %d", len(assessments))
	}
}

func TestConformityRepository_Integration_List_WithStatusFilter(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-filter-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Create assessments with different statuses
	for i, status := range []AssessmentStatus{AssessmentStatusDraft, AssessmentStatusDraft, AssessmentStatusSubmitted} {
		assessment := &ConformityAssessment{
			ID:             uuid.New().String(),
			OrgID:          orgID,
			SystemID:       "system-" + string(rune('0'+i)),
			SystemName:     "System " + string(rune('0'+i)),
			RiskCategory:   RiskCategoryHighRisk,
			Status:         status,
			Version:        1,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Filter by draft status
	assessments, total, err := repo.List(ctx, orgID, AssessmentStatusDraft, 10, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 2 {
		t.Errorf("Expected total 2 draft assessments, got %d", total)
	}
	if len(assessments) != 2 {
		t.Errorf("Expected 2 assessments, got %d", len(assessments))
	}
	for _, a := range assessments {
		if a.Status != AssessmentStatusDraft {
			t.Errorf("Expected status draft, got %s", a.Status)
		}
	}
}

func TestConformityRepository_Integration_List_Pagination(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-page-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Create 5 assessments
	for i := 0; i < 5; i++ {
		assessment := &ConformityAssessment{
			ID:             uuid.New().String(),
			OrgID:          orgID,
			SystemID:       "system-" + string(rune('0'+i)),
			SystemName:     "System " + string(rune('0'+i)),
			RiskCategory:   RiskCategoryHighRisk,
			Status:         AssessmentStatusDraft,
			Version:        1,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC().Add(time.Duration(i) * time.Second),
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Get first page
	assessments, total, err := repo.List(ctx, orgID, "", 2, 0)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 5 {
		t.Errorf("Expected total 5, got %d", total)
	}
	if len(assessments) != 2 {
		t.Errorf("Expected 2 assessments on page 1, got %d", len(assessments))
	}

	// Get second page
	assessments2, _, err := repo.List(ctx, orgID, "", 2, 2)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(assessments2) != 2 {
		t.Errorf("Expected 2 assessments on page 2, got %d", len(assessments2))
	}
}

func TestConformityRepository_Integration_Update(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-update-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Create an assessment
	assessment := &ConformityAssessment{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		SystemID:       "ai-system-update",
		SystemName:     "Original Name",
		RiskCategory:   RiskCategoryHighRisk,
		Status:         AssessmentStatusDraft,
		Version:        1,
		AssessmentDate: time.Now().UTC(),
		CreatedBy:      "test-user",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update the assessment
	assessment.SystemName = "Updated Name"
	assessment.Status = AssessmentStatusInProgress
	assessment.Version = 2
	assessment.Requirements = []RequirementStatus{
		{RequirementID: "req-new", Article: "Article 9", Description: "Updated Requirement", Status: "compliant"},
	}

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update
	retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.SystemName != "Updated Name" {
		t.Errorf("Expected SystemName 'Updated Name', got %s", retrieved.SystemName)
	}
	if retrieved.Status != AssessmentStatusInProgress {
		t.Errorf("Expected Status %s, got %s", AssessmentStatusInProgress, retrieved.Status)
	}
	if retrieved.Version != 2 {
		t.Errorf("Expected Version 2, got %d", retrieved.Version)
	}
	if len(retrieved.Requirements) != 1 {
		t.Errorf("Expected 1 requirement, got %d", len(retrieved.Requirements))
	}
}

func TestConformityRepository_Integration_Update_Submit(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-submit-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Create an assessment
	assessment := &ConformityAssessment{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		SystemID:       "ai-system-submit",
		SystemName:     "System for Submission",
		RiskCategory:   RiskCategoryHighRisk,
		Status:         AssessmentStatusInProgress,
		Version:        1,
		AssessmentDate: time.Now().UTC(),
		CreatedBy:      "test-user",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Submit the assessment
	submitTime := time.Now().UTC()
	assessment.Status = AssessmentStatusSubmitted
	assessment.SubmittedAt = &submitTime
	assessment.SubmittedBy = "submitter@example.com"

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != AssessmentStatusSubmitted {
		t.Errorf("Expected Status %s, got %s", AssessmentStatusSubmitted, retrieved.Status)
	}
	if retrieved.SubmittedAt == nil {
		t.Error("Expected SubmittedAt to be set")
	}
	if retrieved.SubmittedBy != "submitter@example.com" {
		t.Errorf("Expected SubmittedBy 'submitter@example.com', got %s", retrieved.SubmittedBy)
	}
}

func TestConformityRepository_Integration_Update_Approve(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-approve-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	submitTime := time.Now().UTC()
	assessment := &ConformityAssessment{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		SystemID:       "ai-system-approve",
		SystemName:     "System for Approval",
		RiskCategory:   RiskCategoryHighRisk,
		Status:         AssessmentStatusSubmitted,
		Version:        1,
		AssessmentDate: time.Now().UTC(),
		SubmittedAt:    &submitTime,
		SubmittedBy:    "submitter@example.com",
		CreatedBy:      "test-user",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Approve the assessment
	approveTime := time.Now().UTC()
	validUntil := time.Now().UTC().AddDate(1, 0, 0)
	assessment.Status = AssessmentStatusApproved
	assessment.ApprovedAt = &approveTime
	assessment.ApprovedBy = "approver@example.com"
	assessment.ValidUntil = &validUntil

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != AssessmentStatusApproved {
		t.Errorf("Expected Status %s, got %s", AssessmentStatusApproved, retrieved.Status)
	}
	if retrieved.ApprovedAt == nil {
		t.Error("Expected ApprovedAt to be set")
	}
	if retrieved.ApprovedBy != "approver@example.com" {
		t.Errorf("Expected ApprovedBy 'approver@example.com', got %s", retrieved.ApprovedBy)
	}
	if retrieved.ValidUntil == nil {
		t.Error("Expected ValidUntil to be set")
	}
}

func TestConformityRepository_Integration_Update_Reject(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-reject-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	submitTime := time.Now().UTC()
	assessment := &ConformityAssessment{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		SystemID:       "ai-system-reject",
		SystemName:     "System for Rejection",
		RiskCategory:   RiskCategoryHighRisk,
		Status:         AssessmentStatusSubmitted,
		Version:        1,
		AssessmentDate: time.Now().UTC(),
		SubmittedAt:    &submitTime,
		SubmittedBy:    "submitter@example.com",
		CreatedBy:      "test-user",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Reject the assessment
	rejectTime := time.Now().UTC()
	assessment.Status = AssessmentStatusRejected
	assessment.RejectedAt = &rejectTime
	assessment.RejectedBy = "reviewer@example.com"
	assessment.RejectionReason = "Insufficient evidence for Article 10 compliance"

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != AssessmentStatusRejected {
		t.Errorf("Expected Status %s, got %s", AssessmentStatusRejected, retrieved.Status)
	}
	if retrieved.RejectedAt == nil {
		t.Error("Expected RejectedAt to be set")
	}
	if retrieved.RejectedBy != "reviewer@example.com" {
		t.Errorf("Expected RejectedBy 'reviewer@example.com', got %s", retrieved.RejectedBy)
	}
	if retrieved.RejectionReason != "Insufficient evidence for Article 10 compliance" {
		t.Errorf("Expected RejectionReason, got %s", retrieved.RejectionReason)
	}
}

func TestConformityRepository_Integration_Delete(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-delete-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Create an assessment
	assessment := &ConformityAssessment{
		ID:             uuid.New().String(),
		OrgID:          orgID,
		SystemID:       "ai-system-delete",
		SystemName:     "System to Delete",
		RiskCategory:   RiskCategoryHighRisk,
		Status:         AssessmentStatusDraft,
		Version:        1,
		AssessmentDate: time.Now().UTC(),
		CreatedBy:      "test-user",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete the assessment
	err := repo.Delete(ctx, assessment.OrgID, assessment.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion
	retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected assessment to be deleted")
	}
}

func TestConformityRepository_Integration_GetBySystemID(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-system-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	systemID := "ai-system-versions"

	// Create multiple versions of assessments for the same system
	for i := 1; i <= 3; i++ {
		assessment := &ConformityAssessment{
			ID:             uuid.New().String(),
			OrgID:          orgID,
			SystemID:       systemID,
			SystemName:     "Versioned System",
			RiskCategory:   RiskCategoryHighRisk,
			Status:         AssessmentStatusDraft,
			Version:        i,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Get assessments by system ID
	assessments, err := repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if len(assessments) != 3 {
		t.Errorf("Expected 3 assessments, got %d", len(assessments))
	}

	// Verify ordering (highest version first)
	if assessments[0].Version != 3 {
		t.Errorf("Expected first assessment to have version 3, got %d", assessments[0].Version)
	}
	if assessments[2].Version != 1 {
		t.Errorf("Expected last assessment to have version 1, got %d", assessments[2].Version)
	}
}

func TestConformityRepository_Integration_AllRiskCategories(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-risk-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Test all risk categories
	riskCategories := []RiskCategory{
		RiskCategoryMinimal,
		RiskCategoryLimited,
		RiskCategoryHighRisk,
		RiskCategoryUnacceptable,
	}

	for i, rc := range riskCategories {
		assessment := &ConformityAssessment{
			ID:             uuid.New().String(),
			OrgID:          orgID,
			SystemID:       "system-risk-" + string(rune('0'+i)),
			SystemName:     "System " + string(rc),
			RiskCategory:   rc,
			Status:         AssessmentStatusDraft,
			Version:        1,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error for risk category %s: %v", rc, err)
		}

		retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
		if err != nil {
			t.Fatalf("GetByID() error for risk category %s: %v", rc, err)
		}
		if retrieved.RiskCategory != rc {
			t.Errorf("Expected RiskCategory %s, got %s", rc, retrieved.RiskCategory)
		}
	}
}

func TestConformityRepository_Integration_AllStatuses(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ca-status-"+time.Now().Format("20060102150405"))
	defer cleanupTestConformityAssessments(t, db, orgID)

	ctx := context.Background()

	// Test all statuses
	statuses := []AssessmentStatus{
		AssessmentStatusDraft,
		AssessmentStatusInProgress,
		AssessmentStatusSubmitted,
		AssessmentStatusApproved,
		AssessmentStatusRejected,
	}

	for i, status := range statuses {
		assessment := &ConformityAssessment{
			ID:             uuid.New().String(),
			OrgID:          orgID,
			SystemID:       "system-status-" + string(rune('0'+i)),
			SystemName:     "System " + string(status),
			RiskCategory:   RiskCategoryHighRisk,
			Status:         status,
			Version:        1,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error for status %s: %v", status, err)
		}

		retrieved, err := repo.GetByID(ctx, assessment.OrgID, assessment.ID)
		if err != nil {
			t.Fatalf("GetByID() error for status %s: %v", status, err)
		}
		if retrieved.Status != status {
			t.Errorf("Expected Status %s, got %s", status, retrieved.Status)
		}
	}
}
