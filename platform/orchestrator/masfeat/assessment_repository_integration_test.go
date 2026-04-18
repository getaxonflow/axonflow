// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Integration tests for AssessmentRepository
// These tests require DATABASE_URL to be set

func TestAssessmentRepository_Integration_NewPostgresAssessmentRepository(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to have the provided database connection")
	}
}

func TestAssessmentRepository_Integration_Create(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-create-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	assessment := &FEATAssessment{
		OrgID:          orgID,
		SystemID:       "sys-" + uuid.New().String()[:8],
		AssessmentType: "initial",
		Status:         FEATStatusPending,
		AssessmentDate: time.Now().UTC(),
		Assessors:      []string{"assessor1@example.com", "assessor2@example.com"},
		CreatedBy:      "test-user",
	}

	err := repo.Create(ctx, assessment)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if assessment.ID == "" {
		t.Error("Expected ID to be generated")
	}
	if assessment.Version != 1 {
		t.Errorf("Expected Version 1, got %d", assessment.Version)
	}

	// Verify by retrieving
	retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected assessment to be found")
	}
	if retrieved.AssessmentType != "initial" {
		t.Errorf("Expected AssessmentType 'initial', got %s", retrieved.AssessmentType)
	}
	if retrieved.Status != FEATStatusPending {
		t.Errorf("Expected Status 'pending', got %s", retrieved.Status)
	}
	if len(retrieved.Assessors) != 2 {
		t.Errorf("Expected 2 assessors, got %d", len(retrieved.Assessors))
	}
}

func TestAssessmentRepository_Integration_Create_WithScores(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-scores-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	fairness := 85.5
	ethics := 90.0
	accountability := 88.0
	transparency := 92.5
	overall := 89.0
	validUntil := time.Now().UTC().AddDate(1, 0, 0)

	assessment := &FEATAssessment{
		OrgID:               orgID,
		SystemID:            "sys-" + uuid.New().String()[:8],
		AssessmentType:      "periodic",
		Status:              FEATStatusApproved,
		AssessmentDate:      time.Now().UTC(),
		ValidUntil:          &validUntil,
		FairnessScore:       &fairness,
		EthicsScore:         &ethics,
		AccountabilityScore: &accountability,
		TransparencyScore:   &transparency,
		OverallScore:        &overall,
		CreatedBy:           "test-user",
	}

	err := repo.Create(ctx, assessment)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.FairnessScore == nil || *retrieved.FairnessScore != 85.5 {
		t.Errorf("Expected FairnessScore 85.5, got %v", retrieved.FairnessScore)
	}
	if retrieved.EthicsScore == nil || *retrieved.EthicsScore != 90.0 {
		t.Errorf("Expected EthicsScore 90.0, got %v", retrieved.EthicsScore)
	}
	if retrieved.AccountabilityScore == nil || *retrieved.AccountabilityScore != 88.0 {
		t.Errorf("Expected AccountabilityScore 88.0, got %v", retrieved.AccountabilityScore)
	}
	if retrieved.TransparencyScore == nil || *retrieved.TransparencyScore != 92.5 {
		t.Errorf("Expected TransparencyScore 92.5, got %v", retrieved.TransparencyScore)
	}
	if retrieved.OverallScore == nil || *retrieved.OverallScore != 89.0 {
		t.Errorf("Expected OverallScore 89.0, got %v", retrieved.OverallScore)
	}
	if retrieved.ValidUntil == nil {
		t.Error("Expected ValidUntil to be set")
	}
}

func TestAssessmentRepository_Integration_GetByID_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-notfound-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	retrieved, err := repo.GetByID(ctx, orgID, "non-existent-id")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent ID")
	}
}

func TestAssessmentRepository_Integration_List(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-list-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create multiple assessments
	for i := 0; i < 5; i++ {
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       "sys-list-" + uuid.New().String()[:8],
			AssessmentType: "initial",
			Status:         FEATStatusPending,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// List all
	assessments, err := repo.List(ctx, orgID, ListParams{Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(assessments) != 5 {
		t.Errorf("Expected 5 assessments, got %d", len(assessments))
	}
}

func TestAssessmentRepository_Integration_List_WithStatusFilter(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-status-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create assessments with different statuses
	statuses := []FEATAssessmentStatus{FEATStatusPending, FEATStatusPending, FEATStatusInProgress, FEATStatusCompleted, FEATStatusApproved}
	for _, status := range statuses {
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       "sys-status-" + uuid.New().String()[:8],
			AssessmentType: "initial",
			Status:         status,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Filter by pending status
	pending, err := repo.List(ctx, orgID, ListParams{Status: string(FEATStatusPending), Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(pending) != 2 {
		t.Errorf("Expected 2 pending assessments, got %d", len(pending))
	}
}

func TestAssessmentRepository_Integration_List_WithSystemIDFilter(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-sysfilter-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	targetSystemID := "target-sys-" + uuid.New().String()[:8]

	// Create assessments for different systems
	for i := 0; i < 3; i++ {
		systemID := "other-sys-" + uuid.New().String()[:8]
		if i == 1 || i == 2 {
			systemID = targetSystemID
		}
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       systemID,
			AssessmentType: "initial",
			Status:         FEATStatusPending,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Filter by system ID
	filtered, err := repo.List(ctx, orgID, ListParams{SystemID: targetSystemID, Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(filtered) != 2 {
		t.Errorf("Expected 2 assessments for target system, got %d", len(filtered))
	}
}

func TestAssessmentRepository_Integration_List_Pagination(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-page-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create 7 assessments
	for i := 0; i < 7; i++ {
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       "sys-page-" + uuid.New().String()[:8],
			AssessmentType: "initial",
			Status:         FEATStatusPending,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// First page
	page1, err := repo.List(ctx, orgID, ListParams{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page1) != 3 {
		t.Errorf("Expected 3 assessments on page 1, got %d", len(page1))
	}

	// Second page
	page2, err := repo.List(ctx, orgID, ListParams{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page2) != 3 {
		t.Errorf("Expected 3 assessments on page 2, got %d", len(page2))
	}

	// Third page
	page3, err := repo.List(ctx, orgID, ListParams{Limit: 3, Offset: 6})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page3) != 1 {
		t.Errorf("Expected 1 assessment on page 3, got %d", len(page3))
	}
}

func TestAssessmentRepository_Integration_Update(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-update-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create an assessment
	assessment := &FEATAssessment{
		OrgID:          orgID,
		SystemID:       "sys-update-" + uuid.New().String()[:8],
		AssessmentType: "initial",
		Status:         FEATStatusPending,
		AssessmentDate: time.Now().UTC(),
		CreatedBy:      "test-user",
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update the assessment
	fairness := 85.0
	assessment.Status = FEATStatusInProgress
	assessment.FairnessScore = &fairness
	assessment.Findings = []Finding{
		{ID: "f1", Pillar: PillarFairness, Severity: "minor", Description: "Finding 1"},
		{ID: "f2", Pillar: PillarEthics, Severity: "observation", Description: "Finding 2"},
	}
	assessment.Recommendations = []string{"Recommendation 1"}

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update
	retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != FEATStatusInProgress {
		t.Errorf("Expected Status 'in_progress', got %s", retrieved.Status)
	}
	if retrieved.FairnessScore == nil || *retrieved.FairnessScore != 85.0 {
		t.Errorf("Expected FairnessScore 85.0, got %v", retrieved.FairnessScore)
	}
	if retrieved.Version != 2 {
		t.Errorf("Expected Version 2, got %d", retrieved.Version)
	}
	if len(retrieved.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(retrieved.Findings))
	}
	if len(retrieved.Recommendations) != 1 {
		t.Errorf("Expected 1 recommendation, got %d", len(retrieved.Recommendations))
	}
}

func TestAssessmentRepository_Integration_Update_Submit(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-submit-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create an assessment with all scores
	fairness := 85.0
	ethics := 90.0
	accountability := 88.0
	transparency := 92.0

	assessment := &FEATAssessment{
		OrgID:               orgID,
		SystemID:            "sys-submit-" + uuid.New().String()[:8],
		AssessmentType:      "initial",
		Status:              FEATStatusInProgress,
		AssessmentDate:      time.Now().UTC(),
		FairnessScore:       &fairness,
		EthicsScore:         &ethics,
		AccountabilityScore: &accountability,
		TransparencyScore:   &transparency,
		CreatedBy:           "test-user",
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update to completed with submission info
	assessment.Status = FEATStatusCompleted
	now := time.Now().UTC()
	assessment.SubmittedAt = &now
	assessment.SubmittedBy = "submitter@example.com"

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != FEATStatusCompleted {
		t.Errorf("Expected Status 'completed', got %s", retrieved.Status)
	}
	if retrieved.SubmittedAt == nil {
		t.Error("Expected SubmittedAt to be set")
	}
	if retrieved.SubmittedBy != "submitter@example.com" {
		t.Errorf("Expected SubmittedBy 'submitter@example.com', got %s", retrieved.SubmittedBy)
	}
}

func TestAssessmentRepository_Integration_Update_Approve(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-approve-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a completed assessment
	fairness := 85.0
	ethics := 90.0
	accountability := 88.0
	transparency := 92.0

	assessment := &FEATAssessment{
		OrgID:               orgID,
		SystemID:            "sys-approve-" + uuid.New().String()[:8],
		AssessmentType:      "initial",
		Status:              FEATStatusCompleted,
		AssessmentDate:      time.Now().UTC(),
		FairnessScore:       &fairness,
		EthicsScore:         &ethics,
		AccountabilityScore: &accountability,
		TransparencyScore:   &transparency,
		CreatedBy:           "test-user",
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Approve the assessment
	approvedAt := time.Now().UTC()
	validUntil := time.Now().UTC().AddDate(1, 0, 0)
	assessment.Status = FEATStatusApproved
	assessment.ApprovedAt = &approvedAt
	assessment.ApprovedBy = "approver@example.com"
	assessment.ValidUntil = &validUntil

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != FEATStatusApproved {
		t.Errorf("Expected Status 'approved', got %s", retrieved.Status)
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

func TestAssessmentRepository_Integration_Update_Reject(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-reject-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a completed assessment
	assessment := &FEATAssessment{
		OrgID:          orgID,
		SystemID:       "sys-reject-" + uuid.New().String()[:8],
		AssessmentType: "initial",
		Status:         FEATStatusCompleted,
		AssessmentDate: time.Now().UTC(),
		CreatedBy:      "test-user",
	}
	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Reject the assessment
	rejectedAt := time.Now().UTC()
	assessment.Status = FEATStatusRejected
	assessment.RejectedAt = &rejectedAt
	assessment.RejectedBy = "rejector@example.com"
	assessment.RejectionReason = "Insufficient documentation for fairness assessment"

	err := repo.Update(ctx, assessment)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved.Status != FEATStatusRejected {
		t.Errorf("Expected Status 'rejected', got %s", retrieved.Status)
	}
	if retrieved.RejectedAt == nil {
		t.Error("Expected RejectedAt to be set")
	}
	if retrieved.RejectedBy != "rejector@example.com" {
		t.Errorf("Expected RejectedBy 'rejector@example.com', got %s", retrieved.RejectedBy)
	}
	if retrieved.RejectionReason != "Insufficient documentation for fairness assessment" {
		t.Errorf("Expected RejectionReason, got %s", retrieved.RejectionReason)
	}
}

func TestAssessmentRepository_Integration_GetLatestForSystem(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-latest-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	systemID := "sys-latest-" + uuid.New().String()[:8]

	// Create multiple assessments for the same system
	for i := 0; i < 3; i++ {
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       systemID,
			AssessmentType: "initial",
			Status:         FEATStatusPending,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		time.Sleep(50 * time.Millisecond) // Ensure distinct timestamps
	}

	// Get latest
	latest, err := repo.GetLatestForSystem(ctx, orgID, systemID)
	if err != nil {
		t.Fatalf("GetLatestForSystem() error = %v", err)
	}

	if latest == nil {
		t.Fatal("Expected latest assessment to be found")
	}
	if latest.SystemID != systemID {
		t.Errorf("Expected SystemID %s, got %s", systemID, latest.SystemID)
	}
}

func TestAssessmentRepository_Integration_GetLatestForSystem_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-latest-nf-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	latest, err := repo.GetLatestForSystem(ctx, orgID, "non-existent-system")
	if err != nil {
		t.Fatalf("GetLatestForSystem() error = %v", err)
	}
	if latest != nil {
		t.Error("Expected nil for non-existent system")
	}
}

func TestAssessmentRepository_Integration_AllAssessmentTypes(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-types-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Test all assessment types (these are plain strings)
	types := []string{
		"initial",
		"periodic",
		"ad_hoc",
	}

	for _, at := range types {
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       "sys-type-" + uuid.New().String()[:8],
			AssessmentType: at,
			Status:         FEATStatusPending,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error for type %s: %v", at, err)
		}

		retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
		if err != nil {
			t.Fatalf("GetByID() error for type %s: %v", at, err)
		}
		if retrieved.AssessmentType != at {
			t.Errorf("Expected AssessmentType %s, got %s", at, retrieved.AssessmentType)
		}
	}
}

func TestAssessmentRepository_Integration_AllStatuses(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-all-status-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Test all assessment statuses
	statuses := []FEATAssessmentStatus{
		FEATStatusPending,
		FEATStatusInProgress,
		FEATStatusCompleted,
		FEATStatusApproved,
		FEATStatusRejected,
	}

	for _, status := range statuses {
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       "sys-status-" + uuid.New().String()[:8],
			AssessmentType: "initial",
			Status:         status,
			AssessmentDate: time.Now().UTC(),
			CreatedBy:      "test-user",
		}
		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error for status %s: %v", status, err)
		}

		retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
		if err != nil {
			t.Fatalf("GetByID() error for status %s: %v", status, err)
		}
		if retrieved.Status != status {
			t.Errorf("Expected Status %s, got %s", status, retrieved.Status)
		}
	}
}

func TestAssessmentRepository_Integration_WithFindings(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-findings-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	findings := []Finding{
		{ID: "f1", Pillar: PillarFairness, Severity: "major", Category: "bias", Description: "Model shows 5% disparity in approval rates across demographic groups"},
		{ID: "f2", Pillar: PillarTransparency, Severity: "minor", Category: "documentation", Description: "Documentation for training data sources is incomplete"},
		{ID: "f3", Pillar: PillarAccountability, Severity: "observation", Category: "monitoring", Description: "No regular monitoring process is in place"},
	}
	recommendations := []string{
		"Implement bias mitigation techniques to reduce disparity",
		"Complete documentation of all training data sources",
		"Establish monthly monitoring cadence",
	}

	assessment := &FEATAssessment{
		OrgID:           orgID,
		SystemID:        "sys-findings-" + uuid.New().String()[:8],
		AssessmentType:  "initial",
		Status:          FEATStatusPending,
		AssessmentDate:  time.Now().UTC(),
		Findings:        findings,
		Recommendations: recommendations,
		CreatedBy:       "test-user",
	}

	if err := repo.Create(ctx, assessment); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if len(retrieved.Findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(retrieved.Findings))
	}
	if len(retrieved.Recommendations) != 3 {
		t.Errorf("Expected 3 recommendations, got %d", len(retrieved.Recommendations))
	}
	if retrieved.Findings[0].Description != findings[0].Description {
		t.Errorf("Expected first finding description to match, got %s", retrieved.Findings[0].Description)
	}
}

func TestAssessmentRepository_Integration_ScoreRange(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-assess-range-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Test boundary values for scores (0-100)
	scores := []float64{0.0, 50.0, 100.0}

	for _, score := range scores {
		s := score // local copy for pointer
		assessment := &FEATAssessment{
			OrgID:          orgID,
			SystemID:       "sys-range-" + uuid.New().String()[:8],
			AssessmentType: "initial",
			Status:         FEATStatusPending,
			AssessmentDate: time.Now().UTC(),
			FairnessScore:  &s,
			EthicsScore:    &s,
			CreatedBy:      "test-user",
		}

		if err := repo.Create(ctx, assessment); err != nil {
			t.Fatalf("Create() error for score %f: %v", score, err)
		}

		retrieved, err := repo.GetByID(ctx, orgID, assessment.ID)
		if err != nil {
			t.Fatalf("GetByID() error for score %f: %v", score, err)
		}
		if *retrieved.FairnessScore != score {
			t.Errorf("Expected FairnessScore %f, got %f", score, *retrieved.FairnessScore)
		}
	}
}
