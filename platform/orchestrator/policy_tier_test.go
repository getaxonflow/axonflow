// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// mockLicenseChecker is a mock license checker for testing.
type mockLicenseChecker struct {
	isEnterprise bool
}

func (m *mockLicenseChecker) IsEnterprise() bool {
	return m.isEnterprise
}

func TestTierValidationError_Error(t *testing.T) {
	err := NewTierValidationError("test message", "TEST_CODE")
	expected := "test message (TEST_CODE)"
	if err.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, err.Error())
	}
}

func TestIsTierValidationError(t *testing.T) {
	tierErr := NewTierValidationError("test", "TEST")
	if !IsTierValidationError(tierErr) {
		t.Error("Expected IsTierValidationError to return true for TierValidationError")
	}

	regularErr := errors.New("regular error")
	if IsTierValidationError(regularErr) {
		t.Error("Expected IsTierValidationError to return false for regular error")
	}
}

func TestDefaultLicenseChecker_IsEnterprise(t *testing.T) {
	checker := &DefaultLicenseChecker{}
	if checker.IsEnterprise() {
		t.Error("DefaultLicenseChecker should return false for IsEnterprise")
	}
}

func TestEnvLicenseChecker_IsEnterprise(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"empty value", "", false},
		{"community mode", "community", false},
		{"COMMUNITY uppercase", "COMMUNITY", false},
		{"saas mode", "saas", true},
		{"enterprise mode", "enterprise", true},
		{"banking mode", "banking", true},
		{"travel mode", "travel", true},
		{"healthcare mode", "healthcare", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tt.envValue)
			checker := NewEnvLicenseChecker()
			if checker.IsEnterprise() != tt.expected {
				t.Errorf("Expected IsEnterprise()=%v for DEPLOYMENT_MODE=%q", tt.expected, tt.envValue)
			}
		})
	}
}

func TestMockLicenseChecker(t *testing.T) {
	// Test Community mode
	communityChecker := &mockLicenseChecker{isEnterprise: false}
	if communityChecker.IsEnterprise() {
		t.Error("Community checker should return false")
	}

	// Test Enterprise mode
	enterpriseChecker := &mockLicenseChecker{isEnterprise: true}
	if !enterpriseChecker.IsEnterprise() {
		t.Error("Enterprise checker should return true")
	}
}

func TestPolicyService_CreatePolicy_RejectSystemTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyServiceWithLicense(repo, nil, &mockLicenseChecker{isEnterprise: true})

	// Even with Enterprise license, system tier should be rejected
	req := &CreatePolicyRequest{
		Name:        "Test Policy",
		Description: "Test description",
		Type:        "content",
		Tier:        TierSystem,
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "log"},
		},
		Priority: 100,
		Enabled:  true,
	}

	_, err = service.CreatePolicy(context.Background(), "tenant-1", req, "user-1")
	if err == nil {
		t.Fatal("Expected error for system tier creation")
	}

	if !IsTierValidationError(err) {
		t.Errorf("Expected TierValidationError, got %T: %v", err, err)
	}

	tierErr := err.(*TierValidationError)
	if tierErr.Code != ErrCodeSystemTierImmutable {
		t.Errorf("Expected code %s, got %s", ErrCodeSystemTierImmutable, tierErr.Code)
	}

	// Ensure no database operations were attempted
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unexpected database operations: %v", err)
	}
}

func TestPolicyService_CreatePolicy_OrganizationTierRequiresEnterprise(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)

	// Test with Community license (should fail)
	communityService := NewPolicyServiceWithLicense(repo, nil, &mockLicenseChecker{isEnterprise: false})

	req := &CreatePolicyRequest{
		Name:        "Org Policy",
		Description: "Organization-wide policy",
		Type:        "content",
		Tier:        TierOrganization,
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "log"},
		},
		Priority: 100,
		Enabled:  true,
	}

	_, err = communityService.CreatePolicy(context.Background(), "tenant-1", req, "user-1")
	if err == nil {
		t.Fatal("Expected error for organization tier in Community mode")
	}

	if !IsTierValidationError(err) {
		t.Errorf("Expected TierValidationError, got %T: %v", err, err)
	}

	tierErr := err.(*TierValidationError)
	if tierErr.Code != ErrCodeOrgTierEnterprise {
		t.Errorf("Expected code %s, got %s", ErrCodeOrgTierEnterprise, tierErr.Code)
	}

	// Ensure no database operations were attempted
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unexpected database operations: %v", err)
	}
}

func TestPolicyService_CreatePolicy_TenantTierPolicyLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	communityService := NewPolicyServiceWithLicense(repo, nil, &mockLicenseChecker{isEnterprise: false})

	// Mock count returning at limit
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(CommunityPolicyLimit))

	req := &CreatePolicyRequest{
		Name:        "Test Policy",
		Description: "Test",
		Type:        "content",
		Tier:        TierTenant,
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "log"},
		},
		Priority: 100,
		Enabled:  true,
	}

	_, err = communityService.CreatePolicy(context.Background(), "tenant-1", req, "user-1")
	if err == nil {
		t.Fatal("Expected error when policy limit reached")
	}

	if !IsTierValidationError(err) {
		t.Errorf("Expected TierValidationError, got %T: %v", err, err)
	}

	tierErr := err.(*TierValidationError)
	if tierErr.Code != ErrCodePolicyLimitExceeded {
		t.Errorf("Expected code %s, got %s", ErrCodePolicyLimitExceeded, tierErr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Database expectations not met: %v", err)
	}
}

func TestPolicyRepository_CountByTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)

	mock.ExpectQuery("SELECT COUNT").
		WithArgs("tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(15))

	count, err := repo.CountByTenant(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if count != 15 {
		t.Errorf("Expected count 15, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Database expectations not met: %v", err)
	}
}

func TestPolicyService_UpdatePolicy_RejectSystemTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyServiceWithLicense(repo, nil, &mockLicenseChecker{isEnterprise: true})

	now := time.Now()

	// Mock GetByID returning a system tier policy (args: policyID, tenantID per query)
	mock.ExpectQuery("SELECT").
		WithArgs("system-policy-1", "tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"policy_id", "name", "description", "policy_type", "category", "tier",
			"conditions", "actions", "tenant_id", "organization_id",
			"priority", "enabled", "version", "created_by", "updated_by",
			"created_at", "updated_at",
		}).AddRow(
			"system-policy-1", "System Policy", "A system policy", "content", "security", "system",
			`[]`, `[]`, "tenant-1", "",
			100, true, 1, "system", "system",
			now, now,
		))

	name := "Updated Name"
	req := &UpdatePolicyRequest{
		Name: &name,
	}

	_, err = service.UpdatePolicy(context.Background(), "tenant-1", "system-policy-1", req, "user-1")
	if err == nil {
		t.Fatal("Expected error for system tier update")
	}

	if !IsTierValidationError(err) {
		t.Errorf("Expected TierValidationError, got %T: %v", err, err)
	}

	tierErr := err.(*TierValidationError)
	if tierErr.Code != ErrCodeSystemTierImmutable {
		t.Errorf("Expected code %s, got %s", ErrCodeSystemTierImmutable, tierErr.Code)
	}
}

func TestPolicyService_DeletePolicy_RejectSystemTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyServiceWithLicense(repo, nil, &mockLicenseChecker{isEnterprise: true})

	now := time.Now()

	// Mock GetByID returning a system tier policy (args: policyID, tenantID per query)
	mock.ExpectQuery("SELECT").
		WithArgs("system-policy-1", "tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"policy_id", "name", "description", "policy_type", "category", "tier",
			"conditions", "actions", "tenant_id", "organization_id",
			"priority", "enabled", "version", "created_by", "updated_by",
			"created_at", "updated_at",
		}).AddRow(
			"system-policy-1", "System Policy", "A system policy", "content", "security", "system",
			`[]`, `[]`, "tenant-1", "",
			100, true, 1, "system", "system",
			now, now,
		))

	err = service.DeletePolicy(context.Background(), "tenant-1", "system-policy-1", "user-1")
	if err == nil {
		t.Fatal("Expected error for system tier delete")
	}

	if !IsTierValidationError(err) {
		t.Errorf("Expected TierValidationError, got %T: %v", err, err)
	}

	tierErr := err.(*TierValidationError)
	if tierErr.Code != ErrCodeSystemTierImmutable {
		t.Errorf("Expected code %s, got %s", ErrCodeSystemTierImmutable, tierErr.Code)
	}
}
