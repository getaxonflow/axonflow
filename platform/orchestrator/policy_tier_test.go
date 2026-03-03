// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/license"
)

// Test Ed25519 seeds — deterministic, same as ee/platform/agent/license/keygen_test.go
const (
	testEntSeedB64 = "fifqSWAaVJy1qk89VwvqXYnXmlSCF3VfGRiK4e1kF0g="
)

// genTestLicenseKey generates an Ed25519-signed test license key for the given tier.
func genTestLicenseKey(tier string) string {
	seed, _ := base64.StdEncoding.DecodeString(testEntSeedB64)
	privKey := ed25519.NewKeyFromSeed(seed)

	type payload struct {
		Tier        string   `json:"tier"`
		TenantID    string   `json:"tenant_id"`
		ServiceName string   `json:"service_name"`
		ServiceType string   `json:"service_type"`
		Permissions []string `json:"permissions"`
		IssuedAt    string   `json:"issued_at"`
		ExpiresAt   string   `json:"expires_at"`
	}

	p := payload{
		Tier:        tier,
		TenantID:    "test",
		ServiceName: "platform",
		ServiceType: "backend-service",
		Permissions: []string{"mcp:*:*", "llm:*:*"},
		IssuedAt:    time.Now().Format("20060102"),
		ExpiresAt:   time.Now().AddDate(1, 0, 0).Format("20060102"),
	}
	pJSON, _ := json.Marshal(p)
	pB64 := base64.RawURLEncoding.EncodeToString(pJSON)
	sig := ed25519.Sign(privKey, []byte(pB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return "AXON-" + pB64 + "." + sigB64
}

// setupTestKeypair overrides embedded production public keys with test keys.
func setupTestKeypair(t *testing.T) {
	t.Helper()
	entSeed, _ := base64.StdEncoding.DecodeString(testEntSeedB64)
	entPriv := ed25519.NewKeyFromSeed(entSeed)
	entPub := entPriv.Public().(ed25519.PublicKey)
	// Use enterprise key for both (tests only use enterprise-tier licenses)
	restore := license.OverridePublicKeysForTest(entPub, entPub)
	t.Cleanup(restore)
}

// mockLicenseChecker is a mock license checker for testing.
type mockLicenseChecker struct {
	tier                     license.Tier
	policyLimit              int
	orgPolicyLimit           int
	policyConnectorLimit     int
	auditRetentionDays       int
	maxLLMProviders          int
	maxExecutionHistory      int
	maxConcurrentExecutions  int
	maxPlans                 int
	maxVersionsPerPlan       int
	maxSSEConnections        int
	maxCostEstimatesPerDay   int
	maxPendingApprovals      int
	mediaGovernanceEnabled   bool
	hitlApprovalEnabled      bool
	hitlExpiryHours          int
	policySimulationEnabled  bool
	maxSimulationsPerDay     int
	maxImpactReportInputs    int
	evidenceExportEnabled    bool
	maxEvidenceExportRecords int
	maxEvidenceWindowDays    int
	maxEvidenceExportsPerDay int
}

// newMockLicenseChecker creates a mock license checker with sensible defaults.
func newMockLicenseChecker(tier license.Tier) *mockLicenseChecker {
	m := &mockLicenseChecker{tier: tier}
	limits := license.GetTierLimits(tier)
	m.policyLimit = limits.TenantPolicies
	m.orgPolicyLimit = limits.OrgPolicies
	m.policyConnectorLimit = limits.CustomPolicyConnectors
	m.auditRetentionDays = limits.AuditRetentionDays
	m.maxLLMProviders = limits.MaxLLMProviders
	m.maxExecutionHistory = limits.MaxExecutionHistory
	m.maxConcurrentExecutions = limits.MaxConcurrentExec
	m.maxPlans = limits.MaxPlans
	m.maxVersionsPerPlan = limits.MaxVersionsPerPlan
	m.maxSSEConnections = limits.MaxSSEConnections
	m.maxCostEstimatesPerDay = limits.MaxCostEstimatesPerDay
	m.maxPendingApprovals = limits.MaxPendingApprovals
	m.mediaGovernanceEnabled = limits.MediaGovernanceEnabled
	m.hitlApprovalEnabled = limits.HITLApprovalEnabled
	m.hitlExpiryHours = limits.HITLExpiryHours
	m.policySimulationEnabled = limits.PolicySimulationEnabled
	m.maxSimulationsPerDay = limits.MaxSimulationsPerDay
	m.maxImpactReportInputs = limits.MaxImpactReportInputs
	m.evidenceExportEnabled = limits.EvidenceExportEnabled
	m.maxEvidenceExportRecords = limits.MaxEvidenceExportRecords
	m.maxEvidenceWindowDays = limits.MaxEvidenceWindowDays
	m.maxEvidenceExportsPerDay = limits.MaxEvidenceExportsPerDay
	return m
}

func (m *mockLicenseChecker) IsEnterprise() bool {
	return license.IsPaidTier(m.tier)
}

func (m *mockLicenseChecker) Tier() license.Tier {
	return m.tier
}

func (m *mockLicenseChecker) PolicyLimit() int {
	return m.policyLimit
}

func (m *mockLicenseChecker) OrgPolicyLimit() int {
	return m.orgPolicyLimit
}

func (m *mockLicenseChecker) CustomPolicyConnectorLimit() int {
	return m.policyConnectorLimit
}

func (m *mockLicenseChecker) AuditRetentionDays() int {
	return m.auditRetentionDays
}

func (m *mockLicenseChecker) MaxLLMProviders() int {
	return m.maxLLMProviders
}

func (m *mockLicenseChecker) MaxExecutionHistory() int {
	return m.maxExecutionHistory
}

func (m *mockLicenseChecker) MaxConcurrentExecutions() int {
	return m.maxConcurrentExecutions
}

func (m *mockLicenseChecker) MaxPlans() int {
	return m.maxPlans
}

func (m *mockLicenseChecker) MaxVersionsPerPlan() int {
	return m.maxVersionsPerPlan
}

func (m *mockLicenseChecker) MaxSSEConnections() int {
	return m.maxSSEConnections
}

func (m *mockLicenseChecker) MaxCostEstimatesPerDay() int {
	return m.maxCostEstimatesPerDay
}

func (m *mockLicenseChecker) MaxPendingApprovals() int {
	return m.maxPendingApprovals
}

func (m *mockLicenseChecker) MediaGovernanceEnabled() bool {
	return m.mediaGovernanceEnabled
}

func (m *mockLicenseChecker) IsHITLApprovalEnabled() bool {
	return m.hitlApprovalEnabled
}

func (m *mockLicenseChecker) HITLExpiryHours() int {
	return m.hitlExpiryHours
}

func (m *mockLicenseChecker) IsPolicySimulationEnabled() bool {
	return m.policySimulationEnabled
}

func (m *mockLicenseChecker) MaxSimulationsPerDay() int {
	return m.maxSimulationsPerDay
}

func (m *mockLicenseChecker) MaxImpactReportInputs() int {
	return m.maxImpactReportInputs
}

func (m *mockLicenseChecker) IsEvidenceExportEnabled() bool {
	return m.evidenceExportEnabled
}

func (m *mockLicenseChecker) MaxEvidenceExportRecords() int {
	return m.maxEvidenceExportRecords
}

func (m *mockLicenseChecker) MaxEvidenceWindowDays() int {
	return m.maxEvidenceWindowDays
}

func (m *mockLicenseChecker) MaxEvidenceExportsPerDay() int {
	return m.maxEvidenceExportsPerDay
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
	setupTestKeypair(t)

	tests := []struct {
		name       string
		licenseKey string
		expected   bool
	}{
		{"empty license key", "", false},
		{"invalid license key", "invalid-key", false},
		{"random string", "some-random-garbage", false},
		{"valid enterprise license", genTestLicenseKey("Enterprise"), true},
		{"valid professional license", genTestLicenseKey("Professional"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AXONFLOW_LICENSE_KEY", tt.licenseKey)
			checker := NewEnvLicenseChecker()
			if checker.IsEnterprise() != tt.expected {
				t.Errorf("Expected IsEnterprise()=%v for AXONFLOW_LICENSE_KEY=%q", tt.expected, tt.licenseKey)
			}
		})
	}
}

func TestMockLicenseChecker(t *testing.T) {
	// Test Community mode
	communityChecker := newMockLicenseChecker(license.TierCommunity)
	if communityChecker.IsEnterprise() {
		t.Error("Community checker should return false for IsEnterprise")
	}
	if communityChecker.Tier() != license.TierCommunity {
		t.Errorf("Expected tier %s, got %s", license.TierCommunity, communityChecker.Tier())
	}
	if communityChecker.PolicyLimit() != license.CommunityLimits.TenantPolicies {
		t.Errorf("Expected policy limit %d, got %d", license.CommunityLimits.TenantPolicies, communityChecker.PolicyLimit())
	}
	if communityChecker.OrgPolicyLimit() != 0 {
		t.Errorf("Expected org policy limit 0, got %d", communityChecker.OrgPolicyLimit())
	}
	if communityChecker.CustomPolicyConnectorLimit() != license.CommunityLimits.CustomPolicyConnectors {
		t.Errorf("Expected connector limit %d, got %d", license.CommunityLimits.CustomPolicyConnectors, communityChecker.CustomPolicyConnectorLimit())
	}
	if communityChecker.AuditRetentionDays() != 3 {
		t.Errorf("Expected audit retention 3 days, got %d", communityChecker.AuditRetentionDays())
	}

	// Test Evaluation mode
	evalChecker := newMockLicenseChecker(license.TierEvaluation)
	if evalChecker.IsEnterprise() {
		t.Error("Evaluation checker should return false for IsEnterprise")
	}
	if evalChecker.Tier() != license.TierEvaluation {
		t.Errorf("Expected tier %s, got %s", license.TierEvaluation, evalChecker.Tier())
	}
	if evalChecker.PolicyLimit() != license.EvaluationLimits.TenantPolicies {
		t.Errorf("Expected policy limit %d, got %d", license.EvaluationLimits.TenantPolicies, evalChecker.PolicyLimit())
	}
	if evalChecker.OrgPolicyLimit() != license.EvaluationLimits.OrgPolicies {
		t.Errorf("Expected org policy limit %d, got %d", license.EvaluationLimits.OrgPolicies, evalChecker.OrgPolicyLimit())
	}
	if evalChecker.CustomPolicyConnectorLimit() != license.EvaluationLimits.CustomPolicyConnectors {
		t.Errorf("Expected connector limit %d, got %d", license.EvaluationLimits.CustomPolicyConnectors, evalChecker.CustomPolicyConnectorLimit())
	}
	if evalChecker.AuditRetentionDays() != 14 {
		t.Errorf("Expected audit retention 14 days, got %d", evalChecker.AuditRetentionDays())
	}

	// Test Enterprise mode
	enterpriseChecker := newMockLicenseChecker(license.TierEnterprise)
	if !enterpriseChecker.IsEnterprise() {
		t.Error("Enterprise checker should return true")
	}
	if enterpriseChecker.Tier() != license.TierEnterprise {
		t.Errorf("Expected tier %s, got %s", license.TierEnterprise, enterpriseChecker.Tier())
	}
	if enterpriseChecker.PolicyLimit() != -1 {
		t.Errorf("Expected unlimited policy limit (-1), got %d", enterpriseChecker.PolicyLimit())
	}
	if enterpriseChecker.OrgPolicyLimit() != -1 {
		t.Errorf("Expected unlimited org policy limit (-1), got %d", enterpriseChecker.OrgPolicyLimit())
	}
	if enterpriseChecker.CustomPolicyConnectorLimit() != -1 {
		t.Errorf("Expected unlimited connector limit (-1), got %d", enterpriseChecker.CustomPolicyConnectorLimit())
	}
}

func TestPolicyService_CreatePolicy_RejectSystemTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyServiceWithLicense(repo, nil, newMockLicenseChecker(license.TierEnterprise))

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

func TestPolicyService_CreatePolicy_OrganizationTierRequiresEvaluationOrHigher(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)

	// Test with Community license (should fail)
	communityService := NewPolicyServiceWithLicense(repo, nil, newMockLicenseChecker(license.TierCommunity))

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
	if tierErr.Code != ErrCodeOrgTierEvaluationOrHigher {
		t.Errorf("Expected code %s, got %s", ErrCodeOrgTierEvaluationOrHigher, tierErr.Code)
	}

	// Ensure no database operations were attempted
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unexpected database operations: %v", err)
	}
}

func TestPolicyService_CreatePolicy_EvaluationTierOrgPolicyLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	evalService := NewPolicyServiceWithLicense(repo, nil, newMockLicenseChecker(license.TierEvaluation))

	// Mock count returning at Evaluation tier limit (5 org policies)
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(license.EvaluationLimits.OrgPolicies))

	req := &CreatePolicyRequest{
		Name:        "Org Policy 6",
		Description: "One too many org policies",
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

	_, err = evalService.CreatePolicy(context.Background(), "tenant-1", req, "user-1")
	if err == nil {
		t.Fatal("Expected error when org policy limit reached for Evaluation tier")
	}

	if !IsTierValidationError(err) {
		t.Errorf("Expected TierValidationError, got %T: %v", err, err)
	}

	tierErr := err.(*TierValidationError)
	if tierErr.Code != ErrCodeOrgPolicyLimitExceeded {
		t.Errorf("Expected code %s, got %s", ErrCodeOrgPolicyLimitExceeded, tierErr.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Database expectations not met: %v", err)
	}
}

func TestPolicyService_CreatePolicy_EvaluationTierTenantPolicyLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	evalService := NewPolicyServiceWithLicense(repo, nil, newMockLicenseChecker(license.TierEvaluation))

	// Mock count returning at Evaluation tier limit (50 tenant policies)
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(license.EvaluationLimits.TenantPolicies))

	req := &CreatePolicyRequest{
		Name:        "Policy 51",
		Description: "One too many policies",
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

	_, err = evalService.CreatePolicy(context.Background(), "tenant-1", req, "user-1")
	if err == nil {
		t.Fatal("Expected error when policy limit reached for Evaluation tier")
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

func TestPolicyService_CreatePolicy_TenantTierPolicyLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer db.Close()

	repo := NewPolicyRepository(db)
	communityService := NewPolicyServiceWithLicense(repo, nil, newMockLicenseChecker(license.TierCommunity))

	// Mock count returning at limit
	mock.ExpectQuery("SELECT COUNT").
		WithArgs("tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(license.CommunityLimits.TenantPolicies))

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
	service := NewPolicyServiceWithLicense(repo, nil, newMockLicenseChecker(license.TierEnterprise))

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
	service := NewPolicyServiceWithLicense(repo, nil, newMockLicenseChecker(license.TierEnterprise))

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
