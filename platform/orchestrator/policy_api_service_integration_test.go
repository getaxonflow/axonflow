// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0

package orchestrator

import (
	"context"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Integration tests for PolicyService
// These tests require DATABASE_URL to be set

func TestPolicyService_Integration_NewPolicyService(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)

	if service == nil {
		t.Fatal("Expected non-nil service")
	}
	if service.repo != repo {
		t.Error("Expected service to have the provided repository")
	}
}

func TestPolicyService_Integration_CreatePolicy(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-create-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	req := &CreatePolicyRequest{
		Name:        "Service Create Test",
		Description: "Created via service",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "sensitive"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{"message": "Blocked"}},
		},
		Priority: 100,
		Enabled:  true,
	}

	policy, err := service.CreatePolicy(ctx, tenantID, req, "test-user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	if policy == nil {
		t.Fatal("Expected non-nil policy")
	}
	if policy.ID == "" {
		t.Error("Expected policy ID to be generated")
	}
	if policy.Name != req.Name {
		t.Errorf("Expected name %s, got %s", req.Name, policy.Name)
	}
	if policy.TenantID != tenantID {
		t.Errorf("Expected tenantID %s, got %s", tenantID, policy.TenantID)
	}
}

func TestPolicyService_Integration_CreatePolicy_ValidationError(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)

	ctx := context.Background()

	// Invalid request - name too short
	req := &CreatePolicyRequest{
		Name: "AB", // Too short
		Type: "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
	}

	_, err := service.CreatePolicy(ctx, "tenant", req, "user")
	if err == nil {
		t.Fatal("Expected validation error")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("Expected ValidationError, got %T", err)
	}
	if len(valErr.Errors) == 0 {
		t.Error("Expected at least one validation error")
	}
}

func TestPolicyService_Integration_GetPolicy(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-get-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create first
	req := &CreatePolicyRequest{
		Name:        "Service Get Test",
		Description: "For get test",
		Type:        "user",
		Conditions: []PolicyCondition{
			{Field: "user.role", Operator: "equals", Value: "admin"},
		},
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{}},
		},
		Priority: 50,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Get the policy
	policy, err := service.GetPolicy(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}

	if policy == nil {
		t.Fatal("Expected policy to be found")
	}
	if policy.ID != created.ID {
		t.Errorf("Expected ID %s, got %s", created.ID, policy.ID)
	}
}

func TestPolicyService_Integration_ListPolicies(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-list-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create multiple policies
	for i := 0; i < 5; i++ {
		req := &CreatePolicyRequest{
			Name:        "Service List Test " + string(rune('A'+i)),
			Description: "For list test",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority: i * 10,
			Enabled:  true,
		}
		_, err := service.CreatePolicy(ctx, tenantID, req, "user")
		if err != nil {
			t.Fatalf("CreatePolicy() error = %v", err)
		}
	}

	// List policies
	params := ListPoliciesParams{
		Page:     1,
		PageSize: 10,
	}
	response, err := service.ListPolicies(ctx, tenantID, params)
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}

	if len(response.Policies) != 5 {
		t.Errorf("Expected 5 policies, got %d", len(response.Policies))
	}
	if response.Pagination.TotalItems != 5 {
		t.Errorf("Expected total 5, got %d", response.Pagination.TotalItems)
	}
	if response.Pagination.Page != 1 {
		t.Errorf("Expected page 1, got %d", response.Pagination.Page)
	}
}

func TestPolicyService_Integration_UpdatePolicy(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-update-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create first
	req := &CreatePolicyRequest{
		Name:        "Service Update Test",
		Description: "Original",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "original"},
		},
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{}},
		},
		Priority: 50,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Update
	newName := "Updated Service Policy"
	newDesc := "Updated via service"
	updateReq := &UpdatePolicyRequest{
		Name:        &newName,
		Description: &newDesc,
	}

	updated, err := service.UpdatePolicy(ctx, tenantID, created.ID, updateReq, "updater")
	if err != nil {
		t.Fatalf("UpdatePolicy() error = %v", err)
	}

	if updated == nil {
		t.Fatal("Expected updated policy")
	}
	if updated.Name != newName {
		t.Errorf("Expected name %s, got %s", newName, updated.Name)
	}
}

func TestPolicyService_Integration_UpdatePolicy_ValidationError(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-updateval-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create first
	req := &CreatePolicyRequest{
		Name:        "Service Update Validation Test",
		Description: "Original",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority: 50,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Try invalid update - name too short
	shortName := "AB"
	updateReq := &UpdatePolicyRequest{
		Name: &shortName,
	}

	_, err = service.UpdatePolicy(ctx, tenantID, created.ID, updateReq, "user")
	if err == nil {
		t.Fatal("Expected validation error")
	}

	_, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("Expected ValidationError, got %T", err)
	}
}

func TestPolicyService_Integration_DeletePolicy(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-delete-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create first
	req := &CreatePolicyRequest{
		Name:        "Service Delete Test",
		Description: "To be deleted",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "delete"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority: 100,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Delete
	err = service.DeletePolicy(ctx, tenantID, created.ID, "deleter")
	if err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	// Verify deleted
	policy, err := service.GetPolicy(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if policy != nil {
		t.Error("Expected policy to be deleted")
	}
}

func TestPolicyService_Integration_TestPolicy(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-testpol-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy that blocks queries containing "password"
	req := &CreatePolicyRequest{
		Name:        "Password Block Policy",
		Description: "Blocks password queries",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "password"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{"message": "Password queries are not allowed"}},
		},
		Priority: 100,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Test with matching query
	testReq := &TestPolicyRequest{
		Query:       "show me the password for admin",
		RequestType: "query",
	}

	result, err := service.TestPolicy(ctx, tenantID, created.ID, testReq)
	if err != nil {
		t.Fatalf("TestPolicy() error = %v", err)
	}

	if !result.Matched {
		t.Error("Expected policy to match")
	}
	if !result.Blocked {
		t.Error("Expected request to be blocked")
	}
	if result.EvalTimeMs <= 0 {
		t.Error("Expected positive evaluation time")
	}

	// Test with non-matching query
	testReq2 := &TestPolicyRequest{
		Query:       "show me the weather",
		RequestType: "query",
	}

	result2, err := service.TestPolicy(ctx, tenantID, created.ID, testReq2)
	if err != nil {
		t.Fatalf("TestPolicy() error = %v", err)
	}

	if result2.Matched {
		t.Error("Expected policy not to match")
	}
	if result2.Blocked {
		t.Error("Expected request not to be blocked")
	}
}

func TestPolicyService_Integration_TestPolicy_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)

	ctx := context.Background()

	testReq := &TestPolicyRequest{
		Query: "test",
	}

	_, err := service.TestPolicy(ctx, "tenant", "non-existent-id", testReq)
	if err == nil {
		t.Fatal("Expected error for non-existent policy")
	}
}

func TestPolicyService_Integration_GetPolicyVersions(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-versions-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy
	req := &CreatePolicyRequest{
		Name:        "Service Versions Test",
		Description: "For version testing",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority: 100,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Update it
	newName := "Updated for versions"
	_, err = service.UpdatePolicy(ctx, tenantID, created.ID, &UpdatePolicyRequest{Name: &newName}, "user")
	if err != nil {
		t.Fatalf("UpdatePolicy() error = %v", err)
	}

	// Get versions
	response, err := service.GetPolicyVersions(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("GetPolicyVersions() error = %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}
	if len(response.Versions) < 1 {
		t.Error("Expected at least 1 version")
	}
}

func TestPolicyService_Integration_ExportPolicies(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-export-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create policies
	for i := 0; i < 3; i++ {
		req := &CreatePolicyRequest{
			Name:        "Export Policy " + string(rune('A'+i)),
			Description: "For export",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority: i * 10,
			Enabled:  true,
		}
		_, err := service.CreatePolicy(ctx, tenantID, req, "user")
		if err != nil {
			t.Fatalf("CreatePolicy() error = %v", err)
		}
	}

	// Export
	response, err := service.ExportPolicies(ctx, tenantID)
	if err != nil {
		t.Fatalf("ExportPolicies() error = %v", err)
	}

	if len(response.Policies) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(response.Policies))
	}
	if response.TenantID != tenantID {
		t.Errorf("Expected tenantID %s, got %s", tenantID, response.TenantID)
	}
	if response.ExportedAt.IsZero() {
		t.Error("Expected ExportedAt to be set")
	}
}

func TestPolicyService_Integration_ImportPolicies(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-import-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Import policies
	importReq := &ImportPoliciesRequest{
		Policies: []CreatePolicyRequest{
			{
				Name:        "Imported Policy 1",
				Description: "First",
				Type:        "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "test"},
				},
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{}},
				},
				Priority: 10,
				Enabled:  true,
			},
			{
				Name:        "Imported Policy 2",
				Description: "Second",
				Type:        "user",
				Conditions: []PolicyCondition{
					{Field: "user.role", Operator: "equals", Value: "admin"},
				},
				Actions: []PolicyAction{
					{Type: "log", Config: map[string]interface{}{}},
				},
				Priority: 20,
				Enabled:  true,
			},
		},
		OverwriteMode: "skip",
	}

	result, err := service.ImportPolicies(ctx, tenantID, importReq, "importer")
	if err != nil {
		t.Fatalf("ImportPolicies() error = %v", err)
	}

	if result.Created != 2 {
		t.Errorf("Expected 2 created, got %d", result.Created)
	}
}

func TestPolicyService_Integration_ImportPolicies_ValidationError(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)

	ctx := context.Background()

	// Import with invalid policy
	importReq := &ImportPoliciesRequest{
		Policies: []CreatePolicyRequest{
			{
				Name: "AB", // Too short
				Type: "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "test"},
				},
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{}},
				},
			},
		},
	}

	_, err := service.ImportPolicies(ctx, "tenant", importReq, "user")
	if err == nil {
		t.Fatal("Expected validation error")
	}
}

func TestPolicyService_Integration_TestPolicy_UserConditions(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-usercond-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy that checks user role
	req := &CreatePolicyRequest{
		Name:        "Admin Only Policy",
		Description: "Only allows admin",
		Type:        "user",
		Conditions: []PolicyCondition{
			{Field: "user.role", Operator: "equals", Value: "admin"},
		},
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{"level": "info"}},
		},
		Priority: 100,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Test with admin user
	testReq := &TestPolicyRequest{
		Query: "any query",
		User:  map[string]interface{}{"role": "admin"},
	}

	result, err := service.TestPolicy(ctx, tenantID, created.ID, testReq)
	if err != nil {
		t.Fatalf("TestPolicy() error = %v", err)
	}

	if !result.Matched {
		t.Error("Expected policy to match for admin user")
	}

	// Test with non-admin user
	testReq2 := &TestPolicyRequest{
		Query: "any query",
		User:  map[string]interface{}{"role": "user"},
	}

	result2, err := service.TestPolicy(ctx, tenantID, created.ID, testReq2)
	if err != nil {
		t.Fatalf("TestPolicy() error = %v", err)
	}

	if result2.Matched {
		t.Error("Expected policy not to match for non-admin user")
	}
}

func TestPolicyService_Integration_TestPolicy_ContextConditions(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	service := NewPolicyService(repo, nil)
	tenantID := "test-svc-ctxcond-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy that checks context
	req := &CreatePolicyRequest{
		Name:        "Production Only Policy",
		Description: "Only runs in production",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "context.env", Operator: "equals", Value: "production"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority: 100,
		Enabled:  true,
	}

	created, err := service.CreatePolicy(ctx, tenantID, req, "user")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	// Test with production context
	testReq := &TestPolicyRequest{
		Query:   "any query",
		Context: map[string]interface{}{"env": "production"},
	}

	result, err := service.TestPolicy(ctx, tenantID, created.ID, testReq)
	if err != nil {
		t.Fatalf("TestPolicy() error = %v", err)
	}

	if !result.Matched {
		t.Error("Expected policy to match for production context")
	}

	// Test with staging context
	testReq2 := &TestPolicyRequest{
		Query:   "any query",
		Context: map[string]interface{}{"env": "staging"},
	}

	result2, err := service.TestPolicy(ctx, tenantID, created.ID, testReq2)
	if err != nil {
		t.Fatalf("TestPolicy() error = %v", err)
	}

	if result2.Matched {
		t.Error("Expected policy not to match for staging context")
	}
}

// Skip test for empty DATABASE_URL
func TestPolicyService_SkipsWithoutDB(t *testing.T) {
	originalURL := os.Getenv("DATABASE_URL")
	defer func() {
		if originalURL != "" {
			_ = os.Setenv("DATABASE_URL", originalURL)
		}
	}()

	_ = os.Unsetenv("DATABASE_URL")

	// This should not panic
	t.Run("service tests skip without DATABASE_URL", func(t *testing.T) {
		dbURL := os.Getenv("DATABASE_URL")
		if dbURL == "" {
			t.Skip("Skipping - DATABASE_URL not set (expected)")
		}
	})
}
