// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0

package orchestrator

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Integration tests for PolicyRepository
// These tests require DATABASE_URL to be set

func getTestDB(t *testing.T) *sql.DB {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test - DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
}

func cleanupTestPolicies(t *testing.T, db *sql.DB, tenantID string) {
	_, err := db.Exec("DELETE FROM policy_versions WHERE policy_id IN (SELECT policy_id FROM dynamic_policies WHERE tenant_id = $1)", tenantID)
	if err != nil {
		t.Logf("Warning: failed to cleanup policy_versions: %v", err)
	}
	_, err = db.Exec("DELETE FROM dynamic_policies WHERE tenant_id = $1", tenantID)
	if err != nil {
		t.Logf("Warning: failed to cleanup dynamic_policies: %v", err)
	}
}

func TestPolicyRepository_Integration_NewPolicyRepository(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to have the provided database connection")
	}
}

func TestPolicyRepository_Integration_Create(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-create-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	policy := &PolicyResource{
		Name:        "Test Create Policy",
		Description: "A test policy for create operation",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "sensitive"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{"message": "Blocked"}},
		},
		Priority:  100,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}

	err := repo.Create(ctx, policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if policy.ID == "" {
		t.Error("Expected policy ID to be generated")
	}
	if policy.Version != 1 {
		t.Errorf("Expected version 1, got %d", policy.Version)
	}
	if policy.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if policy.UpdatedAt.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}
}

func TestPolicyRepository_Integration_GetByID(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-getbyid-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy first
	policy := &PolicyResource{
		Name:        "Test GetByID Policy",
		Description: "A test policy for GetByID operation",
		Type:        "user",
		Conditions: []PolicyCondition{
			{Field: "user.role", Operator: "equals", Value: "admin"},
		},
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{"level": "info"}},
		},
		Priority:  50,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}

	err := repo.Create(ctx, policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Retrieve the policy
	retrieved, err := repo.GetByID(ctx, tenantID, policy.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected policy to be found")
	}
	if retrieved.Name != policy.Name {
		t.Errorf("Expected name %s, got %s", policy.Name, retrieved.Name)
	}
	if retrieved.Type != policy.Type {
		t.Errorf("Expected type %s, got %s", policy.Type, retrieved.Type)
	}
	if len(retrieved.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(retrieved.Conditions))
	}
}

func TestPolicyRepository_Integration_GetByID_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	ctx := context.Background()

	// Try to get a non-existent policy
	retrieved, err := repo.GetByID(ctx, "non-existent-tenant", "non-existent-policy-id")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil policy for non-existent ID")
	}
}

func TestPolicyRepository_Integration_List(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-list-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create multiple policies
	for i := 0; i < 5; i++ {
		policy := &PolicyResource{
			Name:        "Test List Policy " + string(rune('A'+i)),
			Description: "A test policy for list operation",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority:  i * 10,
			Enabled:   i%2 == 0, // Alternate enabled/disabled
			TenantID:  tenantID,
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		}
		if err := repo.Create(ctx, policy); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// List all policies
	params := ListPoliciesParams{
		Page:     1,
		PageSize: 10,
	}
	policies, total, err := repo.List(ctx, tenantID, params)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 5 {
		t.Errorf("Expected total 5, got %d", total)
	}
	if len(policies) != 5 {
		t.Errorf("Expected 5 policies, got %d", len(policies))
	}
}

func TestPolicyRepository_Integration_List_WithFilters(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-listfilter-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create policies with different types
	types := []string{"content", "user", "risk"}
	for i, ptype := range types {
		policy := &PolicyResource{
			Name:        "Test Filter Policy " + ptype,
			Description: "A test policy for filter operation",
			Type:        ptype,
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority:  i * 10,
			Enabled:   true,
			TenantID:  tenantID,
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		}
		if err := repo.Create(ctx, policy); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Filter by type
	params := ListPoliciesParams{
		Type:     "content",
		Page:     1,
		PageSize: 10,
	}
	policies, total, err := repo.List(ctx, tenantID, params)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 1 {
		t.Errorf("Expected total 1 for content type, got %d", total)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
	if policies[0].Type != "content" {
		t.Errorf("Expected type content, got %s", policies[0].Type)
	}
}

func TestPolicyRepository_Integration_List_WithEnabledFilter(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-enabled-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create enabled and disabled policies
	for i := 0; i < 4; i++ {
		policy := &PolicyResource{
			Name:        "Test Enabled Policy " + string(rune('A'+i)),
			Description: "A test policy",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority:  i * 10,
			Enabled:   i < 2, // First 2 enabled, last 2 disabled
			TenantID:  tenantID,
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		}
		if err := repo.Create(ctx, policy); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Filter by enabled=true
	enabled := true
	params := ListPoliciesParams{
		Enabled:  &enabled,
		Page:     1,
		PageSize: 10,
	}
	policies, total, err := repo.List(ctx, tenantID, params)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 2 {
		t.Errorf("Expected total 2 enabled policies, got %d", total)
	}
	for _, p := range policies {
		if !p.Enabled {
			t.Error("Expected all policies to be enabled")
		}
	}
}

func TestPolicyRepository_Integration_List_WithSearch(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-search-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create policies with different names
	names := []string{"Security Policy", "Access Control", "Data Protection"}
	for i, name := range names {
		policy := &PolicyResource{
			Name:        name,
			Description: "Test description",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority:  i * 10,
			Enabled:   true,
			TenantID:  tenantID,
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		}
		if err := repo.Create(ctx, policy); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Search for "Security"
	params := ListPoliciesParams{
		Search:   "Security",
		Page:     1,
		PageSize: 10,
	}
	policies, total, err := repo.List(ctx, tenantID, params)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 1 {
		t.Errorf("Expected total 1 for search 'Security', got %d", total)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}
}

func TestPolicyRepository_Integration_List_Pagination(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-pagination-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create 10 policies
	for i := 0; i < 10; i++ {
		policy := &PolicyResource{
			Name:        fmt.Sprintf("Pagination Test %d", i),
			Description: "Test policy",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority:  i,
			Enabled:   true,
			TenantID:  tenantID,
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		}
		if err := repo.Create(ctx, policy); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Get first page (5 items)
	params := ListPoliciesParams{
		Page:     1,
		PageSize: 5,
	}
	policies, total, err := repo.List(ctx, tenantID, params)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if total != 10 {
		t.Errorf("Expected total 10, got %d", total)
	}
	if len(policies) != 5 {
		t.Errorf("Expected 5 policies on page 1, got %d", len(policies))
	}

	// Get second page
	params.Page = 2
	policies2, _, err := repo.List(ctx, tenantID, params)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(policies2) != 5 {
		t.Errorf("Expected 5 policies on page 2, got %d", len(policies2))
	}
}

func TestPolicyRepository_Integration_Update(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-update-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy first
	policy := &PolicyResource{
		Name:        "Test Update Policy",
		Description: "Original description",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "original"},
		},
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{}},
		},
		Priority:  50,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}

	err := repo.Create(ctx, policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update the policy
	newName := "Updated Policy Name"
	newDesc := "Updated description"
	newPriority := 200
	updateReq := &UpdatePolicyRequest{
		Name:        &newName,
		Description: &newDesc,
		Priority:    &newPriority,
	}

	updated, err := repo.Update(ctx, tenantID, policy.ID, updateReq, "updater-user")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if updated == nil {
		t.Fatal("Expected updated policy")
	}
	if updated.Name != newName {
		t.Errorf("Expected name %s, got %s", newName, updated.Name)
	}
	if updated.Description != newDesc {
		t.Errorf("Expected description %s, got %s", newDesc, updated.Description)
	}
	if updated.Priority != newPriority {
		t.Errorf("Expected priority %d, got %d", newPriority, updated.Priority)
	}
	if updated.Version != 2 {
		t.Errorf("Expected version 2, got %d", updated.Version)
	}
}

func TestPolicyRepository_Integration_Update_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	ctx := context.Background()

	newName := "Updated Name"
	updateReq := &UpdatePolicyRequest{
		Name: &newName,
	}

	updated, err := repo.Update(ctx, "non-existent-tenant", "non-existent-policy", updateReq, "user")
	if err != nil {
		t.Fatalf("Update() unexpected error = %v", err)
	}
	if updated != nil {
		t.Error("Expected nil for non-existent policy")
	}
}

func TestPolicyRepository_Integration_Delete(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-delete-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy first
	policy := &PolicyResource{
		Name:        "Test Delete Policy",
		Description: "To be deleted",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "delete"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority:  100,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}

	err := repo.Create(ctx, policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete the policy
	err = repo.Delete(ctx, tenantID, policy.ID, "deleter-user")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's deleted
	retrieved, err := repo.GetByID(ctx, tenantID, policy.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected policy to be deleted")
	}
}

func TestPolicyRepository_Integration_GetVersions(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-versions-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy
	policy := &PolicyResource{
		Name:        "Test Versions Policy",
		Description: "For version testing",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority:  100,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}

	err := repo.Create(ctx, policy)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update it a couple times
	newName := "Updated Name v2"
	_, err = repo.Update(ctx, tenantID, policy.ID, &UpdatePolicyRequest{Name: &newName}, "user")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	newName = "Updated Name v3"
	_, err = repo.Update(ctx, tenantID, policy.ID, &UpdatePolicyRequest{Name: &newName}, "user")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Get versions
	versions, err := repo.GetVersions(ctx, tenantID, policy.ID)
	if err != nil {
		t.Fatalf("GetVersions() error = %v", err)
	}

	if len(versions) < 1 {
		t.Errorf("Expected at least 1 version entry, got %d", len(versions))
	}

	// Versions should be in descending order
	for i := 1; i < len(versions); i++ {
		if versions[i].Version > versions[i-1].Version {
			t.Error("Versions should be in descending order")
		}
	}
}

func TestPolicyRepository_Integration_ExportAll(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-export-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create some policies
	for i := 0; i < 3; i++ {
		policy := &PolicyResource{
			Name:        "Export Test " + string(rune('A'+i)),
			Description: "For export",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority:  i * 10,
			Enabled:   true,
			TenantID:  tenantID,
			CreatedBy: "test-user",
			UpdatedBy: "test-user",
		}
		if err := repo.Create(ctx, policy); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// Export all
	policies, err := repo.ExportAll(ctx, tenantID)
	if err != nil {
		t.Fatalf("ExportAll() error = %v", err)
	}

	if len(policies) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(policies))
	}
}

func TestPolicyRepository_Integration_ImportBulk(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-import-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Import policies
	policies := []CreatePolicyRequest{
		{
			Name:        "Import Policy 1",
			Description: "First import",
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
			Name:        "Import Policy 2",
			Description: "Second import",
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
	}

	result, err := repo.ImportBulk(ctx, tenantID, policies, "skip", "import-user")
	if err != nil {
		t.Fatalf("ImportBulk() error = %v", err)
	}

	if result.Created != 2 {
		t.Errorf("Expected 2 created, got %d", result.Created)
	}
	if result.Skipped != 0 {
		t.Errorf("Expected 0 skipped, got %d", result.Skipped)
	}
	if result.Updated != 0 {
		t.Errorf("Expected 0 updated, got %d", result.Updated)
	}
}

func TestPolicyRepository_Integration_ImportBulk_SkipExisting(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-importskip-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create an existing policy
	policy := &PolicyResource{
		Name:        "Existing Policy",
		Description: "Already exists",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority:  10,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}
	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Import with same name (should skip)
	policies := []CreatePolicyRequest{
		{
			Name:        "Existing Policy",
			Description: "New description",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "new"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority: 20,
			Enabled:  true,
		},
	}

	result, err := repo.ImportBulk(ctx, tenantID, policies, "skip", "import-user")
	if err != nil {
		t.Fatalf("ImportBulk() error = %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("Expected 1 skipped, got %d", result.Skipped)
	}
	if result.Created != 0 {
		t.Errorf("Expected 0 created, got %d", result.Created)
	}
}

func TestPolicyRepository_Integration_ImportBulk_OverwriteExisting(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-importoverwrite-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create an existing policy
	policy := &PolicyResource{
		Name:        "Overwrite Policy",
		Description: "Original description",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "original"},
		},
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{}},
		},
		Priority:  10,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}
	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Import with same name (should overwrite)
	policies := []CreatePolicyRequest{
		{
			Name:        "Overwrite Policy",
			Description: "Updated description",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "updated"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority: 99,
			Enabled:  false,
		},
	}

	result, err := repo.ImportBulk(ctx, tenantID, policies, "overwrite", "import-user")
	if err != nil {
		t.Fatalf("ImportBulk() error = %v", err)
	}

	if result.Updated != 1 {
		t.Errorf("Expected 1 updated, got %d", result.Updated)
	}

	// Verify the policy was updated
	retrieved, err := repo.GetByID(ctx, tenantID, policy.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if retrieved.Description != "Updated description" {
		t.Errorf("Expected updated description, got %s", retrieved.Description)
	}
	if retrieved.Priority != 99 {
		t.Errorf("Expected priority 99, got %d", retrieved.Priority)
	}
}

func TestPolicyRepository_Integration_ImportBulk_ErrorMode(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-importerror-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create an existing policy
	policy := &PolicyResource{
		Name:        "Error Mode Policy",
		Description: "Already exists",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority:  10,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}
	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Import with same name (should error)
	policies := []CreatePolicyRequest{
		{
			Name:        "Error Mode Policy",
			Description: "Duplicate",
			Type:        "content",
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "test"},
			},
			Actions: []PolicyAction{
				{Type: "block", Config: map[string]interface{}{}},
			},
			Priority: 20,
			Enabled:  true,
		},
	}

	result, err := repo.ImportBulk(ctx, tenantID, policies, "error", "import-user")
	if err != nil {
		t.Fatalf("ImportBulk() unexpected error = %v", err)
	}

	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(result.Errors))
	}
}

func TestPolicyRepository_Integration_FindByName(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPolicyRepository(db)
	tenantID := "test-tenant-findname-" + time.Now().Format("20060102150405")
	defer cleanupTestPolicies(t, db, tenantID)

	ctx := context.Background()

	// Create a policy
	policy := &PolicyResource{
		Name:        "Find By Name Policy",
		Description: "Test",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{}},
		},
		Priority:  100,
		Enabled:   true,
		TenantID:  tenantID,
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
	}
	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Find by name
	found, err := repo.findByName(ctx, tenantID, "Find By Name Policy")
	if err != nil {
		t.Fatalf("findByName() error = %v", err)
	}
	if found == nil {
		t.Fatal("Expected policy to be found")
	}
	if found.Name != policy.Name {
		t.Errorf("Expected name %s, got %s", policy.Name, found.Name)
	}

	// Find non-existent
	notFound, err := repo.findByName(ctx, tenantID, "Non-Existent Policy")
	if err != nil {
		t.Fatalf("findByName() error = %v", err)
	}
	if notFound != nil {
		t.Error("Expected nil for non-existent policy")
	}
}
