// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewStaticPolicyRepository tests repository creation.
func TestNewStaticPolicyRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewStaticPolicyRepository(db)
	assert.NotNil(t, repo)
	assert.Equal(t, db, repo.db)
}

// TestCreate tests policy creation with tier validation.
func TestCreate(t *testing.T) {
	tests := []struct {
		name        string
		policy      *StaticPolicy
		setupMock   func(mock sqlmock.Sqlmock)
		wantErr     error
		errContains string
	}{
		{
			name: "system tier rejected",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "security-sqli",
				Tier:     TierSystem,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// No DB calls expected
			},
			wantErr: ErrSystemTierCreation,
		},
		{
			name: "invalid tier rejected",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "security-sqli",
				Tier:     "invalid",
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// No DB calls expected
			},
			wantErr: ErrInvalidTier,
		},
		{
			name: "invalid category rejected",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "invalid-category",
				Tier:     TierTenant,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// No DB calls expected
			},
			wantErr: ErrInvalidCategory,
		},
		{
			name: "invalid pattern rejected",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "security-sqli",
				Tier:     TierTenant,
				Pattern:  `[invalid`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// No DB calls expected
			},
			errContains: "invalid regex pattern",
		},
		{
			name: "tenant tier success - community under limit",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "security-sqli",
				Tier:     TierTenant,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
				Enabled:  true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Community)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Community"))

				// Count tenant policies
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

				// Insert policy
				mock.ExpectExec(`INSERT INTO static_policies`).
					WillReturnResult(sqlmock.NewResult(1, 1))

				// Record version
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: nil,
		},
		{
			name: "tenant tier limit reached - community",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "security-sqli",
				Tier:     TierTenant,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Community)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Community"))

				// Count tenant policies - at limit
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(30))
			},
			wantErr: ErrTenantPolicyLimitReached,
		},
		{
			name: "tenant tier no limit - enterprise",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "security-sqli",
				Tier:     TierTenant,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
				Enabled:  true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("ENT"))

				// Insert policy (no count check for Enterprise)
				mock.ExpectExec(`INSERT INTO static_policies`).
					WillReturnResult(sqlmock.NewResult(1, 1))

				// Record version
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: nil,
		},
		{
			name: "organization tier requires enterprise",
			policy: &StaticPolicy{
				Name:           "Test Policy",
				Category:       "security-sqli",
				Tier:           TierOrganization,
				Pattern:        `\btest\b`,
				Action:         "block",
				Severity:       "high",
				TenantID:       "tenant-1",
				OrganizationID: strPtr("org-1"),
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Community - should fail)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Community"))
			},
			wantErr: ErrOrgTierRequiresEnterprise,
		},
		{
			name: "organization tier success - enterprise",
			policy: &StaticPolicy{
				Name:           "Org Policy",
				Category:       "security-sqli",
				Tier:           TierOrganization,
				Pattern:        `\btest\b`,
				Action:         "block",
				Severity:       "high",
				TenantID:       "tenant-1",
				OrganizationID: strPtr("org-1"),
				Enabled:        true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("PLUS"))

				// Insert policy
				mock.ExpectExec(`INSERT INTO static_policies`).
					WillReturnResult(sqlmock.NewResult(1, 1))

				// Record version
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: nil,
		},
		{
			name: "organization tier requires org_id",
			policy: &StaticPolicy{
				Name:     "Org Policy",
				Category: "security-sqli",
				Tier:     TierOrganization,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
				// Missing OrganizationID
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("ENT"))
			},
			errContains: "organization_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewStaticPolicyRepository(db)
			err = repo.Create(context.Background(), tt.policy, "test-user")

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else if tt.errContains != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestUpdate tests policy update with tier enforcement.
func TestUpdate(t *testing.T) {
	tests := []struct {
		name        string
		policyID    string
		update      *UpdateStaticPolicyRequest
		setupMock   func(mock sqlmock.Sqlmock)
		wantErr     error
		errContains string
	}{
		{
			name:     "system tier cannot be updated",
			policyID: "policy-1",
			update: &UpdateStaticPolicyRequest{
				Name: strPtr("New Name"),
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID returns system tier policy
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "sys_test", "System Policy", "security-sqli", `\btest\b`, "critical",
						sql.NullString{}, "block", "system", 100, true,
						nil, "global", sql.NullString{},
						nil, nil, 1,
						time.Now(), time.Now(), sql.NullString{}, sql.NullString{}, nil,
					))
			},
			wantErr: ErrSystemPolicyModification,
		},
		{
			name:     "tenant tier can be updated",
			policyID: "policy-1",
			update: &UpdateStaticPolicyRequest{
				Name:        strPtr("Updated Name"),
				Description: strPtr("Updated description"),
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				now := time.Now()
				// GetByID returns tenant tier policy
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						"Test description", "block", "tenant", 50, true,
						nil, "tenant-1", nil,
						nil, nil, 1,
						now, now, "user1", "user1", nil,
					))

				// Update query - returns the updated policy
				mock.ExpectQuery(`UPDATE static_policies SET`).
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"version", "created_at", "updated_at", "created_by", "updated_by",
					}).AddRow(
						"policy-1", "custom_test", "Updated Name", "security-sqli", `\btest\b`, "high",
						"Updated description", "block", "tenant", 50, true,
						nil, "tenant-1", nil,
						2, now, now, "user1", "test-user",
					))

				// Record version
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: nil,
		},
		{
			name:     "invalid pattern rejected",
			policyID: "policy-1",
			update: &UpdateStaticPolicyRequest{
				Pattern: strPtr(`[invalid`),
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID returns tenant tier policy
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						nil, "block", "tenant", 50, true,
						nil, "tenant-1", nil,
						nil, nil, 1,
						time.Now(), time.Now(), nil, nil, nil,
					))
			},
			errContains: "invalid regex pattern",
		},
		{
			name:     "policy not found",
			policyID: "nonexistent",
			update: &UpdateStaticPolicyRequest{
				Name: strPtr("New Name"),
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("nonexistent").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: ErrPolicyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewStaticPolicyRepository(db)
			_, err = repo.Update(context.Background(), tt.policyID, tt.update, "test-user")

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else if tt.errContains != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestDelete tests policy deletion.
func TestDelete(t *testing.T) {
	tests := []struct {
		name      string
		policyID  string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   error
	}{
		{
			name:     "system tier cannot be deleted",
			policyID: "policy-1",
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID returns system tier policy
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "sys_test", "System Policy", "security-sqli", `\btest\b`, "critical",
						nil, "block", "system", 100, true,
						nil, "global", nil,
						nil, nil, 1,
						time.Now(), time.Now(), nil, nil, nil,
					))
			},
			wantErr: ErrSystemPolicyDeletion,
		},
		{
			name:     "tenant tier can be deleted",
			policyID: "policy-1",
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID returns tenant tier policy
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						nil, "block", "tenant", 50, true,
						nil, "tenant-1", nil,
						nil, nil, 1,
						time.Now(), time.Now(), nil, nil, nil,
					))

				// Soft delete
				mock.ExpectExec(`UPDATE static_policies SET deleted_at`).
					WillReturnResult(sqlmock.NewResult(0, 1))

				// Record version
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: nil,
		},
		{
			name:     "policy not found",
			policyID: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("nonexistent").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: ErrPolicyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewStaticPolicyRepository(db)
			err = repo.Delete(context.Background(), tt.policyID, "test-user")

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestGetByID tests getting a policy by ID.
func TestGetByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()

	mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
		WithArgs("policy-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "name", "category", "pattern", "severity",
			"description", "action", "tier", "priority", "enabled",
			"organization_id", "tenant_id", "org_id",
			"tags", "metadata", "version",
			"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
		}).AddRow(
			"policy-1", "custom_test", "Test Policy", "security-sqli", `\btest\b`, "high",
			sql.NullString{Valid: true, String: "Test description"}, "block", "tenant", 50, true,
			nil, "tenant-1", sql.NullString{},
			`["tag1", "tag2"]`, `{"key": "value"}`, 1,
			now, now, sql.NullString{Valid: true, String: "user1"}, sql.NullString{Valid: true, String: "user2"}, nil,
		))

	repo := NewStaticPolicyRepository(db)
	policy, err := repo.GetByID(context.Background(), "policy-1")

	require.NoError(t, err)
	assert.Equal(t, "policy-1", policy.ID)
	assert.Equal(t, "custom_test", policy.PolicyID)
	assert.Equal(t, "Test Policy", policy.Name)
	assert.Equal(t, "Test description", policy.Description)
	assert.Equal(t, PolicyTier("tenant"), policy.Tier)
	assert.Equal(t, []string{"tag1", "tag2"}, policy.Tags)
	assert.Equal(t, "user1", policy.CreatedBy)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestList tests listing policies with filters.
func TestList(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	tier := TierTenant

	// Count query
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// List query
	mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "name", "category", "pattern", "severity",
			"description", "action", "tier", "priority", "enabled",
			"organization_id", "tenant_id", "org_id",
			"tags", "metadata", "version",
			"created_at", "updated_at", "created_by", "updated_by",
		}).AddRow(
			"policy-1", "custom_1", "Policy 1", "security-sqli", `\btest1\b`, "high",
			nil, "block", "tenant", 50, true,
			nil, "tenant-1", nil,
			nil, nil, 1,
			now, now, nil, nil,
		).AddRow(
			"policy-2", "custom_2", "Policy 2", "security-sqli", `\btest2\b`, "medium",
			nil, "warn", "tenant", 40, true,
			nil, "tenant-1", nil,
			nil, nil, 1,
			now, now, nil, nil,
		))

	repo := NewStaticPolicyRepository(db)
	result, err := repo.List(context.Background(), "tenant-1", &ListStaticPoliciesParams{
		Tier:     &tier,
		Page:     1,
		PageSize: 20,
	})

	require.NoError(t, err)
	assert.Len(t, result.Policies, 2)
	assert.Equal(t, 2, result.Pagination.TotalItems)
	assert.Equal(t, 1, result.Pagination.TotalPages)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetEffective tests getting effective policies with tier hierarchy.
func TestGetEffective(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	orgID := "org-1"

	mock.ExpectQuery(`SELECT .* FROM static_policies sp LEFT JOIN policy_overrides po ON`).
		WithArgs("tenant-1", "org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "name", "category", "pattern", "severity",
			"description", "action", "tier", "priority", "enabled",
			"organization_id", "tenant_id", "org_id",
			"tags", "metadata", "version",
			"created_at", "updated_at", "created_by", "updated_by",
			"override_id", "action_override", "enabled_override",
			"expires_at", "override_reason",
		}).AddRow(
			"sys-1", "sys_sqli_1", "System SQLi Policy", "security-sqli", `\bDROP\b`, "critical",
			nil, "block", "system", 100, true,
			nil, "global", nil,
			nil, nil, 1,
			now, now, nil, nil,
			"override-1", "warn", nil, // Has override
			nil, "Testing phase",
		).AddRow(
			"org-1", "org_policy_1", "Org Policy", "pii-global", `\bSSN\b`, "high",
			nil, "block", "organization", 80, true,
			"org-1", "tenant-1", nil,
			nil, nil, 1,
			now, now, nil, nil,
			nil, nil, nil, // No override
			nil, nil,
		))

	repo := NewStaticPolicyRepository(db)
	policies, err := repo.GetEffective(context.Background(), "tenant-1", &orgID)

	require.NoError(t, err)
	assert.Len(t, policies, 2)

	// First policy has override
	assert.True(t, policies[0].HasOverride)
	assert.NotNil(t, policies[0].OverrideAction)
	assert.Equal(t, OverrideAction("warn"), *policies[0].OverrideAction)
	assert.Equal(t, "Testing phase", policies[0].OverrideReason)

	// Second policy has no override
	assert.False(t, policies[1].HasOverride)
	assert.Nil(t, policies[1].OverrideAction)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetVersions tests version history retrieval with license-based limits.
func TestGetVersions(t *testing.T) {
	tests := []struct {
		name          string
		licenseTier   string
		expectedLimit int
	}{
		{
			name:          "community limited to 5",
			licenseTier:   "Community",
			expectedLimit: 5,
		},
		{
			name:          "enterprise no limit",
			licenseTier:   "ENT",
			expectedLimit: 1000,
		},
		{
			name:          "enterprise plus no limit",
			licenseTier:   "PLUS",
			expectedLimit: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			require.NoError(t, err)
			defer db.Close()

			// Check license tier
			mock.ExpectQuery(`SELECT license_tier FROM clients`).
				WithArgs("tenant-1").
				WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow(tt.licenseTier))

			// Get versions - use a simpler regex pattern
			mock.ExpectQuery(`SELECT id, policy_id, version, snapshot, change_type, change_summary, changed_by, changed_at`).
				WithArgs("policy-1", tt.expectedLimit).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "policy_id", "version", "snapshot", "change_type",
					"change_summary", "changed_by", "changed_at",
				}).AddRow(
					"v1", "policy-1", 1, []byte(`{"name": "Test"}`), "create",
					"Created", "user1", time.Now(),
				))

			repo := NewStaticPolicyRepository(db)
			versions, err := repo.GetVersions(context.Background(), "policy-1", "tenant-1")

			require.NoError(t, err)
			require.Len(t, versions, 1)
			assert.Equal(t, "v1", versions[0].ID)
			assert.Equal(t, 1, versions[0].Version)

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestToggleEnabled tests enabling/disabling policies.
func TestToggleEnabled(t *testing.T) {
	tests := []struct {
		name      string
		policyID  string
		enabled   bool
		tier      string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   error
	}{
		{
			name:     "system policy cannot be disabled",
			policyID: "policy-1",
			enabled:  false,
			tier:     "system",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "sys_test", "System Policy", "security-sqli", `\btest\b`, "critical",
						nil, "block", "system", 100, true,
						nil, "global", nil,
						nil, nil, 1,
						time.Now(), time.Now(), nil, nil, nil,
					))
			},
			wantErr: ErrSystemPolicyModification,
		},
		{
			name:     "tenant policy can be disabled",
			policyID: "policy-1",
			enabled:  false,
			tier:     "tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						nil, "block", "tenant", 50, true,
						nil, "tenant-1", nil,
						nil, nil, 1,
						time.Now(), time.Now(), nil, nil, nil,
					))

				mock.ExpectExec(`UPDATE static_policies SET enabled`).
					WillReturnResult(sqlmock.NewResult(0, 1))

				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewStaticPolicyRepository(db)
			err = repo.ToggleEnabled(context.Background(), tt.policyID, tt.enabled, "test-user")

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestVersionHistoryRecording tests that version history is recorded correctly.
func TestVersionHistoryRecording(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	policy := &StaticPolicy{
		ID:       "policy-1",
		PolicyID: "custom_test",
		Name:     "Test Policy",
		Category: "security-sqli",
		Pattern:  `\btest\b`,
		Action:   "block",
		Tier:     TierTenant,
		Version:  1,
	}

	// Record version
	mock.ExpectExec(`INSERT INTO static_policy_versions`).
		WillReturnResult(sqlmock.NewResult(1, 1))

	repo := NewStaticPolicyRepository(db)
	err = repo.recordVersion(context.Background(), policy, "create", "Policy created", "test-user")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCountTenantPolicies tests counting tenant policies.
func TestCountTenantPolicies(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
		WithArgs("tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(15))

	repo := NewStaticPolicyRepository(db)
	count, err := repo.countTenantPolicies(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, 15, count)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestIsEnterpriseLicense tests license tier detection.
func TestIsEnterpriseLicense(t *testing.T) {
	tests := []struct {
		name       string
		tier       string
		isNotFound bool
		expected   bool
	}{
		{"community", "Community", false, false},
		{"professional", "PRO", false, false},
		{"enterprise", "ENT", false, true},
		{"enterprise plus", "PLUS", false, true},
		{"not found", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			if tt.isNotFound {
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnError(sql.ErrNoRows)
			} else {
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow(tt.tier))
			}

			repo := NewStaticPolicyRepository(db)
			isEnterprise, err := repo.isEnterpriseLicense(context.Background(), "tenant-1")

			require.NoError(t, err)
			assert.Equal(t, tt.expected, isEnterprise)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// Benchmark tests
func BenchmarkCreate(b *testing.B) {
	db, mock, err := sqlmock.New()
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	policy := &StaticPolicy{
		Name:     "Benchmark Policy",
		Category: "security-sqli",
		Tier:     TierTenant,
		Pattern:  `\btest\b`,
		Action:   "block",
		Severity: "high",
		TenantID: "tenant-1",
		Enabled:  true,
	}

	for i := 0; i < b.N; i++ {
		mock.ExpectQuery(`SELECT license_tier FROM clients`).
			WithArgs("tenant-1").
			WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("ENT"))
		mock.ExpectExec(`INSERT INTO static_policies`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`INSERT INTO static_policy_versions`).
			WillReturnResult(sqlmock.NewResult(1, 1))

		repo := NewStaticPolicyRepository(db)
		_ = repo.Create(context.Background(), policy, "test-user")
	}
}

// Helper functions
func strPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

// TestPatternValidation tests pattern validation functions.
func TestPatternValidation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
		errType error
	}{
		{"valid simple pattern", `\btest\b`, false, nil},
		{"valid complex pattern", `(?i)select\s+.*\s+from`, false, nil},
		{"empty pattern", "", true, ErrPatternEmpty},
		{"whitespace pattern", "   ", true, ErrPatternEmpty},
		{"too long pattern", string(make([]byte, 1001)), true, ErrPatternTooLong},
		{"invalid syntax", `[invalid`, true, nil},
		{"valid with groups", `(\d{3})-(\d{2})-(\d{4})`, false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePatternWithLimits(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Note: TestValidatePatternDetailed and TestTestPattern are defined in pattern_validator_test.go

// TestPolicySnapshot tests that policy snapshots are created correctly.
func TestPolicySnapshot(t *testing.T) {
	policy := &StaticPolicy{
		ID:          "policy-1",
		PolicyID:    "custom_test",
		Name:        "Test Policy",
		Category:    "security-sqli",
		Tier:        TierTenant,
		Pattern:     `\btest\b`,
		Action:      "block",
		Severity:    "high",
		Priority:    50,
		Enabled:     true,
		TenantID:    "tenant-1",
		Version:     1,
		Tags:        []string{"tag1", "tag2"},
		Description: "Test description",
	}

	// Test that policy can be marshaled to JSON
	data, err := json.Marshal(policy)
	require.NoError(t, err)

	// Unmarshal and verify
	var unmarshaled StaticPolicy
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, policy.ID, unmarshaled.ID)
	assert.Equal(t, policy.Name, unmarshaled.Name)
	assert.Equal(t, policy.Tier, unmarshaled.Tier)
	assert.Equal(t, policy.Tags, unmarshaled.Tags)
}
