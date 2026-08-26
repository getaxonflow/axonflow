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

	sharedpolicy "axonflow/platform/shared/policy"
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
				OrgID:    "tenant-1",
				Enabled:  true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Community)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Community"))

				// Count tenant policies — org-scoped (#3048).
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("tenant-1", "tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: Create wraps the INSERT in
				// WithOrgScope so app.current_org_id is pinned before the
				// WITH CHECK predicate fires under app_role.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policies`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: recordVersion also wraps its INSERT
				// in WithOrgScope (mig 110 added FORCE RLS to
				// static_policy_versions keyed on app.current_org_id).
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
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
				// #3490: countTenantPolicies takes the org explicitly and
				// refuses an empty one, so this case must carry an OrgID to
				// keep testing what it is named for -- the tenant-policy
				// LIMIT. Without it the Create fails on the org guard instead
				// and never reaches the limit check, which would silently turn
				// a limit assertion into a guard assertion.
				OrgID: "tenant-1",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Community)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Community"))

				// Count tenant policies - at limit — org-scoped (#3048).
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("tenant-1", "tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(30))
				mock.ExpectCommit()
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
				OrgID:    "tenant-1",
				Enabled:  true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Enterprise"))

				// v9 Phase 8 #2384 PR-C1: Insert wrapped in WithOrgScope.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policies`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: recordVersion wrap.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			wantErr: nil,
		},
		{
			name: "organization tier requires enterprise",
			policy: &StaticPolicy{
				Name:     "Test Policy",
				Category: "security-sqli",
				Tier:     TierOrganization,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
				OrgID:    "org-1",
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
				Name:     "Org Policy",
				Category: "security-sqli",
				Tier:     TierOrganization,
				Pattern:  `\btest\b`,
				Action:   "block",
				Severity: "high",
				TenantID: "tenant-1",
				OrgID:    "tenant-1",
				Enabled:  true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Plus"))

				// v9 Phase 8 #2384 PR-C1: Insert wrapped in WithOrgScope.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policies`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: recordVersion wrap.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
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
				// #3334: OrgID deliberately unset. The guard used to read the
				// retired organization_id column; it reads org_id now, which
				// is the key that actually decides isolation and selection -
				// so an org-tier policy without one is an unselectable row.
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Enterprise"))
			},
			errContains: "org_id is required",
		},
		{
			// Issue #1081: Test that require_approval action (HITL) properly sets phase and action columns
			name: "require_approval action sets correct phase columns",
			policy: &StaticPolicy{
				Name:        "HITL Credit Scoring",
				Category:    "sensitive-data",
				Tier:        TierTenant,
				Pattern:     `(?i)credit\s*scor`,
				Action:      "require_approval",
				Severity:    "critical",
				TenantID:    "tenant-1",
				OrgID:       "tenant-1",
				Description: "Requires human approval for credit scoring decisions",
				Enabled:     true,
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Enterprise for HITL)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Enterprise"))

				// v9 Phase 8 #2384 PR-C1: Insert wrapped in WithOrgScope.
				// Insert verifies phase and action columns:
				// For require_approval: phase="request", action_request="require_approval", action_response=NULL
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policies`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: recordVersion wrap.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
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
						"tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "sys_test", "System Policy", "security-sqli", `\btest\b`, "critical",
						sql.NullString{}, "block", "system", 100, true,
						"global", "global",
						sql.NullString{}, nil, 1,
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
				// GetByID returns tenant tier policy (with org_id populated so
				// the wrapped UPDATE has a non-empty scope key).
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						"Test description", "block", "tenant", 50, true,
						"tenant-1", "tenant-1",
						nil, nil, 1,
						now, now, "user1", "user1", nil,
					))

				// v9 Phase 8 #2384 PR-C1: Update wraps the UPDATE...RETURNING
				// in WithOrgScope using the fetched policy.OrgID. Begin →
				// SET LOCAL → UPDATE → Commit.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectQuery(`UPDATE static_policies SET`).
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"tenant_id", "org_id",
						"version", "created_at", "updated_at", "created_by", "updated_by",
					}).AddRow(
						"policy-1", "custom_test", "Updated Name", "security-sqli", `\btest\b`, "high",
						"Updated description", "block", "tenant", 50, true,
						"tenant-1", "tenant-1",
						2, now, now, "user1", "test-user",
					))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: recordVersion wraps its INSERT in
				// WithOrgScope using the updated policy's OrgID (tenant-1).
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
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
						"tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						nil, "block", "tenant", 50, true,
						"tenant-1", nil,
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
						"tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "sys_test", "System Policy", "security-sqli", `\btest\b`, "critical",
						nil, "block", "system", 100, true,
						"global", nil,
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
				// GetByID returns tenant tier policy with org_id populated.
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						nil, "block", "tenant", 50, true,
						"tenant-1", "tenant-1",
						nil, nil, 1,
						time.Now(), time.Now(), nil, nil, nil,
					))

				// v9 Phase 8 #2384 PR-C1: Soft-delete UPDATE wrapped in
				// WithOrgScope using the fetched policy.OrgID.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`UPDATE static_policies SET deleted_at`).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: recordVersion wraps its INSERT in
				// WithOrgScope using the fetched policy.OrgID (tenant-1).
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
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
			"tenant_id", "org_id",
			"tags", "metadata", "version",
			"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
		}).AddRow(
			"policy-1", "custom_test", "Test Policy", "security-sqli", `\btest\b`, "high",
			sql.NullString{Valid: true, String: "Test description"}, "block", "tenant", 50, true,
			"tenant-1", sql.NullString{},
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

	listCols := []string{
		"id", "policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tier", "priority", "enabled",
		"tenant_id", "org_id",
		"tags", "metadata", "version",
		"created_at", "updated_at", "created_by", "updated_by",
	}

	// #3048: List runs two DISJOINT scoped passes — the tenant scope
	// (tier <> 'system' AND tenant_id = $N) then the 'global' scope
	// (tier = 'system') — merged + paginated in memory. No COUNT query.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("tenant-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
		WillReturnRows(sqlmock.NewRows(listCols).AddRow(
			"policy-1", "custom_1", "Policy 1", "security-sqli", `\btest1\b`, "high",
			nil, "block", "tenant", 50, true,
			"tenant-1", nil,
			nil, nil, 1,
			now, now, nil, nil,
		).AddRow(
			"policy-2", "custom_2", "Policy 2", "security-sqli", `\btest2\b`, "medium",
			nil, "warn", "tenant", 40, true,
			"tenant-1", nil,
			nil, nil, 1,
			now, now, nil, nil,
		))
	mock.ExpectCommit()
	// Global pass: no system rows match the tier filter in this fixture.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(GlobalOrgSentinel).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
		WillReturnRows(sqlmock.NewRows(listCols))
	mock.ExpectCommit()

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

	policyCols := []string{
		"id", "policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tier", "priority", "enabled",
		"tenant_id", "org_id", "segment_id",
		"tags", "metadata", "version",
		"created_at", "updated_at", "created_by", "updated_by",
	}

	// #3048: GetEffective runs pass A (caller org scope: tenant/org-tier
	// rows + the live static overrides), then pass B ('global' scope:
	// system-tier rows). Overrides are applied in Go from the pass-A map.
	// #3051 (P3): both passes also carry a trailing segment_id predicate
	// arg (pq.Array(segArg)); this fixture passes nil segmentIDs, so both
	// rows below are segment_id NULL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies sp`).
		WithArgs("org-1", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(policyCols).AddRow(
			"org-pol-1", "org_policy_1", "Org Policy", "pii-global", `\bSSN\b`, "high",
			nil, "block", "organization", 80, true,
			"tenant-1", "org-1", nil,
			nil, nil, 1,
			now, now, nil, nil,
		))
	mock.ExpectQuery(`SELECT po\.id, po\.policy_id`).
		WithArgs("org-1", "tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "action_override", "enabled_override", "expires_at", "override_reason", "tenant_id",
		}).AddRow(
			"override-1", "sys-1", "warn", nil, nil, "Testing phase", "tenant-1",
		))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(GlobalOrgSentinel).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies sp`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(policyCols).AddRow(
			"sys-1", "sys_sqli_1", "System SQLi Policy", "security-sqli", `\bDROP\b`, "critical",
			nil, "block", "system", 100, true,
			"global", "global", nil,
			nil, nil, 1,
			now, now, nil, nil,
		))
	mock.ExpectCommit()

	repo := NewStaticPolicyRepository(db)
	policies, err := repo.GetEffective(context.Background(), "tenant-1", &orgID, nil)

	require.NoError(t, err)
	assert.Len(t, policies, 2)

	// System policy sorts first (tier rank); it carries the override.
	assert.True(t, policies[0].HasOverride)
	assert.NotNil(t, policies[0].OverrideAction)
	assert.Equal(t, OverrideAction("warn"), *policies[0].OverrideAction)
	assert.Equal(t, "Testing phase", policies[0].OverrideReason)

	// Organization-tier policy has no override.
	assert.False(t, policies[1].HasOverride)
	assert.Nil(t, policies[1].OverrideAction)

	// Neither policy is segment-scoped (segment_id NULL on both rows).
	assert.Nil(t, policies[0].SegmentID)
	assert.Nil(t, policies[1].SegmentID)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetEffective_SegmentScoped tests that a segment-scoped policy row
// (segment_id IS NOT NULL) is decoded with SegmentID populated and NEVER
// carries an applied override (ADR-060 #2989 P3, Decision 1 — segment
// policies must never enter the override-downgrade path), even if the
// pass-A override map has a live override keyed to its policy ID (the
// map-lookup gate in GetEffective is the defense-in-depth for this, since
// #3048 removed the LEFT JOIN whose predicate used to exclude segment rows
// upstream).
func TestGetEffective_SegmentScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	orgID := "org-1"

	policyCols := []string{
		"id", "policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tier", "priority", "enabled",
		"tenant_id", "org_id", "segment_id",
		"tags", "metadata", "version",
		"created_at", "updated_at", "created_by", "updated_by",
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies sp`).
		WithArgs("org-1", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(policyCols).AddRow(
			"seg-1", "finance_block", "Finance Segment Block", "pii-global", `\bSSN\b`, "critical",
			nil, "block", "tenant", 80, true,
			"tenant-1", "org-1", "finance",
			nil, nil, 1,
			now, now, nil, nil,
		))
	mock.ExpectQuery(`SELECT po\.id, po\.policy_id`).
		WithArgs("org-1", "tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "action_override", "enabled_override", "expires_at", "override_reason", "tenant_id",
		}).AddRow(
			// A live override keyed to seg-1 — must never surface on the
			// segment-scoped policy below (ADR-060 Decision 1).
			"override-x", "seg-1", "warn", nil, nil, "should never apply to a segment policy", "tenant-1",
		))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(GlobalOrgSentinel).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies sp`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(policyCols))
	mock.ExpectCommit()

	repo := NewStaticPolicyRepository(db)
	policies, err := repo.GetEffective(context.Background(), "tenant-1", &orgID, []string{"finance"})

	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].SegmentID)
	assert.Equal(t, "finance", *policies[0].SegmentID)
	assert.False(t, policies[0].HasOverride)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetEffective_TenantOverrideBeatsLaterCreatedOrgOverride is the named
// regression test for #3296's tenant-vs-org override precedence bug: the
// pre-#3296 inline override map iterated policy_overrides rows in created_at
// ASC order and overwrote a single map[policyUUID]override entry on every
// hit, so a LATER-created org-level override silently beat an EARLIER
// tenant-level override for the same policy — contradicting the
// tenant-always-wins contract the (deleted, fully-tested)
// PolicyOverrideRepository.GetEffectiveAction enforced. #3296 adopts
// policy.EffectiveOverride (platform/shared/policy/override.go), which
// resolves tenant-beats-org UNCONDITIONALLY, never by creation order.
//
// Fixture: a tenant-tier policy has two live overrides — a tenant-scoped
// "warn" created FIRST, and an org-scoped "log" created SECOND (the query
// orders by created_at ASC, so the org row is scanned last, reproducing the
// exact ordering that broke the old map). The effective policy MUST carry
// the tenant row's action ("warn"), not the later org row's ("log").
func TestGetEffective_TenantOverrideBeatsLaterCreatedOrgOverride(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	orgID := "org-1"

	policyCols := []string{
		"id", "policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tier", "priority", "enabled",
		"tenant_id", "org_id", "segment_id",
		"tags", "metadata", "version",
		"created_at", "updated_at", "created_by", "updated_by",
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies sp`).
		WithArgs("org-1", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(policyCols).AddRow(
			"pol-1", "tenant_policy_1", "Tenant Policy", "pii-global", `\bSSN\b`, "high",
			nil, "block", "tenant", 80, true,
			"tenant-1", "org-1", nil,
			nil, nil, 1,
			now, now, nil, nil,
		))
	// Tenant-scoped row created FIRST (tenant_id populated), org-scoped row
	// created SECOND (tenant_id NULL, so the org branch of the WHERE matched)
	// — returned in created_at ASC order, org row last.
	mock.ExpectQuery(`SELECT po\.id, po\.policy_id`).
		WithArgs("org-1", "tenant-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "action_override", "enabled_override", "expires_at", "override_reason", "tenant_id",
		}).
			AddRow("override-tenant", "pol-1", "warn", nil, nil, "tenant override (earlier)", "tenant-1").
			AddRow("override-org", "pol-1", "log", nil, nil, "org override (later)", nil))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(GlobalOrgSentinel).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT .* FROM static_policies sp`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(policyCols))
	mock.ExpectCommit()

	repo := NewStaticPolicyRepository(db)
	policies, err := repo.GetEffective(context.Background(), "tenant-1", &orgID, nil)

	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.True(t, policies[0].HasOverride)
	require.NotNil(t, policies[0].OverrideAction)
	assert.Equal(t, OverrideAction("warn"), *policies[0].OverrideAction,
		"tenant-level override must win even though the org-level override was created LATER")
	assert.Equal(t, "tenant override (earlier)", policies[0].OverrideReason)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- #3320: applyEffectiveOverride per-attribute resolution --------------

// TestApplyEffectiveOverride_DisableOnlyRowSetsHasOverride is the disable-only
// regression: a row with action_override NULL and enabled_override=false
// must still set HasOverride and resolve the policy as disabled, rather than
// being dropped entirely (which used to leave the policy's own Enabled=true
// standing, silently re-enforcing a policy the tenant deliberately turned
// off).
func TestApplyEffectiveOverride_DisableOnlyRowSetsHasOverride(t *testing.T) {
	policy := StaticPolicy{ID: "pol-1", Action: "block", Enabled: true}
	rows := []staticOverrideRow{
		{
			id:      "override-disable",
			enabled: sql.NullBool{Bool: false, Valid: true},
			reason:  sql.NullString{String: "BI false positives", Valid: true},
			scope:   sharedpolicy.OverrideScopeTenant,
		},
	}

	effective := applyEffectiveOverride(policy, rows)

	require.True(t, effective.HasOverride, "a disable-only row must set HasOverride")
	require.NotNil(t, effective.OverrideEnabled)
	assert.False(t, *effective.OverrideEnabled)
	assert.False(t, effective.EffectiveEnabled(), "the policy must resolve as disabled")
	assert.Nil(t, effective.OverrideAction, "no row had an opinion on action")
	assert.Equal(t, "block", effective.EffectiveAction(), "action falls back to the policy's own action")
	require.Len(t, effective.OverrideContributions, 1)
	assert.Equal(t, "override-disable", effective.OverrideContributions[0].RowID)
}

// TestApplyEffectiveOverride_OrgActionSurvivesActionlessTenantDisable is the
// worked example from the #3320 review: an org-level "warn" action override
// and a DIFFERENT tenant-level disable-only override both exist for the same
// policy. The tenant's disable must win on Enabled, and the org's action must
// still apply — the action-less tenant row must not force scope resolution
// to "tenant" and discard the org's valid action.
func TestApplyEffectiveOverride_OrgActionSurvivesActionlessTenantDisable(t *testing.T) {
	policy := StaticPolicy{ID: "sys_sqli_or_true", Action: "block", Enabled: true}
	rows := []staticOverrideRow{
		{
			id:     "org-tuning",
			action: sql.NullString{String: "warn", Valid: true},
			reason: sql.NullString{String: "tuning", Valid: true},
			scope:  sharedpolicy.OverrideScopeOrg,
		},
		{
			id:      "tenant-disable",
			enabled: sql.NullBool{Bool: false, Valid: true},
			reason:  sql.NullString{String: "BI FPs", Valid: true},
			scope:   sharedpolicy.OverrideScopeTenant,
		},
	}

	effective := applyEffectiveOverride(policy, rows)

	require.True(t, effective.HasOverride)
	require.NotNil(t, effective.OverrideAction)
	assert.Equal(t, OverrideAction("warn"), *effective.OverrideAction)
	assert.Equal(t, "warn", effective.EffectiveAction())
	require.NotNil(t, effective.OverrideEnabled)
	assert.False(t, *effective.OverrideEnabled)
	assert.False(t, effective.EffectiveEnabled())
	require.Len(t, effective.OverrideContributions, 2, "both rows must be attributed")
}

// TestApplyEffectiveOverride_TenantActionBeatsOrgAction pins plain
// action-only tenant-beats-org precedence still holds under the per-attribute
// resolution.
func TestApplyEffectiveOverride_TenantActionBeatsOrgAction(t *testing.T) {
	policy := StaticPolicy{ID: "pol-1", Action: "block", Enabled: true}
	rows := []staticOverrideRow{
		{id: "org-row", action: sql.NullString{String: "log", Valid: true}, reason: sql.NullString{String: "org", Valid: true}, scope: sharedpolicy.OverrideScopeOrg},
		{id: "tenant-row", action: sql.NullString{String: "warn", Valid: true}, reason: sql.NullString{String: "tenant", Valid: true}, scope: sharedpolicy.OverrideScopeTenant},
	}

	effective := applyEffectiveOverride(policy, rows)

	require.NotNil(t, effective.OverrideAction)
	assert.Equal(t, OverrideAction("warn"), *effective.OverrideAction)
	assert.Equal(t, "tenant", effective.OverrideReason)
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
			licenseTier:   "Enterprise",
			expectedLimit: 1000,
		},
		{
			name:          "enterprise plus no limit",
			licenseTier:   "Plus",
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

			// Get versions — org-scoped with a parent-ownership predicate
			// (#3048); ctx has no org so the scope key falls back to the
			// tenant (the org == tenant identity).
			//
			// Decision 5 (#3490): the query binds THREE args, not four. The
			// caller tenant is no longer one of them - the predicate is
			// `tier='system' OR org_id = $2` - and $2 is the same value the
			// set_config above binds, so a future edit that let the GUC and
			// the predicate diverge fails this expectation.
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT set_config`).
				WithArgs("tenant-1").
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery(`SELECT v.id, v.policy_id, v.version, v.snapshot, v.change_type, v.change_summary, v.changed_by, v.changed_at`).
				WithArgs("policy-1", "tenant-1", tt.expectedLimit).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "policy_id", "version", "snapshot", "change_type",
					"change_summary", "changed_by", "changed_at",
				}).AddRow(
					"v1", "policy-1", 1, []byte(`{"name": "Test"}`), "create",
					"Created", "user1", time.Now(),
				))
			mock.ExpectCommit()

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
						"tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "sys_test", "System Policy", "security-sqli", `\btest\b`, "critical",
						nil, "block", "system", 100, true,
						"global", nil,
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
						"tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"policy-1", "custom_test", "Tenant Policy", "security-sqli", `\btest\b`, "high",
						nil, "block", "tenant", 50, true,
						"tenant-1", "tenant-1",
						nil, nil, 1,
						time.Now(), time.Now(), nil, nil, nil,
					))

				// v9 Phase 8 #2384 PR-C1: ToggleEnabled wraps UPDATE in
				// WithOrgScope using the fetched policy.OrgID.
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`UPDATE static_policies SET enabled`).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()

				// v9 Phase 8 #2384 PR-C1: recordVersion wraps its INSERT in
				// WithOrgScope using the fetched policy.OrgID (tenant-1).
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("tenant-1").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO static_policy_versions`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
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
		// v9 Phase 8 #2384 PR-C1: recordVersion now requires non-empty
		// policy.OrgID (mig 110 keyed RLS on app.current_org_id); set it
		// so the WithOrgScope wrap inside recordVersion succeeds.
		OrgID: "tenant-1",
	}

	// v9 Phase 8 #2384 PR-C1: recordVersion wraps its INSERT in
	// WithOrgScope using policy.OrgID.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("tenant-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO static_policy_versions`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

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

	// #3048: org-scoped count. #3490: the org is an explicit parameter and is
	// DELIBERATELY different from the tenant here -- the pre-#3490 code took
	// one identifier and used it as both, so a test that passed the same
	// string for both could not tell the GUC apart from the row predicate and
	// would still pass if the two were swapped.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
		WithArgs("tenant-1", "org-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(15))
	mock.ExpectCommit()

	repo := NewStaticPolicyRepository(db)
	count, err := repo.countTenantPolicies(context.Background(), "org-1", "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, 15, count)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCountTenantPolicies_RefusesWithoutOrg pins the fail-closed direction of
// #3490. The removed code fell back to `scopeOrg = tenantID` when no org was
// available, which under app-role set the RLS GUC to a string that is not an
// organisation -- the USING clause then matched nothing, COUNT(*) came back 0,
// and the Community tenant-policy limit silently authorised the write it
// exists to refuse. An uncountable quota must be an error, not a zero.
//
// The assertion is that NO statement is issued at all: a refusal that still
// opened a transaction would mean the guard ran after the scope was taken.
func TestCountTenantPolicies_RefusesWithoutOrg(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewStaticPolicyRepository(db)
	count, err := repo.countTenantPolicies(context.Background(), "", "tenant-1")

	require.Error(t, err, "an empty org must refuse rather than count in an unknown organisation")
	assert.Contains(t, err.Error(), "orgID must be non-empty")
	assert.Equal(t, 0, count)
	// No Begin, no Exec, no Query were expected, so this also proves the
	// refusal happened before any database work.
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
		{"professional", "Professional", false, false},
		{"enterprise", "Enterprise", false, true},
		{"enterprise plus", "Plus", false, true},
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
		// v9 Phase 8 #2384 PR-C1: Create + recordVersion both require
		// non-empty OrgID for the WithOrgScope wrap.
		OrgID:   "tenant-1",
		Enabled: true,
	}

	for i := 0; i < b.N; i++ {
		mock.ExpectQuery(`SELECT license_tier FROM clients`).
			WithArgs("tenant-1").
			WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Enterprise"))
		// v9 Phase 8 #2384 PR-C1: Create wraps INSERT in WithOrgScope.
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
			WithArgs("tenant-1").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`INSERT INTO static_policies`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		// v9 Phase 8 #2384 PR-C1: recordVersion wraps INSERT in WithOrgScope.
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
			WithArgs("tenant-1").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`INSERT INTO static_policy_versions`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

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
