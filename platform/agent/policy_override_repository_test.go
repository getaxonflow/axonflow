// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewPolicyOverrideRepository tests repository creation.
func TestNewPolicyOverrideRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPolicyOverrideRepository(db)
	assert.NotNil(t, repo)
	assert.NotNil(t, repo.staticPolicyRepo)
}

// TestCreateOverride tests override creation with Enterprise license requirement.
func TestCreateOverride(t *testing.T) {
	tenantID := "tenant-1"
	actionWarn := ActionWarn

	tests := []struct {
		name        string
		override    *PolicyOverride
		setupMock   func(mock sqlmock.Sqlmock)
		wantErr     error
		errContains string
	}{
		{
			name: "missing reason rejected",
			override: &PolicyOverride{
				PolicyID:       "policy-1",
				TenantID:       &tenantID,
				ActionOverride: &actionWarn,
				OverrideReason: "", // Missing
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// No DB calls expected
			},
			wantErr: ErrOverrideReasonRequired,
		},
		{
			name: "invalid action rejected",
			override: &PolicyOverride{
				PolicyID:       "policy-1",
				TenantID:       &tenantID,
				ActionOverride: func() *OverrideAction { a := OverrideAction("invalid"); return &a }(),
				OverrideReason: "Testing",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// No DB calls expected
			},
			wantErr: ErrInvalidOverrideAction,
		},
		{
			name: "community license rejected",
			override: &PolicyOverride{
				PolicyID:       "policy-1",
				TenantID:       &tenantID,
				ActionOverride: &actionWarn,
				OverrideReason: "Testing in warn mode",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				// Check license tier (Community - should fail)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Community"))
			},
			wantErr: ErrOverrideRequiresEnterprise,
		},
		{
			name: "non-system policy rejected",
			override: &PolicyOverride{
				PolicyID:       "policy-1",
				TenantID:       &tenantID,
				ActionOverride: &actionWarn,
				OverrideReason: "Testing",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				now := time.Now()
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("ENT"))

				// GetByID returns tenant tier policy (not system)
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
						now, now, nil, nil, nil,
					))
			},
			wantErr: ErrOnlySystemPoliciesOverridable,
		},
		{
			name: "successful override creation",
			override: &PolicyOverride{
				PolicyID:       "sys-policy-1",
				TenantID:       &tenantID,
				ActionOverride: &actionWarn,
				OverrideReason: "Testing in warn mode before full rollout",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				now := time.Now()
				// Check license tier (Enterprise)
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("PLUS"))

				// GetByID returns system tier policy
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("sys-policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"sys-policy-1", "sys_sqli_1", "System SQLi Policy", "security-sqli", `\bDROP\b`, "critical",
						nil, "block", "system", 100, true,
						nil, "global", nil,
						nil, nil, 1,
						now, now, nil, nil, nil,
					))

				// Check existing override
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM policy_overrides`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				// Insert override
				mock.ExpectExec(`INSERT INTO policy_overrides`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: nil,
		},
		{
			name: "duplicate override rejected",
			override: &PolicyOverride{
				PolicyID:       "sys-policy-1",
				TenantID:       &tenantID,
				ActionOverride: &actionWarn,
				OverrideReason: "Testing",
			},
			setupMock: func(mock sqlmock.Sqlmock) {
				now := time.Now()
				// Check license tier
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("ENT"))

				// GetByID returns system tier policy
				mock.ExpectQuery(`SELECT .* FROM static_policies WHERE`).
					WithArgs("sys-policy-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "tier", "priority", "enabled",
						"organization_id", "tenant_id", "org_id",
						"tags", "metadata", "version",
						"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
					}).AddRow(
						"sys-policy-1", "sys_sqli_1", "System SQLi Policy", "security-sqli", `\bDROP\b`, "critical",
						nil, "block", "system", 100, true,
						nil, "global", nil,
						nil, nil, 1,
						now, now, nil, nil, nil,
					))

				// Check existing override - already exists
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM policy_overrides`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			},
			wantErr: ErrOverrideAlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewPolicyOverrideRepository(db)
			err = repo.Create(context.Background(), tt.override, "test-user")

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

// TestDeleteOverride tests override deletion.
func TestDeleteOverride(t *testing.T) {
	tests := []struct {
		name       string
		overrideID string
		setupMock  func(mock sqlmock.Sqlmock)
		wantErr    error
	}{
		{
			name:       "successful deletion",
			overrideID: "override-1",
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID first
				mock.ExpectQuery(`SELECT .* FROM policy_overrides WHERE`).
					WithArgs("override-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "policy_type",
						"organization_id", "tenant_id",
						"action_override", "enabled_override",
						"override_reason", "expires_at",
						"created_by", "created_at", "updated_by", "updated_at",
					}).AddRow(
						"override-1", "policy-1", "static",
						nil, "tenant-1",
						"warn", nil,
						"Testing", nil,
						"user1", time.Now(), "user1", time.Now(),
					))

				// Delete
				mock.ExpectExec(`DELETE FROM policy_overrides WHERE id`).
					WithArgs("override-1").
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: nil,
		},
		{
			name:       "override not found",
			overrideID: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				// GetByID returns not found
				mock.ExpectQuery(`SELECT .* FROM policy_overrides WHERE`).
					WithArgs("nonexistent").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: ErrOverrideNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewPolicyOverrideRepository(db)
			err = repo.Delete(context.Background(), tt.overrideID, "test-user")

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestGetEffectiveAction tests the effective action resolution.
func TestGetEffectiveAction(t *testing.T) {
	orgID := "org-1"

	tests := []struct {
		name           string
		policyID       string
		tenantID       string
		orgID          *string
		setupMock      func(mock sqlmock.Sqlmock)
		expectedAction OverrideAction
		hasOverride    bool
		wantErr        bool
	}{
		{
			name:     "tenant override takes precedence",
			policyID: "policy-1",
			tenantID: "tenant-1",
			orgID:    &orgID,
			setupMock: func(mock sqlmock.Sqlmock) {
				// Tenant override exists
				mock.ExpectQuery(`SELECT action_override, enabled_override, expires_at FROM policy_overrides WHERE`).
					WithArgs("policy-1", "tenant-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"action_override", "enabled_override", "expires_at",
					}).AddRow("warn", nil, nil))
			},
			expectedAction: ActionWarn,
			hasOverride:    true,
			wantErr:        false,
		},
		{
			name:     "org override when no tenant override",
			policyID: "policy-1",
			tenantID: "tenant-1",
			orgID:    &orgID,
			setupMock: func(mock sqlmock.Sqlmock) {
				// No tenant override
				mock.ExpectQuery(`SELECT action_override, enabled_override, expires_at FROM policy_overrides WHERE`).
					WithArgs("policy-1", "tenant-1").
					WillReturnError(sql.ErrNoRows)

				// Org override exists
				mock.ExpectQuery(`SELECT action_override, enabled_override, expires_at FROM policy_overrides WHERE`).
					WithArgs("policy-1", "org-1").
					WillReturnRows(sqlmock.NewRows([]string{
						"action_override", "enabled_override", "expires_at",
					}).AddRow("log", nil, nil))
			},
			expectedAction: ActionLog,
			hasOverride:    true,
			wantErr:        false,
		},
		{
			name:     "no override",
			policyID: "policy-1",
			tenantID: "tenant-1",
			orgID:    nil,
			setupMock: func(mock sqlmock.Sqlmock) {
				// No tenant override
				mock.ExpectQuery(`SELECT action_override, enabled_override, expires_at FROM policy_overrides WHERE`).
					WithArgs("policy-1", "tenant-1").
					WillReturnError(sql.ErrNoRows)
			},
			expectedAction: "",
			hasOverride:    false,
			wantErr:        false,
		},
		{
			name:     "expired override ignored",
			policyID: "policy-1",
			tenantID: "tenant-1",
			orgID:    nil,
			setupMock: func(mock sqlmock.Sqlmock) {
				// Query excludes expired, so no rows returned
				mock.ExpectQuery(`SELECT action_override, enabled_override, expires_at FROM policy_overrides WHERE`).
					WithArgs("policy-1", "tenant-1").
					WillReturnError(sql.ErrNoRows)
			},
			expectedAction: "",
			hasOverride:    false,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewPolicyOverrideRepository(db)
			action, hasOverride, err := repo.GetEffectiveAction(context.Background(), tt.policyID, tt.tenantID, tt.orgID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.hasOverride, hasOverride)
				if tt.hasOverride {
					assert.Equal(t, tt.expectedAction, action)
				}
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestGetByID tests override retrieval.
func TestGetOverrideByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	expiry := now.Add(24 * time.Hour)

	mock.ExpectQuery(`SELECT .* FROM policy_overrides WHERE`).
		WithArgs("override-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type",
			"organization_id", "tenant_id",
			"action_override", "enabled_override",
			"override_reason", "expires_at",
			"created_by", "created_at", "updated_by", "updated_at",
		}).AddRow(
			"override-1", "policy-1", "static",
			nil, "tenant-1",
			"warn", true,
			"Testing phase", expiry,
			"user1", now, "user2", now,
		))

	repo := NewPolicyOverrideRepository(db)
	override, err := repo.GetByID(context.Background(), "override-1")

	require.NoError(t, err)
	assert.Equal(t, "override-1", override.ID)
	assert.Equal(t, "policy-1", override.PolicyID)
	assert.NotNil(t, override.ActionOverride)
	assert.Equal(t, ActionWarn, *override.ActionOverride)
	assert.NotNil(t, override.EnabledOverride)
	assert.True(t, *override.EnabledOverride)
	assert.Equal(t, "Testing phase", override.OverrideReason)
	assert.NotNil(t, override.ExpiresAt)
	assert.Equal(t, "user1", override.CreatedBy)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestListOverridesForTenant tests listing overrides.
func TestListOverridesForTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	orgID := "org-1"

	mock.ExpectQuery(`SELECT .* FROM policy_overrides WHERE`).
		WithArgs("tenant-1", "org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type",
			"organization_id", "tenant_id",
			"action_override", "enabled_override",
			"override_reason", "expires_at",
			"created_by", "created_at", "updated_by", "updated_at",
		}).AddRow(
			"override-1", "policy-1", "static",
			nil, "tenant-1",
			"warn", nil,
			"Tenant level", nil,
			"user1", now, "user1", now,
		).AddRow(
			"override-2", "policy-2", "static",
			"org-1", nil,
			"log", nil,
			"Org level", nil,
			"user2", now, "user2", now,
		))

	repo := NewPolicyOverrideRepository(db)
	overrides, err := repo.ListOverridesForTenant(context.Background(), "tenant-1", &orgID, false)

	require.NoError(t, err)
	assert.Len(t, overrides, 2)
	assert.Equal(t, "override-1", overrides[0].ID)
	assert.Equal(t, "override-2", overrides[1].ID)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCleanupExpiredOverrides tests expired override cleanup.
func TestCleanupExpiredOverrides(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`DELETE FROM policy_overrides WHERE expires_at IS NOT NULL AND expires_at <= NOW`).
		WillReturnResult(sqlmock.NewResult(0, 5))

	repo := NewPolicyOverrideRepository(db)
	count, err := repo.CleanupExpiredOverrides(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 5, count)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestDeleteByPolicyID tests deletion by policy ID.
func TestDeleteByPolicyID(t *testing.T) {
	tenantID := "tenant-1"

	tests := []struct {
		name      string
		policyID  string
		tenantID  *string
		orgID     *string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   error
	}{
		{
			name:     "delete tenant override",
			policyID: "policy-1",
			tenantID: &tenantID,
			orgID:    nil,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`DELETE FROM policy_overrides WHERE policy_id`).
					WithArgs("policy-1", tenantID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: nil,
		},
		{
			name:     "override not found",
			policyID: "nonexistent",
			tenantID: &tenantID,
			orgID:    nil,
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`DELETE FROM policy_overrides WHERE policy_id`).
					WithArgs("nonexistent", tenantID).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantErr: ErrOverrideNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			tt.setupMock(mock)

			repo := NewPolicyOverrideRepository(db)
			err = repo.DeleteByPolicyID(context.Background(), tt.policyID, tt.tenantID, tt.orgID, "test-user")

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestOverrideExists tests the existence check.
func TestOverrideExists(t *testing.T) {
	tenantID := "tenant-1"

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM policy_overrides`).
		WithArgs("policy-1", tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	repo := NewPolicyOverrideRepository(db)
	exists, err := repo.overrideExists(context.Background(), "policy-1", &tenantID, nil)

	require.NoError(t, err)
	assert.True(t, exists)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestOverrideExpiry tests override expiry handling.
func TestOverrideExpiry(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{"nil expiry (never expires)", nil, false},
		{"future expiry", &future, false},
		{"past expiry", &past, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			override := &PolicyOverride{
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.expected, override.IsExpired())
		})
	}
}

// TestOverrideLevel tests the override level detection.
func TestOverrideLevel(t *testing.T) {
	tenantID := "tenant-1"
	orgID := "org-1"

	t.Run("tenant level", func(t *testing.T) {
		override := &PolicyOverride{
			TenantID: &tenantID,
		}
		assert.True(t, override.IsTenantLevel())
		assert.False(t, override.IsOrgLevel())
	})

	t.Run("org level", func(t *testing.T) {
		override := &PolicyOverride{
			OrganizationID: &orgID,
		}
		assert.False(t, override.IsTenantLevel())
		assert.True(t, override.IsOrgLevel())
	})
}

// Benchmark tests
func BenchmarkGetEffectiveAction(b *testing.B) {
	db, mock, err := sqlmock.New()
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	for i := 0; i < b.N; i++ {
		mock.ExpectQuery(`SELECT action_override, enabled_override, expires_at FROM policy_overrides WHERE`).
			WillReturnError(sql.ErrNoRows)

		repo := NewPolicyOverrideRepository(db)
		_, _, _ = repo.GetEffectiveAction(context.Background(), "policy-1", "tenant-1", nil)
	}
}

func TestGetOverrideForPolicy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewPolicyOverrideRepository(db)
	ctx := context.Background()
	tenantID := "tenant-1"

	t.Run("returns override when found", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type",
			"organization_id", "tenant_id",
			"action_override", "enabled_override",
			"override_reason", "expires_at",
			"created_by", "created_at", "updated_by", "updated_at",
		}).AddRow(
			"override-1", "policy-1", "static",
			nil, "tenant-1",
			"block", true,
			"Testing", nil,
			"admin", time.Now(), nil, time.Now(),
		)

		mock.ExpectQuery(`SELECT`).
			WithArgs("policy-1", tenantID).
			WillReturnRows(rows)

		override, err := repo.GetOverrideForPolicy(ctx, "policy-1", &tenantID, nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if override.PolicyID != "policy-1" {
			t.Errorf("expected policy_id 'policy-1', got %s", override.PolicyID)
		}
		if override.ActionOverride == nil || *override.ActionOverride != "block" {
			t.Errorf("expected action_override 'block', got %v", override.ActionOverride)
		}
	})

	t.Run("returns error when not found", func(t *testing.T) {
		mock.ExpectQuery(`SELECT`).
			WithArgs("policy-2", tenantID).
			WillReturnError(sql.ErrNoRows)

		_, err := repo.GetOverrideForPolicy(ctx, "policy-2", &tenantID, nil)
		if err != ErrOverrideNotFound {
			t.Errorf("expected ErrOverrideNotFound, got %v", err)
		}
	})

	t.Run("filters by org when tenant is nil", func(t *testing.T) {
		orgID := "org-1"
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type",
			"organization_id", "tenant_id",
			"action_override", "enabled_override",
			"override_reason", "expires_at",
			"created_by", "created_at", "updated_by", "updated_at",
		}).AddRow(
			"override-2", "policy-3", "static",
			"org-1", nil,
			nil, false,
			"Disabled for org", nil,
			"admin", time.Now(), nil, time.Now(),
		)

		mock.ExpectQuery(`SELECT`).
			WithArgs("policy-3", orgID).
			WillReturnRows(rows)

		override, err := repo.GetOverrideForPolicy(ctx, "policy-3", nil, &orgID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if override.OrganizationID == nil || *override.OrganizationID != "org-1" {
			t.Errorf("expected org_id 'org-1', got %v", override.OrganizationID)
		}
	})
}
