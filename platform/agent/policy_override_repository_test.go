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
}

// GetEffectiveAction and its precedence tests (formerly here, "tenant
// override takes precedence" / "org override when no tenant override" /
// "no override" / "expired override ignored") were removed by #3296 Slice 2:
// GetEffectiveAction had no live production caller (verified via
// `grep -rn "GetEffectiveAction" --include='*.go' .`  — only this file and
// the benchmark below referenced it), so the method was deleted as dead
// code. Its precedence coverage was ported, case-for-case, onto
// platform/shared/policy/override_test.go's TestEffectiveOverride_* suite,
// which now pins the same tenant-beats-org-beats-none contract via the
// shared EffectiveOverride primitive WS-3a adopts for
// static_policy_repository.go's GetEffective.

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
			"tenant_id",
			"action_override", "enabled_override",
			"override_reason", "expires_at",
			"created_by", "created_at", "updated_by", "updated_at",
		}).AddRow(
			"override-1", "policy-1", "static",
			"tenant-1",
			"warn", nil,
			"Tenant level", nil,
			"user1", now, "user1", now,
		).AddRow(
			"override-2", "policy-2", "static",
			nil,
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
		// #3334: an org-scoped row is one with a NULL tenant. It used to also
		// require the retired organization_id column to be non-nil, but the
		// schema's own valid_override_scope CHECK made the two conjuncts
		// inseparable, and migration core/165 now guarantees OrgID is
		// populated on every row regardless of scope.
		override := &PolicyOverride{
			OrgID: orgID,
		}
		assert.False(t, override.IsTenantLevel())
		assert.True(t, override.IsOrgLevel())
	})
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
			"tenant_id", "org_id",
			"action_override", "enabled_override",
			"override_reason", "expires_at",
			"created_by", "created_at", "updated_by", "updated_at",
		}).AddRow(
			"override-1", "policy-1", "static",
			"tenant-1", "org-1",
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
			"tenant_id", "org_id",
			"action_override", "enabled_override",
			"override_reason", "expires_at",
			"created_by", "created_at", "updated_by", "updated_at",
		}).AddRow(
			"override-2", "policy-3", "static",
			nil, "org-1",
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
		// #3334: the row is org-scoped because its tenant is NULL, which is
		// what the retired organization_id column used to say redundantly.
		if override.TenantID != nil {
			t.Errorf("expected an org-scoped row (NULL tenant), got tenant %v", *override.TenantID)
		}
		if !override.IsOrgLevel() {
			t.Error("expected IsOrgLevel() true for a NULL-tenant row")
		}
	})
}
