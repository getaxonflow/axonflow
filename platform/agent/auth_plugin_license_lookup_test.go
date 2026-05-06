//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
)

// =============================================================================
// lookupActivePluginLicenseTier — DB-backed tier resolution for the inline
// auth path. Replaces the work that used to live in plugin_claim_middleware.go
// (deleted in the same PR that introduced this helper).
// =============================================================================

func TestLookupActivePluginLicenseTier_HappyPath(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery(`SELECT tier, tenant_id, revoked_at\s+FROM plugin_user_licenses\s+WHERE license_token_jti = \$1`).
		WithArgs("jti-active").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}).
			AddRow("Pro", "cs_abc", nil))

	tier, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-active", "cs_abc")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tier != license.TierPro {
		t.Errorf("expected TierPro, got %q", tier)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

func TestLookupActivePluginLicenseTier_NotFound_SentinelError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery(`SELECT tier, tenant_id, revoked_at`).
		WithArgs("jti-missing").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}))

	_, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-missing", "cs_abc")
	if !errors.Is(err, errPluginLicenseNotFound) {
		t.Errorf("expected errPluginLicenseNotFound, got %v", err)
	}
}

func TestLookupActivePluginLicenseTier_RevokedRow_SentinelError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	revokedTime := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`SELECT tier, tenant_id, revoked_at`).
		WithArgs("jti-revoked").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}).
			AddRow("Pro", "cs_abc", revokedTime))

	_, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-revoked", "cs_abc")
	if !errors.Is(err, errPluginLicenseNotFound) {
		t.Errorf("revoked row should map to errPluginLicenseNotFound, got %v", err)
	}
}

func TestLookupActivePluginLicenseTier_TenantMismatch_SentinelError(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery(`SELECT tier, tenant_id, revoked_at`).
		WithArgs("jti-mismatch").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}).
			AddRow("Pro", "cs_xyz", nil))

	// Token's auth-resolved tenant is cs_abc; row's tenant is cs_xyz.
	_, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-mismatch", "cs_abc")
	if !errors.Is(err, errPluginLicenseTenantMismatch) {
		t.Errorf("expected errPluginLicenseTenantMismatch, got %v", err)
	}
}

func TestLookupActivePluginLicenseTier_NilDB_Errors(t *testing.T) {
	_, err := lookupActivePluginLicenseTier(context.Background(), nil, "jti", "cs_abc")
	if err == nil {
		t.Error("expected error for nil db, got nil")
	}
}

// =============================================================================
// mapPluginLicenseLookupError — sentinel-to-HTTP-status mapping
// =============================================================================

func TestMapPluginLicenseLookupError_NotFound_401(t *testing.T) {
	authErr := mapPluginLicenseLookupError(errPluginLicenseNotFound, "jti-x")
	if authErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", authErr.StatusCode)
	}
}

func TestMapPluginLicenseLookupError_TenantMismatch_403(t *testing.T) {
	authErr := mapPluginLicenseLookupError(errPluginLicenseTenantMismatch, "jti-x")
	if authErr.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", authErr.StatusCode)
	}
}

func TestMapPluginLicenseLookupError_DBError_503(t *testing.T) {
	authErr := mapPluginLicenseLookupError(errors.New("connection refused"), "jti-x")
	if authErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", authErr.StatusCode)
	}
}
