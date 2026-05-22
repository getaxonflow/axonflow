//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
)

// Community-build coverage for auth_plugin_license_lookup.go. The
// existing enterprise-build test suite covers the same surface under
// `//go:build enterprise`; community-build CI's Unit Tests: Agent job
// doesn't include those tests, so the function bodies showed 0% local
// + 0% community-CI coverage. These tests close that gap.
//
// The lookup helper is consumed by the inline auth path
// (validateCommunitySaasAuth — auth.go) which is enabled on both
// editions. Coverage parity between the two test trees is the goal.

func TestLookupActivePluginLicenseTier_Community_HappyPath(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery(`SELECT tier, tenant_id, revoked_at\s+FROM plugin_user_licenses\s+WHERE license_token_jti = \$1`).
		WithArgs("jti-happy").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}).
			AddRow("Pro", "tenant-A", nil))

	tier, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-happy", "tenant-A")
	if err != nil {
		t.Fatalf("happy-path lookup: %v", err)
	}
	if tier != license.Tier("Pro") {
		t.Errorf("tier = %q, want Pro", tier)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestLookupActivePluginLicenseTier_Community_NilDBErrors(t *testing.T) {
	_, err := lookupActivePluginLicenseTier(context.Background(), nil, "j", "t")
	if err == nil || err.Error() != "plugin_user_licenses lookup: db is nil" {
		t.Errorf("nil db expected sentinel error, got: %v", err)
	}
}

func TestLookupActivePluginLicenseTier_Community_NoRowsReturnsSentinel(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectQuery(`SELECT tier`).WithArgs("jti-missing").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}))

	_, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-missing", "t")
	if !errors.Is(err, errPluginLicenseNotFound) {
		t.Errorf("ErrNoRows expected errPluginLicenseNotFound, got: %v", err)
	}
}

func TestLookupActivePluginLicenseTier_Community_RevokedReturnsSentinel(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	revokedAt := time.Now()
	mock.ExpectQuery(`SELECT tier`).WithArgs("jti-revoked").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}).
			AddRow("Pro", "tenant-A", revokedAt))

	_, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-revoked", "tenant-A")
	if !errors.Is(err, errPluginLicenseNotFound) {
		t.Errorf("revoked-at populated expected errPluginLicenseNotFound, got: %v", err)
	}
}

func TestLookupActivePluginLicenseTier_Community_TenantMismatch(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectQuery(`SELECT tier`).WithArgs("jti-mismatch").
		WillReturnRows(sqlmock.NewRows([]string{"tier", "tenant_id", "revoked_at"}).
			AddRow("Pro", "tenant-OTHER", nil))

	_, err := lookupActivePluginLicenseTier(context.Background(), db, "jti-mismatch", "tenant-A")
	if !errors.Is(err, errPluginLicenseTenantMismatch) {
		t.Errorf("tenant mismatch expected errPluginLicenseTenantMismatch, got: %v", err)
	}
}

func TestMapPluginLicenseLookupError_Community(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantSub    string
	}{
		{"not_found_returns_401", errPluginLicenseNotFound, http.StatusUnauthorized, "license_not_found_or_revoked"},
		{"tenant_mismatch_returns_403", errPluginLicenseTenantMismatch, http.StatusForbidden, "license_tenant_mismatch"},
		{"unknown_db_error_returns_503", errors.New("connection refused"), http.StatusServiceUnavailable, "license_lookup_unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapPluginLicenseLookupError(c.err, "jti-X")
			if got == nil {
				t.Fatal("mapPluginLicenseLookupError returned nil")
			}
			if got.StatusCode != c.wantStatus {
				t.Errorf("StatusCode = %d, want %d", got.StatusCode, c.wantStatus)
			}
			if !strings.Contains(got.Message, c.wantSub) {
				t.Errorf("Message %q does not contain %q", got.Message, c.wantSub)
			}
		})
	}
}
