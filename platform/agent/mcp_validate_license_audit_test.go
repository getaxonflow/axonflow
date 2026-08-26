// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// =============================================================================
// #2684 (Gap B): validateServiceLicense permission-denied canonical audit.
//
// validateServiceLicense gates a service-license request through
// EvaluateMCPPermission — making it a Policy Enforcement Point — but its
// authz-failure (permission denied, 403) previously wrote NO canonical audit row
// (sibling of #2683 HOLE D). It now emits a canonical plane=mcp 'blocked' row via
// writeMCPDecisionAudit, keyed on the AUTHENTICATED request identity passed by the
// caller (never the service-license deployment id, which is the licensee, not a
// customer tenant).
//
// Red-on-revert: this pins the canonical INSERT; removing the writeMCPDecisionAudit
// emit leaves an unmet sqlmock expectation. setUsageDBMock + expectCanonicalDecisionRow
// + captureArg are shared with the sibling MCP-plane audit tests in this package.
// =============================================================================

// craftServiceLicense signs a service license with the enterprise test seed
// (matches TestValidateServiceLicense_EnterpriseMode_* in mcp_handler_test.go).
func craftServiceLicense(t *testing.T, permissions []string) string {
	t.Helper()
	entSeed, err := base64.StdEncoding.DecodeString("xV0rl8D6oQg7aoVvF6XA3KhN4Qb8PMmLfJyiF4JCkZc=")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	privKey := ed25519.NewKeyFromSeed(entSeed)
	payload := map[string]interface{}{
		"tier":         "Enterprise",
		"tenant_id":    "test-tenant",
		"service_name": "test-service",
		"service_type": "backend-service",
		"permissions":  permissions,
		"issued_at":    "20260209",
		"expires_at":   "20991231",
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := ed25519.Sign(privKey, []byte(payloadBase64))
	sigBase64 := base64.RawURLEncoding.EncodeToString(sig)
	return "AXON-" + payloadBase64 + "." + sigBase64
}

// TestValidateServiceLicense_PermissionDenied_WritesCanonicalAudit pins the
// canonical plane=mcp 'blocked' audit_logs row the permission-denied authz
// failure now writes (#2684). Red-on-revert: drop the emit → unmet expectation.
func TestValidateServiceLicense_PermissionDenied_WritesCanonicalAudit(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	mock, restore := setUsageDBMock(t)
	defer restore()

	// The service has only redis permission; the request is for postgres → denied.
	licenseKey := craftServiceLicense(t, []string{"mcp:redis:query"})
	expectCanonicalDecisionRow(mock, "mcp_permission_check", mcpVerdictBlocked)

	w := httptest.NewRecorder()
	granted, err := validateServiceLicense(context.Background(), w, licenseKey,
		"postgres", "query", "query", "tenant-test", "org-test", "client-test", 4 /* #3424: the caller's measured elapsed ms */)

	if err == nil {
		t.Error("expected permission-denied error")
	}
	if granted {
		t.Error("granted = true, want false on permission denied")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("HTTP %d, want 403: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("canonical audit row not written (revert of the #2684 fix): %v", err)
	}
}

// TestValidateServiceLicense_PermissionDenied_AuditIsSecretFree asserts the
// recorded query + policy_details carry only the connector:op descriptor — the
// service license key is never passed to the writer, so it structurally cannot
// land in the row.
func TestValidateServiceLicense_PermissionDenied_AuditIsSecretFree(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	mock, restore := setUsageDBMock(t)
	defer restore()

	licenseKey := craftServiceLicense(t, []string{"mcp:redis:query"})

	var queryArg, detailsJSON []byte
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(),              // id
			sqlmock.AnyArg(),              // request_id
			sqlmock.AnyArg(),              // timestamp
			sqlmock.AnyArg(),              // user_id
			sqlmock.AnyArg(),              // user_email
			sqlmock.AnyArg(),              // user_role
			sqlmock.AnyArg(),              // client_id
			sqlmock.AnyArg(),              // tenant_id
			sqlmock.AnyArg(),              // org_id
			"mcp_permission_check",        // request_type
			captureArg{dst: &queryArg},    // query
			sqlmock.AnyArg(),              // query_hash
			mcpVerdictBlocked,             // policy_decision
			captureArg{dst: &detailsJSON}, // policy_details JSONB
			sqlmock.AnyArg(),              // decision_id
			PlaneMCP,                      // plane=mcp
			nil,                           // correlation_id
			nil,                           // redacted_fields
			nil,                           // session_id NULL (#2753)
			sqlmock.AnyArg(),              // response_time_ms (#3424)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := httptest.NewRecorder()
	_, _ = validateServiceLicense(context.Background(), w, licenseKey,
		"postgres", "query", "query", "tenant-test", "org-test", "client-test", 4 /* #3424: the caller's measured elapsed ms */)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected audit row: %v", err)
	}
	if strings.Contains(string(queryArg), licenseKey) || strings.Contains(string(detailsJSON), licenseKey) {
		t.Error("service license key leaked into the audit row")
	}
	if !strings.Contains(string(queryArg), "postgres:query") {
		t.Errorf("query descriptor = %q, want it to name connector:op", string(queryArg))
	}
}
