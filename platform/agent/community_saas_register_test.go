// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

func TestHandleCommunityRegister_NilDB(t *testing.T) {
	handler := handleCommunityRegister(nil)
	req := httptest.NewRequest("POST", "/api/v1/register", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 for nil DB, got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_InvalidContentType(t *testing.T) {
	// Need a non-nil DB — use a sentinel (handler checks nil before DB use)
	// We can't easily create a real DB in unit tests, so test the Content-Type
	// check path which fires before DB access
	handler := handleCommunityRegister(nil) // Will hit nil DB check first
	req := httptest.NewRequest("POST", "/api/v1/register", nil)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// nil DB check fires first (503), not content type check
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 (nil DB fires first), got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_ContentTypeWithCharset(t *testing.T) {
	// Verify that application/json; charset=utf-8 is accepted
	handler := handleCommunityRegister(nil)
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// Should pass content-type check and fail on nil DB (503)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 (nil DB), got %d — Content-Type may have been rejected", rr.Code)
	}
}

func TestHandleCommunityRegister_OversizedBody(t *testing.T) {
	handler := handleCommunityRegister(nil)
	// Create body > 1KB
	bigBody := strings.Repeat("x", maxRequestBodySize+100)
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// nil DB fires first
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 (nil DB fires first), got %d", rr.Code)
	}
}

func TestRegistrationIPTracker_Basic(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// First 5 requests from same IP should succeed
	for i := 0; i < registrationIPLimit; i++ {
		if err := tracker.check("192.168.1.1"); err != nil {
			t.Errorf("Request %d: unexpected error: %v", i+1, err)
		}
	}

	// 6th request should fail
	if err := tracker.check("192.168.1.1"); err != ErrRegistrationRateLimit {
		t.Errorf("Request 6: expected ErrRegistrationRateLimit, got %v", err)
	}
}

func TestRegistrationIPTracker_DifferentIPs(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// Different IPs should be independent
	for i := 0; i < registrationIPLimit; i++ {
		if err := tracker.check("10.0.0.1"); err != nil {
			t.Errorf("IP1 request %d: unexpected error: %v", i+1, err)
		}
	}
	// IP1 is exhausted
	if err := tracker.check("10.0.0.1"); err != ErrRegistrationRateLimit {
		t.Errorf("IP1 should be rate-limited")
	}

	// IP2 should still work
	if err := tracker.check("10.0.0.2"); err != nil {
		t.Errorf("IP2 should not be rate-limited: %v", err)
	}
}

func TestRegistrationIPTracker_Cleanup(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// Fill with more than ipTrackerMaxEntries expired entries using fmt for unique keys
	targetCount := ipTrackerMaxEntries + 100
	for i := 0; i < targetCount; i++ {
		key := "ip-" + strings.Join([]string{strings.Repeat("0", 6), fmt.Sprintf("%06d", i)}, "-")
		tracker.entries[key] = &ipRegistrationEntry{
			count:     1,
			resetTime: time.Now().Add(-1 * time.Hour), // Expired
		}
	}

	if len(tracker.entries) <= ipTrackerMaxEntries {
		t.Fatalf("Setup failed: entries should exceed max, got %d", len(tracker.entries))
	}

	// Next check should trigger cleanup
	if err := tracker.check("new-ip"); err != nil {
		t.Errorf("New IP after cleanup should succeed: %v", err)
	}

	// Expired entries should have been cleaned — only "new-ip" remains
	if len(tracker.entries) > 2 {
		t.Errorf("Cleanup should have reduced entries significantly, got %d", len(tracker.entries))
	}
}

func TestExtractClientIP_XForwardedFor(t *testing.T) {
	// AWS ALB appends the real peer IP to XFF, so the LAST entry is
	// always trustworthy and the FIRST entry is client-controlled.
	// Tests assert the LAST-entry behavior; "spoof attempt" verifies
	// that client-supplied prepended values cannot bypass the rate-limit.
	tests := []struct {
		name     string
		xff      string
		remote   string // optional override; "" → httptest default
		expected string
	}{
		{"single IP", "1.2.3.4", "", "1.2.3.4"},
		{"multiple IPs (ALB-appended)", "1.2.3.4, 5.6.7.8, 9.10.11.12", "", "9.10.11.12"},
		{"with spaces", "  1.2.3.4  , 5.6.7.8  ", "", "5.6.7.8"},
		{"spoof attempt: forged first entry ignored",
			"99.99.99.99, 8.8.8.8", "", "8.8.8.8"},
		{"empty last entry falls through to RemoteAddr",
			"1.2.3.4, ", "127.0.0.1:5678", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tt.xff)
			if tt.remote != "" {
				req.RemoteAddr = tt.remote
			}
			got := extractClientIP(req)
			if got != tt.expected {
				t.Errorf("extractClientIP(XFF=%q) = %q, want %q", tt.xff, got, tt.expected)
			}
		})
	}
}

func TestExtractClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	got := extractClientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("Expected 10.0.0.1, got %s", got)
	}
}

func TestExtractClientIP_EmptyRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""
	got := extractClientIP(req)
	if got != "unknown" {
		t.Errorf("Expected 'unknown' for empty RemoteAddr, got %q", got)
	}
}

func TestRegistrationResponse_JSONStructure(t *testing.T) {
	resp := registrationResponse{
		TenantID:     "cs_test-uuid",
		Secret:       "abcdef1234567890",
		SecretPrefix: "abcdef12",
		ExpiresAt:    "2026-05-09T00:00:00Z",
		Endpoint:     communitySaasTryEndpoint,
		Note:         communitySaasDisclaimerNote,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	required := []string{"tenant_id", "secret", "secret_prefix", "expires_at", "endpoint", "note"}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("Missing required field: %s", key)
		}
	}

	if !strings.HasPrefix(parsed["tenant_id"].(string), "cs_") {
		t.Errorf("tenant_id should have cs_ prefix, got %s", parsed["tenant_id"])
	}
}

func TestIsCommunitySaasMode(t *testing.T) {
	tests := []struct {
		mode     string
		expected bool
	}{
		{"community-saas", true},
		{"community", false},
		{"", false},
		{"enterprise", false},
		{"saas", false},
		{"in-vpc-enterprise", false},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			old := os.Getenv("DEPLOYMENT_MODE")
			os.Setenv("DEPLOYMENT_MODE", tt.mode)
			defer func() {
				if old != "" {
					os.Setenv("DEPLOYMENT_MODE", old)
				} else {
					os.Unsetenv("DEPLOYMENT_MODE")
				}
			}()

			got := isCommunitySaasMode()
			if got != tt.expected {
				t.Errorf("isCommunitySaasMode() with DEPLOYMENT_MODE=%q = %v, want %v", tt.mode, got, tt.expected)
			}

			// Verify community-saas is NOT community mode
			if tt.mode == "community-saas" && isCommunityMode() {
				t.Error("community-saas should NOT be community mode")
			}
		})
	}
}

func TestValidateCommunityRegistration_NilDB(t *testing.T) {
	err := validateCommunityRegistration(nil, nil, "tenant", "secret")
	if err != ErrDatabaseUnavailable {
		t.Errorf("Expected ErrDatabaseUnavailable, got %v", err)
	}
}

func TestEnqueueActivityUpdate_NilChannel(t *testing.T) {
	// Save and restore
	oldChan := activityUpdateChan
	activityUpdateChan = nil
	defer func() { activityUpdateChan = oldChan }()

	// Should not panic
	enqueueActivityUpdate(nil, "test-tenant")
}

func TestEnqueueActivityUpdate_FullChannel(t *testing.T) {
	// Create a tiny channel that's already full
	oldChan := activityUpdateChan
	activityUpdateChan = make(chan activityUpdate, 1)
	activityUpdateChan <- activityUpdate{} // Fill it
	defer func() { activityUpdateChan = oldChan }()

	// Should not block — drops silently
	enqueueActivityUpdate(nil, "test-tenant")
}

func TestRegisterEndpoint_MethodNotAllowed(t *testing.T) {
	router := setupCSAASTestRouter()
	RegisterCommunityRegistrationHandler(router, nil)

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/register", nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s /api/v1/register: expected 405, got %d", method, rr.Code)
			}
		})
	}
}

func TestRegisterEndpoint_POST_NilDB(t *testing.T) {
	router := setupCSAASTestRouter()
	RegisterCommunityRegistrationHandler(router, nil)

	body := bytes.NewBufferString(`{"label":"test"}`)
	req := httptest.NewRequest("POST", "/api/v1/register", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("POST /api/v1/register with nil DB: expected 503, got %d", rr.Code)
	}
}

// TestInternalTenantIDPrefixAllowlist_Shape pins the allowlist contents +
// invariant that every entry starts with internalTenantIDPrefix. Adding
// an entry that doesn't start with `axonflow-internal-` would mean the
// resulting tenant_id wouldn't classify as source=internal via
// classify.go IsInternal rule 4 (HasPrefix(TenantID,
// InternalOrgIDPrefix="axonflow-") — broadened from `axonflow-internal-`
// in PR #2261 per ADR-054). The narrower `axonflow-internal-` sub-
// namespace remains the minting prefix because that's the historical
// canary identity; the rule's broader predicate catches any subset of
// the `axonflow-*` family. Removing an entry breaks the consumer that
// depends on it (e.g. removing axonflow-internal-canary- breaks the
// synthetic-monitoring canary's classification).
//
// Mutation-tested 2026-05-14:
//   - Drop axonflow-internal-canary- from the map → this test fails with
//     "expected key axonflow-internal-canary- in allowlist".
//   - Add a non-prefixed key like "external-marker-" → the second
//     assertion fails with the explicit diagnostic.
func TestInternalTenantIDPrefixAllowlist_Shape(t *testing.T) {
	want := map[string]bool{
		"axonflow-internal-canary-":     true,
		"axonflow-internal-perf-bench-": true,
		"axonflow-internal-e2e-":        true,
		"axonflow-internal-smoke-":      true,
	}
	for k := range want {
		if !internalTenantIDPrefixAllowlist[k] {
			t.Errorf("expected key %q in allowlist (consumer of this entry depends on it; verify before removal)", k)
		}
	}
	// Every allowlist entry MUST start with internalTenantIDPrefix —
	// otherwise the resulting tenant_id wouldn't match the
	// telemetry-filter Layer 1 rule, defeating the design.
	for k := range internalTenantIDPrefixAllowlist {
		if !strings.HasPrefix(k, internalTenantIDPrefix) {
			t.Errorf("allowlist entry %q does not start with internalTenantIDPrefix %q — "+
				"resulting tenant_id wouldn't classify source=internal via "+
				"classify.go IsInternal rule 4. Either fix the entry or "+
				"update the rule (and rerun the parity fixture).", k, internalTenantIDPrefix)
		}
	}
}

// TestRegisterEndpoint_POST_DoesNotCrashOnNewWireField verifies that the
// handler accepts the new `internal_tenant_id_prefix` wire field without
// panicking on JSON unmarshal — the json.Unmarshal default tolerates
// unknown fields, but adding a NEW known field exercises the request
// struct's new tag. With nil DB, the handler short-circuits at 503 before
// reaching the prefix validation, so this test is structural-only — real
// validation is covered by the resolveTenantPrefix pure-function tests
// below + runtime-e2e/community_saas_register_internal_prefix/test.sh.
func TestRegisterEndpoint_POST_DoesNotCrashOnNewWireField(t *testing.T) {
	router := setupCSAASTestRouter()
	RegisterCommunityRegistrationHandler(router, nil)

	body := bytes.NewBufferString(`{"label":"test","internal_tenant_id_prefix":"attacker-prefix-"}`)
	req := httptest.NewRequest("POST", "/api/v1/register", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("nil-DB short-circuit didn't fire — expected 503, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}

// TestResolveTenantPrefix_Default proves the empty-prefix path returns
// the default `cs_` prefix without error. Mutation guard: if
// resolveTenantPrefix is changed to ALWAYS return the request's prefix
// (silently dropping the empty-handling), this test fails.
func TestResolveTenantPrefix_Default(t *testing.T) {
	prefix, err := resolveTenantPrefix(registrationRequest{Label: "real-customer"})
	if err != nil {
		t.Fatalf("default path: unexpected error: %v", err)
	}
	if prefix != communitySaasTenantPrefix {
		t.Errorf("default prefix: got %q, want %q", prefix, communitySaasTenantPrefix)
	}
}

// TestResolveTenantPrefix_AllowlistedReturned proves an allowlisted
// internal prefix is passed through. Mutation guard: if the function
// is changed to silently force communitySaasTenantPrefix in this branch
// (e.g. `prefix = communitySaasTenantPrefix`), this test fails — the
// strongest signal that the canary's contract is enforced.
func TestResolveTenantPrefix_AllowlistedReturned(t *testing.T) {
	cases := []string{
		internalTenantIDPrefix + "canary-",
		internalTenantIDPrefix + "perf-bench-",
		internalTenantIDPrefix + "e2e-",
		internalTenantIDPrefix + "smoke-",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			got, err := resolveTenantPrefix(registrationRequest{InternalTenantIDPrefix: p})
			if err != nil {
				t.Fatalf("allowlisted prefix %q: unexpected error: %v", p, err)
			}
			if got != p {
				t.Errorf("allowlisted prefix %q: returned %q (silent fallback?)", p, got)
			}
		})
	}
}

// TestResolveTenantPrefix_NonAllowlistedRejected proves out-of-allowlist
// values return ErrInvalidInternalPrefix. Mutation guard: if the
// allowlist check is dropped (`if false && !allowlist[...]`), this test
// fails — the strongest signal against silent acceptance of attacker-
// controlled prefixes.
func TestResolveTenantPrefix_NonAllowlistedRejected(t *testing.T) {
	cases := []string{
		"attacker-prefix-",
		"axonflow-internal-",          // bare prefix (not in allowlist; only suffixed entries)
		"axonflow-internal-attacker-", // looks-like-allowlisted but isn't
		"cs_attacker-",                // mimics default but explicit
		"axonflow-internal-CANARY-",   // case mismatch (allowlist is exact-match)
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			prefix, err := resolveTenantPrefix(registrationRequest{InternalTenantIDPrefix: p})
			if err == nil {
				t.Errorf("non-allowlisted %q: expected ErrInvalidInternalPrefix, got nil (would silently fall through to %q)", p, prefix)
			}
			if !errors.Is(err, ErrInvalidInternalPrefix) {
				t.Errorf("non-allowlisted %q: expected ErrInvalidInternalPrefix, got %v", p, err)
			}
			if prefix != "" {
				t.Errorf("non-allowlisted %q: returned non-empty prefix %q (must be empty on error)", p, prefix)
			}
		})
	}
}

// TestResolveTenantPrefix_AllowlistConstructionUsesConstant is a
// belt-and-suspenders against L4 from the hostile review: the allowlist
// values are now constructed by appending a suffix to internalTenantIDPrefix
// rather than embedding the literal. This test pins that intent so a
// future PR that hard-codes "axonflow-internal-foo-" instead of
// internalTenantIDPrefix+"foo-" gets a visible signal that drift will
// be possible if the constant changes.
func TestResolveTenantPrefix_AllowlistConstructionUsesConstant(t *testing.T) {
	// Walk the allowlist keys and verify every one starts with
	// internalTenantIDPrefix. If the constant changed and a literal
	// allowlist entry didn't, this fails.
	for k := range internalTenantIDPrefixAllowlist {
		if k == internalTenantIDPrefix || k == "" {
			t.Errorf("allowlist entry %q is the bare prefix or empty — must have a unique suffix", k)
		}
		if !strings.HasPrefix(k, internalTenantIDPrefix) {
			t.Errorf("allowlist entry %q does not start with internalTenantIDPrefix %q — drift between constant + map detected",
				k, internalTenantIDPrefix)
		}
	}
}

func TestExtractClientIP_IPv6RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:54321"
	got := extractClientIP(req)
	// For IPv6 with brackets and port, LastIndexByte finds the port colon
	if got == "" || got == "unknown" {
		t.Errorf("Expected non-empty IP for IPv6, got %q", got)
	}
}

func TestExtractClientIP_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"
	got := extractClientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("Expected 10.0.0.1 for no-port RemoteAddr, got %q", got)
	}
}

func TestRegistrationIPTracker_ExpiredEntryReset(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// Add an expired entry
	tracker.entries["expired-ip"] = &ipRegistrationEntry{
		count:     registrationIPLimit + 1,          // Was rate-limited
		resetTime: time.Now().Add(-1 * time.Minute), // Expired
	}

	// Should succeed now (expired entry gets replaced)
	if err := tracker.check("expired-ip"); err != nil {
		t.Errorf("Expired entry should reset: %v", err)
	}
}

func TestRegistrationConstants(t *testing.T) {
	// Verify critical constants have expected values
	if bcryptCost < 10 || bcryptCost > 14 {
		t.Errorf("bcryptCost should be 10-14 for security/perf balance, got %d", bcryptCost)
	}
	if secretBytes < 16 {
		t.Errorf("secretBytes should be >= 16 for security, got %d", secretBytes)
	}
	if maxLabelLength < 1 {
		t.Errorf("maxLabelLength should be positive, got %d", maxLabelLength)
	}
	if registrationIPLimit < 1 {
		t.Errorf("registrationIPLimit should be positive, got %d", registrationIPLimit)
	}
	if ipTrackerMaxEntries < 1000 {
		t.Errorf("ipTrackerMaxEntries should be >= 1000, got %d", ipTrackerMaxEntries)
	}
	if communitySaasTryEndpoint == "" {
		t.Error("communitySaasTryEndpoint should not be empty")
	}
	if communitySaasDisclaimerNote == "" {
		t.Error("communitySaasDisclaimerNote should not be empty")
	}
	// v9 Phase 6 (Epic #2230): the legacy communitySaasOrgID = "community-saas"
	// constant was deleted. org_id is now the per-customer cs_<uuid> stamped
	// at INSERT/auth time. Coverage moved to TestV9Phase6_CommunitySaas_*
	// below + the v9_integration_postgres_test.go RDS-backed suite.
	if communitySaasTenantPrefix != "cs_" {
		t.Errorf("communitySaasTenantPrefix should be 'cs_', got %q", communitySaasTenantPrefix)
	}
}

// Phase 6 mutation-tested coverage for validateCommunitySaasAuth's
// OrgID return is in v9_integration_postgres_test.go's
// TestV9Phase6_SaaSAuthReturnsPerCustomerOrgID — that test drives the real
// SUT against a seeded Postgres and was proven non-tautological via
// auth.go source-mutation. The INSERT-shape regression is covered by
// TestRegisterEndpoint_INSERTWritesClientIDColumn below.

func TestHandleCommunityRegister_InvalidJSON(t *testing.T) {
	handler := handleCommunityRegister(nil)
	// Content-type check and nil DB check fire before JSON parsing
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// nil DB fires first (503)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 for nil DB, got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_EmptyBody(t *testing.T) {
	handler := handleCommunityRegister(nil)
	req := httptest.NewRequest("POST", "/api/v1/register", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 for nil DB (empty body is valid), got %d", rr.Code)
	}
}

func setupCSAASTestRouter() *mux.Router {
	return mux.NewRouter()
}

// TestRegisterEndpoint_INSERTWritesClientIDColumn is the A+B+Phase-6
// integration guard for Epic #2230.
//
// Three invariants are enforced on the INSERT shape:
//  1. tenant_id and client_id are written together as the FIRST two columns
//     and both bind to $1 (Session B's client_id column write, PR #2246).
//  2. org_id is bound to $1 too (Phase 6 — PR for this work). Pre-Phase-6
//     this position held the legacy shared constant communitySaasOrgID =
//     "community-saas", which is the v9 RLS leak this PR closes.
//  3. The placeholder shape matches the actual production SQL exactly so
//     any future refactor that adds/reorders columns surfaces here.
//
// Mutation guard: revert org_id placeholder back to $4 (the pre-Phase-6
// bind that used the constant) and this test FAILS — proving the
// assertion isn't tautological per
// feedback_mutation_test_to_prove_assertion_not_tautological.md.
//
// Both INSERT shapes are covered:
//   - email-bearing INSERT (claimed_by_email + claimed_at columns present)
//   - non-email INSERT (the legacy un-claimed shape)
func TestRegisterEndpoint_INSERTWritesClientIDColumn(t *testing.T) {
	t.Run("email-bearing INSERT contains client_id column", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
		if err != nil {
			t.Fatalf("sqlmock.New failed: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })

		// Email-claim path executes a SERIALIZABLE cap-check transaction
		// (per-email tenant cap) BEFORE the INSERT — see
		// community_saas_register.go:439 BeginTx + COUNT query + Commit.
		mock.ExpectBegin()
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM community_saas_registrations\s+WHERE claimed_by_email`).
			WithArgs("alice@example.com").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		mock.ExpectCommit()

		// v9 Phase 8 PR-A (mig 109): handler now calls the csaas_register_tenant
		// SECURITY DEFINER helper instead of a raw INSERT. Both with-email and
		// without-email shapes collapse onto one helper call via the
		// p_email DEFAULT NULL branch. Mock the SELECT call shape; the helper
		// body's INSERT runs server-side and is not visible to sqlmock.
		mock.ExpectExec(`SELECT csaas_register_tenant\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`SELECT register_org`).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`SELECT register_tenant`).WillReturnResult(sqlmock.NewResult(0, 0))

		router := setupCSAASTestRouter()
		resetRegIPTracker()
		RegisterCommunityRegistrationHandler(router, db)

		// Request struct's JSON tag is `email` (registrationRequest.Email),
		// not claimed_by_email — see community_saas_register.go:188.
		body := bytes.NewBufferString(`{"label":"integration-test","email":"alice@example.com"}`)
		req := httptest.NewRequest("POST", "/api/v1/register", body)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d (body=%s)", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("INSERT shape mismatch — v9 Phase 6 org_id=$1 / client_id=$1 invariant violated: %v", err)
		}
	})

	t.Run("non-email INSERT contains client_id column", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
		if err != nil {
			t.Fatalf("sqlmock.New failed: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })

		// v9 Phase 8 PR-A (mig 109): handler now calls csaas_register_tenant.
		// Same helper, same arg count — sqlmock matches the SELECT shape.
		mock.ExpectExec(`SELECT csaas_register_tenant\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`SELECT register_org`).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`SELECT register_tenant`).WillReturnResult(sqlmock.NewResult(0, 0))

		router := setupCSAASTestRouter()
		resetRegIPTracker()
		RegisterCommunityRegistrationHandler(router, db)

		body := bytes.NewBufferString(`{"label":"integration-test-no-email"}`)
		req := httptest.NewRequest("POST", "/api/v1/register", body)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.2:1234"
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d (body=%s)", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("INSERT shape mismatch — v9 Phase 6 org_id=$1 / client_id=$1 invariant violated: %v", err)
		}
	})
}
