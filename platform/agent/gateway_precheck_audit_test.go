// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"

	"axonflow/platform/agent/indonesia"
	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// #2642 (AUDIT-FIX-D): Gateway pre-check → canonical audit_logs decision row
//
// Before #2642 the Gateway pre-check (handlePolicyPreCheck) persisted ONLY to the
// gateway_contexts satellite (approved = !Blocked), which the portal's decisions
// feed (orchestrator GET /api/v1/decisions, reading audit_logs) never reads. So a
// PII redaction collapsed to approved=true — indistinguishable from a clean allow —
// and every early-return deny (kill-switch, circuit-breaker, PII block, budget,
// tenant mismatch, invalid token) wrote no portal-visible row at all. The handler
// now ALSO writes a canonical plane=gateway audit_logs row via
// recordGatewayPreCheckAudit → writeDecisionAuditLog (the DB half of the writer
// /decide + the MCP planes use), carrying the canonical past-tense policy_decision
// (#2638 / #2630: allowed | blocked | redacted | needs_approval). These tests pin
// the verdict mapping, the writer's column contract (plane, keying, vocab), and —
// red-on-revert — that the handler actually emits the row on the representative
// deny paths AND that a redaction is DISTINGUISHABLE from a clean allow.
//
// kill-switch + circuit-breaker deny paths are community build-tag STUBS in the
// unit build (rbi/killswitch_community.go always returns IsBlocked=false;
// circuitbreaker community Check always allows) so they cannot be driven to deny
// in-process — they are exercised live in runtime-e2e/2642_gateway_precheck_audit
// (enterprise build + real PDP), which the DoD mandates. budget/tenant-mismatch/
// invalid-token deny paths reuse the SAME recordGatewayPreCheckAudit writer pinned
// by TestRecordGatewayPreCheckAudit_WritesCanonicalRow below.
// =============================================================================

// TestGatewayPreCheckAuditVerdict pins the terminal-outcome → canonical-verdict
// mapping, including precedence: a HITL hold outranks a hard block (the request is
// pending approval, not refused), and a block outranks a redaction.
func TestGatewayPreCheckAuditVerdict(t *testing.T) {
	cases := []struct {
		name              string
		blocked           bool
		requiresHITL      bool
		requiresRedaction bool
		want              string
	}{
		{"clean allow", false, false, false, gatewayAuditAllowed},
		{"redaction only", false, false, true, gatewayAuditRedacted},
		{"hard block", true, false, false, gatewayAuditBlocked},
		{"HITL hold", false, true, false, gatewayAuditNeedsApproval},
		{"block outranks redaction", true, false, true, gatewayAuditBlocked},
		{"HITL outranks block", true, true, false, gatewayAuditNeedsApproval},
		{"HITL outranks block+redaction", true, true, true, gatewayAuditNeedsApproval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gatewayPreCheckAuditVerdict(tc.blocked, tc.requiresHITL, tc.requiresRedaction); got != tc.want {
				t.Errorf("gatewayPreCheckAuditVerdict(%v,%v,%v) = %q, want %q", tc.blocked, tc.requiresHITL, tc.requiresRedaction, got, tc.want)
			}
		})
	}
}

// TestRecordGatewayPreCheckAudit_WritesCanonicalRow pins the writer contract for
// every verdict the pre-check can emit: a single INSERT INTO audit_logs keyed by
// contextID (id=decide_<contextID>, decision_id=<contextID>), request_type=
// decision_<stage>, plane=gateway, policy_decision=<canonical verdict>, and the
// inbound traceparent threaded into correlation_id. Every early-return deny passes
// gatewayAuditBlocked through this same writer, so this is the red-on-revert guard
// for those paths' persistence as well.
func TestRecordGatewayPreCheckAudit_WritesCanonicalRow(t *testing.T) {
	verdicts := []string{gatewayAuditAllowed, gatewayAuditBlocked, gatewayAuditRedacted, gatewayAuditNeedsApproval}
	for _, verdict := range verdicts {
		t.Run(verdict, func(t *testing.T) {
			mockDB, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer mockDB.Close()

			origDB := usageDB
			usageDB = mockDB
			defer func() { usageDB = origDB }()

			const contextID = "ctx-abc-123"
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(
					"decide_"+contextID,                // id (PK keyed by contextID)
					contextID,                          // request_id (audit.requestID empty → defaults to decisionID)
					sqlmock.AnyArg(),                   // timestamp
					sqlmock.AnyArg(),                   // user_id
					sqlmock.AnyArg(),                   // user_email
					sqlmock.AnyArg(),                   // user_role
					"gw-client",                        // client_id
					"tenant-x",                         // tenant_id
					"org-x",                            // org_id
					"decision_llm",                     // request_type — decision_<stage>
					sqlmock.AnyArg(),                   // query
					sqlmock.AnyArg(),                   // query_hash
					verdict,                            // policy_decision — canonical past-tense vocab
					sqlmock.AnyArg(),                   // policy_details (JSONB)
					contextID,                          // decision_id (first-class column, keyed by contextID)
					PlaneGateway,                       // plane — the Gateway pre-check surface (#2642)
					nil,                                // obligations (pre-check emits none)
					"0af7651916cd43dd8448eb211c80319c", // correlation_id — threaded traceparent
					nil,                                // redacted_fields — pre-check emits none → NULL (#2643)
					nil,                                // session_id — context unstamped (untrusted) → NULL (#2896)
				).
				WillReturnResult(sqlmock.NewResult(0, 1))

			audit := decisionAuditInput{
				clientID:      "gw-client",
				query:         "some query",
				correlationID: "0af7651916cd43dd8448eb211c80319c",
			}
			recordGatewayPreCheckAudit(context.Background(), contextID, "org-x", "tenant-x", "llm", verdict, []string{"p1"}, []string{"reason"}, audit)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("canonical audit_logs row not written as expected for verdict %q: %v", verdict, err)
			}
		})
	}
}

// newPreCheckRecorder drives handlePolicyPreCheck through apiAuthMiddleware in
// community mode (the integration-test pattern) and returns the recorder.
func newPreCheckRecorder(t *testing.T, query string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(PreCheckRequest{ClientID: "test-client-2642", Query: query})
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", "test-key")
	rr := httptest.NewRecorder()
	apiAuthMiddleware(http.HandlerFunc(handlePolicyPreCheck)).ServeHTTP(rr, req)
	return rr
}

// setupPreCheckAuditTest wires community mode, a sqlmock usageDB, deterministic
// detectors, and nils out the optional DB-backed services (circuit-breaker / cost /
// shared engine / satellite authDB) so the ONLY DB write the handler performs is
// the canonical audit row under test. Returns the mock + a cleanup.
func setupPreCheckAuditTest(t *testing.T) (sqlmock.Sqlmock, func()) {
	t.Helper()
	communityCleanup := setupCommunityModeForTest(t)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}

	origUsageDB := usageDB
	origAuthDB := authDB
	origCB := circuitBreakerInstance
	origCost := costService
	origEngine := sharedpolicy.GetGlobalEngine()
	origIndo := indonesiaPIIDetector

	usageDB = mockDB
	authDB = nil // satellite write no-ops → only the canonical row hits usageDB
	circuitBreakerInstance = nil
	costService = nil
	sharedpolicy.SetGlobalEngine(nil) // main exit takes the no-policy-engine branch (no DB)
	indonesiaPIIDetector = indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	ResetDetectionConfigCache()

	return mock, func() {
		usageDB = origUsageDB
		authDB = origAuthDB
		circuitBreakerInstance = origCB
		costService = origCost
		sharedpolicy.SetGlobalEngine(origEngine)
		indonesiaPIIDetector = origIndo
		mockDB.Close()
		ResetDetectionConfigCache()
		communityCleanup()
	}
}

// expectGatewayAuditRow registers the single canonical INSERT the handler must
// perform, asserting plane=gateway + the expected policy_decision + request_type.
func expectGatewayAuditRow(mock sqlmock.Sqlmock, wantDecision string) {
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // request_id
			sqlmock.AnyArg(), // timestamp
			sqlmock.AnyArg(), // user_id
			sqlmock.AnyArg(), // user_email
			sqlmock.AnyArg(), // user_role
			sqlmock.AnyArg(), // client_id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // org_id
			"decision_llm",   // request_type (no data_sources → stage llm)
			sqlmock.AnyArg(), // query
			sqlmock.AnyArg(), // query_hash
			wantDecision,     // policy_decision — the verdict this test pins
			sqlmock.AnyArg(), // policy_details
			sqlmock.AnyArg(), // decision_id
			PlaneGateway,     // plane
			sqlmock.AnyArg(), // obligations
			sqlmock.AnyArg(), // correlation_id
			sqlmock.AnyArg(), // redacted_fields (#2643)
			nil,              // session_id — context unstamped (untrusted) → NULL (#2896)
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// TestGatewayPreCheck_IndonesiaBlockEmitsCanonicalAuditRow is the red-on-revert
// guard for the Indonesia PII block deny path: a NIK under PII_ACTION=block MUST
// write a canonical audit_logs row with policy_decision='blocked' + plane=gateway.
// Remove the recordGatewayPreCheckAudit call from that branch and the expected
// INSERT never fires → ExpectationsWereMet fails.
func TestGatewayPreCheck_IndonesiaBlockEmitsCanonicalAuditRow(t *testing.T) {
	mock, cleanup := setupPreCheckAuditTest(t)
	defer cleanup()
	t.Setenv("PII_ACTION", "block")
	ResetDetectionConfigCache()

	expectGatewayAuditRow(mock, gatewayAuditBlocked)

	rr := newPreCheckRecorder(t, "Customer NIK is 3174042506780001")

	var resp PreCheckResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Approved {
		t.Error("expected approved=false for NIK under PII_ACTION=block")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Indonesia block path did not emit the canonical audit_logs row: %v", err)
	}
}

// TestGatewayPreCheck_IndiaBlockEmitsCanonicalAuditRow covers the distinct India /
// RBI PII block deny call site (a 12-digit Aadhaar does not match the 16-digit NIK
// pattern, so the Indonesia detector passes and checkRBIPII blocks). policy_decision
// must be 'blocked' + plane=gateway.
func TestGatewayPreCheck_IndiaBlockEmitsCanonicalAuditRow(t *testing.T) {
	mock, cleanup := setupPreCheckAuditTest(t)
	defer cleanup()
	t.Setenv("PII_ACTION", "block")
	ResetDetectionConfigCache()

	expectGatewayAuditRow(mock, gatewayAuditBlocked)

	rr := newPreCheckRecorder(t, "My Aadhaar number is 234567890123")

	var resp PreCheckResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Approved {
		t.Error("expected approved=false for Aadhaar under PII_ACTION=block")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("India/RBI block path did not emit the canonical audit_logs row: %v", err)
	}
}

// TestGatewayPreCheck_InvalidUserTokenEmitsCanonicalAuditRow drives the
// enterprise-mode early-return deny path (line ~480): a user token that fails
// validation MUST still write a canonical plane=gateway audit_logs row with
// policy_decision='blocked' (the refusal is auditable) and a FIXED reason — never
// the token material. Injects AuthKindEnterprise via context (no middleware/license
// needed) so the deny fires before any policy/detection DB call.
func TestGatewayPreCheck_InvalidUserTokenEmitsCanonicalAuditRow(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise") // not community → ResolveUser validates the token

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	expectGatewayAuditRow(mock, gatewayAuditBlocked)

	body, _ := json.Marshal(PreCheckRequest{ClientID: "ent-client", Query: "hello", UserToken: "not-a-valid-jwt"})
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyAuthKind, AuthKindEnterprise)
	ctx = context.WithValue(ctx, ContextKeyClientID, "ent-client")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "ent-tenant")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "ent-org")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req)

	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for an invalid user token, got %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("invalid-token deny path did not emit the canonical audit_logs row: %v", err)
	}
}

// TestGatewayPreCheck_TenantMismatchEmitsCanonicalAuditRow drives the
// tenant-isolation deny path (line ~519): a VALID enterprise user token whose
// tenant_id claim differs from the client's credential tenant must write a
// canonical plane=gateway audit_logs row with policy_decision='blocked'. The
// refusal of a cross-tenant token is exactly the kind of security event that must
// be auditable. (validateUserToken reads tenant_id from the claim without forcing
// it equal to the credential tenant, so this branch is reachable with a real JWT.)
func TestGatewayPreCheck_TenantMismatchEmitsCanonicalAuditRow(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	defer func() { jwtSecret = origSecret }()

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// A valid token whose tenant_id claim ("other-tenant") differs from the
	// client's credential tenant ("ent-tenant") injected via context below.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   float64(7),
		"tenant_id": "other-tenant",
		"email":     "x@example.com",
	})
	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	expectGatewayAuditRow(mock, gatewayAuditBlocked)

	body, _ := json.Marshal(PreCheckRequest{ClientID: "ent-client", Query: "hello", UserToken: signed})
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyAuthKind, AuthKindEnterprise)
	ctx = context.WithValue(ctx, ContextKeyClientID, "ent-client")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "ent-tenant")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "ent-org")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 on tenant mismatch, got %d: %s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("tenant-mismatch deny path did not emit the canonical audit_logs row: %v", err)
	}
}

// TestGatewayPreCheck_RedactionDistinguishableFromAllow is the headline guard for
// bucket D: a redaction and a clean allow must land as DIFFERENT canonical verdicts
// (redacted vs allowed), not both collapsed to approved=true. NIK under
// PII_ACTION=redact → 'redacted'; a clean query → 'allowed'.
func TestGatewayPreCheck_RedactionDistinguishableFromAllow(t *testing.T) {
	t.Run("NIK under redact → redacted", func(t *testing.T) {
		mock, cleanup := setupPreCheckAuditTest(t)
		defer cleanup()
		t.Setenv("PII_ACTION", "redact")
		ResetDetectionConfigCache()

		expectGatewayAuditRow(mock, gatewayAuditRedacted)

		rr := newPreCheckRecorder(t, "Customer NIK is 3174042506780001")

		var resp PreCheckResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !resp.Approved {
			t.Errorf("expected approved=true under PII_ACTION=redact, got block_reason=%s", resp.BlockReason)
		}
		if !resp.RequiresRedaction {
			t.Error("expected requires_redaction=true for NIK under PII_ACTION=redact")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("redaction did not emit policy_decision='redacted': %v", err)
		}
	})

	t.Run("clean query → allowed", func(t *testing.T) {
		mock, cleanup := setupPreCheckAuditTest(t)
		defer cleanup()
		ResetDetectionConfigCache()

		expectGatewayAuditRow(mock, gatewayAuditAllowed)

		rr := newPreCheckRecorder(t, "What is the capital of France?")

		var resp PreCheckResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !resp.Approved {
			t.Errorf("expected approved=true for a clean query, got block_reason=%s", resp.BlockReason)
		}
		if resp.RequiresRedaction {
			t.Error("clean query must not require redaction")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("clean allow did not emit policy_decision='allowed': %v", err)
		}
	})
}
