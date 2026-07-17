// Copyright 2025 AxonFlow
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

// Unit tests for handleDecide (Decision Mode -- ADR-056 / epic #2426).
//
// These tests exercise the in-process handler via httptest. Runtime proof
// against a live agent stack lives in runtime-e2e/2426_decision_api/.

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/agent/circuitbreaker"
	sharedpolicy "axonflow/platform/shared/policy"
)

// decideForTest sends a DecideRequest body through the raw handler (no
// auth middleware) so test cases can deterministically control the
// community-mode flow without needing JWTs. Returns the recorder.
func decideForTest(t *testing.T, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
	return rr
}

// installSharedEngineWithMockDB swaps the global shared-policy engine for one
// backed by sqlmock so SQLi/PII detection runs the real validators in-process.
func installSharedEngineWithMockDB(t *testing.T) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	// handleDecide now makes a policy-derived category lookup
	// (EnabledPIICategories, #2565) in addition to EvaluateRequest. Those two
	// GetPolicies calls share a cache key for a real (non-empty) tenant, but a
	// blank-tenant test path can produce two distinct keys (EvaluateRequest
	// substitutes DefaultTenant; EnabledPIICategories doesn't), so allow several
	// empty-result SELECTs. Extra unmet expectations are harmless (the tests
	// don't assert ExpectationsWereMet).
	mockSQL.MatchExpectationsInOrder(false)
	for i := 0; i < 4; i++ {
		mockSQL.ExpectQuery("SELECT").WillReturnRows(
			sqlmock.NewRows([]string{"id", "name", "pattern", "category", "severity", "action", "enabled", "tier", "tenant_id", "description", "metadata"}),
		)
	}
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{}, nil)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
}

// installCircuitBreaker wires the community stub breaker that always allows.
// Tests that need a blocking breaker swap it again in-line.
func installCircuitBreaker(t *testing.T) {
	t.Helper()
	old := circuitBreakerInstance
	circuitBreakerInstance = circuitbreaker.New(circuitbreaker.NewRepository(nil), circuitbreaker.Config{})
	t.Cleanup(func() { circuitBreakerInstance = old })
}

// --- Verdict allow (clean query, no triggers) ---

func TestHandleDecide_VerdictAllow(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage: DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{
			GatewayID: "test-llm-gateway",
			TenantID:  "test-tenant",
		},
		Target: DecisionTarget{Type: "llm", Model: "gpt-4o", Provider: "openai"},
		Query:  "What is the weather today?",
	})
	rr := decideForTest(t, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v -- body=%s", err, rr.Body.String())
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("verdict: got %q want %q (reasons=%v)", resp.Verdict, VerdictAllow, resp.Reasons)
	}
	if resp.DecisionID == "" {
		t.Error("decision_id must be set on every response")
	}
	if !isValidW3CTraceID(resp.TraceID) {
		t.Errorf("trace_id %q is not a valid W3C trace_id (32 lowercase hex)", resp.TraceID)
	}
	if resp.Obligations == nil {
		t.Error("obligations must always be a non-nil slice for stable PEP parsing")
	}
	if resp.Stage != DecisionStageLLM {
		t.Errorf("stage echo: got %q want %q", resp.Stage, DecisionStageLLM)
	}
	if resp.ExpiresAt.IsZero() {
		t.Error("expires_at must be populated")
	}
}

// TestHandleDecide_IndonesiaNIKRedactObligation pins the /decide half of the
// #2571 fix: under PII_ACTION=redact, a checksum-valid NIK must emit EXACTLY ONE
// redact_pii obligation that names check-input as its fulfillment endpoint.
// Before the fix /decide flagged Indonesia PII for block only, so under redact
// it returned allow with NO obligation and the NIK slipped through. Mirrors the
// pre-check integration test on the /decide plane (deterministic, no license).
func TestHandleDecide_IndonesiaNIKRedactObligation(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("PII_ACTION", "redact")
	ResetDetectionConfigCache()
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "test-llm-gateway", TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o", Provider: "openai"},
		Query:          "Customer NIK is 3174042506780001",
	})
	rr := decideForTest(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v -- body=%s", err, rr.Body.String())
	}
	if resp.Verdict != VerdictAllow {
		t.Fatalf("verdict: got %q want %q (redact, not block); reasons=%v", resp.Verdict, VerdictAllow, resp.Reasons)
	}

	redactCount := 0
	var ob DecisionObligation
	for _, o := range resp.Obligations {
		if o.Type == ObligationRedactPII {
			redactCount++
			ob = o
		}
	}
	if redactCount != 1 {
		t.Fatalf("expected exactly one redact_pii obligation for a NIK under PII_ACTION=redact, got %d (obligations=%+v)", redactCount, resp.Obligations)
	}
	if ob.Fulfillment == nil || !strings.Contains(ob.Fulfillment.Endpoint, "check-input") {
		t.Errorf("redact_pii obligation must name check-input as its fulfillment endpoint, got %+v", ob.Fulfillment)
	}
}

// --- Verdict mapping (pure, no engine/DB needed) ---
//
// The handler delegates verdict choice to mapPolicyResultToVerdict so the
// four verdict transitions can be tested deterministically. Live-engine
// SQLi/PII detection paths require DB-seeded patterns and are exercised
// by runtime-e2e/2426_decision_api/ end-to-end.

func TestMapPolicyResultToVerdict_AllPaths(t *testing.T) {
	cases := []struct {
		name        string
		in          *StaticPolicyResult
		community   bool
		wantVerdict string
		wantReason  string // empty = none required
		wantOblig   string // obligation type (empty = none expected)
	}{
		{
			name:        "nil result is allow",
			in:          nil,
			wantVerdict: VerdictAllow,
		},
		{
			name:        "clean result is allow",
			in:          &StaticPolicyResult{TriggeredPolicies: []string{}},
			wantVerdict: VerdictAllow,
		},
		{
			name:        "blocked is deny with reason",
			in:          &StaticPolicyResult{Blocked: true, Reason: "SQL injection detected", TriggeredPolicies: []string{"sys_sqli_union"}},
			wantVerdict: VerdictDeny,
			wantReason:  "SQL injection detected",
		},
		{
			name:        "requires_approval in enterprise mode is needs_approval",
			in:          &StaticPolicyResult{RequiresApproval: true, TriggeredPolicies: []string{"hitl_eu_ai_act"}},
			community:   false,
			wantVerdict: VerdictNeedsApproval,
			wantReason:  "require_approval",
		},
		{
			name:        "requires_approval in community mode auto-allows (HITL is enterprise-only)",
			in:          &StaticPolicyResult{RequiresApproval: true, TriggeredPolicies: []string{"hitl_eu_ai_act"}},
			community:   true,
			wantVerdict: VerdictAllow,
		},
		{
			name:        "requires_redaction is allow + obligation",
			in:          &StaticPolicyResult{RequiresRedaction: true, Reason: "SSN detected"},
			wantVerdict: VerdictAllow,
			wantOblig:   "redact_pii",
		},
		{
			name:        "blocked takes precedence over redaction",
			in:          &StaticPolicyResult{Blocked: true, Reason: "blocked", RequiresRedaction: true},
			wantVerdict: VerdictDeny,
			wantReason:  "blocked",
		},
		{
			// #2965: a warn/log PII match carries no obligation but must surface
			// an advisory reason, so a matched policy is never a silent allow.
			name:        "advisory match is allow + reason, no obligation",
			in:          &StaticPolicyResult{AdvisoryReasons: []string{"pii-indonesia detected by policy sys_pii_indonesia_ktp (action=log); no redaction applied"}},
			wantVerdict: VerdictAllow,
			wantReason:  "pii-indonesia detected by policy sys_pii_indonesia_ktp (action=log); no redaction applied",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reasons, obligations := mapPolicyResultToVerdict(tc.in, tc.community)
			if verdict != tc.wantVerdict {
				t.Errorf("verdict: got %q want %q", verdict, tc.wantVerdict)
			}
			if tc.wantReason != "" {
				found := false
				for _, r := range reasons {
					if r == tc.wantReason {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("reasons %v missing expected %q", reasons, tc.wantReason)
				}
			}
			if tc.wantOblig != "" {
				found := false
				for _, o := range obligations {
					if o.Type == tc.wantOblig {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("obligations %v missing expected type %q", obligations, tc.wantOblig)
				}
			}
			if reasons == nil {
				t.Error("reasons must always be non-nil for stable JSON output")
			}
			if obligations == nil {
				t.Error("obligations must always be non-nil for stable JSON output")
			}
		})
	}
}

// TestNewRedactPIIObligation_SelfDescribing pins the #2563 contract: every
// redact_pii obligation the PDP emits carries a complete Fulfillment block
// naming the engine endpoint, so a PEP never has to infer how to discharge it
// (and can never be tempted to hand-roll redaction).
func TestNewRedactPIIObligation_SelfDescribing(t *testing.T) {
	ob := newRedactPIIObligation("RBI India PII detected: Aadhaar")
	if ob.Type != ObligationRedactPII {
		t.Fatalf("type=%q want %q", ob.Type, ObligationRedactPII)
	}
	if ob.Detail == "" {
		t.Error("detail should carry the human-readable reason")
	}
	if ob.Fulfillment == nil {
		t.Fatal("obligation is not self-describing: Fulfillment is nil")
	}
	if ob.Fulfillment.Endpoint != requestRedactionEndpoint {
		t.Errorf("endpoint=%q want %q", ob.Fulfillment.Endpoint, requestRedactionEndpoint)
	}
	if ob.Fulfillment.Method != http.MethodPost {
		t.Errorf("method=%q want POST", ob.Fulfillment.Method)
	}
	if ob.Fulfillment.Phase != ObligationPhaseRequest {
		t.Errorf("phase=%q want %q", ob.Fulfillment.Phase, ObligationPhaseRequest)
	}
}

// TestMapPolicyResultToVerdict_ObligationIsFulfillable asserts that the redact
// obligation produced by the verdict mapping is engine-fulfillable (not a bare
// {type,detail}). This is the structural guard against regressing to the
// pre-#2563 obligation shape.
func TestMapPolicyResultToVerdict_ObligationIsFulfillable(t *testing.T) {
	_, _, obligations := mapPolicyResultToVerdict(
		&StaticPolicyResult{RequiresRedaction: true, Reason: "NIK detected"}, false)
	if len(obligations) != 1 {
		t.Fatalf("obligations=%d want 1", len(obligations))
	}
	ob := obligations[0]
	if ob.Type != ObligationRedactPII || ob.Fulfillment == nil {
		t.Fatalf("obligation not self-describing: %+v", ob)
	}
	if ob.Fulfillment.Endpoint != requestRedactionEndpoint || ob.Fulfillment.Phase != ObligationPhaseRequest {
		t.Fatalf("fulfillment wrong: %+v", ob.Fulfillment)
	}
}

// TestDecide_MatchedPIIPolicy_NeverBareAllow is the #2965 CLASS GUARD — the
// item that kills the bug family, not just the pii-indonesia instance. For
// EVERY pii-* category, under every resolved action a PII match can carry, a
// MATCHED policy run through the real convert→verdict pipeline must NEVER return
// verdict=allow with BOTH empty obligations AND empty reasons. A matched policy
// always produces a governance signal (obligation, deny reason, needs_approval,
// or advisory reason). The postures are the RESOLVED match action the engine
// hands convert (block ⇒ Blocked=true; everything else ⇒ non-blocking match).
// require_approval is included specifically because the community-mode branch
// drops HITL — the case R3 round 2 caught the action-aware switch reintroducing
// as a bare allow.
func TestDecide_MatchedPIIPolicy_NeverBareAllow(t *testing.T) {
	// The pii-* category surface. Kept as an explicit list (mirroring
	// shared/policy TestIsPIIPolicyCategory_Convention) with a forward-compat
	// synthetic entry so a future pii-* jurisdiction is auto-covered by the
	// same guard — the convergence onto the shared prefix predicate means a new
	// pii-* category needs no code change here to be governed.
	piiCategories := []sharedpolicy.PolicyCategory{
		sharedpolicy.CategoryPIIGlobal,
		sharedpolicy.CategoryPIIUS,
		sharedpolicy.CategoryPIIIndia,
		sharedpolicy.CategoryPIIEU,
		sharedpolicy.CategoryPIISingapore,
		sharedpolicy.CategoryPIIIndonesia,     // #2965 — the reported instance
		sharedpolicy.PolicyCategory("pii-zz"), // forward-compat: any pii-* is covered
	}
	// The four PII_ACTION postures, expressed as the resolved action the engine
	// stamps onto match.Action (BuildActionOverrides maps PII_ACTION onto every
	// pii-* category identically).
	postures := []struct {
		name    string
		action  sharedpolicy.Action
		blocked bool
	}{
		{"block", sharedpolicy.ActionBlock, true},
		{"redact", sharedpolicy.ActionRedact, false},
		{"warn", sharedpolicy.ActionWarn, false},
		{"log", sharedpolicy.ActionLog, false},
		// Not a PII_ACTION posture (BuildActionOverrides never yields it), but a
		// tenant/dynamic pii-* policy can carry require_approval as its stored
		// action — must still signal, incl. in community mode where HITL is dropped.
		{"require_approval", sharedpolicy.ActionRequireApproval, false},
	}

	for _, cat := range piiCategories {
		for _, p := range postures {
			t.Run(string(cat)+"/"+p.name, func(t *testing.T) {
				rr := &sharedpolicy.RequestResult{
					Blocked: p.blocked,
					MatchedPolicies: []sharedpolicy.PolicyMatch{{
						PolicyID: "sys_" + string(cat),
						Action:   p.action,
						Category: cat,
						Severity: sharedpolicy.SeverityCritical,
					}},
				}
				if p.blocked {
					rr.BlockReason = "blocked by " + string(cat)
				}
				// Run the FULL bridge: convert (shared → static) then the
				// verdict mapping — the exact path /decide uses. Tested in both
				// editions because community drops HITL, which is the axis the
				// require_approval bare-allow regression hid on.
				for _, community := range []bool{false, true} {
					result := convertSharedResultToStatic(rr)
					verdict, reasons, obligations := mapPolicyResultToVerdict(result, community)

					// The property: a matched policy is never a silent allow.
					if verdict == VerdictAllow && len(obligations) == 0 && len(reasons) == 0 {
						t.Fatalf("BARE ALLOW for matched %s under posture %s (community=%v): "+
							"verdict=allow, no obligations, no reasons — a matched policy produced zero governance signal",
							cat, p.name, community)
					}

					// Stronger, posture-specific expectations so the guard can't
					// be satisfied by the wrong signal.
					switch p.name {
					case "block":
						if verdict != VerdictDeny {
							t.Errorf("%s/block community=%v: verdict=%q want deny", cat, community, verdict)
						}
					case "redact":
						if verdict != VerdictAllow || len(obligations) == 0 {
							t.Errorf("%s/redact community=%v: want allow+obligation, got verdict=%q obligations=%d", cat, community, verdict, len(obligations))
						}
					case "warn", "log":
						if verdict != VerdictAllow || len(reasons) == 0 || len(obligations) != 0 {
							t.Errorf("%s/%s community=%v: want allow+reason+no-obligation, got verdict=%q reasons=%d obligations=%d",
								cat, p.name, community, verdict, len(reasons), len(obligations))
						}
					case "require_approval":
						if community {
							// HITL is enterprise-only → community falls through to
							// allow, so the advisory reason is the ONLY signal.
							if verdict != VerdictAllow || len(reasons) == 0 {
								t.Errorf("%s/require_approval community: want allow+advisory-reason, got verdict=%q reasons=%d", cat, verdict, len(reasons))
							}
						} else {
							if verdict != VerdictNeedsApproval {
								t.Errorf("%s/require_approval enterprise: want needs_approval, got verdict=%q", cat, verdict)
							}
						}
					}
				}
			})
		}
	}
}

// TestHandleDecide_VerdictDeny_LiveEngine asserts the handler's deny path
// against the real shared engine. Requires DB-seeded SQLI policies; the
// reference pre-check test (TestPreCheckHandler_PolicyBlock) skips for the
// same reason. Runtime proof under runtime-e2e/2426_decision_api/.
func TestHandleDecide_VerdictDeny_LiveEngine(t *testing.T) {
	t.Skip("Requires DB-seeded SQLI policies — runtime proof under runtime-e2e/2426_decision_api/")
}

// --- Circuit breaker blocks the request (HTTP 503 + Retry-After) ---
//
// The 503 path requires the enterprise circuit-breaker (Trip / Check
// blocking-result paths only exist in the enterprise build of
// platform/agent/circuitbreaker). Under the community build the breaker
// stub always returns Allowed=true. This test exercises what we CAN
// exercise here -- that the handler tolerates a nil-or-allow-only
// breaker without crashing -- and the 503 envelope shape is validated
// in the enterprise build's integration tests.

func TestHandleDecide_CircuitBreakerStubAllows(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "What is the weather today?",
	})
	rr := decideForTest(t, body)
	if rr.Code != http.StatusOK {
		t.Errorf("community-stub breaker should let request through; got %d -- body=%s", rr.Code, rr.Body.String())
	}
}

// --- 400 missing required fields ---

func TestHandleDecide_MissingFields_400(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	cases := []struct {
		name string
		body DecideRequest
		want string
	}{
		{
			name: "missing stage",
			body: DecideRequest{Query: "hello"},
			want: "stage",
		},
		{
			name: "invalid stage",
			body: DecideRequest{Stage: "database", Query: "hello"},
			want: "stage",
		},
		{
			name: "missing query",
			body: DecideRequest{Stage: DecisionStageLLM},
			want: "query",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.body)
			rr := decideForTest(t, b)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status: got %d want 400; body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// --- 400 invalid JSON body ---

func TestHandleDecide_InvalidJSON_400(t *testing.T) {
	rr := decideForTest(t, []byte("{not json"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400; body=%s", rr.Code, rr.Body.String())
	}
}

// --- 401 auth failure in enterprise mode (via auth middleware) ---

func TestHandleDecide_AuthFailure_401(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "What is the weather?",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header -- enterprise mode requires it.

	rr := httptest.NewRecorder()
	apiAuthMiddleware(http.HandlerFunc(handleDecide)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401; body=%s", rr.Code, rr.Body.String())
	}
}

// --- Enterprise-mode service caller without user_token synthesizes a service user (closes H1 from R3 round 1) ---

func TestHandleDecide_EnterpriseMode_ServiceCaller_NoUserToken(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "llm-gateway-01"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "hello",
		// user_token intentionally empty: a PEP gateway is a service, not
		// a human; it should not be forced to forward a JWT.
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Stamp matching enterprise identity into context so the tenant
	// comparison passes and the handler reaches the user-resolution step.
	ctx := req.Context()
	ctx = context.WithValue(ctx, ContextKeyTenantID, "ent-tenant")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "ent-org")
	ctx = context.WithValue(ctx, ContextKeyClientID, "ent-client")
	ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("enterprise service-caller path should succeed: got HTTP %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v -- body=%s", err, rr.Body.String())
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("verdict: got %q want %q", resp.Verdict, VerdictAllow)
	}
	if !isValidW3CTraceID(resp.TraceID) {
		t.Errorf("trace_id %q is not W3C-valid", resp.TraceID)
	}
}

// --- Tenant assertion mismatch (body vs auth) is rejected in non-community mode ---

func TestHandleDecide_TenantMismatch_403(t *testing.T) {
	// Use community mode for the handler-only path -- in enterprise mode
	// the test would need a valid JWT to reach the body-vs-auth comparison.
	// To exercise the comparison we pre-set context tenant != body tenant.
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "different-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "hello",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Stamp a different tenant into context directly so we reach the
	// comparison without the middleware short-circuit.
	ctx := req.Context()
	ctx = context.WithValue(ctx, ContextKeyTenantID, "auth-tenant")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "auth-org")
	ctx = context.WithValue(ctx, ContextKeyClientID, "auth-client")
	ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status: got %d want 403; body=%s", rr.Code, rr.Body.String())
	}
}

// --- W3C traceparent header is reused for trace correlation ---

func TestHandleDecide_TraceIDReusesTraceparent(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	parentTraceID := "0af7651916cd43dd8448eb211c80319c"
	traceparent := "00-" + parentTraceID + "-b7ad6b7169203331-01"

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "What is the weather today?",
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", traceparent)

	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TraceID != parentTraceID {
		t.Errorf("trace_id: got %q want %q (must reuse traceparent for end-to-end correlation)", resp.TraceID, parentTraceID)
	}
}

// --- Malformed traceparent does not contaminate the response ---

func TestHandleDecide_TraceIDFallback_OnMalformedTraceparent(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	cases := []string{
		"",                                // empty
		"garbage",                         // not W3C
		"00-tooshort-b7ad6b7169203331-01", // wrong trace-id length
		"00-00000000000000000000000000000000-b7ad6b7169203331-01", // all-zero trace-id
		"00-NOT_HEX_XXXXXXXXXXXXXXXXXXXXXXXX-b7ad6b7169203331-01", // non-hex
	}
	for _, tp := range cases {
		t.Run(tp, func(t *testing.T) {
			body, _ := json.Marshal(DecideRequest{
				Stage:          DecisionStageLLM,
				CallerIdentity: DecisionCallerIdentity{TenantID: "test-tenant"},
				Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
				Query:          "hello",
			})
			req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			if tp != "" {
				req.Header.Set("traceparent", tp)
			}
			rr := httptest.NewRecorder()
			handleDecide(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
			}
			var resp DecideResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !isValidW3CTraceID(resp.TraceID) {
				t.Errorf("fallback trace_id %q is not W3C-valid", resp.TraceID)
			}
		})
	}
}

// --- hoistBlockingPolicy: blocking ID lands at position 0 ---

func TestHoistBlockingPolicy(t *testing.T) {
	cases := []struct {
		name     string
		in       []string
		blocking string
		want     []string
	}{
		{"empty input prepends", nil, "block_id", []string{"block_id"}},
		{"already first is no-op", []string{"block_id", "redact_id"}, "block_id", []string{"block_id", "redact_id"}},
		{"swap to first when not at 0", []string{"redact_pii", "block_sqli"}, "block_sqli", []string{"block_sqli", "redact_pii"}},
		{"missing prepends", []string{"redact_pii"}, "block_sqli", []string{"block_sqli", "redact_pii"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hoistBlockingPolicy(tc.in, tc.blocking)
			if len(got) != len(tc.want) {
				t.Fatalf("len: got %d want %d (%v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d]: got %q want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// --- decisionExpiresAfter: env override + default fallback + invalid handling ---

func TestDecisionExpiresAfter(t *testing.T) {
	// Default (env unset).
	t.Setenv(envDecisionExpiresAfter, "")
	if got := decisionExpiresAfter(); got != decisionResponseDefaultTTL {
		t.Errorf("default: got %v want %v", got, decisionResponseDefaultTTL)
	}
	// Valid override.
	t.Setenv(envDecisionExpiresAfter, "30s")
	if got := decisionExpiresAfter(); got != 30*time.Second {
		t.Errorf("30s override: got %v", got)
	}
	// Invalid (garbage) -- falls back to default, does not panic.
	t.Setenv(envDecisionExpiresAfter, "not-a-duration")
	if got := decisionExpiresAfter(); got != decisionResponseDefaultTTL {
		t.Errorf("invalid fallback: got %v want %v", got, decisionResponseDefaultTTL)
	}
	// Zero / negative -- treat as invalid and fall back.
	t.Setenv(envDecisionExpiresAfter, "0s")
	if got := decisionExpiresAfter(); got != decisionResponseDefaultTTL {
		t.Errorf("0s fallback: got %v want %v", got, decisionResponseDefaultTTL)
	}
}

// --- RegisterDecisionHandlers wires route on a mux.Router ---

func TestRegisterDecisionHandlers(t *testing.T) {
	r := mux.NewRouter()
	RegisterDecisionHandlers(r)
	match := &mux.RouteMatch{}
	req := httptest.NewRequest("POST", decisionHandlerPath, nil)
	if !r.Match(req, match) {
		t.Errorf("POST %s did not match any route", decisionHandlerPath)
	}
}

// --- writeDecideResponse produces valid JSON with non-nil slices ---

func TestWriteDecideResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	writeDecideResponse(rr, http.StatusOK, DecideResponse{
		Verdict:    VerdictAllow,
		DecisionID: "test-id",
		TraceID:    "abcd1234abcd1234abcd1234abcd1234",
	})
	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d want 200", rr.Code)
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v -- body=%s", err, rr.Body.String())
	}
	if resp.Obligations == nil {
		t.Error("obligations must be non-nil even when empty")
	}
	if resp.EvaluatedPolicies == nil {
		t.Error("evaluated_policies must be non-nil even when empty")
	}
}

// --- Community-mode tenant fallback from body ---

func TestHandleDecide_CommunityModeTenantFallback(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage: DecisionStageAgent,
		CallerIdentity: DecisionCallerIdentity{
			GatewayID: "agent-gw",
			TenantID:  "body-tenant",
			OrgID:     "body-org",
		},
		Target: DecisionTarget{Type: "agent"},
		Query:  "hello from agent gateway",
	})
	rr := decideForTest(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("verdict: got %q want %q", resp.Verdict, VerdictAllow)
	}
	if resp.Stage != DecisionStageAgent {
		t.Errorf("stage: got %q want %q", resp.Stage, DecisionStageAgent)
	}
}

// --- Full handler with all three stages ---

func TestHandleDecide_AllStages(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	for _, stage := range []string{DecisionStageLLM, DecisionStageTool, DecisionStageAgent} {
		t.Run(stage, func(t *testing.T) {
			body, _ := json.Marshal(DecideRequest{
				Stage:          stage,
				CallerIdentity: DecisionCallerIdentity{TenantID: "test"},
				Target:         DecisionTarget{Type: stage},
				Query:          "hello",
			})
			rr := decideForTest(t, body)
			if rr.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
			}
			var resp DecideResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Stage != stage {
				t.Errorf("stage: got %q want %q", resp.Stage, stage)
			}
		})
	}
}

// --- Nil circuit breaker tolerated ---

func TestHandleDecide_NilCircuitBreaker(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineWithMockDB(t)
	old := circuitBreakerInstance
	circuitBreakerInstance = nil
	t.Cleanup(func() { circuitBreakerInstance = old })

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "test"},
		Target:         DecisionTarget{Type: "llm"},
		Query:          "hello",
	})
	rr := decideForTest(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("nil CB should not crash: got %d; body=%s", rr.Code, rr.Body.String())
	}
}

// --- No shared engine → allow (bypass path) ---

func TestHandleDecide_NoSharedEngine(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "test"},
		Target:         DecisionTarget{Type: "llm"},
		Query:          "hello",
	})
	rr := decideForTest(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("no-engine bypass: got %d; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Verdict != VerdictAllow {
		t.Errorf("verdict: got %q want %q", resp.Verdict, VerdictAllow)
	}
}

// --- sendDecideError produces deny verdict in error envelope ---

func TestSendDecideError(t *testing.T) {
	rr := httptest.NewRecorder()
	sendDecideError(rr, "test error", http.StatusBadRequest, "id-1", "trace-1")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rr.Code)
	}
	var env map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env["verdict"] != VerdictDeny {
		t.Errorf("verdict: got %v want %q", env["verdict"], VerdictDeny)
	}
	if env["decision_id"] != "id-1" {
		t.Errorf("decision_id: got %v want 'id-1'", env["decision_id"])
	}
	if env["trace_id"] != "trace-1" {
		t.Errorf("trace_id: got %v want 'trace-1'", env["trace_id"])
	}
}

// --- Helper: validate W3C trace_id shape (32 lowercase hex, not all-zero) ---

func isValidW3CTraceID(s string) bool {
	if len(s) != 32 {
		return false
	}
	if s == "00000000000000000000000000000000" {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ============================================================================
// #2643 — /decide early-return deny audit completeness.
//
// Every early-return deny (decode / invalid stage / empty query / cross-tenant
// & cross-org impersonation / tenant mismatch / rejected user token) must write
// a canonical plane=decision audit_logs row BEFORE returning. Each test below is
// red-on-revert: removing the auditEarlyDeny call (or reverting the canonical
// vocabulary) leaves the INSERT expectation unmet and fails the test.
// ============================================================================

// jsonbBytes extracts the raw JSON bytes from a JSONB driver value (sqlmock
// hands either []byte or string depending on the driver path).
func jsonbBytes(v driver.Value) ([]byte, bool) {
	switch x := v.(type) {
	case []byte:
		return x, true
	case string:
		return []byte(x), true
	default:
		return nil, false
	}
}

// decideSecurityDetailsMatcher asserts the policy_details JSONB carries the
// security-event classification + the attempted (impersonated) identity (#2643).
// Empty want* fields are not checked.
type decideSecurityDetailsMatcher struct {
	wantEvent           string
	wantAttemptedTenant string
	wantAttemptedOrg    string
}

func (m decideSecurityDetailsMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d map[string]interface{}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	if d["security_event"] != m.wantEvent {
		return false
	}
	if m.wantAttemptedTenant != "" && d["attempted_tenant_id"] != m.wantAttemptedTenant {
		return false
	}
	if m.wantAttemptedOrg != "" && d["attempted_org_id"] != m.wantAttemptedOrg {
		return false
	}
	return true
}

// redactedFieldsMatcher asserts the redacted_fields JSONB array column carries
// the wanted field path (#2643 structural fix).
type redactedFieldsMatcher struct{ want string }

func (m redactedFieldsMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var fields []string
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, f := range fields {
		if f == m.want {
			return true
		}
	}
	return false
}

// decideAuditInsertArgs builds the positional WithArgs matcher for the 20-column
// audit_logs INSERT: every column is AnyArg except policy_decision (canonical,
// pos 13), policy_details (optional matcher, pos 14), plane (=decision, pos
// 16) and session_id (pos 20, pinned NULL — #2896: none of these tests stamp a
// client session id under the trust gate, so it must stay NULL). Callers
// override individual positions (e.g. tenant_id pos 8) to assert the actual
// authenticated identity alongside the attempted one.
func decideAuditInsertArgs(policyDecision string, details driver.Value) []driver.Value {
	args := make([]driver.Value, 20)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[12] = policyDecision // policy_decision
	if details != nil {
		args[13] = details // policy_details JSONB
	}
	args[15] = PlaneDecision // plane
	args[19] = nil           // session_id — NULL on untrusted paths (#2896)
	return args
}

// withMockUsageDB swaps the package usageDB for a sqlmock for the duration of a
// test and returns the mock.
func withMockUsageDB(t *testing.T) sqlmock.Sqlmock {
	t.Helper()
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	orig := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = orig })
	return mock
}

// mintUserTokenWithTenant signs an HS256 user token carrying a tenant_id claim,
// so ResolveUser (enterprise) returns a user whose tenant can be made to
// disagree with the authenticated client tenant. jwtSecret must be set first.
func mintUserTokenWithTenant(t *testing.T, tenant string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": tenant,
		"email":     "user@example.com",
		"role":      "user",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwtSecret)
	if err != nil {
		t.Fatalf("mint user token: %v", err)
	}
	return tok
}

// TestCanonicalAuditVerdict pins the wire->canonical mapping (#2643 / #2638):
// allow->allowed, deny->blocked, needs_approval unchanged, canonical values
// idempotent, and any UNKNOWN value fails SAFE to error (never allowed). This
// is the structural guard that the legacy `deny` token can never reach
// audit_logs.policy_decision again.
func TestCanonicalAuditVerdict(t *testing.T) {
	cases := map[string]string{
		VerdictAllow:         AuditVerdictAllowed,
		VerdictDeny:          AuditVerdictBlocked,
		VerdictNeedsApproval: VerdictNeedsApproval,
		AuditVerdictAllowed:  AuditVerdictAllowed,
		AuditVerdictBlocked:  AuditVerdictBlocked,
		AuditVerdictRedacted: AuditVerdictRedacted,
		AuditVerdictError:    AuditVerdictError,
		"some-future-token":  AuditVerdictError, // fail-safe
		"":                   AuditVerdictError, // fail-safe
	}
	for in, want := range cases {
		if got := canonicalAuditVerdict(in); got != want {
			t.Errorf("canonicalAuditVerdict(%q) = %q, want %q", in, got, want)
		}
	}
	if canonicalAuditVerdict(VerdictDeny) == VerdictDeny {
		t.Fatal("wire 'deny' must never be the audit_logs value")
	}
	if canonicalAuditVerdict(VerdictAllow) == VerdictAllow {
		t.Fatal("wire 'allow' must never be the audit_logs value")
	}
}

// TestHandleDecide_AuditsDecodeError_AsError: a malformed body — never evaluated
// — still writes a canonical plane=decision row classified as 'error'.
func TestHandleDecide_AuditsDecodeError_AsError(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(AuditVerdictError, nil)...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	rr := decideForTest(t, []byte("{not json"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("decode-error early deny must write an audit row: %v", err)
	}
}

// TestHandleDecide_AuditsInvalidStage_AsError + EmptyQuery: malformed-request
// validation denies also produce a canonical 'error' row.
func TestHandleDecide_AuditsInvalidStage_AsError(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(AuditVerdictError, nil)...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	b, _ := json.Marshal(DecideRequest{Stage: "database", Query: "hello"})
	rr := decideForTest(t, b)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("invalid-stage early deny must write an audit row: %v", err)
	}
}

func TestHandleDecide_AuditsEmptyQuery_AsError(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(AuditVerdictError, nil)...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	b, _ := json.Marshal(DecideRequest{Stage: DecisionStageLLM, Query: ""})
	rr := decideForTest(t, b)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("empty-query early deny must write an audit row: %v", err)
	}
}

// decideEnterpriseReq builds a handler request with enterprise identity stamped
// into context (no middleware), mirroring TestHandleDecide_TenantMismatch_403.
func decideEnterpriseReq(t *testing.T, body DecideRequest, ctxTenant, ctxOrg string) *http.Request {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	ctx := req.Context()
	ctx = context.WithValue(ctx, ContextKeyTenantID, ctxTenant)
	ctx = context.WithValue(ctx, ContextKeyOrgID, ctxOrg)
	ctx = context.WithValue(ctx, ContextKeyClientID, "auth-client")
	ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
	return req.WithContext(ctx)
}

// TestHandleDecide_AuditsTenantImpersonation_AsBlocked: a body caller_identity
// asserting a DIFFERENT tenant than the authenticated credentials is denied 403
// AND audited as a `blocked` security row capturing attempted-vs-actual.
func TestHandleDecide_AuditsTenantImpersonation_AsBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	mock := withMockUsageDB(t)

	args := decideAuditInsertArgs(AuditVerdictBlocked,
		decideSecurityDetailsMatcher{wantEvent: "tenant_impersonation", wantAttemptedTenant: "victim-tenant"})
	args[7] = "auth-tenant" // tenant_id COLUMN = actual authenticated identity
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "victim-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "hello",
	}, "auth-tenant", "auth-org")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("tenant-impersonation deny must write a blocked audit row: %v", err)
	}
}

// TestHandleDecide_AuditsOrgImpersonation_AsBlocked: a body caller_identity
// asserting a different org (tenant matching) is denied + audited as blocked.
func TestHandleDecide_AuditsOrgImpersonation_AsBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	mock := withMockUsageDB(t)

	args := decideAuditInsertArgs(AuditVerdictBlocked,
		decideSecurityDetailsMatcher{wantEvent: "org_impersonation", wantAttemptedOrg: "victim-org"})
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{TenantID: "auth-tenant", OrgID: "victim-org"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "hello",
	}, "auth-tenant", "auth-org")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("org-impersonation deny must write a blocked audit row: %v", err)
	}
}

// TestHandleDecide_AuditsUserTokenRejected_AsBlocked: an enterprise caller that
// supplies a NON-empty but invalid user_token is a rejected access attempt —
// audited as blocked, not 401-ing invisibly.
func TestHandleDecide_AuditsUserTokenRejected_AsBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })
	mock := withMockUsageDB(t)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(AuditVerdictBlocked,
			decideSecurityDetailsMatcher{wantEvent: "user_token_rejected"})...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:     "hello",
		UserToken: "not.a.valid.jwt",
	}, "ent-tenant", "ent-org")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("rejected user_token must write a blocked audit row: %v", err)
	}
}

// TestHandleDecide_AuditsTenantMismatch_AsBlocked: a VALID user_token whose
// tenant_id claim disagrees with the authenticated client tenant is denied 403
// and audited as a blocked tenant_mismatch capturing the attempted tenant.
func TestHandleDecide_AuditsTenantMismatch_AsBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })
	mock := withMockUsageDB(t)

	token := mintUserTokenWithTenant(t, "other-tenant")

	args := decideAuditInsertArgs(AuditVerdictBlocked,
		decideSecurityDetailsMatcher{wantEvent: "tenant_mismatch", wantAttemptedTenant: "other-tenant"})
	args[7] = "ent-tenant" // tenant_id COLUMN = actual authenticated identity
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	req := decideEnterpriseReq(t, DecideRequest{
		Stage:     DecisionStageLLM,
		Target:    DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:     "hello",
		UserToken: token,
	}, "ent-tenant", "ent-org")
	rr := httptest.NewRecorder()
	handleDecide(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("tenant-mismatch deny must write a blocked audit row: %v", err)
	}
}

// TestWriteDecisionAuditLog_PersistsRedactedFields proves the agent INSERT now
// carries the redacted_fields JSONB column (#2643), previously omitted so only
// the orchestrator BatchWriter populated it.
func TestWriteDecisionAuditLog_PersistsRedactedFields(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	args := decideAuditInsertArgs(AuditVerdictAllowed, nil)
	args[18] = redactedFieldsMatcher{want: "$.customer.ssn"} // redacted_fields column
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	writeDecisionAuditLog(context.Background(), mockDB,
		"dec-rf", "org", "tenant", "llm", VerdictAllow,
		nil, nil, nil, false,
		decisionAuditInput{clientID: "c", redactedFields: []string{"$.customer.ssn"}})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("redacted_fields must be persisted to the agent INSERT: %v", err)
	}
}

// TestWriteDecisionAuditLog_NilDBIncrementsFailureMetric proves the best-effort
// write is OBSERVABLE, not silent (#2643): a nil DB increments the reason=nodb
// failure counter instead of returning silently.
func TestWriteDecisionAuditLog_NilDBIncrementsFailureMetric(t *testing.T) {
	before := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("nodb"))
	writeDecisionAuditLog(context.Background(), nil,
		"dec-x", "o", "t", "llm", VerdictDeny, nil, nil, nil, false,
		decisionAuditInput{})
	after := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("nodb"))
	if after <= before {
		t.Errorf("nil-db write must increment the nodb failure metric: before=%v after=%v", before, after)
	}
}

// TestWriteDecisionAuditLog_InsertFailureIncrementsMetric proves a failing
// INSERT is observable via reason=insert (and never panics — best-effort).
func TestWriteDecisionAuditLog_InsertFailureIncrementsMetric(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnError(errors.New("boom"))

	before := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("insert"))
	writeDecisionAuditLog(context.Background(), mockDB,
		"dec-x", "o", "t", "llm", VerdictDeny, nil, nil, nil, false,
		decisionAuditInput{clientID: "c"})
	after := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("insert"))
	if after <= before {
		t.Errorf("insert failure must increment the insert failure metric: before=%v after=%v", before, after)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestSanitizeAuditIdentity bounds an untrusted attempted identity (#2643).
func TestSanitizeAuditIdentity(t *testing.T) {
	if got := sanitizeAuditIdentity("  tenant-x  "); got != "tenant-x" {
		t.Errorf("trim: got %q", got)
	}
	if got := sanitizeAuditIdentity("ten\x00ant\x07-y"); got != "tenant-y" {
		t.Errorf("strip control: got %q", got)
	}
	if got := sanitizeAuditIdentity(""); got != "" {
		t.Errorf("empty: got %q", got)
	}
	long := strings.Repeat("a", 200)
	if got := sanitizeAuditIdentity(long); len(got) != maxGatewayIDLen {
		t.Errorf("cap: len=%d want %d", len(got), maxGatewayIDLen)
	}
}
