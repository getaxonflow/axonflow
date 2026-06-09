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
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

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
		"",                                                    // empty
		"garbage",                                             // not W3C
		"00-tooshort-b7ad6b7169203331-01",                     // wrong trace-id length
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
