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

// Unit tests for Decision Mode request-context canonicalization +
// persistence (#2509 / epic #2508). canonicalizeRequestContext is a pure
// function, so the full edge-case matrix is table-driven here; the audit
// JSONB write is exercised against sqlmock.

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/telemetry"
)

func TestCanonicalizeRequestContext(t *testing.T) {
	// The default decision-context allowlist.
	allow := defaultDecisionContextAllowlist

	cases := []struct {
		name          string
		raw           map[string]interface{}
		wantKept      map[string]string
		wantTruncated bool
	}{
		{
			name:          "nil input",
			raw:           nil,
			wantKept:      map[string]string{},
			wantTruncated: false,
		},
		{
			name:          "empty input",
			raw:           map[string]interface{}{},
			wantKept:      map[string]string{},
			wantTruncated: false,
		},
		{
			name: "canonicalizes mixed-case hyphenated keys",
			raw: map[string]interface{}{
				"X-AI-Agent":        "claude-code",
				"X-Session-ID":      "sess-abc123",
				"X-Leader-Identity": "leader@example.com",
			},
			wantKept: map[string]string{
				"x_ai_agent":        "claude-code",
				"x_session_id":      "sess-abc123",
				"x_leader_identity": "leader@example.com",
			},
			wantTruncated: false,
		},
		{
			name: "drops keys not on the allowlist",
			raw: map[string]interface{}{
				"X-AI-Agent":    "claude-code",
				"X-Disallowed":  "nope",
				"Authorization": "Bearer secret",
			},
			wantKept:      map[string]string{"x_ai_agent": "claude-code"},
			wantTruncated: false,
		},
		{
			name: "separator-insensitive allowlist match (underscore form)",
			raw: map[string]interface{}{
				"x_ai_agent":   "claude-code",
				"X_Session_ID": "sess-1",
			},
			wantKept: map[string]string{
				"x_ai_agent":   "claude-code",
				"x_session_id": "sess-1",
			},
			wantTruncated: false,
		},
		{
			name: "non-string values are dropped without error",
			raw: map[string]interface{}{
				"X-AI-Agent":   "claude-code",
				"X-Session-ID": 12345, // int → dropped
				"X-Leader-Identity": map[string]interface{}{ // object → dropped
					"nested": "value",
				},
			},
			wantKept:      map[string]string{"x_ai_agent": "claude-code"},
			wantTruncated: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, truncated := canonicalizeRequestContext(tc.raw, allow)
			if truncated != tc.wantTruncated {
				t.Errorf("truncated: got %v want %v", truncated, tc.wantTruncated)
			}
			if !reflect.DeepEqual(kept, tc.wantKept) {
				t.Errorf("kept:\n got  %#v\n want %#v", kept, tc.wantKept)
			}
		})
	}
}

func TestCanonicalizeRequestContext_PrefixAllowlist(t *testing.T) {
	// A configured prefix entry (trailing "*") is matched end-to-end through
	// canonicalizeRequestContext — case- and separator-insensitively — and
	// non-matching keys are dropped.
	allow := []string{"x-tenant-*"}
	kept, truncated := canonicalizeRequestContext(map[string]interface{}{
		"X-Tenant-Merchant": "m-42",
		"x-tenant-region":   "jakarta",
		"x-other":           "drop-me",
	}, allow)
	if truncated {
		t.Errorf("truncated: got true want false")
	}
	want := map[string]string{"x_tenant_merchant": "m-42", "x_tenant_region": "jakarta"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept:\n got  %#v\n want %#v", kept, want)
	}
}

func TestCanonicalizeRequestContext_ValueLengthCap(t *testing.T) {
	long := strings.Repeat("a", 400) // > maxContextValueLen (256)
	kept, truncated := canonicalizeRequestContext(
		map[string]interface{}{"X-AI-Agent": long},
		defaultDecisionContextAllowlist,
	)
	if truncated {
		t.Errorf("value-length cap must not set the key-count truncated flag; got true")
	}
	got := kept["x_ai_agent"]
	if len(got) > maxContextValueLen {
		t.Errorf("value not capped: len=%d want <= %d", len(got), maxContextValueLen)
	}
	if got != strings.Repeat("a", maxContextValueLen) {
		t.Errorf("value cap should keep the first %d bytes; got len=%d", maxContextValueLen, len(got))
	}
}

func TestCanonicalizeRequestContext_StripsUnprintable(t *testing.T) {
	// Embed control chars (NUL, bell, newline) + a zero-width space; all
	// must be stripped, leaving the printable remainder.
	raw := map[string]interface{}{
		"X-AI-Agent": "cla\x00ude\x07-co\nde​",
	}
	kept, _ := canonicalizeRequestContext(raw, defaultDecisionContextAllowlist)
	if got := kept["x_ai_agent"]; got != "claude-code" {
		t.Errorf("unprintable strip: got %q want %q", got, "claude-code")
	}
}

func TestCanonicalizeRequestContext_KeyCountCap(t *testing.T) {
	// 12 distinct allowlisted keys (x-tenant-k00..k11) > maxContextKeys (10).
	allow := []string{"x-tenant-*"}
	raw := make(map[string]interface{}, 12)
	for i := 0; i < 12; i++ {
		raw[fmt.Sprintf("x-tenant-k%02d", i)] = fmt.Sprintf("v%02d", i)
	}
	kept, truncated := canonicalizeRequestContext(raw, allow)
	if !truncated {
		t.Fatal("expected truncated=true when key count exceeds the cap")
	}
	if len(kept) != maxContextKeys {
		t.Fatalf("kept %d keys, want exactly %d", len(kept), maxContextKeys)
	}
	// Deterministic: sorted keys keep k00..k09, drop k10/k11.
	if _, ok := kept["x_tenant_k00"]; !ok {
		t.Error("sorted cap must keep x_tenant_k00")
	}
	if _, ok := kept["x_tenant_k11"]; ok {
		t.Error("sorted cap must drop x_tenant_k11")
	}
}

func TestCanonicalizeRequestContext_ExactlyCapNotTruncated(t *testing.T) {
	allow := []string{"x-tenant-*"}
	raw := make(map[string]interface{}, maxContextKeys)
	for i := 0; i < maxContextKeys; i++ {
		raw[fmt.Sprintf("x-tenant-k%02d", i)] = fmt.Sprintf("v%02d", i)
	}
	kept, truncated := canonicalizeRequestContext(raw, allow)
	if truncated {
		t.Errorf("exactly maxContextKeys must NOT be flagged truncated")
	}
	if len(kept) != maxContextKeys {
		t.Errorf("kept %d, want %d", len(kept), maxContextKeys)
	}
}

func TestCanonicalizeRequestContext_CollisionIsDeterministic(t *testing.T) {
	// Two allowlisted raw keys whose 32-char canonical forms collide. The
	// result must be deterministic (first sorted raw key wins), not a random
	// map-iteration winner. Both share the first 32 canonical chars; the
	// distinguishing AAA/BBB suffix sits past the 32-char canonical cap (the
	// stem is intentionally long enough to keep that true).
	allow := []string{"x-tenant-*"}
	raw := map[string]interface{}{
		"x-tenant-merchant-region-alpha-zone-AAA": "first",
		"x-tenant-merchant-region-alpha-zone-BBB": "second",
	}
	ck := canonicalContextKey("x-tenant-merchant-region-alpha-zone-AAA")
	// Sanity: confirm the two raw keys actually collide post-canonicalization.
	if ck != canonicalContextKey("x-tenant-merchant-region-alpha-zone-BBB") {
		t.Skip("test inputs no longer collide; adjust fixture")
	}
	for i := 0; i < 50; i++ {
		kept, _ := canonicalizeRequestContext(raw, allow)
		if len(kept) != 1 {
			t.Fatalf("collision must collapse to 1 key, got %d", len(kept))
		}
		if kept[ck] != "first" {
			t.Fatalf("collision winner must be deterministic (first sorted raw key='first'), got %q", kept[ck])
		}
	}
}

func TestCanonicalContextKey(t *testing.T) {
	cases := map[string]string{
		"X-AI-Agent":            "x_ai_agent",
		"x-session-id":          "x_session_id",
		"X_Leader_Identity":     "x_leader_identity",
		"  X-Tenant-Region ":    "x_tenant_region",
		"---":                   "",                                    // nothing alphanumeric
		"":                      "",                                    // empty
		"A!!!B":                 "a_b",                                 // collapse non-alnum run
		strings.Repeat("a", 50): strings.Repeat("a", maxContextKeyLen), // length cap
	}
	for in, want := range cases {
		if got := canonicalContextKey(in); got != want {
			t.Errorf("canonicalContextKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchContextAllowlist(t *testing.T) {
	allow := []string{"x-ai-agent", "x-session-id", "x-tenant-*"}
	yes := []string{"X-AI-Agent", "x-ai-agent", "x_ai_agent", "X-Session-ID", "x-tenant-merchant", "X-Tenant-Anything"}
	no := []string{"authorization", "x-disallowed", "x-ten", "", "tenant-x"}
	for _, k := range yes {
		if !matchContextAllowlist(k, allow) {
			t.Errorf("matchContextAllowlist(%q) = false, want true", k)
		}
	}
	for _, k := range no {
		if matchContextAllowlist(k, allow) {
			t.Errorf("matchContextAllowlist(%q) = true, want false", k)
		}
	}
}

func TestDecisionContextAllowlist_EnvOverride(t *testing.T) {
	// Unset → default.
	t.Setenv(envDecisionContextAllowlist, "")
	if got := decisionContextAllowlist(); !reflect.DeepEqual(got, defaultDecisionContextAllowlist) {
		t.Errorf("empty env should yield default; got %v", got)
	}
	// Custom comma list, with blanks trimmed.
	t.Setenv(envDecisionContextAllowlist, " x-foo , ,x-bar-* ")
	got := decisionContextAllowlist()
	want := []string{"x-foo", "x-bar-*"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("custom allowlist parse: got %v want %v", got, want)
	}
	// Only-blanks override falls back to default rather than disabling capture.
	t.Setenv(envDecisionContextAllowlist, " , , ")
	if got := decisionContextAllowlist(); !reflect.DeepEqual(got, defaultDecisionContextAllowlist) {
		t.Errorf("only-blanks override should fall back to default; got %v", got)
	}
}

// policyDetailsHasContext is a sqlmock argument matcher asserting the
// policy_details JSONB carries the expected context map + decision_id.
type policyDetailsHasContext struct {
	wantDecisionID string
	wantContext    map[string]string
	wantTruncated  bool
}

func (m policyDetailsHasContext) Match(v driver.Value) bool {
	var raw []byte
	switch x := v.(type) {
	case []byte:
		raw = x
	case string:
		raw = []byte(x)
	default:
		return false
	}
	var details map[string]interface{}
	if err := json.Unmarshal(raw, &details); err != nil {
		return false
	}
	if details["decision_id"] != m.wantDecisionID {
		return false
	}
	ctx, ok := details["context"].(map[string]interface{})
	if !ok {
		return false
	}
	for k, want := range m.wantContext {
		if ctx[k] != want {
			return false
		}
	}
	if m.wantTruncated {
		if t, _ := details["context_truncated"].(bool); !t {
			return false
		}
	}
	return true
}

func TestWriteDecisionAuditLog_PersistsContextJSONB(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	reqContext := map[string]string{
		"x_ai_agent":   "claude-code",
		"x_session_id": "sess-abc123",
	}

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			"decide_dec-1",       // id
			"dec-1",              // request_id
			sqlmock.AnyArg(),     // timestamp
			7,                    // user_id
			"svc@axonflow.local", // user_email
			"service",            // user_role
			"client-x",           // client_id
			"tenant-rocket",      // tenant_id
			"org-acme",           // org_id
			"decision_llm",       // request_type
			"hello",              // query
			sqlmock.AnyArg(),     // query_hash
			"allowed",            // policy_decision canonicalized from wire "allow" (#2643)
			policyDetailsHasContext{
				wantDecisionID: "dec-1",
				wantContext:    reqContext,
			},
			"dec-1",         // decision_id (first-class column; #2592)
			PlaneDecision,   // plane defaults to decision (input.plane unset)
			nil,             // obligations (none)
			"trace-corr-99", // correlation_id (#2598): the shared cross-stage key
			nil,             // redacted_fields (#2643): unset on input → NULL
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	writeDecisionAuditLog(context.Background(), mockDB,
		"dec-1", "org-acme", "tenant-rocket", "llm", "allow",
		[]string{"p_pii_us"}, []string{"clean"},
		reqContext, false,
		decisionAuditInput{
			clientID:      "client-x",
			requestID:     "dec-1",
			userEmail:     "svc@axonflow.local",
			userRole:      "service",
			userID:        7,
			query:         "hello",
			correlationID: "trace-corr-99",
		},
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestWriteDecisionAuditLog_NilDBIsNoop(t *testing.T) {
	// Must not panic when usageDB is unset (best-effort audit).
	writeDecisionAuditLog(context.Background(), nil,
		"dec-1", "org", "tenant", "llm", "allow", nil, nil, nil, false,
		decisionAuditInput{})
}

// TestRecordDecideDecision_NilAuditSkipsWrite proves the OpenAI-compat
// contract: when recordDecideDecision is called with audit==nil (the 5
// openai_compat_handler.go call sites), NO audit_logs row is written — that
// caller persists via recordOpenAICompatAudit → llm_call_audits instead.
// We assert the absence by leaving an INSERT expectation UNMET.
func TestRecordDecideDecision_NilAuditSkipsWrite(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// If the nil-audit path wrongly wrote, this expectation would be met.
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	// decisionTracerProvider is nil in unit tests → returns the fallback
	// trace id; the nil context/audit means no span attrs + no DB write.
	got := recordDecideDecision(context.Background(),
		"dec-x", "org", "tenant", "llm", "allow", nil, 1, nil,
		"fallbacktrace", nil, false, nil)
	if got != "fallbacktrace" {
		t.Errorf("expected fallback trace id passthrough, got %q", got)
	}
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Error("audit_logs INSERT must NOT fire on the nil-audit (OpenAI-compat) path")
	}
}

// TestRecordDecideDecision_WithTracerAndAudit covers the tracer-wired branch:
// a non-nil provider (noop here, returns "") + a non-nil audit input → the
// audit_logs INSERT fires AND the function falls back to the supplied trace id
// because the noop tracer yields "".
func TestRecordDecideDecision_WithTracerAndAudit(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// Empty AXONFLOW_OTEL_ENDPOINT → noop provider (non-nil; RecordDecision "").
	t.Setenv("AXONFLOW_OTEL_ENDPOINT", "")
	origProvider := decisionTracerProvider
	decisionTracerProvider = telemetry.NewDecisionTracer(context.Background())
	defer func() { decisionTracerProvider = origProvider }()

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			"decide_dec-t", "dec-t", sqlmock.AnyArg(), 0,
			"u@x.local", "service", "client", "tenant", "org",
			"decision_tool", "q", sqlmock.AnyArg(), "blocked", // policy_decision canonicalized from wire "deny" (#2643)
			policyDetailsHasContext{wantDecisionID: "dec-t", wantContext: map[string]string{"x_ai_agent": "claude-code"}, wantTruncated: true},
			"dec-t",       // decision_id (first-class column; #2592)
			PlaneDecision, // plane defaults to decision
			nil,           // obligations (none)
			nil,           // correlation_id (#2598): unset on input → NULL
			nil,           // redacted_fields (#2643): unset on input → NULL
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	got := recordDecideDecision(context.Background(),
		"dec-t", "org", "tenant", "tool", "deny",
		[]string{"pol-x"}, 3, []string{"blocked"},
		"fallback-trace", map[string]string{"x_ai_agent": "claude-code"}, true,
		&decisionAuditInput{clientID: "client", requestID: "dec-t", userEmail: "u@x.local", userRole: "service", query: "q"})

	if got != "fallback-trace" {
		t.Errorf("noop tracer should yield fallback trace id, got %q", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestWriteDecisionAuditLog_FallbackPlaceholders covers the NOT-NULL-column
// fallback branches (empty identity → placeholders) + the no-reason / no-context
// path (reason key omitted, context key omitted).
func TestWriteDecisionAuditLog_FallbackPlaceholders(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			"decide_dec-fb", "dec-fb", sqlmock.AnyArg(), 0,
			"unknown@axonflow.local",  // user_email fallback
			"service",                 // user_role fallback
			"unknown",                 // client_id fallback
			"unknown",                 // tenant_id fallback
			"",                        // org_id (empty allowed; nullable)
			"decision_llm", "(empty)", // request_type + query fallback
			sqlmock.AnyArg(), "allowed", // policy_decision canonicalized from wire "allow" (#2643)
			sqlmock.AnyArg(), // policy_details — no reason/context keys
			"dec-fb",         // decision_id (first-class column; #2592)
			PlaneDecision,    // plane defaults to decision (input.plane unset)
			nil,              // obligations (none)
			nil,              // correlation_id (#2598): unset on input → NULL
			nil,              // redacted_fields (#2643): unset on input → NULL
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	writeDecisionAuditLog(context.Background(), mockDB,
		"dec-fb", "", "", "llm", "allow",
		nil, nil, nil, false,
		decisionAuditInput{}) // all identity fields empty

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestWriteDecisionAuditLog_InsertErrorIsNonFatal covers the error-log branch:
// a failing INSERT must not panic (audit is best-effort).
func TestWriteDecisionAuditLog_InsertErrorIsNonFatal(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	mock.ExpectExec("INSERT INTO audit_logs").WillReturnError(errors.New("boom"))

	writeDecisionAuditLog(context.Background(), mockDB,
		"dec-err", "org", "tenant", "llm", "deny",
		[]string{"p"}, []string{"r"}, map[string]string{"x_ai_agent": "a"}, false,
		decisionAuditInput{clientID: "c", userEmail: "e@x", userRole: "user", query: "q"})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// policyDetailsHasGatewayID is a sqlmock matcher asserting the audit row's
// policy_details JSONB carries gateway_id (#2520 Claude Desktop origin).
type policyDetailsHasGatewayID struct {
	wantGatewayID string
}

func (m policyDetailsHasGatewayID) Match(v driver.Value) bool {
	var raw []byte
	switch x := v.(type) {
	case []byte:
		raw = x
	case string:
		raw = []byte(x)
	default:
		return false
	}
	var details map[string]interface{}
	if err := json.Unmarshal(raw, &details); err != nil {
		return false
	}
	return details["gateway_id"] == m.wantGatewayID
}

// TestWriteDecisionAuditLog_PersistsGatewayID proves a claude_desktop.* origin
// lands at policy_details->>'gateway_id' so Desktop traffic is distinguishable
// in the audit trail (#2520).
func TestWriteDecisionAuditLog_PersistsGatewayID(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			"decide_dec-gw", "dec-gw", sqlmock.AnyArg(), 7,
			"svc@axonflow.local", "service", "client-x", "tenant-rocket",
			"org-acme", "decision_tool", "list merchants", sqlmock.AnyArg(),
			"allowed", // policy_decision canonicalized from wire "allow" (#2643)
			policyDetailsHasGatewayID{wantGatewayID: "claude_desktop.fleet-mac"},
			"dec-gw",      // decision_id (first-class column; #2592)
			PlaneDecision, // plane defaults to decision
			nil,           // obligations (none)
			nil,           // correlation_id (#2598): unset on input → NULL
			nil,           // redacted_fields (#2643): unset on input → NULL
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	writeDecisionAuditLog(context.Background(), mockDB,
		"dec-gw", "org-acme", "tenant-rocket", "tool", "allow",
		[]string{"p_clean"}, []string{"clean"}, nil, false,
		decisionAuditInput{
			clientID:  "client-x",
			requestID: "dec-gw",
			userEmail: "svc@axonflow.local",
			userRole:  "service",
			userID:    7,
			query:     "list merchants",
			gatewayID: "claude_desktop.fleet-mac",
		},
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// obligationsJSONMatcher asserts the audit row's obligations JSONB column
// carries an obligation of the wanted type (#2592 / ADR-058 Phase 1).
type obligationsJSONMatcher struct {
	wantType string
}

func (m obligationsJSONMatcher) Match(v driver.Value) bool {
	var raw []byte
	switch x := v.(type) {
	case []byte:
		raw = x
	case string:
		raw = []byte(x)
	default:
		return false
	}
	var obs []DecisionObligation
	if err := json.Unmarshal(raw, &obs); err != nil {
		return false
	}
	for _, o := range obs {
		if o.Type == m.wantType {
			return true
		}
	}
	return false
}

// TestWriteDecisionAuditLog_PersistsPlaneAndObligations is the #2592 red-on-revert
// guard for the writer half: the audit row must carry the first-class
// decision_id column, the plane taken from the audit input (NOT the default),
// and the structured obligations JSONB (not flattened into reasons). If the
// writer stops appending these columns the positional WithArgs match fails.
func TestWriteDecisionAuditLog_PersistsPlaneAndObligations(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			"decide_dec-ob", "dec-ob", sqlmock.AnyArg(), 7,
			"svc@axonflow.local", "service", "client-x", "tenant-rocket",
			"org-acme", "decision_tool", "lookup merchant", sqlmock.AnyArg(),
			"allow",          // policy_decision — plane=mcp is NOT canonicalized (#2643 scopes to plane=decision)
			sqlmock.AnyArg(), // policy_details JSONB
			"dec-ob",         // decision_id (first-class column)
			PlaneMCP,         // plane from the audit input (not the default)
			obligationsJSONMatcher{wantType: ObligationRedactPII}, // obligations JSONB
			nil, // correlation_id (#2598): unset on input → NULL
			nil, // redacted_fields (#2643): unset on input → NULL
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	writeDecisionAuditLog(context.Background(), mockDB,
		"dec-ob", "org-acme", "tenant-rocket", "tool", "allow",
		[]string{"pii-id"}, []string{"redact"}, nil, false,
		decisionAuditInput{
			clientID:    "client-x",
			requestID:   "dec-ob",
			userEmail:   "svc@axonflow.local",
			userRole:    "service",
			userID:      7,
			query:       "lookup merchant",
			plane:       PlaneMCP,
			obligations: []DecisionObligation{newRedactPIIObligation("NIK detected")},
		},
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestSanitizeGatewayID(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "claude_desktop.host-x", "claude_desktop.host-x"},
		{"trims", "  claude_desktop.h  ", "claude_desktop.h"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"strips control", "claude_desktop.\x00\x07host", "claude_desktop.host"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeGatewayID(c.in); got != c.want {
				t.Fatalf("sanitizeGatewayID(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
	// Length cap: a 200-char id is capped to maxGatewayIDLen.
	long := ""
	for i := 0; i < 200; i++ {
		long += "a"
	}
	if got := sanitizeGatewayID(long); len(got) != maxGatewayIDLen {
		t.Fatalf("oversize gateway_id not capped: len=%d want=%d", len(got), maxGatewayIDLen)
	}
}
