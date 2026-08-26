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

package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// mockPolicyRefresher is a test double for PolicyEngineRefresher.
type mockPolicyRefresher struct {
	called bool
}

func (m *mockPolicyRefresher) RefreshPolicies() error {
	m.called = true
	return nil
}

func TestNewPolicyServiceWithRefresher(t *testing.T) {
	repo := &PolicyRepository{} // nil db is fine for constructor test
	refresher := &mockPolicyRefresher{}

	service := NewPolicyServiceWithRefresher(repo, refresher)

	if service == nil {
		t.Fatal("NewPolicyServiceWithRefresher() returned nil")
	}
	if service.repo != repo {
		t.Error("Expected service.repo to match the provided repository")
	}
	if service.policyRefresher == nil {
		t.Error("Expected service.policyRefresher to be set")
	}
	if service.policyEngine != nil {
		t.Error("Expected service.policyEngine to be nil (not provided)")
	}
	if service.licenseChecker == nil {
		t.Error("Expected service.licenseChecker to be set (default env checker)")
	}
}

func TestNewPolicyServiceWithRefresher_NilRefresher(t *testing.T) {
	repo := &PolicyRepository{}

	service := NewPolicyServiceWithRefresher(repo, nil)

	if service == nil {
		t.Fatal("NewPolicyServiceWithRefresher() with nil refresher returned nil")
	}
	if service.policyRefresher != nil {
		t.Error("Expected service.policyRefresher to be nil when nil is passed")
	}
	if service.licenseChecker == nil {
		t.Error("Expected service.licenseChecker to be set")
	}
}

func TestNewPolicyServiceWithLicense(t *testing.T) {
	repo := &PolicyRepository{}
	engine := &fakeSegmentLookuper{}
	lc := NewEnvLicenseChecker()

	service := NewPolicyServiceWithLicense(repo, engine, lc)

	if service == nil {
		t.Fatal("NewPolicyServiceWithLicense() returned nil")
	}
	if service.repo != repo {
		t.Error("Expected service.repo to match")
	}
	if service.policyEngine != engine {
		t.Error("Expected service.policyEngine to match")
	}
	if service.licenseChecker != lc {
		t.Error("Expected service.licenseChecker to match")
	}
}

// #3296: the four tests below (TestPolicyService_EvaluateCondition,
// TestPolicyService_EvaluateConditions, TestPolicyTestEvaluator_Operators,
// TestPolicyService_EvaluateCondition_Additional) were relocated here from
// policy_api_handlers_test.go — they exercise PolicyService.evaluateCondition
// / evaluateConditions (policy_api_service.go), not anything in the HTTP
// handler file they used to live in. TestPolicyService_EvaluateOperator_Additional
// was renamed to TestPolicyTestEvaluator_Operators and rewritten to call the
// shared policyTestEvaluator directly, since PolicyService.evaluateOperator
// was deleted (#3296) — its comparison logic now lives in
// platform/shared/policy/condition_evaluator.go.

func TestPolicyService_EvaluateCondition(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name      string
		condition PolicyCondition
		request   *TestPolicyRequest
		want      bool
	}{
		{
			name:      "contains - match",
			condition: PolicyCondition{Field: "query", Operator: "contains", Value: "password"},
			request:   &TestPolicyRequest{Query: "Show me the password for admin"},
			want:      true,
		},
		{
			name:      "contains - no match",
			condition: PolicyCondition{Field: "query", Operator: "contains", Value: "password"},
			request:   &TestPolicyRequest{Query: "Show me the weather"},
			want:      false,
		},
		{
			name:      "equals - match",
			condition: PolicyCondition{Field: "request_type", Operator: "equals", Value: "query"},
			request:   &TestPolicyRequest{RequestType: "query"},
			want:      true,
		},
		{
			name:      "equals - no match",
			condition: PolicyCondition{Field: "request_type", Operator: "equals", Value: "mutation"},
			request:   &TestPolicyRequest{RequestType: "query"},
			want:      false,
		},
		{
			name:      "regex - match SSN pattern",
			condition: PolicyCondition{Field: "query", Operator: "regex", Value: `\d{3}-\d{2}-\d{4}`},
			request:   &TestPolicyRequest{Query: "Find record for 123-45-6789"},
			want:      true,
		},
		{
			name:      "regex - no match",
			condition: PolicyCondition{Field: "query", Operator: "regex", Value: `\d{3}-\d{2}-\d{4}`},
			request:   &TestPolicyRequest{Query: "Find record for John Doe"},
			want:      false,
		},
		{
			name:      "user field - match",
			condition: PolicyCondition{Field: "user.role", Operator: "equals", Value: "admin"},
			request:   &TestPolicyRequest{User: map[string]interface{}{"role": "admin"}},
			want:      true,
		},
		{
			name: "contains_any - match",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "contains_any",
				Value:    []interface{}{"ssn", "password", "secret"},
			},
			request: &TestPolicyRequest{Query: "Show me the password"},
			want:    true,
		},
		{
			name: "in - match",
			condition: PolicyCondition{
				Field:    "request_type",
				Operator: "in",
				Value:    []interface{}{"query", "mutation"},
			},
			request: &TestPolicyRequest{RequestType: "query"},
			want:    true,
		},
		{
			name: "not_in - match",
			condition: PolicyCondition{
				Field:    "request_type",
				Operator: "not_in",
				Value:    []interface{}{"admin", "delete"},
			},
			request: &TestPolicyRequest{RequestType: "query"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.evaluateCondition(tt.condition, tt.request)
			if got != tt.want {
				t.Errorf("evaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyService_EvaluateConditions(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name       string
		conditions []PolicyCondition
		request    *TestPolicyRequest
		want       bool
	}{
		{
			name: "all conditions match",
			conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "password"},
				{Field: "request_type", Operator: "equals", Value: "query"},
			},
			request: &TestPolicyRequest{
				Query:       "show me the password",
				RequestType: "query",
			},
			want: true,
		},
		{
			name: "first condition fails",
			conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "secret"},
				{Field: "request_type", Operator: "equals", Value: "query"},
			},
			request: &TestPolicyRequest{
				Query:       "show me the password",
				RequestType: "query",
			},
			want: false,
		},
		{
			name: "second condition fails",
			conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "password"},
				{Field: "request_type", Operator: "equals", Value: "mutation"},
			},
			request: &TestPolicyRequest{
				Query:       "show me the password",
				RequestType: "query",
			},
			want: false,
		},
		{
			// AND over an empty set is vacuously true — zero conditions
			// means the policy applies to everything. See
			// TestEvaluateConditions_EmptyConditionsMatchEverything below
			// for the dedicated regression test and
			// platform/shared/policy/condition_evaluator.go's "Withdrawn"
			// doc section for why a stricter "zero conditions never
			// matches" behavior briefly shipped and was reverted.
			name:       "empty conditions match everything",
			conditions: []PolicyCondition{},
			request: &TestPolicyRequest{
				Query: "anything",
			},
			want: true,
		},
		{
			name:       "nil conditions match everything",
			conditions: nil,
			request: &TestPolicyRequest{
				Query: "anything",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.evaluateConditions(tt.conditions, tt.request)
			if got != tt.want {
				t.Errorf("evaluateConditions() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEvaluateConditions_EmptyConditionsMatchEverything is the dedicated
// regression test for this call site's restored semantics:
// PolicyService.evaluateConditions falls through its AND-loop and
// vacuously returns true for a zero-condition policy
// (TestPolicyService_EvaluateConditions's "empty conditions" case above).
// Creation and update both reject an empty/cleared conditions array, so a
// zero-condition policy reaching TestPolicy at all means a platform-seeded,
// deliberately-unconditional row.
func TestEvaluateConditions_EmptyConditionsMatchEverything(t *testing.T) {
	service := &PolicyService{}
	got := service.evaluateConditions(nil, &TestPolicyRequest{Query: "anything"})
	if !got {
		t.Fatalf("zero conditions must match everything, got false")
	}
}

// TestPolicyTestEvaluator_Operators pins the exact preconfigured shared
// evaluator (policyTestEvaluator, policy_api_service.go) PolicyService uses —
// the direct successor of the deleted PolicyService.evaluateOperator, whose
// comparison logic now lives in
// platform/shared/policy/condition_evaluator.go. contains_any stringifies a
// non-string list item on every caller now (#3296 convergence 2) — see
// TestEvaluateCondition_ContainsAny_NonStringItemStringified in
// db_dynamic_policies_test.go for the same behavior proven on the database
// engine.
func TestPolicyTestEvaluator_Operators(t *testing.T) {
	tests := []struct {
		name           string
		operator       string
		fieldValue     interface{}
		conditionValue interface{}
		want           bool
	}{
		{
			name:           "not_equals match",
			operator:       "not_equals",
			fieldValue:     "foo",
			conditionValue: "bar",
			want:           true,
		},
		{
			name:           "not_equals no match",
			operator:       "not_equals",
			fieldValue:     "foo",
			conditionValue: "foo",
			want:           false,
		},
		{
			name:           "not_contains match",
			operator:       "not_contains",
			fieldValue:     "hello world",
			conditionValue: "foo",
			want:           true,
		},
		{
			name:           "not_contains no match",
			operator:       "not_contains",
			fieldValue:     "hello world",
			conditionValue: "world",
			want:           false,
		},
		{
			name:           "contains_any no match",
			operator:       "contains_any",
			fieldValue:     "hello world",
			conditionValue: []interface{}{"foo", "bar"},
			want:           false,
		},
		{
			name:           "contains_any stringifies a non-string item (1e distinctive knob)",
			operator:       "contains_any",
			fieldValue:     "risk score is 0.9 today",
			conditionValue: []interface{}{0.9},
			want:           true,
		},
		{
			name:           "regex invalid pattern",
			operator:       "regex",
			fieldValue:     "test",
			conditionValue: "[invalid",
			want:           false,
		},
		{
			name:           "regex non-string value",
			operator:       "regex",
			fieldValue:     "test",
			conditionValue: 123,
			want:           false,
		},
		{
			name:           "in no match",
			operator:       "in",
			fieldValue:     "foo",
			conditionValue: []interface{}{"bar", "baz"},
			want:           false,
		},
		{
			name:           "not_in match when value not in list",
			operator:       "not_in",
			fieldValue:     "foo",
			conditionValue: []interface{}{"bar", "baz"},
			want:           true,
		},
		{
			name:           "not_in no match when value in list",
			operator:       "not_in",
			fieldValue:     "bar",
			conditionValue: []interface{}{"bar", "baz"},
			want:           false,
		},
		{
			name:           "unknown operator",
			operator:       "unknown_op",
			fieldValue:     "foo",
			conditionValue: "bar",
			want:           false,
		},
		{
			// #3296 convergence 5: greater_than/less_than were excluded on
			// this evaluator (1e's legacy switch never implemented them) —
			// that exclusion is gone, closing the operator-parity gap with
			// the other three call sites. See TestPolicyTestEvaluator_AllTenOperatorsSupported
			// below for the full ten-operator proof.
			name:           "greater_than is now supported (1e's exclusion was deleted in #3296)",
			operator:       "greater_than",
			fieldValue:     10,
			conditionValue: 5,
			want:           true,
		},
		{
			name:           "less_than is now supported (1e's exclusion was deleted in #3296)",
			operator:       "less_than",
			fieldValue:     5,
			conditionValue: 10,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyTestEvaluator.Match(
				sharedpolicy.MatchCondition{Operator: tt.operator, Value: tt.conditionValue},
				func(string) (any, bool) { return tt.fieldValue, true },
				nil,
			)
			if got != tt.want {
				t.Errorf("policyTestEvaluator.Match(%s) = %v, want %v", tt.operator, got, tt.want)
			}
		})
	}
}

// TestPolicyTestEvaluator_AllTenOperatorsSupported is the #3296 convergence
// 5 proof for this call site: PolicyService.evaluateOperator's legacy switch
// excluded greater_than/less_than (8 of 10 operators); every one of the ten
// now evaluates for real through policyTestEvaluator.
func TestPolicyTestEvaluator_AllTenOperatorsSupported(t *testing.T) {
	tests := []struct {
		operator       string
		fieldValue     interface{}
		conditionValue interface{}
		want           bool
	}{
		{"equals", "x", "x", true},
		{"not_equals", "x", "y", true},
		{"contains", "hello world", "wor", true},
		{"not_contains", "hello world", "zzz", true},
		{"contains_any", "hello world", []interface{}{"zzz", "wor"}, true},
		{"greater_than", 5.0, 1.0, true},
		{"less_than", 1.0, 5.0, true},
		{"regex", "hello", "^hel+o", true},
		{"in", "b", []interface{}{"a", "b"}, true},
		{"not_in", "z", []interface{}{"a", "b"}, true},
	}
	if len(tests) != 10 {
		t.Fatalf("expected exactly 10 operators under test, got %d", len(tests))
	}
	for _, tt := range tests {
		t.Run(tt.operator, func(t *testing.T) {
			got := policyTestEvaluator.Match(
				sharedpolicy.MatchCondition{Operator: tt.operator, Value: tt.conditionValue},
				func(string) (any, bool) { return tt.fieldValue, true },
				nil,
			)
			if got != tt.want {
				t.Errorf("operator %q must evaluate for real on the policy-test evaluator, got %v want %v", tt.operator, got, tt.want)
			}
		})
	}
}

func TestPolicyService_EvaluateCondition_Additional(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name      string
		condition PolicyCondition
		request   *TestPolicyRequest
		want      bool
	}{
		{
			name:      "context field match",
			condition: PolicyCondition{Field: "context.env", Operator: "equals", Value: "production"},
			request: &TestPolicyRequest{
				Context: map[string]interface{}{"env": "production"},
			},
			want: true,
		},
		{
			name:      "context field no match",
			condition: PolicyCondition{Field: "context.env", Operator: "equals", Value: "production"},
			request: &TestPolicyRequest{
				Context: map[string]interface{}{"env": "staging"},
			},
			want: false,
		},
		{
			name:      "user field nil user",
			condition: PolicyCondition{Field: "user.role", Operator: "equals", Value: "admin"},
			request:   &TestPolicyRequest{User: nil},
			want:      false,
		},
		{
			name:      "unknown field",
			condition: PolicyCondition{Field: "unknown_field", Operator: "equals", Value: "test"},
			request:   &TestPolicyRequest{Query: "test"},
			want:      false,
		},
		{
			// #3296 R3: an unresolvable field must short-circuit to false
			// regardless of operator — proves the ok=false short-circuit in
			// policyTestFieldValue actually runs BEFORE Match, not merely
			// "resolves to nil and lets the operator switch decide". A naive
			// wiring (resolve nil, always ok=true) would make this a spurious
			// MATCH ("<nil>" != "admin"), silently widening what an
			// unresolvable-field not_equals condition matches.
			name:      "unknown field with not_equals must not spuriously match",
			condition: PolicyCondition{Field: "unknown_field", Operator: "not_equals", Value: "admin"},
			request:   &TestPolicyRequest{Query: "test"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.evaluateCondition(tt.condition, tt.request)
			if got != tt.want {
				t.Errorf("evaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- #3296: TestPolicy segment-awareness ---
//
// applySegmentScopeToTestVerdict is exercised directly (rather than only
// through the full TestPolicy(...) DB-backed path) because TestPolicyRequest
// carries no identity/segment fields at all — see TestPolicy's doc in
// policy_api_service.go for why. These tests use the SAME
// withOrchestratorSegmentResolver / fakeOrchestratorSegmentResolver test
// doubles segment_policy_gate_test.go already established for the
// orchestrator's other #3296-family call sites, and the SAME ctxKeyUser
// run.go's /process path binds, so they pin the real resolution contract
// rather than a second one invented for this file.

func sharedidentityResolvedIdentityWithSegment(segmentID string) sharedidentity.ResolvedIdentity {
	return sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: sharedidentity.SegmentID(segmentID)}},
	}
}

// fakeSegmentLookuper is a minimal SegmentLookuper (policy_api_service.go)
// test double.
//
// #3319: replaces the retired in-memory DynamicPolicyEngine this file used
// to construct directly (`&DynamicPolicyEngine{policies: []DynamicPolicy{...}}`)
// purely to exercise PolicyService.lookupPolicySegmentID / TestPolicy's
// segment-awareness (#3296). PolicyService now depends on the narrow
// SegmentLookuper interface, not a concrete engine type, so this double only
// needs to answer LookupSegmentID.
type fakeSegmentLookuper struct {
	policyID  string
	segmentID string
}

func (f *fakeSegmentLookuper) LookupSegmentID(policyID string) (string, bool) {
	if policyID == f.policyID {
		return f.segmentID, true
	}
	return "", false
}

func testPolicyEngineWithSegment(policyID, segmentID string) SegmentLookuper {
	return &fakeSegmentLookuper{policyID: policyID, segmentID: segmentID}
}

func TestApplySegmentScopeToTestVerdict_NoVerifiedIdentity_DegradesObservably(t *testing.T) {
	const policySegment = "seg-finance"
	ResetOrchestratorSegmentResolverForTest()
	s := &PolicyService{policyEngine: testPolicyEngineWithSegment("pol-1", policySegment)}

	// No ctxKeyUser bound at all — the universal case on this path today.
	matched, note := s.applySegmentScopeToTestVerdict(context.Background(), "pol-1", true)

	if !matched {
		t.Fatal("expected the condition-only verdict to pass through unchanged when no verified identity is available")
	}
	if note == "" {
		t.Fatal("expected an observable degrade note when segment scoping could not be evaluated, got empty string")
	}
	// The disclaimer is generic (identity is unavailable before the policy's
	// own segment scope is ever looked up), so it must not name this
	// specific policy's segment identifier either.
	if strings.Contains(note, policySegment) {
		t.Fatalf("identity-unavailable explanation must not name a segment identifier, got %q", note)
	}
}

func TestApplySegmentScopeToTestVerdict_SegmentMember_Matches(t *testing.T) {
	const policySegment = "seg-finance"
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{
		resolved: sharedidentityResolvedIdentityWithSegment(policySegment),
	})
	s := &PolicyService{policyEngine: testPolicyEngineWithSegment("pol-1", policySegment)}
	ctx := context.WithValue(context.Background(), ctxKeyUser, UserContext{OrgID: "org-a", Email: "alice@example.com"})

	matched, note := s.applySegmentScopeToTestVerdict(ctx, "pol-1", true)

	if !matched {
		t.Fatalf("expected a segment member's verdict to stand, got matched=false (note=%q)", note)
	}
	// The segment identifier is internal bookkeeping — no operational need
	// to echo it back, even to a verified member.
	if strings.Contains(note, policySegment) {
		t.Fatalf("member explanation must not name the segment identifier, got %q", note)
	}
}

func TestApplySegmentScopeToTestVerdict_SegmentNonMember_DoesNotMatch(t *testing.T) {
	const policySegment = "seg-finance"
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{
		resolved: sharedidentityResolvedIdentityWithSegment("seg-engineering"),
	})
	s := &PolicyService{policyEngine: testPolicyEngineWithSegment("pol-1", policySegment)}
	ctx := context.WithValue(context.Background(), ctxKeyUser, UserContext{OrgID: "org-a", Email: "alice@example.com"})

	// Conditions evaluated true, but the caller is not a member of the
	// policy's segment — must be forced to false regardless.
	matched, note := s.applySegmentScopeToTestVerdict(ctx, "pol-1", true)

	if matched {
		t.Fatal("expected a non-member's verdict to be forced to false regardless of condition evaluation")
	}
	if note == "" {
		t.Fatal("expected an explanatory note for the exclusion")
	}
	// #3266: a non-member must never learn the segment's identifier, or even
	// that the policy is segment-scoped at all — that is disclosure to a
	// non-member, the exact class this epic exists to close.
	if strings.Contains(note, policySegment) {
		t.Fatalf("non-member explanation must not name the segment, got %q", note)
	}
	if strings.Contains(strings.ToLower(note), "segment") {
		t.Fatalf("non-member explanation must not reveal that the policy is segment-scoped at all, got %q", note)
	}
}

func TestApplySegmentScopeToTestVerdict_ResolutionFails_FailsClosed(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{err: errors.New("scim query failed")})
	s := &PolicyService{policyEngine: testPolicyEngineWithSegment("pol-1", "seg-finance")}
	ctx := context.WithValue(context.Background(), ctxKeyUser, UserContext{OrgID: "org-a", Email: "alice@example.com"})

	// #3293 fail-closed invariant: a genuine resolution ERROR must never be
	// treated as "caller has zero segments" (which would still correctly
	// exclude here) — it must be surfaced as a forced non-match, the same
	// direction enforcement takes (EvaluateDynamicPolicies denies the whole
	// request on segOK=false), not silently proceed as if unscoped.
	matched, note := s.applySegmentScopeToTestVerdict(ctx, "pol-1", true)

	if matched {
		t.Fatal("a segment resolution failure must fail closed (forced non-match), never silently pass")
	}
	if note == "" {
		t.Fatal("expected a note explaining the resolution failure")
	}
}

func TestApplySegmentScopeToTestVerdict_NotSegmentScoped_Unaffected(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{
		resolved: sharedidentityResolvedIdentityWithSegment("seg-engineering"),
	})
	// Policy has NO SegmentID — not segment-scoped at all.
	s := &PolicyService{policyEngine: testPolicyEngineWithSegment("pol-1", "")}
	ctx := context.WithValue(context.Background(), ctxKeyUser, UserContext{OrgID: "org-a", Email: "alice@example.com"})

	matched, _ := s.applySegmentScopeToTestVerdict(ctx, "pol-1", true)
	if !matched {
		t.Fatal("a non-segment-scoped policy must never be excluded by segment logic")
	}
}

func TestApplySegmentScopeToTestVerdict_PolicyEngineNil_ScopeUnknown_Unaffected(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{
		resolved: sharedidentityResolvedIdentityWithSegment("seg-engineering"),
	})
	// No in-memory engine wired at all — segment-scope status for the policy
	// is UNKNOWN, must not be treated as "definitely unscoped" OR "definitely
	// excluded"; condition-only evaluation stands.
	s := &PolicyService{}
	ctx := context.WithValue(context.Background(), ctxKeyUser, UserContext{OrgID: "org-a", Email: "alice@example.com"})

	matched, _ := s.applySegmentScopeToTestVerdict(ctx, "pol-1", true)
	if !matched {
		t.Fatal("unknown segment-scope status must not force a non-match")
	}
}

func TestVerifiedTestIdentity(t *testing.T) {
	if _, ok := verifiedTestIdentity(context.Background()); ok {
		t.Fatal("expected no verified identity on a bare context")
	}
	ctx := context.WithValue(context.Background(), ctxKeyUser, UserContext{OrgID: "org-a", Email: "a@example.com"})
	u, ok := verifiedTestIdentity(ctx)
	if !ok {
		t.Fatal("expected a verified identity when ctxKeyUser is bound")
	}
	if u.OrgID != "org-a" || u.Email != "a@example.com" {
		t.Fatalf("unexpected identity: %+v", u)
	}
}
