// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/agent/fincrime"
	"axonflow/platform/agent/hitl"
	sharedpolicy "axonflow/platform/shared/policy"
)

// failingHITLService returns a fixed error so the enqueue chokepoint's
// classification arms can be driven without a database.
type failingHITLService struct{ err error }

func (f *failingHITLService) CreateApprovalRequest(_ context.Context, _ HITLCreateInput) (*HITLApprovalRequest, error) {
	return nil, f.err
}

func (f *failingHITLService) GetApprovalRequest(_ context.Context, _ uuid.UUID) (*HITLApprovalRequest, error) {
	return nil, f.err
}

func withBridge(t *testing.T, svc HITLService) {
	t.Helper()
	prev := fincrimeHITLBridge
	t.Cleanup(func() { fincrimeHITLBridge = prev })
	if svc == nil {
		fincrimeHITLBridge = nil
		return
	}
	fincrimeHITLBridge = NewHITLBridge(svc)
}

// --- FinCrime outcome identity (#3509 DoD) -----------------------------------

// TestFinCrimeEnqueue_RowIsUnchangedByTheRefactor pins every field of the
// HITLCreateInput the FinCrime seam produces, against values transcribed from
// the PRE-change call site:
//
//	fincrimeHITLBridge.CreateApprovalFromPolicy(ctx,
//	    orgID, tenantID, clientID, userID,
//	    query,
//	    "fincrime_review",
//	    policyID, policyName,
//	    reason,
//	    "high",
//	    "AML/CFT",
//	    "",            // -> bridge default "Article 14"
//	)
//
// with the bridge then setting RiskClassification=mapSeverityToRisk("high")
// and ExpiresIn=DefaultApprovalExpiration.
//
// The seam now routes through enqueueApproval instead. If that refactor
// changed ANY value that reaches the database, this fails - which is the whole
// point: "outcome-identical" has to be a property the build checks, not a
// sentence in a pull request.
func TestFinCrimeEnqueue_RowIsUnchangedByTheRefactor(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)

	id := createFinCrimeApprovalForDecision(context.Background(),
		"org-A", "tenant-A", "client-A", "42", "wire 900000 to ACME", fcApprovalResult(), nil)
	if id == "" {
		t.Fatal("expected an approval id")
	}

	want := HITLCreateInput{
		OrgID:               "org-A",
		TenantID:            "tenant-A",
		ClientID:            "client-A",
		UserID:              "42",
		OriginalQuery:       "wire 900000 to ACME",
		RequestType:         "fincrime_review",
		RequestContext:      nil,
		TriggeredPolicyID:   fincrime.PolicyIDMLFraudScore,
		TriggeredPolicyName: "FinCrime ML Fraud Score (Engine B, advisory)",
		Severity:            "high",
		EUAIActArticle:      "Article 14",
		ComplianceFramework: "AML/CFT",
		RiskClassification:  "high-risk",
		ExpiresIn:           DefaultApprovalExpiration,
	}
	// TriggerReason comes from the seam result's first reason; assert it
	// separately so the fixture is not restated here.
	want.TriggerReason = rec.last.TriggerReason
	if rec.last.TriggerReason == "" {
		t.Fatal("trigger reason must be populated")
	}
	if !reflect.DeepEqual(rec.last, want) {
		t.Fatalf("FinCrime queue row DRIFTED.\n got: %+v\nwant: %+v", rec.last, want)
	}
	// The raw query is deliberately preserved on this path. If a future change
	// switches it to a descriptor, that is a FinCrime behaviour change and must
	// be a deliberate decision, not a side effect.
	if rec.last.OriginalQuery != "wire 900000 to ACME" {
		t.Fatalf("FinCrime original_query changed to %q", rec.last.OriginalQuery)
	}
	// RequestContext must stay nil: the pre-change path never set one, and a
	// non-nil value writes a different request_context JSONB blob.
	if rec.last.RequestContext != nil {
		t.Fatalf("FinCrime request_context is no longer nil: %v", rec.last.RequestContext)
	}
}

// TestCreateApprovalFromPolicy_DelegationIsFieldIdentical pins the claim made
// in CreateApprovalFromPolicy's doc comment: routing it through CreateApproval
// produces the identical input it used to build inline.
func TestCreateApprovalFromPolicy_DelegationIsFieldIdentical(t *testing.T) {
	rec := &recordingHITLService{}
	b := NewHITLBridge(rec)

	if _, err := b.CreateApprovalFromPolicy(context.Background(),
		"o", "t", "c", "u", "the query", "some_type", "pid", "pname", "because", "medium", "", ""); err != nil {
		t.Fatalf("CreateApprovalFromPolicy: %v", err)
	}

	want := HITLCreateInput{
		OrgID: "o", TenantID: "t", ClientID: "c", UserID: "u",
		OriginalQuery: "the query", RequestType: "some_type",
		TriggeredPolicyID: "pid", TriggeredPolicyName: "pname",
		TriggerReason: "because", Severity: "medium",
		EUAIActArticle:      "Article 14",   // empty arg -> bridge default
		ComplianceFramework: "EU AI Act",    // empty arg -> bridge default
		RiskClassification:  "limited-risk", // mapSeverityToRisk("medium")
		ExpiresIn:           DefaultApprovalExpiration,
	}
	if !reflect.DeepEqual(rec.last, want) {
		t.Fatalf("delegation is not field-identical.\n got: %+v\nwant: %+v", rec.last, want)
	}
}

// --- The descriptor, and what must never be in it ---------------------------

func TestHITLQueryDescriptor_NeverCarriesTheQuery(t *testing.T) {
	secret := "transfer 50000 for aadhaar 2234-5678-9012 to account 91234567"
	in := policyStepUpInput{
		Plane:      hitlPlaneDecide,
		Stage:      "llm",
		Target:     "tool ledger/read_balance",
		DecisionID: "dec-1",
		Query:      secret,
	}
	got := hitlQueryDescriptor(in)
	if strings.Contains(got, secret) {
		t.Fatalf("descriptor carries the raw query: %q", got)
	}
	// A substring check on the whole query would still pass if only a fragment
	// leaked, so check the identifiers a leak would most plausibly carry.
	for _, frag := range []string{"2234-5678-9012", "91234567", "50000", "aadhaar"} {
		if strings.Contains(got, frag) {
			t.Fatalf("descriptor carries query fragment %q: %q", frag, got)
		}
	}
	// It must still be useful to a reviewer.
	for _, want := range []string{hitlPlaneDecide, "llm", "ledger/read_balance", "dec-1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("descriptor is missing %q: %q", want, got)
		}
	}
}

func TestEnqueuePolicyStepUp_RecordsHashNotContent(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)

	secret := "select * from payroll where ssn = '123-45-6789'"
	res := enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "7", PolicyID: "eu_ai_act_hitl", PolicyName: "EU AI Act HITL",
		Severity: "high", DecisionID: "dec-9", Query: secret,
	})
	if res.Outcome != hitlEnqueueCreated {
		t.Fatalf("outcome = %q, want created", res.Outcome)
	}
	if strings.Contains(rec.last.OriginalQuery, "123-45-6789") {
		t.Fatalf("original_query leaked content: %q", rec.last.OriginalQuery)
	}
	hash, _ := rec.last.RequestContext["query_hash"].(string)
	if hash != hitlQueryHash(secret) {
		t.Fatalf("query_hash = %q, want %q", hash, hitlQueryHash(secret))
	}
	if strings.Contains(hash, "123-45-6789") {
		t.Fatal("hash is not a hash")
	}
	if got, _ := rec.last.RequestContext["decision_id"].(string); got != "dec-9" {
		t.Fatalf("decision_id = %q", got)
	}
	if rec.last.RequestType != HITLRequestTypePolicyStepUp {
		t.Fatalf("request_type = %q, want %q", rec.last.RequestType, HITLRequestTypePolicyStepUp)
	}
}

// --- The cap, which is the landmine ------------------------------------------

// TestEnqueue_CapReachedIsExplicitAndHolds is the boundary case the brief
// singled out: a tenant at MaxPendingApprovals must not silently stop getting
// reviewable entries. The hold stands (RequestID empty means the plane keeps
// refusing) and the caller and the audit row are TOLD, with a detail string
// that names the cause.
func TestEnqueue_CapReachedIsExplicitAndHolds(t *testing.T) {
	withBridge(t, &failingHITLService{err: hitl.ErrPendingApprovalLimitExceeded})

	res := enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneAgentRequest, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "7", PolicyID: "p", Severity: "high", Query: "q",
	})
	if res.Outcome != hitlEnqueueCapReached {
		t.Fatalf("outcome = %q, want %q", res.Outcome, hitlEnqueueCapReached)
	}
	if res.RequestID != "" {
		t.Fatalf("no entry was created, so RequestID must be empty; got %q", res.RequestID)
	}
	if res.Detail == "" {
		t.Fatal("a cap-reached hold must not be silent: Detail is empty")
	}
	for _, want := range []string{"pending-approval limit", "remains held"} {
		if !strings.Contains(res.Detail, want) {
			t.Fatalf("Detail does not say %q: %q", want, res.Detail)
		}
	}
}

func TestEnqueue_FailureArmsAreClassified(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"cap", hitl.ErrPendingApprovalLimitExceeded, hitlEnqueueCapReached},
		{"tier", hitl.ErrHITLApprovalDisabledByTier, hitlEnqueueTierDisabled},
		{"wrapped cap", fmt.Errorf("create approval request: %w", hitl.ErrPendingApprovalLimitExceeded), hitlEnqueueCapReached},
		{"unrelated error", errors.New("x"), hitlEnqueueError},
		{"write failure", errors.New("insert approval request: connection reset"), hitlEnqueueError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withBridge(t, &failingHITLService{err: tc.err})
			res := enqueuePolicyStepUp(context.Background(), policyStepUpInput{
				Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
				UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
			})
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %q, want %q", res.Outcome, tc.want)
			}
			if res.RequestID != "" {
				t.Fatalf("RequestID must be empty on a failure, got %q", res.RequestID)
			}
			if res.Detail == "" {
				t.Fatal("every failure arm must carry a detail")
			}
		})
	}
}

func TestEnqueue_RefusesWithoutOrgScope(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)
	res := enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
	})
	if res.Outcome != hitlEnqueueError {
		t.Fatalf("outcome = %q, want %q", res.Outcome, hitlEnqueueError)
	}
	if rec.last.OrgID != "" {
		t.Fatal("an org-less enqueue must never reach the service")
	}
}

func TestEnqueue_UnwiredBridgeIsVisibleNotSilent(t *testing.T) {
	withBridge(t, nil)
	res := enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
	})
	if res.Outcome != hitlEnqueueUnavailable {
		t.Fatalf("outcome = %q, want %q", res.Outcome, hitlEnqueueUnavailable)
	}
}

// TestEnqueue_UnattributedPolicyIsNamedAsSuch: a held request whose triggering
// policy could not be resolved still gets a reviewable entry, but the entry
// must not invent an attribution.
func TestEnqueue_UnattributedPolicyIsNamedAsSuch(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)
	res := enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneGatewayPreCheck, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "", PolicyName: "", Severity: "", Query: "q",
	})
	if res.Outcome != hitlEnqueueCreated {
		t.Fatalf("outcome = %q, want created", res.Outcome)
	}
	if rec.last.TriggeredPolicyID != "require_approval" {
		t.Fatalf("policy id = %q", rec.last.TriggeredPolicyID)
	}
	if !strings.Contains(strings.ToLower(rec.last.TriggeredPolicyName), "unattributed") {
		t.Fatalf("an unattributed entry must say so: %q", rec.last.TriggeredPolicyName)
	}
	// An invalid/empty severity must be normalised, or the row fails the
	// hitl_valid_severity CHECK and the entry silently never exists.
	if rec.last.Severity != "high" {
		t.Fatalf("severity = %q, want the normalised default", rec.last.Severity)
	}
}

func TestEnqueue_InvalidSeverityIsNormalised(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)
	// "warn" is a policy ACTION, not a severity; the tier engine has emitted
	// values this table's CHECK constraint rejects.
	enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "warn", Query: "q",
	})
	if !validHITLSeverity(rec.last.Severity) {
		t.Fatalf("severity %q would fail hitl_valid_severity", rec.last.Severity)
	}
	// A VALID severity must survive untouched.
	enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "critical", Query: "q",
	})
	if rec.last.Severity != "critical" {
		t.Fatalf("a valid severity was rewritten to %q", rec.last.Severity)
	}
}

// --- Attribution -------------------------------------------------------------

// TestConvertSharedResult_AttributesTheApprovingPolicy: the entry must name the
// rule that HELD the request, not whichever rule matched first.
func TestConvertSharedResult_AttributesTheApprovingPolicy(t *testing.T) {
	res := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{PolicyID: "sys_pii_ssn", PolicyName: "US SSN", Category: sharedpolicy.CategoryPIIUS, Action: sharedpolicy.ActionRedact},
			{PolicyID: "eu_ai_act_hitl", PolicyName: "EU AI Act Article 14 oversight",
				Category: sharedpolicy.CategoryComplianceEUAIAct, Action: sharedpolicy.ActionRequireApproval},
		},
	})
	if !res.RequiresApproval {
		t.Fatal("RequiresApproval not set")
	}
	if res.ApprovalPolicyID != "eu_ai_act_hitl" {
		t.Fatalf("ApprovalPolicyID = %q; naming the first match instead of the approving one is the defect", res.ApprovalPolicyID)
	}
	if res.ApprovalPolicyName != "EU AI Act Article 14 oversight" {
		t.Fatalf("ApprovalPolicyName = %q", res.ApprovalPolicyName)
	}
	// No require_approval match -> no attribution at all, never a placeholder.
	none := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{PolicyID: "sys_pii_ssn", Category: sharedpolicy.CategoryPIIUS, Action: sharedpolicy.ActionRedact},
		},
	})
	if none.RequiresApproval || none.ApprovalPolicyID != "" {
		t.Fatalf("attribution leaked onto a non-approval result: %+v", none)
	}
}

// --- The FinCrime / policy-authored split ------------------------------------

func TestDecideApprovalIsPolicyAuthored(t *testing.T) {
	packRow := &sharedpolicy.RequestResult{MatchedPolicies: []sharedpolicy.PolicyMatch{{
		PolicyID: "fincrime_structuring_pattern_stepup", Category: sharedpolicy.CategoryFinCrime,
		Action: sharedpolicy.ActionRequireApproval,
	}}}
	plainRow := &sharedpolicy.RequestResult{MatchedPolicies: []sharedpolicy.PolicyMatch{{
		PolicyID: "eu_ai_act_hitl", Category: sharedpolicy.CategoryComplianceEUAIAct,
		Action: sharedpolicy.ActionRequireApproval,
	}}}
	cases := []struct {
		name string
		fc   *fincrime.Result
		sr   *sharedpolicy.RequestResult
		want bool
	}{
		{"no fincrime at all", nil, plainRow, true},
		{"seam requires approval", fcApprovalResult(), plainRow, false},
		{"fincrime pack row drove it", nil, packRow, false},
		{"seam present but not stepping up", &fincrime.Result{}, plainRow, true},
		{"nothing at all", nil, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideApprovalIsPolicyAuthored(tc.fc, tc.sr); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// --- The grant TTL, and the boot refusal -------------------------------------

func TestHITLGrantTTL_DefaultAndClamping(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", defaultHITLGrantTTL},
		{"900", 15 * time.Minute},
		{"60", time.Minute},
		{"1", minHITLGrantTTL},       // below the floor -> clamped up
		{"999999", maxHITLGrantTTL},  // above the ceiling -> clamped down
		{"  120  ", 2 * time.Minute}, // whitespace tolerated
		{"nonsense", defaultHITLGrantTTL},
		{"0", defaultHITLGrantTTL},
		{"-5", defaultHITLGrantTTL},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv(EnvHITLGrantTTLSeconds, tc.raw)
			if got := hitlGrantTTL(); got != tc.want {
				t.Fatalf("hitlGrantTTL() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestHITLGrantTTL_DefaultIsGenerousEnoughForAHuman pins the reasoning, not
// just the number: the caller does not poll (the Decision Mode MCP adapter
// returns JSON-RPC -32002 and gives up), so a reviewer who approves and then
// tells the user to retry must not be racing a sub-minute window. Single use
// is what makes a generous value safe.
func TestHITLGrantTTL_DefaultIsGenerousEnoughForAHuman(t *testing.T) {
	t.Setenv(EnvHITLGrantTTLSeconds, "")
	if got := hitlGrantTTL(); got < 5*time.Minute {
		t.Fatalf("default TTL %s is too short to survive a human round trip", got)
	}
}

func TestClampHITLGrantTTL(t *testing.T) {
	if got := clampHITLGrantTTL(time.Second); got != minHITLGrantTTL {
		t.Fatalf("floor: %s", got)
	}
	if got := clampHITLGrantTTL(72 * time.Hour); got != maxHITLGrantTTL {
		t.Fatalf("ceiling: %s", got)
	}
	if got := clampHITLGrantTTL(10 * time.Minute); got != 10*time.Minute {
		t.Fatalf("in-range value was rewritten: %s", got)
	}
}

// --- Grant consumption, fail-closed ------------------------------------------

// TestConsumeApprovalGrant_FailsClosedOnMissingSubject: a lookup missing any
// identity dimension would match across users or across orgs. It must refuse
// BEFORE reaching the store, and the refusal must be OBSERVABLE rather than
// collapsing into the "nothing to spend" case that every ordinary request
// produces.
//
// Asserting only the (id, ok) pair is NOT enough and an earlier version of
// this test proved it: with the guard deleted the call reaches a repo-less
// service, which returns nothing, so the outcome is identical and the test
// passes with the hole wide open. The distinguishing evidence is the metric
// label - missing_subject (a wiring defect an operator must see) versus none
// (the normal case). That distinction is the only thing that can fail here.
func TestConsumeApprovalGrant_FailsClosedOnMissingSubject(t *testing.T) {
	prev := mcpHITLService
	t.Cleanup(func() { mcpHITLService = prev })
	mcpHITLService = &hitl.Service{}

	full := hitl.GrantSubject{OrgID: "o", TenantID: "t", ClientID: "c", UserID: "1"}
	// EVERY dimension, one at a time. A grant that matched on a missing one
	// would cross an org, a tenant, a credential or a person - and the
	// credential clause is not decoration: a token-less enterprise PEP has the
	// synthetic user id "0", so `user_id` alone does not separate two callers
	// in the same organisation.
	cases := []struct {
		name          string
		subj          hitl.GrantSubject
		policy, query string
	}{
		{"no org", hitl.GrantSubject{TenantID: "t", ClientID: "c", UserID: "1"}, "p", "q"},
		{"no tenant", hitl.GrantSubject{OrgID: "o", ClientID: "c", UserID: "1"}, "p", "q"},
		{"no client", hitl.GrantSubject{OrgID: "o", TenantID: "t", UserID: "1"}, "p", "q"},
		{"no user", hitl.GrantSubject{OrgID: "o", TenantID: "t", ClientID: "c"}, "p", "q"},
		{"no policy", full, "", "q"},
		// The query is part of the key now: a grant admits the request the
		// reviewer saw, so a lookup without one would admit any request.
		{"no query", full, "p", ""},
		{"nothing at all", hitl.GrantSubject{}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			beforeMissing := grantCounter(t, hitlGrantMissingSubject)
			beforeNone := grantCounter(t, hitlGrantNone)
			id, ok := consumeApprovalGrant(context.Background(), hitlPlaneDecide, tc.subj, tc.policy, tc.query)
			if ok || id != "" {
				t.Fatalf("%+v policy=%q query=%q admitted a request", tc.subj, tc.policy, tc.query)
			}
			if got := grantCounter(t, hitlGrantMissingSubject); got != beforeMissing+1 {
				t.Fatalf("%+v policy=%q: refusal was not counted as %s (%v -> %v); "+
					"an unobservable refusal is indistinguishable from a request with no approval waiting",
					tc.subj, tc.policy, hitlGrantMissingSubject, beforeMissing, got)
			}
			if got := grantCounter(t, hitlGrantNone); got != beforeNone {
				t.Fatalf("%+v policy=%q: refusal was miscounted as %s", tc.subj, tc.policy, hitlGrantNone)
			}
		})
	}
}

// TestApprovalPolicyKey_WriteAndReadAgree pins the single defect the shared
// key exists to prevent: the enqueue substituting a placeholder for an
// unattributed hold while the consume passes the raw empty value. The two
// halves disagreeing is silent - the reviewer's approval is unspendable
// forever and every retry mints another row, which is #3509 defect 2 again.
func TestApprovalPolicyKey_WriteAndReadAgree(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)

	// The WRITE side, through the real enqueue, with no attribution.
	enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "", Severity: "high", Query: "q",
	})
	written := rec.last.TriggeredPolicyID
	if written == "" {
		t.Fatal("the enqueue wrote an empty triggered_policy_id")
	}
	// The READ side must produce the identical key from the identical input.
	if got := approvalPolicyKey(""); got != written {
		t.Fatalf("the consume would look up %q while the enqueue wrote %q: "+
			"every approval of an unattributed hold would be unspendable", got, written)
	}
	// And an attributed policy must pass through untouched on both sides.
	if got := approvalPolicyKey("eu_ai_act_hitl"); got != "eu_ai_act_hitl" {
		t.Fatalf("an attributed policy id was rewritten to %q", got)
	}
	// The LITERAL, pinned. Write and read agreeing is not enough on its own,
	// because both halves route through this one function and would agree with
	// each other whatever it returned. The value lands in
	// hitl_approval_queue.triggered_policy_id, which the portal renders to a
	// reviewer and which the public docs name, so it is an interface and not an
	// implementation detail.
	if written != "require_approval" {
		t.Fatalf("the unattributed placeholder is %q; it is reviewer-visible and documented as require_approval", written)
	}
}

// grantCounter reads one hitlGrantConsumeTotal series on the decide plane.
func grantCounter(t *testing.T, outcome string) float64 {
	t.Helper()
	return testutil.ToFloat64(hitlGrantConsumeTotal.WithLabelValues(hitlPlaneDecide, outcome))
}

// TestEnqueue_OutcomesAreCounted pins that every enqueue outcome reaches the
// metric. The pre-#3509 seam logged and moved on, so an operator whose queue
// silently stopped filling had nothing to alert on; a counter that is declared
// but never incremented would reproduce that exactly, while looking fixed.
func TestEnqueue_OutcomesAreCounted(t *testing.T) {
	cases := []struct {
		name    string
		svc     HITLService
		outcome string
	}{
		{"created", &recordingHITLService{}, hitlEnqueueCreated},
		{"cap", &failingHITLService{err: hitl.ErrPendingApprovalLimitExceeded}, hitlEnqueueCapReached},
		{"tier", &failingHITLService{err: hitl.ErrHITLApprovalDisabledByTier}, hitlEnqueueTierDisabled},
		{"error", &failingHITLService{err: errors.New("boom")}, hitlEnqueueError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withBridge(t, tc.svc)
			before := testutil.ToFloat64(hitlPolicyEnqueueTotal.WithLabelValues(hitlPlaneAgentRequest, tc.outcome))
			enqueuePolicyStepUp(context.Background(), policyStepUpInput{
				Plane: hitlPlaneAgentRequest, OrgID: "o", TenantID: "t", ClientID: "c",
				UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
			})
			after := testutil.ToFloat64(hitlPolicyEnqueueTotal.WithLabelValues(hitlPlaneAgentRequest, tc.outcome))
			if after != before+1 {
				t.Fatalf("%s was not counted (%v -> %v)", tc.outcome, before, after)
			}
		})
	}
}

func TestConsumeApprovalGrant_UnwiredServiceHolds(t *testing.T) {
	prev := mcpHITLService
	t.Cleanup(func() { mcpHITLService = prev })
	mcpHITLService = nil
	full := hitl.GrantSubject{OrgID: "o", TenantID: "t", ClientID: "c", UserID: "1"}
	if id, ok := consumeApprovalGrant(context.Background(), hitlPlaneDecide, full, "p", "q"); ok || id != "" {
		t.Fatal("an unwired HITL service must never admit a held request")
	}
}

// TestRequestTypePolicyStepUpMatchesHITLPackage pins the duplicated constant.
// platform/agent imports platform/agent/hitl, so the reverse edge would be a
// cycle and the value has to exist on both sides. A drift between them would
// mean entries are written under one value and the consume predicate matches
// another, so every approval would be unspendable - the exact defect this
// change removes, arriving silently.
func TestRequestTypePolicyStepUpMatchesHITLPackage(t *testing.T) {
	if HITLRequestTypePolicyStepUp != hitl.RequestTypePolicyStepUp {
		t.Fatalf("agent has %q, hitl has %q: entries would be written under one value and never matched by the other",
			HITLRequestTypePolicyStepUp, hitl.RequestTypePolicyStepUp)
	}
}

// TestApprovalReasons_AreDistinguishable: the reason a PEP sees for "pending
// review" and for "a human already approved this" must never be confusable.
func TestApprovalReasons_AreDistinguishable(t *testing.T) {
	pending := policyStepUpReason("abc")
	admitted := approvalGrantReason("abc")
	if pending == admitted {
		t.Fatal("pending and admitted read identically")
	}
	if !strings.Contains(pending, "pending") {
		t.Fatalf("pending reason = %q", pending)
	}
	if !strings.Contains(admitted, "spent") {
		t.Fatalf("admitted reason must say the grant is spent: %q", admitted)
	}
}

func TestDecideTargetDescriptor(t *testing.T) {
	cases := []struct{ server, tool, typ, want string }{
		{"ledger", "read_balance", "tool", "tool ledger/read_balance"},
		{"", "read_balance", "tool", "tool read_balance"},
		{"ledger", "", "tool", "tool server ledger"},
		{"", "", "llm", "llm"},
		{"", "", "", ""},
	}
	for _, tc := range cases {
		if got := decideTargetDescriptor(tc.server, tc.tool, tc.typ); got != tc.want {
			t.Fatalf("(%q,%q,%q) = %q, want %q", tc.server, tc.tool, tc.typ, got, tc.want)
		}
	}
}

// TestMapPolicyResultToVerdict_BlockedBeatsApproval pins the precedence the
// grant-spend guard depends on: a result that is BOTH Blocked and
// RequiresApproval maps to deny, never to needs_approval.
//
// It is the premise of `!policyResult.Blocked` on both consume sites. Without
// that guard the caller's single-use approval is spent on a request the deny
// refuses anyway, and single use means they do not get it back. If this
// precedence ever inverts, the guard becomes wrong in the opposite direction
// and this is where that shows up.
func TestMapPolicyResultToVerdict_BlockedBeatsApproval(t *testing.T) {
	both := &StaticPolicyResult{
		Blocked:          true,
		Reason:           "blocked by sys_sqli",
		RequiresApproval: true,
		ApprovalPolicyID: "eu_ai_act_hitl",
	}
	verdict, reasons, _ := mapPolicyResultToVerdict(both, false)
	if verdict != VerdictDeny {
		t.Fatalf("verdict = %q, want %q: a blocked request must not be reported as merely awaiting approval", verdict, VerdictDeny)
	}
	// And the deny must not carry the require_approval reason, which would tell
	// a PEP to wait for a reviewer on a request no reviewer can release.
	for _, r := range reasons {
		if r == "require_approval" {
			t.Fatal("a deny carried the require_approval reason")
		}
	}
	// Sanity, so the case above is not passing because the mapping ignores
	// RequiresApproval entirely: without the block it IS needs_approval.
	onlyApproval := &StaticPolicyResult{RequiresApproval: true, ApprovalPolicyID: "eu_ai_act_hitl"}
	if v, _, _ := mapPolicyResultToVerdict(onlyApproval, false); v != VerdictNeedsApproval {
		t.Fatalf("without the block the verdict is %q, want %q", v, VerdictNeedsApproval)
	}
}

// TestEnqueue_JoinsAnAlreadyPendingReview pins the dedup: a retry must join the
// approval a reviewer is already looking at, not mint a second one.
//
// The mechanism is a repository lookup, so this exercises the branch through
// the service seam that the request path uses, and asserts the OUTCOME the
// plane sees. Unbounded growth here is not a tidiness issue: before #3509 these
// planes wrote no rows at all, so a PEP retry loop would put a caller-driven,
// unbounded write on the approval queue and bury the one decision a reviewer
// has to make - and on Enterprise the pending cap (-1) does not run to bound it.
func TestEnqueue_JoinsAnAlreadyPendingReview(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)
	prev := mcpHITLService
	t.Cleanup(func() { mcpHITLService = prev })
	// A repo-less service: FindOpenPolicyStepUp returns ("", nil), so the
	// enqueue must fall THROUGH and create. This is the safe-direction half.
	mcpHITLService = &hitl.Service{}

	before := testutil.ToFloat64(hitlPolicyEnqueueTotal.WithLabelValues(hitlPlaneDecide, hitlEnqueueCreated))
	res := enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
	})
	if res.Outcome != hitlEnqueueCreated {
		t.Fatalf("with no open entry the enqueue must CREATE, got %q", res.Outcome)
	}
	if after := testutil.ToFloat64(hitlPolicyEnqueueTotal.WithLabelValues(hitlPlaneDecide, hitlEnqueueCreated)); after != before+1 {
		t.Fatalf("created was not counted (%v -> %v)", before, after)
	}
	// An incomplete subject must ALSO fall through to the enqueue rather than
	// silently skipping the dedup lookup and then skipping the create too.
	res = enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
	})
	if res.Outcome != hitlEnqueueCreated {
		t.Fatalf("an incomplete subject must still get an entry, got %q", res.Outcome)
	}

	// The TAKEN side. Without driving this, deleting the whole dedup branch
	// leaves every assertion above green - a mutation run proved exactly that,
	// which is why the lookup has a seam at all.
	var gotSubj hitl.GrantSubject
	var gotPolicy, gotPlane, gotHash string
	prevLookup := findOpenPolicyStepUp
	t.Cleanup(func() { findOpenPolicyStepUp = prevLookup })
	findOpenPolicyStepUp = func(_ context.Context, subj hitl.GrantSubject, policyID, plane, queryHash string) (string, error) {
		gotSubj, gotPolicy, gotPlane, gotHash = subj, policyID, plane, queryHash
		return "existing-request-id", nil
	}
	beforeCreated := testutil.ToFloat64(hitlPolicyEnqueueTotal.WithLabelValues(hitlPlaneDecide, hitlEnqueueCreated))
	res = enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
	})
	if res.Outcome != hitlEnqueueDeduped {
		t.Fatalf("with an open entry the enqueue must JOIN it, got %q", res.Outcome)
	}
	if res.RequestID != "existing-request-id" {
		t.Fatalf("the caller was handed %q instead of the open entry", res.RequestID)
	}
	if afterCreated := testutil.ToFloat64(hitlPolicyEnqueueTotal.WithLabelValues(hitlPlaneDecide, hitlEnqueueCreated)); afterCreated != beforeCreated {
		t.Fatal("a deduped hold was ALSO counted as created; a retry loop would read as new oversight work")
	}
	// The lookup must be given the full subject, or it would join another
	// caller's pending review.
	want := hitl.GrantSubject{OrgID: "o", TenantID: "t", ClientID: "c", UserID: "1"}
	if gotSubj != want {
		t.Fatalf("dedup looked up %+v, want %+v", gotSubj, want)
	}
	if gotPolicy != "p" {
		t.Fatalf("dedup looked up policy %q, want %q", gotPolicy, "p")
	}
	// The PLANE and the QUERY HASH are part of the key, and both are load
	// bearing. Without the plane, one caller held on two planes for one rule
	// collapses to a single review and the other planes stop producing entries
	// at all. Without the hash, a DIFFERENT request tripping the same policy
	// joins the first entry, so the reviewer approves a descriptor and a
	// decision id that belong to another request.
	if gotPlane != hitlPlaneDecide {
		t.Fatalf("dedup looked up plane %q, want %q; two planes would collapse into one review", gotPlane, hitlPlaneDecide)
	}
	if gotHash != hitlQueryHash("q") {
		t.Fatalf("dedup looked up hash %q, want %q; a different request would join this review", gotHash, hitlQueryHash("q"))
	}

	// A lookup ERROR must fall through to the enqueue: a duplicate entry is a
	// nuisance, a missing entry is the defect this work removes.
	findOpenPolicyStepUp = func(_ context.Context, _ hitl.GrantSubject, _, _, _ string) (string, error) {
		return "", errors.New("database unavailable")
	}
	res = enqueuePolicyStepUp(context.Background(), policyStepUpInput{
		Plane: hitlPlaneDecide, OrgID: "o", TenantID: "t", ClientID: "c",
		UserID: "1", PolicyID: "p", Severity: "high", Query: "q",
	})
	if res.Outcome != hitlEnqueueCreated {
		t.Fatalf("a failed dedup lookup must still raise an entry, got %q", res.Outcome)
	}
}

// TestEnqueueOutcomes_AreDistinctValues: "deduped" is a SUCCESS outcome and
// must not be confused with "created" (new oversight work) or with any failure
// outcome (no reviewer will see this). An operator alerting on "anything that
// is not created" would page on every retry loop; one alerting on failures
// alone must not have deduped folded into a failure bucket.
func TestEnqueueOutcomes_AreDistinctValues(t *testing.T) {
	all := []string{
		hitlEnqueueCreated, hitlEnqueueDeduped, hitlEnqueueCapReached,
		hitlEnqueueTierDisabled, hitlEnqueueUnavailable, hitlEnqueueError,
	}
	seen := map[string]bool{}
	for _, o := range all {
		if o == "" {
			t.Fatal("an enqueue outcome is the empty string; it would be invisible as a metric label")
		}
		if seen[o] {
			t.Fatalf("two enqueue outcomes share the value %q", o)
		}
		seen[o] = true
	}
	if hitlEnqueueDeduped == hitlEnqueueCreated {
		t.Fatal("deduped and created must be distinguishable: one is new oversight work, one is a retry")
	}
}

// TestPreCheckBlockOutranksHold pins the pre-check plane's precedence, which
// diverged from its two siblings and was not survivable once this plane began
// raising queue entries.
//
// A request blocked by one policy and held by another used to answer
// `block_reason: require_approval` - the sentinel every shipped SDK matches to
// enter its HITL wait - while `approved` stayed false. The caller waited for an
// approval that could never release it, because approving does not remove a
// block, and after #3509 it also minted an entry per retry.
func TestPreCheckBlockOutranksHold(t *testing.T) {
	cases := []struct {
		name      string
		result    *StaticPolicyResult
		community bool
		want      bool
	}{
		{"held only", &StaticPolicyResult{RequiresApproval: true}, false, true},
		{"blocked AND held", &StaticPolicyResult{Blocked: true, RequiresApproval: true}, false, false},
		{"blocked only", &StaticPolicyResult{Blocked: true}, false, false},
		{"neither", &StaticPolicyResult{}, false, false},
		{"held, community mode", &StaticPolicyResult{RequiresApproval: true}, true, false},
		{"nil result", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := preCheckRequiresHITL(tc.result, tc.community); got != tc.want {
				t.Fatalf("preCheckRequiresHITL = %v, want %v", got, tc.want)
			}
		})
	}

	// The precedence must agree with the plane that has always had it right.
	// A divergence here is exactly how the two came apart in the first place.
	both := &StaticPolicyResult{Blocked: true, RequiresApproval: true, Reason: "blocked by sys_sqli"}
	decideVerdict, _, _ := mapPolicyResultToVerdict(both, false)
	if decideVerdict == VerdictNeedsApproval {
		t.Fatal("/decide would report needs_approval for a blocked request; the two planes have diverged again")
	}
	if preCheckRequiresHITL(both, false) {
		t.Fatal("the pre-check would report a hold where /decide reports a deny")
	}
}

// TestEnqueue_DedupIsScopedToOnePlaneAndOneQuery pins the two discriminators
// that a review found missing, in the direction that matters: a hold that is
// NOT the same request must NOT join.
//
// Both were real. Without the plane, the same caller held on /decide and then
// on /api/request for one rule produced ONE entry, so two of the three planes
// this change exists to fix stopped writing anything. Without the query hash,
// a different request tripping the same policy joined the first entry and the
// reviewer approved metadata describing something else.
func TestEnqueue_DedupIsScopedToOnePlaneAndOneQuery(t *testing.T) {
	rec := &recordingHITLService{}
	withBridge(t, rec)
	prevLookup := findOpenPolicyStepUp
	t.Cleanup(func() { findOpenPolicyStepUp = prevLookup })

	// A store holding ONE open entry: decide plane, query "first".
	openPlane, openHash := hitlPlaneDecide, hitlQueryHash("first")
	findOpenPolicyStepUp = func(_ context.Context, _ hitl.GrantSubject, _, plane, queryHash string) (string, error) {
		if plane == openPlane && queryHash == openHash {
			return "existing-request-id", nil
		}
		return "", nil
	}

	base := policyStepUpInput{OrgID: "o", TenantID: "t", ClientID: "c", UserID: "1", PolicyID: "p", Severity: "high"}
	cases := []struct {
		name  string
		plane string
		query string
		want  string
	}{
		{"same plane, same query -> joins", hitlPlaneDecide, "first", hitlEnqueueDeduped},
		{"same plane, DIFFERENT query -> new entry", hitlPlaneDecide, "second", hitlEnqueueCreated},
		{"DIFFERENT plane, same query -> new entry", hitlPlaneAgentRequest, "first", hitlEnqueueCreated},
		{"different plane and query -> new entry", hitlPlaneGatewayPreCheck, "second", hitlEnqueueCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.Plane, in.Query = tc.plane, tc.query
			if got := enqueuePolicyStepUp(context.Background(), in); got.Outcome != tc.want {
				t.Fatalf("outcome = %q, want %q", got.Outcome, tc.want)
			}
		})
	}
}
