package agent

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/contract"
)

// The fixtures below drive the REAL evaluator, not a stub, because the defect
// this file pins lived between the evaluator and the wire.
//
// A checksum-valid Indonesian NIK under PII_ACTION=redact is the one
// in-process input that produces an ALLOW carrying a mandatory obligation
// (decision_handler.go attaches newRedactPIIObligation to a VerdictAllow, and
// mapObligations renders it Mandatory). The same NIK under PII_ACTION=block
// denies, and under PII_ACTION=warn allows with no obligation at all - so the
// three postures give an allow-with-obligation, a denial, and an
// allow-without-obligation over ONE query, which keeps the control cases from
// differing in anything but the property under test.
const (
	// authzenPIIQuery carries a checksum-valid NIK. Its detection is what
	// produces the obligation; it is not itself asserted on.
	authzenPIIQuery = `{"args":{"query":"Customer NIK is 3174042506780001"}}`
)

// authzenPIIEnvelope is the envelope every case in this file sends.
func authzenPIIEnvelope(t *testing.T) string {
	t.Helper()
	return singularEnvelope(t, okSubject, okAction, okResource, authzenPIIQuery)
}

// installAuthZENPIIWorld sets the deployment posture the fixtures need.
func installAuthZENPIIWorld(t *testing.T, piiAction string) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("PII_ACTION", piiAction)
	ResetDetectionConfigCache()
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
}

func decodeAuthZENResponse(t *testing.T, rr *httptest.ResponseRecorder) contract.AuthZENResponse {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp contract.AuthZENResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v\n%s", err, rr.Body.String())
	}
	return resp
}

// mandatoryObligationCount counts the obligations a PEP is not allowed to
// ignore. Written as a count rather than a boolean so a test can say WHICH
// property failed when it fails.
func mandatoryObligationCount(obs []contract.Obligation) int {
	n := 0
	for _, o := range obs {
		if o.Mandatory {
			n++
		}
	}
	return n
}

// TestAuthZENDeniesRatherThanDroppingAMandatoryObligation is the fail-open this
// file exists to close.
//
// Before the fix, an evaluation that policy ALLOWED subject to a mandatory
// field_redact was rendered to a caller that had not negotiated the profile as
// a bare `{"decision":true}`. The obligation rode in the response context, the
// context was gated on negotiation, and the gate applied to the mandatory
// instruction as well as to the advisory decoration it was written for. The
// caller then proceeded with UNREDACTED PII believing it had been permitted to.
//
// ADR-065 invariant 8 prescribes DENY for a mandatory obligation the PEP cannot
// enforce; a PEP that cannot RECEIVE it is the limiting case.
//
// THE NEGOTIATED HALF IS WHAT MAKES THE UNNEGOTIATED HALF EVIDENCE. `false` on
// its own is also what a policy denial looks like, so a test asserting only
// `decision:false` would pass against a build that denied this request for an
// entirely different reason. Each case therefore pins the state and the
// obligation set the SAME fixture produces to a negotiated caller, and only
// then asserts what the unnegotiated one receives.
func TestAuthZENDeniesRatherThanDroppingAMandatoryObligation(t *testing.T) {
	installAuthZENPIIWorld(t, "redact")
	body := authzenPIIEnvelope(t)

	// The fixture's own premise, asserted rather than assumed: this request is
	// an ALLOW that carries a mandatory obligation. If detection stops flagging
	// this NIK, or the obligation stops being mandatory, every assertion below
	// becomes vacuous and this is the line that says so.
	ref := decodeAuthZENResponse(t, authzenForTest(t, body, negotiated()))
	if ref.Context == nil {
		t.Fatal("the fixture produced no profile context for a negotiated caller")
	}
	if ref.Context.State != contract.StateAllow {
		t.Fatalf("the fixture is not an allow (state=%s); the withheld-obligation deny would be untestable "+
			"against it and a decision:false below would prove nothing", ref.Context.State)
	}
	if got := mandatoryObligationCount(ref.Context.Obligations); got != 1 {
		t.Fatalf("the fixture carries %d mandatory obligations, want 1; obligations=%+v",
			got, ref.Context.Obligations)
	}
	// (b) A caller that DID negotiate is unchanged: it still reads true, and it
	// still receives the obligation. The fix must not buy safety by degrading
	// the callers that were already correct.
	if !ref.Decision {
		t.Error("a negotiated caller no longer receives the allow it is entitled to")
	}
	if ref.Context.Obligations[0].Type != contract.ObFieldRedact {
		t.Errorf("obligation type %q, want %q", ref.Context.Obligations[0].Type, contract.ObFieldRedact)
	}
	if ref.Context.Obligations[0].Params["fulfillment_endpoint"] == "" {
		t.Error("the negotiated caller received an obligation it cannot discharge")
	}

	// (a) The defect. An absent header and an empty one are the same request -
	// a caller asking for AuthZEN 1.0 - and both must be denied rather than
	// handed an allow stripped of its precondition.
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"no profile header", nil},
		{"an empty profile header", map[string]string{authzenProfileHeader: ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := decodeAuthZENResponse(t, authzenForTest(t, body, tc.headers))
			if resp.Decision {
				t.Error("FAIL-OPEN: an allow carrying a mandatory obligation the caller cannot receive " +
					"was rendered decision:true; the caller proceeds with unredacted content")
			}
			// The deny is a BARE deny. Attaching the context here would breach
			// invariant 12 in the other direction: the caller did not negotiate
			// the profile, so it must not be sent one.
			if resp.Context != nil {
				t.Errorf("an unnegotiated caller received a profile context: %s", authzenBody(t, resp))
			}
		})
	}
}

// TestAuthZENStillAllowsAnUnconditionalAllowWithoutTheProfile is the control
// that proves the fix denies the withheld-obligation case and nothing else.
//
// Without it, "deny whenever the header is absent" would pass every assertion
// in the test above while breaking the route for every bare AuthZEN 1.0 caller.
//
// Both cases are an allow with no obligation, reached two different ways: a
// query with no PII at all, and the SAME PII query under PII_ACTION=warn, which
// detects the NIK and attaches nothing. The second matters because it is the
// case where the evaluator did the work and still produced no obligation - a
// fix keyed on "PII was seen" rather than on the obligation would pass the
// first and fail the second.
func TestAuthZENStillAllowsAnUnconditionalAllowWithoutTheProfile(t *testing.T) {
	for _, tc := range []struct {
		name, piiAction, ctx string
	}{
		{"a query with nothing to redact", "redact", okContext},
		{"PII detected under a posture that attaches no obligation", "warn", authzenPIIQuery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installAuthZENPIIWorld(t, tc.piiAction)
			body := singularEnvelope(t, okSubject, okAction, okResource, tc.ctx)

			// The premise: an ALLOW with no mandatory obligation.
			ref := decodeAuthZENResponse(t, authzenForTest(t, body, negotiated()))
			if ref.Context == nil || ref.Context.State != contract.StateAllow {
				t.Fatalf("the control fixture is not an allow: %s", authzenBody(t, ref))
			}
			if got := mandatoryObligationCount(ref.Context.Obligations); got != 0 {
				t.Fatalf("the control fixture carries %d mandatory obligations; it is not a control", got)
			}

			// (c) and the unnegotiated caller still gets its allow.
			resp := decodeAuthZENResponse(t, authzenForTest(t, body, nil))
			if !resp.Decision {
				t.Error("an unconditional allow was denied to a bare AuthZEN 1.0 caller; the fix is " +
					"denying on the absence of the header rather than on the withheld obligation")
			}
			if resp.Context != nil {
				t.Errorf("an unnegotiated caller received a profile context: %s", authzenBody(t, resp))
			}
		})
	}
}

// TestAuthZENDeniedPathIsUnchangedByTheObligationRule is control (d).
//
// The same NIK under PII_ACTION=block denies on policy. That denial must look
// exactly as it did before - decision:false either way, the profile context for
// a negotiated caller carrying StateDeny - and it must NOT be recounted as a
// withheld-obligation deny, or the metric that distinguishes the two says
// nothing.
func TestAuthZENDeniedPathIsUnchangedByTheObligationRule(t *testing.T) {
	installAuthZENPIIWorld(t, "block")
	body := authzenPIIEnvelope(t)

	before := authzenOutcomeCounts(t, "singular", "unknown")
	bare := decodeAuthZENResponse(t, authzenForTest(t, body, nil))
	if bare.Decision {
		t.Error("a denied evaluation was rendered decision:true")
	}
	if bare.Context != nil {
		t.Error("an unnegotiated caller received a profile context")
	}
	after := authzenOutcomeCounts(t, "singular", "unknown")

	if got := after[string(contract.StateDeny)] - before[string(contract.StateDeny)]; got != 1 {
		t.Errorf("the DENY outcome was counted %v times, want 1; a policy denial must still report as DENY", got)
	}
	if got := after[authzenOutcomeObligationWithheld] - before[authzenOutcomeObligationWithheld]; got != 0 {
		t.Errorf("a policy denial was counted %v times as %q; the two are different events with "+
			"different fixes and an operator must be able to tell them apart", got, authzenOutcomeObligationWithheld)
	}

	ref := decodeAuthZENResponse(t, authzenForTest(t, body, negotiated()))
	if ref.Context == nil || ref.Context.State != contract.StateDeny {
		t.Fatalf("the negotiated denial changed shape: %s", authzenBody(t, ref))
	}
	if ref.Decision {
		t.Error("a negotiated caller read a denial as executable")
	}
}

// TestAuthZENPluralShapeIsCoveredToo extends the rule to the other envelope
// shape.
//
// The plural envelope is where obligations ACCUMULATE - one set is built across
// every entry and rendered against the met state - so a fix written against the
// singular shape could easily have missed it. Two PII entries produce two
// mandatory obligations on one allow; an un-negotiated caller must be denied
// exactly as it is for one.
func TestAuthZENPluralShapeIsCoveredToo(t *testing.T) {
	installAuthZENPIIWorld(t, "redact")
	body := `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
		`,"resource":` + okResource + `,"evaluations":[` +
		`{"context":` + authzenPIIQuery + `},` +
		`{"context":` + authzenPIIQuery + `}]}}`

	ref := decodeAuthZENResponse(t, authzenForTest(t, body, negotiated()))
	if ref.Context == nil || ref.Context.State != contract.StateAllow {
		t.Fatalf("the plural fixture is not an allow: %s", authzenBody(t, ref))
	}
	if got := mandatoryObligationCount(ref.Context.Obligations); got != 2 {
		t.Fatalf("the plural fixture accumulated %d mandatory obligations, want 2 (one per entry); "+
			"obligations=%+v", got, ref.Context.Obligations)
	}
	if !ref.Decision {
		t.Error("a negotiated caller lost its plural allow")
	}

	installSharedEngineWithMockDB(t)
	before := authzenOutcomeCounts(t, "plural", "unknown")
	bare := decodeAuthZENResponse(t, authzenForTest(t, body, nil))
	after := authzenOutcomeCounts(t, "plural", "unknown")
	if bare.Decision {
		t.Error("FAIL-OPEN: a plural allow carrying two mandatory obligations was rendered " +
			"decision:true to a caller that can receive neither")
	}
	if got := after[authzenOutcomeObligationWithheld] - before[authzenOutcomeObligationWithheld]; got != 1 {
		t.Errorf("outcome %q counted %v times on the plural shape, want 1", authzenOutcomeObligationWithheld, got)
	}
}

// TestRenderAuthZENOutcomeOverTheWholeProduct sweeps the rule over every input
// it can be given, not the subset the HTTP path can reach.
//
// THE STATES OTHER THAN ALLOW CANNOT BE REACHED WITH AN OBLIGATION SET THROUGH
// THE ROUTE. The legacy evaluator attaches its redact obligation only to a
// VerdictAllow, so `DENY plus a mandatory obligation` and `CHALLENGE plus a
// mandatory obligation` are unreachable in-process - which is precisely why the
// guard that handles them was, until this test existed, asserted by nobody:
// deleting `state == StateAllow` from the rule survived every end-to-end test
// in this file, because every end-to-end denial arrives with an EMPTY
// obligation set and cannot tell the two rules apart. A fixture resting at a
// field's zero value asserts the weaker property.
//
// The sweep is the PRODUCT of the three axes - four states, three negotiation
// values, four obligation sets - rather than a list of interesting rows, so a
// combination cannot be missing by omission. It does NOT replace the handler
// tests above: those pin the CALL SITE, and a rule that is correct in a
// function the handler stopped calling is not a fix.
func TestRenderAuthZENOutcomeOverTheWholeProduct(t *testing.T) {
	mandatory := contract.Obligation{Type: contract.ObFieldRedact, Mandatory: true}
	advisory := contract.Obligation{Type: contract.ObFieldRedact, Mandatory: false}

	obligationSets := map[string][]contract.Obligation{
		"none":               nil,
		"advisory":           {advisory},
		"mandatory":          {mandatory},
		"advisory+mandatory": {advisory, mandatory},
	}
	profiles := map[string]contract.AuthZENProfile{
		"unnegotiated": "",
		"negotiated":   contract.AuthZENProfileV1,
		"unknown":      "axonflow-authzen-profile-2099-01-01",
	}

	for _, state := range contract.AllOperationalStates() {
		for pName, profile := range profiles {
			for oName, obs := range obligationSets {
				name := fmt.Sprintf("%s/%s/%s", state, pName, oName)

				// The rule, restated independently of the implementation:
				// withholding happens only when the decision would have been
				// executable, the caller will not receive the context, and at
				// least one obligation is one it may not ignore.
				delivers := profile == contract.AuthZENProfileV1
				hasMandatory := false
				for _, o := range obs {
					if o.Mandatory {
						hasMandatory = true
					}
				}
				wantWithheld := state == contract.StateAllow && !delivers && hasMandatory
				wantDecision := state == contract.StateAllow && !wantWithheld
				wantOutcome := string(state)
				if wantWithheld {
					wantOutcome = authzenOutcomeObligationWithheld
				}

				got := renderAuthZENOutcome(state, profile, obs)
				if got.decision != wantDecision {
					t.Errorf("%s: decision = %v, want %v", name, got.decision, wantDecision)
				}
				if got.withheld != wantWithheld {
					t.Errorf("%s: withheld = %v, want %v", name, got.withheld, wantWithheld)
				}
				if got.outcome != wantOutcome {
					t.Errorf("%s: outcome = %q, want %q", name, got.outcome, wantOutcome)
				}
				// The two encodings of the outcome must never disagree: a
				// caller reading the boolean and an operator reading the
				// counter describe one request.
				if got.decision && got.outcome != string(contract.StateAllow) {
					t.Errorf("%s: decision:true reported under outcome %q", name, got.outcome)
				}
				// Nothing outside ALLOW may ever be executable, whatever the
				// obligation set does.
				if state != contract.StateAllow && got.decision {
					t.Errorf("%s: a non-ALLOW state was rendered executable", name)
				}
			}
		}
	}
}

// TestAuthZENWithheldObligationDenyIsObservable pins the operator signal.
//
// A silent fail-closed is better than a fail-open and still bad: the callers
// this denies are integrations that need to send a header, and an operator who
// cannot see them cannot go and tell anyone. The signal reuses the existing
// `outcome` label rather than registering a metric, because that label is
// already a closed enum carrying a non-state value (`refused`).
func TestAuthZENWithheldObligationDenyIsObservable(t *testing.T) {
	installAuthZENPIIWorld(t, "redact")
	body := authzenPIIEnvelope(t)

	before := authzenOutcomeCounts(t, "singular", "unknown")
	_ = decodeAuthZENResponse(t, authzenForTest(t, body, nil))
	after := authzenOutcomeCounts(t, "singular", "unknown")

	if got := after[authzenOutcomeObligationWithheld] - before[authzenOutcomeObligationWithheld]; got != 1 {
		t.Errorf("outcome %q counted %v times, want 1", authzenOutcomeObligationWithheld, got)
	}
	// It must not be filed under the ordinary denial, which is the whole point
	// of giving it its own value.
	if got := after[string(contract.StateDeny)] - before[string(contract.StateDeny)]; got != 0 {
		t.Errorf("the withheld-obligation deny was also counted as DENY %v times", got)
	}
	if got := after["refused"] - before["refused"]; got != 0 {
		t.Errorf("the withheld-obligation deny was counted as a refusal %v times; nothing was refused, "+
			"an answer was returned", got)
	}

	// The negotiated caller reports its real state, unchanged.
	beforeN := authzenOutcomeCounts(t, "singular", "unknown")
	_ = decodeAuthZENResponse(t, authzenForTest(t, body, negotiated()))
	afterN := authzenOutcomeCounts(t, "singular", "unknown")
	if got := afterN[string(contract.StateAllow)] - beforeN[string(contract.StateAllow)]; got != 1 {
		t.Errorf("a negotiated allow counted %v times as ALLOW, want 1", got)
	}
	if got := afterN[authzenOutcomeObligationWithheld] - beforeN[authzenOutcomeObligationWithheld]; got != 0 {
		t.Errorf("a negotiated caller's allow was counted as %q %v times", authzenOutcomeObligationWithheld, got)
	}
}

// TestAuthZENWithheldObligationDenyIsLogged pins the OTHER half of the operator
// signal, and it is the half an operator actually sees.
//
// The counter says HOW MANY; the log says WHICH CALLER TO GO AND FIX. There is
// no dashboard and no alert rule in this repository reading
// `axonflow_authzen_requests_total`, so on a live deployment the log line is the
// only thing that surfaces this denial to a human at all - which makes it a
// behaviour of the handler rather than a debugging aid, and behaviour that
// nothing asserts is behaviour that a refactor deletes for free. Neutering the
// emission (`if false && rendered.withheld`) left the whole ./agent/ package
// green before this test existed.
//
// The three properties asserted, in the order they matter:
//
//  1. the line is emitted for a withheld-obligation deny, and it carries the
//     three fields that make it actionable - the origin, the envelope shape and
//     the decision id an operator would look up;
//  2. it carries NO caller content. The route's whole reason for denying is that
//     the request held PII, so a log line quoting the query would move that PII
//     from a governed response into an ungoverned log sink;
//  3. it is NOT emitted for a policy denial or for a negotiated allow. Without
//     that, "log unconditionally" would satisfy (1) while making the line
//     useless for finding the integrations that need to send a header.
func TestAuthZENWithheldObligationDenyIsLogged(t *testing.T) {
	installAuthZENPIIWorld(t, "redact")
	body := authzenPIIEnvelope(t)

	// The premise, asserted rather than assumed: this fixture is an ALLOW
	// carrying a mandatory obligation. Without it a silent run below would be
	// indistinguishable from a fixture that stopped producing the case.
	ref := decodeAuthZENResponse(t, authzenForTest(t, body, negotiated()))
	if ref.Context == nil || ref.Context.State != contract.StateAllow ||
		mandatoryObligationCount(ref.Context.Obligations) != 1 {
		t.Fatalf("the fixture is not an allow carrying one mandatory obligation: %s", authzenBody(t, ref))
	}
	if !authzenDecisionIDPattern.MatchString("decision_id=" + ref.Context.DecisionID + ")") {
		t.Fatalf("the reference decision id %q does not match the shape this test looks for in the log; "+
			"the log assertion below would be asserting the wrong thing", ref.Context.DecisionID)
	}

	installSharedEngineWithMockDB(t)
	logged := captureAuthZENLog(t, func() {
		if resp := decodeAuthZENResponse(t, authzenForTest(t, body, nil)); resp.Decision {
			t.Fatal("the fixture was not denied, so there was nothing to log")
		}
	})

	if !strings.Contains(logged, "[AuthZEN]") || !strings.Contains(logged, "mandatory obligation") {
		t.Fatalf("a withheld-obligation deny was answered SILENTLY. The metric has no alert or dashboard "+
			"in this repository, so this line is the only thing that tells an operator which integration "+
			"is being denied. log=%q", logged)
	}
	// The fields that make it actionable. An operator who cannot tell WHICH
	// caller, on WHICH shape, for WHICH decision has been told only that
	// something, somewhere, was denied.
	for _, want := range []string{
		"origin=unknown",
		"shape=singular",
		string(contract.AuthZENProfileV1),
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("the log line does not carry %q, so it does not say which caller to fix: %q", want, logged)
		}
	}
	// The decision id is asserted by SHAPE, not by value: the denied call is a
	// second evaluation and gets its own id, so the reference call's id is not
	// the one that appears here. A bare `strings.Contains(logged, "decision_id=")`
	// would be satisfied by an EMPTY id, which is the one value that makes the
	// field useless, so the pattern requires a populated one.
	if !authzenDecisionIDPattern.MatchString(logged) {
		t.Errorf("the log line carries no usable decision_id, so an operator cannot look the denial up: %q", logged)
	}
	// No caller content. The request is denied BECAUSE it carries PII; writing
	// that PII into a log sink to announce the denial would defeat the denial.
	for _, leaked := range []string{"3174042506780001", "Customer NIK"} {
		if strings.Contains(logged, leaked) {
			t.Errorf("the log line leaks caller content (%q) into an ungoverned sink: %q", leaked, logged)
		}
	}

	// The controls. A policy denial and a negotiated allow are both ordinary
	// outcomes and must not produce this line, or it stops naming the callers
	// that need a header.
	for _, tc := range []struct {
		name      string
		piiAction string
		headers   map[string]string
	}{
		{"a policy denial", "block", nil},
		{"a negotiated allow carrying the same obligation", "redact", negotiated()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installAuthZENPIIWorld(t, tc.piiAction)
			quiet := captureAuthZENLog(t, func() {
				_ = decodeAuthZENResponse(t, authzenForTest(t, authzenPIIEnvelope(t), tc.headers))
			})
			if strings.Contains(quiet, "mandatory obligation") {
				t.Errorf("%s was logged as a withheld-obligation deny; the line no longer identifies the "+
					"integrations that need to send a header: %q", tc.name, quiet)
			}
		})
	}
}

// TestAuthZENWithheldObligationDenyIsAuditedAsBlocked pins the DURABLE half.
//
// The counter and the log both live in a process; the audit row is what a
// compliance reader, an exam response and the portal's decisions feed are
// built on. It was written inside the delegated evaluation - synchronously,
// before handleDecide returned - and it said `allowed`, because at that point
// the withholding rule had not run and could not have: it needs the negotiated
// profile and the meet across every entry, neither of which exists until every
// delegation is back.
//
// So for a request answered `{"decision":false}` the durable record claimed the
// platform had permitted it, and nothing distinguished it from an allow that
// really happened. That is the more serious half of this defect: the metric can
// tell the two apart and the record could not.
//
// THE INSERT EXPECTATION IS PART OF THE ASSERTION, not scaffolding: it pins that
// the evaluator really did commit an `allowed` row on this plane first, so the
// UPDATE below is amending a wrong record rather than writing into a vacuum.
func TestAuthZENWithheldObligationDenyIsAuditedAsBlocked(t *testing.T) {
	installAuthZENPIIWorld(t, "redact")
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	body := authzenPIIEnvelope(t)

	// The premise: the fixture is an allow carrying a mandatory obligation.
	// Asserted against a negotiated caller, whose own audit row is an ordinary
	// un-amended `allowed`.
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(authzenAuditInsertArgs(AuditVerdictAllowed)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	ref := decodeAuthZENResponse(t, authzenForTest(t, body, negotiated()))
	if ref.Context == nil || ref.Context.State != contract.StateAllow ||
		mandatoryObligationCount(ref.Context.Obligations) != 1 {
		t.Fatalf("the fixture is not an allow carrying one mandatory obligation: %s", authzenBody(t, ref))
	}

	installSharedEngineWithMockDB(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(authzenAuditInsertArgs(AuditVerdictAllowed)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// The amendment. The regexp pins the three things that make the row honest
	// rather than merely different: the outcome the caller was given, the flag a
	// query can find these denials by, and the evaluator's own verdict being
	// PRESERVED rather than overwritten - an amended row that lost "policy
	// permitted this" would answer one auditor's question by destroying
	// another's.
	mock.ExpectExec(`UPDATE audit_logs[\s\S]*authzen_evaluated_policy_decision[\s\S]*authzen_obligation_withheld`).
		WithArgs(AuditVerdictBlocked, sqlmock.AnyArg(), PlaneAccessEvaluation).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if resp := decodeAuthZENResponse(t, authzenForTest(t, body, nil)); resp.Decision {
		t.Fatal("the fixture was not denied, so there was no wrong audit row to amend")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a request answered {\"decision\":false} is still audited as %q. The durable record is what "+
			"a compliance query and an exam response read, and it cannot distinguish this denial from an "+
			"allow that really happened: %v", AuditVerdictAllowed, err)
	}
}

// TestAuthZENAmendsNothingItDidNotWithhold is the control for the amendment.
//
// Without it, "amend on every request" satisfies the test above while
// overwriting every genuine allow on this plane with `blocked` - a far worse
// audit defect than the one being fixed, and one that would show up first in a
// customer's compliance report rather than in CI.
//
// It detects an UPDATE without expecting one: sqlmock errors on a statement it
// was not told about, and the amendment counts that error under
// authzen_withheld_amend. So an unexpected amendment moves the counter, and the
// counter is the assertion.
func TestAuthZENAmendsNothingItDidNotWithhold(t *testing.T) {
	for _, tc := range []struct {
		name      string
		piiAction string
		headers   map[string]string
		verdict   string
	}{
		{"a negotiated allow, which receives its obligation", "redact", negotiated(), AuditVerdictAllowed},
		{"an allow carrying no obligation at all", "warn", nil, AuditVerdictAllowed},
		{"a policy denial", "block", nil, AuditVerdictBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installAuthZENPIIWorld(t, tc.piiAction)
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(authzenAuditInsertArgs(tc.verdict)...).
				WillReturnResult(sqlmock.NewResult(0, 1))

			before := authzenAmendFailureCounts(t)
			_ = decodeAuthZENResponse(t, authzenForTest(t, authzenPIIEnvelope(t), tc.headers))
			after := authzenAmendFailureCounts(t)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the evaluator's own audit row was not written as %q: %v", tc.verdict, err)
			}
			for reason, n := range after {
				if n != before[reason] {
					t.Errorf("%s issued an audit amendment (reason=%s fired): a row this surface did not "+
						"withhold anything from was rewritten", tc.name, reason)
				}
			}
		})
	}
}

// TestAmendAuditForWithheldObligationReportsAMissingRow pins the SILENT branch.
//
// The delegated INSERT is best-effort: a CHECK-constraint violation or a
// database hiccup drops the row and answers 200 anyway. The amendment then
// matches nothing, and "the record is wrong" and "there is no record" are
// equally bad and equally invisible - an UPDATE that touches zero rows raises no
// error. So the zero is counted.
//
// The nil-database case is the deliberate NON-failure: no usage DB means no row
// was inserted to amend, and the delegated writer has already counted `nodb` for
// the same request. Counting it twice would double-report one posture.
func TestAmendAuditForWithheldObligationReportsAMissingRow(t *testing.T) {
	t.Run("the row is not there", func(t *testing.T) {
		mock := withMockUsageDB(t)
		mock.ExpectExec("UPDATE audit_logs").WillReturnResult(sqlmock.NewResult(0, 0))

		before := authzenAmendFailureCounts(t)
		amendAuditForWithheldObligation(context.Background(), usageDB, []string{"dec-1"})
		after := authzenAmendFailureCounts(t)

		if got := after[authzenAuditAmendNoRow] - before[authzenAuditAmendNoRow]; got != 1 {
			t.Errorf("an amendment that matched no row was counted %v times, want 1; a missing durable "+
				"record is as wrong as an incorrect one and raises no error of its own", got)
		}
		if got := after[authzenAuditAmendFailed] - before[authzenAuditAmendFailed]; got != 0 {
			t.Errorf("a zero-row amendment was reported %v times as a failed one; the two have different "+
				"causes and different fixes", got)
		}
	})

	t.Run("the UPDATE errors", func(t *testing.T) {
		mock := withMockUsageDB(t)
		mock.ExpectExec("UPDATE audit_logs").WillReturnError(errors.New("connection reset"))

		before := authzenAmendFailureCounts(t)
		amendAuditForWithheldObligation(context.Background(), usageDB, []string{"dec-1"})
		after := authzenAmendFailureCounts(t)

		if got := after[authzenAuditAmendFailed] - before[authzenAuditAmendFailed]; got != 1 {
			t.Errorf("a failed amendment was counted %v times, want 1", got)
		}
	})

	t.Run("no usage database is not a failure", func(t *testing.T) {
		before := authzenAmendFailureCounts(t)
		amendAuditForWithheldObligation(context.Background(), nil, []string{"dec-1"})
		after := authzenAmendFailureCounts(t)

		for reason, n := range after {
			if n != before[reason] {
				t.Errorf("a DB-less deployment raised %s; the delegated writer already counts nodb for "+
					"this same request, so this would double-report one posture", reason)
			}
		}
	})

	t.Run("no decision ids is a missing row", func(t *testing.T) {
		mock := withMockUsageDB(t)
		before := authzenAmendFailureCounts(t)
		amendAuditForWithheldObligation(context.Background(), usageDB, []string{"", ""})
		after := authzenAmendFailureCounts(t)

		if got := after[authzenAuditAmendNoRow] - before[authzenAuditAmendNoRow]; got != 1 {
			t.Errorf("an amendment with nothing to key on was counted %v times, want 1", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("an unkeyed amendment reached the database: %v", err)
		}
	})
}

// authzenAuditInsertArgs is decideAuditInsertArgs with the plane this surface
// writes. The plane is asserted rather than wildcarded because a row filed under
// the wrong plane is a row the amendment's own WHERE clause would miss.
func authzenAuditInsertArgs(policyDecision string) []driver.Value {
	args := decideAuditInsertArgs(policyDecision, nil)
	args[15] = PlaneAccessEvaluation
	return args
}

// authzenAmendFailureCounts reads every reason label the amendment can raise.
func authzenAmendFailureCounts(t *testing.T) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, reason := range []string{authzenAuditAmendFailed, authzenAuditAmendNoRow} {
		out[reason] = testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues(reason))
	}
	return out
}

// authzenDecisionIDPattern matches a POPULATED decision id in the log line.
// `decision_id=)` - the field present and empty - must not match, because an
// operator cannot look anything up with it.
var authzenDecisionIDPattern = regexp.MustCompile(`decision_id=[0-9a-fA-F-]{36}\)`)

// captureAuthZENLog runs fn with the standard logger redirected and returns
// everything it wrote.
//
// The sink is the package's syncBuf rather than a bare strings.Builder because
// goroutines leaked by earlier tests in this package go on logging, and
// strings.Builder is not safe for concurrent use (caught by -race in #2094).
func captureAuthZENLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf syncBuf
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

// authzenOutcomeCounts reads the request counter for every outcome value this
// surface can emit, at one shape/origin pair.
//
// It enumerates the states from the contract rather than listing them, so a new
// operational state cannot quietly escape the reading.
func authzenOutcomeCounts(t *testing.T, shape, origin string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	outcomes := []string{"refused", authzenOutcomeObligationWithheld}
	for _, s := range contract.AllOperationalStates() {
		outcomes = append(outcomes, string(s))
	}
	for _, o := range outcomes {
		out[o] = testutil.ToFloat64(authzenRequests.WithLabelValues(o, shape, origin))
	}
	return out
}

func authzenBody(t *testing.T, resp contract.AuthZENResponse) string {
	t.Helper()
	raw, err := json.Marshal(resp)
	if err != nil {
		return err.Error()
	}
	return string(raw)
}

// TestMandatoryObligationWithheldIsKeyedOnEnforceability pins the predicate
// itself, over the inputs the HTTP path cannot currently produce.
//
// Every obligation this build renders onto the AuthZEN surface is mandatory
// (mapObligations stamps Mandatory unconditionally, because the legacy contract
// has no advisory obligations), so an ADVISORY obligation is unreachable
// end-to-end today. That is exactly why it is asserted here: the day one is
// emitted, a rule keyed on "are there obligations" would start denying
// operations a bare PEP was entitled to perform, and this is the assertion that
// would go red rather than the customer.
//
// The STATE rows are here for the same reason. The predicate owns all three
// terms of the rule so its two call sites cannot spell it differently, which
// means the state term is now asserted against the predicate rather than
// against one caller's copy of it.
func TestMandatoryObligationWithheldIsKeyedOnEnforceability(t *testing.T) {
	mandatory := contract.Obligation{Mandatory: true}
	advisory := contract.Obligation{Mandatory: false}

	for _, tc := range []struct {
		name        string
		state       contract.OperationalState
		negotiated  contract.AuthZENProfile
		obligations []contract.Obligation
		want        bool
	}{
		{"nothing to withhold", contract.StateAllow, "", nil, false},
		{"an advisory obligation a bare PEP may ignore", contract.StateAllow, "",
			[]contract.Obligation{advisory}, false},
		{"a mandatory obligation the caller cannot receive", contract.StateAllow, "",
			[]contract.Obligation{mandatory}, true},
		{"a mandatory one hiding behind advisory ones", contract.StateAllow, "",
			[]contract.Obligation{advisory, advisory, mandatory}, true},
		{"the caller negotiated, so it receives them", contract.StateAllow, contract.AuthZENProfileV1,
			[]contract.Obligation{mandatory}, false},
		{"an unknown profile is not a negotiated one", contract.StateAllow,
			"axonflow-authzen-profile-2099-01-01", []contract.Obligation{mandatory}, true},
		// The state term. A decision that permits no execution withholds
		// nothing, however its obligation set reads: the boolean is already
		// false and the PEP has nothing to discharge. Reporting these as
		// withheld would file a policy denial under the label whose entire
		// purpose is naming an integration that must send a header.
		{"a denial carrying a mandatory obligation is a policy denial", contract.StateDeny, "",
			[]contract.Obligation{mandatory}, false},
		{"a challenge carrying a mandatory obligation is not a withheld one", contract.StateChallenge, "",
			[]contract.Obligation{mandatory}, false},
		{"an error carrying a mandatory obligation is not a withheld one", contract.StateError, "",
			[]contract.Obligation{mandatory}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := contract.MandatoryObligationWithheld(tc.state, tc.negotiated, tc.obligations); got != tc.want {
				t.Errorf("MandatoryObligationWithheld = %v, want %v", got, tc.want)
			}
		})
	}
}
