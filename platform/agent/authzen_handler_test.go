package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// authzenForTest posts an envelope at the handler, bypassing the auth
// middleware exactly as decideForTest does for the Decision API.
func authzenForTest(t *testing.T, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", authzenHandlerPath, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	handleAuthZENEvaluation(rr, req)
	return rr
}

func negotiated() map[string]string {
	return map[string]string{authzenProfileHeader: string(contract.AuthZENProfileV1)}
}

// singularEnvelope builds a well-formed singular envelope around the pieces a
// test wants to vary, so a test that is about `context` does not restate the
// subject and action and quietly diverge from the shape the others use.
func singularEnvelope(t *testing.T, subject, action, resource, ctx string) string {
	t.Helper()
	return `{"evaluation":{"subject":` + subject + `,"action":` + action +
		`,"resource":` + resource + `,"context":` + ctx + `}}`
}

const (
	okSubject  = `{"type":"gateway","id":"llm-gateway-01"}`
	okAction   = `{"name":"llm.completion"}`
	okResource = `{"type":"llm","id":"llm"}`
	okContext  = `{"args":{"query":"what is the weather"}}`
)

func decodeRefusal(t *testing.T, rr *httptest.ResponseRecorder) contract.AuthZENError {
	t.Helper()
	var e contract.AuthZENError
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("the refusal body is not an AuthZENError: %v\n%s", err, rr.Body.String())
	}
	if err := e.Validate(); err != nil {
		t.Errorf("the refusal is not well formed: %v", err)
	}
	return e
}

// TestAuthZENRefusesEveryConstructItCannotEvaluate is the evidence for the
// no-silent-drops rule, which is the whole security argument for this surface.
//
// Each case sends a request carrying something the evaluator cannot read. The
// only acceptable answer is a refusal that NAMES the member: a decision would
// tell the caller the member was weighed, and every audit of that decision
// would inherit the claim.
//
// The pointer is asserted, not just the code. "unevaluable_attribute" without
// the offending member is a puzzle rather than a diagnosis, and an adapter that
// returned the right code for the wrong field would pass a code-only test.
func TestAuthZENRefusesEveryConstructItCannotEvaluate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		code    contract.AuthZENErrorCode
		pointer string
	}{
		{
			name:    "a subject property the evaluator never reads",
			body:    singularEnvelope(t, `{"type":"gateway","id":"g","properties":{"clearance":"secret"}}`, okAction, okResource, okContext),
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluation/subject/properties",
		},
		{
			name:    "an action property",
			body:    singularEnvelope(t, okSubject, `{"name":"llm.completion","properties":{"urgency":"high"}}`, okResource, okContext),
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluation/action/properties",
		},
		{
			name:    "a resource property",
			body:    singularEnvelope(t, okSubject, okAction, `{"type":"llm","id":"llm","properties":{"tier":"gold"}}`, okContext),
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluation/resource/properties",
		},
		{
			name:    "an unrecognised context member",
			body:    singularEnvelope(t, okSubject, okAction, okResource, `{"args":{"query":"q"},"department":"legal"}`),
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluation/context/department",
		},
		{
			name:    "an argument beside the query",
			body:    singularEnvelope(t, okSubject, okAction, okResource, `{"args":{"query":"q","amount_cents":9000}}`),
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluation/context/args/amount_cents",
		},
		{
			name:    "an end-user subject",
			body:    singularEnvelope(t, `{"type":"identity","id":"alice@example.com"}`, okAction, okResource, okContext),
			code:    contract.ErrUnsupportedSubject,
			pointer: "/evaluation/subject/type",
		},
		{
			name:    "an action outside the evaluable set",
			body:    singularEnvelope(t, okSubject, `{"name":"jira.transition_issue"}`, okResource, okContext),
			code:    contract.ErrUnsupportedAction,
			pointer: "/evaluation/action/name",
		},
		{
			name:    "an action and a resource describing different operations",
			body:    singularEnvelope(t, okSubject, `{"name":"llm.completion"}`, `{"type":"tool","id":"jira/create"}`, okContext),
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluation/resource/type",
		},
		{
			// provider/model reach neither policy, audit nor a human approver
			// (Target.Provider and Target.Model have zero non-test readers), so
			// accepting them would report that they were considered.
			name:    "an llm resource id naming a provider and model nothing reads",
			body:    singularEnvelope(t, okSubject, okAction, `{"type":"llm","id":"openai/gpt-4o"}`, okContext),
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluation/resource/id",
		},
		{
			name:    "an agent resource id nothing would read",
			body:    singularEnvelope(t, okSubject, `{"name":"agent.invoke"}`, `{"type":"agent","id":"billing-agent"}`, okContext),
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluation/resource/id",
		},
		{
			name:    "no content to evaluate",
			body:    singularEnvelope(t, okSubject, okAction, okResource, `{"args":{}}`),
			code:    contract.ErrMissingEvaluableContent,
			pointer: "/evaluation/context/args",
		},
		{
			name:    "an empty query",
			body:    singularEnvelope(t, okSubject, okAction, okResource, `{"args":{"query":"   "}}`),
			code:    contract.ErrMissingEvaluableContent,
			pointer: "/evaluation/context/args/query",
		},
		{
			name:    "a correlation value that is not a string",
			body:    singularEnvelope(t, okSubject, okAction, okResource, `{"args":{"query":"q"},"correlation":{"session":42}}`),
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluation/context/correlation/session",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := authzenForTest(t, tc.body, negotiated())
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422; body=%s", rr.Code, rr.Body.String())
			}
			e := decodeRefusal(t, rr)
			if e.Code != tc.code {
				t.Errorf("code %q, want %q", e.Code, tc.code)
			}
			if e.Pointer != tc.pointer {
				t.Errorf("pointer %q, want %q", e.Pointer, tc.pointer)
			}
			// A refusal must never be mistakeable for a decision. The body is a
			// refusal document, so it carries no `decision` member at all -
			// which is what stops a client that only reads `decision` from
			// treating an unevaluated request as a deny it can proceed past.
			if strings.Contains(rr.Body.String(), `"decision"`) {
				t.Errorf("the refusal body carries a decision member: %s", rr.Body.String())
			}
		})
	}
}

// TestAuthZENRefusalsCoverEveryDeclaredCode is the anti-vacuity guard on the
// suite above.
//
// A refusal code with no test is a branch nobody has exercised, and the refusal
// path is exactly where an adapter fails open. This asserts every declared code
// is reachable from a test in this file, so adding a code without a case fails
// here rather than shipping unexercised.
func TestAuthZENRefusalsCoverEveryDeclaredCode(t *testing.T) {
	exercised := map[contract.AuthZENErrorCode]bool{
		contract.ErrUnevaluableAttribute:    true, // TestAuthZENRefusesEveryConstructItCannotEvaluate
		contract.ErrUnsupportedSubject:      true, // ditto
		contract.ErrUnsupportedAction:       true, // ditto
		contract.ErrUnsupportedResource:     true, // ditto
		contract.ErrMissingEvaluableContent: true, // ditto
		contract.ErrMalformedEnvelope:       true, // TestAuthZENRefusesAMalformedEnvelope
		contract.ErrIncompleteEvaluation:    true, // TestAuthZENRefusesAnIncompleteBulkEntry
		contract.ErrEvaluationUnavailable:   true, // TestAuthZENSurfacesAnUnmappableObligationAsUnavailable
	}
	for _, c := range contract.AllAuthZENErrorCodes() {
		if !exercised[c] {
			t.Errorf("refusal code %q has no test; the refusal path is where an adapter fails open", c)
		}
	}
	for c := range exercised {
		declared := false
		for _, d := range contract.AllAuthZENErrorCodes() {
			if d == c {
				declared = true
			}
		}
		if !declared {
			t.Errorf("the coverage map names %q, which the contract does not declare", c)
		}
	}
}

func TestAuthZENRefusesAMalformedEnvelope(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"neither member", `{}`},
		{"both members", `{"evaluation":{"subject":` + okSubject + `,"action":` + okAction + `,"resource":` + okResource + `},"evaluations":{"evaluations":[{}]}}`},
		{"an empty plural array", `{"evaluations":{"evaluations":[]}}`},
		{"an unknown top-level member", `{"evaluation":{"subject":` + okSubject + `},"evaluate":{}}`},
		{"an unknown member inside an entry", `{"evaluation":{"subject":` + okSubject + `,"action":` + okAction + `,"resource":` + okResource + `,"obligations":[]}}`},
		{"a duplicate member", `{"evaluation":{"subject":` + okSubject + `},"evaluation":{"subject":` + okSubject + `}}`},
		{"not an object", `[]`},
		{"not JSON at all", `{not json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := authzenForTest(t, tc.body, negotiated())
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body=%s", rr.Code, rr.Body.String())
			}
			if e := decodeRefusal(t, rr); e.Code != contract.ErrMalformedEnvelope {
				t.Errorf("code %q, want %q", e.Code, contract.ErrMalformedEnvelope)
			}
		})
	}
}

func TestAuthZENRefusesAnIncompleteBulkEntry(t *testing.T) {
	// The shared base supplies no action, and neither does the entry, so after
	// inheritance the entry still describes nothing evaluable. The decoder
	// accepts this shape - completeness is not a structural property - which is
	// exactly why the adapter has to check it.
	body := `{"evaluations":{"subject":` + okSubject + `,"context":` + okContext +
		`,"evaluations":[{"resource":` + okResource + `}]}}`
	rr := authzenForTest(t, body, negotiated())
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422; body=%s", rr.Code, rr.Body.String())
	}
	e := decodeRefusal(t, rr)
	if e.Code != contract.ErrIncompleteEvaluation {
		t.Errorf("code %q, want %q", e.Code, contract.ErrIncompleteEvaluation)
	}
	if e.Pointer != "/evaluations/evaluations/0" {
		t.Errorf("pointer %q, want the offending entry", e.Pointer)
	}
}

// TestAuthZENAcceptsWhatItCanEvaluate is the control for every refusal above.
//
// Without it the refusal suite could be passing because the adapter refuses
// everything, which would be a surface that is safe and useless.
func TestAuthZENAcceptsWhatItCanEvaluate(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	for _, tc := range []struct{ name, body string }{
		{"an llm completion", singularEnvelope(t, okSubject, okAction, okResource, okContext)},
		{"a tool call", singularEnvelope(t, okSubject, `{"name":"tool.call"}`, `{"type":"tool","id":"jira/create_issue"}`, okContext)},
		{"an agent invocation", singularEnvelope(t, okSubject, `{"name":"agent.invoke"}`, `{"type":"agent","id":"agent"}`, okContext)},
		{"correlation keys alongside the query", singularEnvelope(t, okSubject, okAction, okResource,
			`{"args":{"query":"q"},"correlation":{"x-session-id":"s-1"}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := authzenForTest(t, tc.body, negotiated())
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d, want 200; body=%s", rr.Code, rr.Body.String())
			}
			var resp contract.AuthZENResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decoding: %v\n%s", err, rr.Body.String())
			}
			if resp.Context == nil {
				t.Fatal("a negotiated caller received no profile context")
			}
			if resp.Context.Profile != contract.AuthZENProfileV1 {
				t.Errorf("profile %q", resp.Context.Profile)
			}
			// The response must satisfy the schema every generated client
			// validates against. Asserting the Go struct alone would not catch a
			// response that is well-typed here and refused by an SDK.
			var doc any
			if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
				t.Fatalf("re-decoding: %v", err)
			}
			if err := contract.ValidateAgainstSchema(contract.SchemaAuthZENResponse, doc); err != nil {
				t.Errorf("the response does not satisfy the published schema: %v\n%s", err, rr.Body.String())
			}
		})
	}
}

// TestAuthZENProfileNegotiationGatesTheContext pins ADR-065 invariant 12 at the
// wire.
//
// A caller that did not negotiate cannot act on an obligation or a challenge.
// Sending it the profile payload anyway would hand it a partial interpretation
// it will ignore, which is worse than the boolean it understands.
func TestAuthZENProfileNegotiationGatesTheContext(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
	body := singularEnvelope(t, okSubject, okAction, okResource, okContext)

	for _, tc := range []struct {
		name        string
		headers     map[string]string
		wantContext bool
	}{
		// An ABSENT or EMPTY header is a caller asking for AuthZEN 1.0, and it
		// gets AuthZEN 1.0. An UNRECOGNISED one is a different question and has
		// its own test below: it is refused rather than answered, because a
		// bare boolean would tell a PEP its negotiation succeeded.
		{"no profile header", nil, false},
		{"an empty profile header", map[string]string{authzenProfileHeader: ""}, false},
		{"the negotiated profile", negotiated(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := authzenForTest(t, body, tc.headers)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d; body=%s", rr.Code, rr.Body.String())
			}
			var resp contract.AuthZENResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if got := resp.Context != nil; got != tc.wantContext {
				t.Errorf("context present = %v, want %v; body=%s", got, tc.wantContext, rr.Body.String())
			}
			// The boolean is returned either way. A caller that did not
			// negotiate still gets an answer.
			if !strings.Contains(rr.Body.String(), `"decision"`) {
				t.Errorf("no decision member: %s", rr.Body.String())
			}
		})
	}
}

// TestAuthZENRefusesAProfileItCannotEmit is the other half of negotiation.
//
// The test above proves an ABSENT profile gets the boolean. This proves a
// NAMED-but-unknown one does not: answering it with `{"decision":true}` and no
// context would tell a PEP that negotiated a later profile that its negotiation
// succeeded, and it would proceed on an allow having silently dropped whatever
// mandatory obligation the profile it asked for carries. The refusal is the
// renegotiation signal, and it must name the version this build does emit or
// the caller has nothing to fall back to.
func TestAuthZENRefusesAProfileItCannotEmit(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
	body := singularEnvelope(t, okSubject, okAction, okResource, okContext)

	for _, name := range []string{
		"axonflow-authzen-profile-2099-01-01",
		"axonflow-authzen-profile-2026-08-28",
		"garbage",
	} {
		t.Run(name, func(t *testing.T) {
			rr := authzenForTest(t, body, map[string]string{authzenProfileHeader: name})
			if rr.Code != http.StatusNotAcceptable {
				t.Fatalf("status %d, want 406; body=%s", rr.Code, rr.Body.String())
			}
			// A refusal is a different SHAPE from a decision. A body carrying
			// `decision` would let a client that branches on the member alone
			// read the refusal as a verdict.
			if strings.Contains(rr.Body.String(), `"decision"`) {
				t.Errorf("the refusal carries a decision member: %s", rr.Body.String())
			}
			e := decodeRefusal(t, rr)
			if e.Code != contract.ErrUnevaluableAttribute {
				t.Errorf("code %q, want %q", e.Code, contract.ErrUnevaluableAttribute)
			}
			if !strings.Contains(e.Message, authzenProfileHeader) {
				t.Errorf("the refusal does not name the header the caller must change: %q", e.Message)
			}
			if len(e.Supported) != 1 || e.Supported[0] != string(contract.AuthZENProfileV1) {
				t.Errorf("supported = %v, want the profile this build emits", e.Supported)
			}
		})
	}
}

// TestAuthZENRefusesAnAbsentRequiredType is the tri-state half of the
// impersonation refusal.
//
// The schema marks `type` REQUIRED on the subject and the resource, and nothing
// on the serving path enforced it: every check was written `if type != "" &&
// ...`, so ABSENT read as the one supported value. The consequence was not
// cosmetic. `{"subject":{"type":"user","id":"alice@corp"}}` was refused as
// impersonation, while the byte-identical request with `type` OMITTED was
// ACCEPTED and bound alice@corp to CallerIdentity.GatewayID.
//
// Every case is asserted in BOTH shapes. The omission that mattered most lived
// in a plural envelope's shared base, which the singular refusal tests cannot
// reach.
func TestAuthZENRefusesAnAbsentRequiredType(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	for _, tc := range []struct {
		name    string
		body    string
		code    contract.AuthZENErrorCode
		pointer string
	}{
		{
			name:    "a singular subject with no type",
			body:    singularEnvelope(t, `{"id":"alice@corp"}`, okAction, okResource, okContext),
			code:    contract.ErrUnsupportedSubject,
			pointer: "/evaluation/subject/type",
		},
		{
			name:    "a singular resource with no type",
			body:    singularEnvelope(t, okSubject, okAction, `{"id":"llm"}`, okContext),
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluation/resource/type",
		},
		{
			name: "a shared base whose subject has no type",
			body: `{"evaluations":{"subject":{"id":"alice@corp"},"action":` + okAction +
				`,"context":` + okContext + `,"evaluations":[{"resource":` + okResource + `}]}}`,
			code:    contract.ErrUnsupportedSubject,
			pointer: "/evaluations/evaluations/0/subject/type",
		},
		{
			name: "a shared base whose resource has no type",
			body: `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
				`,"resource":{"id":"llm"},"context":` + okContext + `,"evaluations":[{}]}}`,
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluations/evaluations/0/resource/type",
		},
		{
			name: "an entry whose own resource has no type",
			body: `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
				`,"context":` + okContext + `,"evaluations":[{"resource":{"id":"llm"}}]}}`,
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluations/evaluations/0/resource/type",
		},
		{
			name:    "a singular action with no name",
			body:    singularEnvelope(t, okSubject, `{}`, okResource, okContext),
			code:    contract.ErrUnsupportedAction,
			pointer: "/evaluation/action/name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := authzenForTest(t, tc.body, negotiated())
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422; body=%s", rr.Code, rr.Body.String())
			}
			e := decodeRefusal(t, rr)
			if e.Code != tc.code {
				t.Errorf("code %q, want %q; body=%s", e.Code, tc.code, rr.Body.String())
			}
			if e.Pointer != tc.pointer {
				t.Errorf("pointer %q, want %q", e.Pointer, tc.pointer)
			}
		})
	}

	// The control that makes the refusals above mean something: an omitted type
	// is refused, a STATED end-user type is refused, and the two carry the same
	// code, so a client cannot be told the omission was a different class of
	// problem.
	stated := authzenForTest(t, singularEnvelope(t,
		`{"type":"user","id":"alice@corp"}`, okAction, okResource, okContext), negotiated())
	omitted := authzenForTest(t, singularEnvelope(t,
		`{"id":"alice@corp"}`, okAction, okResource, okContext), negotiated())
	if stated.Code != omitted.Code {
		t.Errorf("a stated end-user subject got %d and the same subject with the type omitted got %d",
			stated.Code, omitted.Code)
	}
}

// TestPluralEntryContextDoesNotDiscardTheBase pins the merge.
//
// `context` is a bag of independent members, and inheriting it all-or-nothing
// meant an entry that supplied its own `args` DISCARDED the base's
// `correlation`. The base is validated like an entry, so an allowlisted
// correlation key there passes every refusal, is accepted, and then reaches no
// audit row - which is precisely the harm the correlation refusal's own message
// names. Mapped or refused, never silently ignored.
//
// The assertion is on the REQUEST the adapter produced rather than on a 200,
// because the dropped key changes nothing a caller can see in the response.
func TestPluralEntryContextDoesNotDiscardTheBase(t *testing.T) {
	raw := `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
		`,"context":{"correlation":{"x-session-id":"s-1"}}` +
		`,"evaluations":[{"resource":` + okResource + `,"context":{"args":{"query":"q"}}}]}}`

	env, err := contract.DecodeAuthZENEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("the fixture does not decode: %v", err)
	}
	mapped, mapErr := mapEnvelope(env)
	if mapErr != nil {
		t.Fatalf("the envelope was refused: %v", mapErr)
	}
	if len(mapped) != 1 {
		t.Fatalf("mapped %d evaluations, want 1", len(mapped))
	}
	got := mapped[0].request
	if got.Query != "q" {
		t.Errorf("query %q, want the entry's own args to survive the merge", got.Query)
	}
	if got.Context["x-session-id"] != "s-1" {
		t.Errorf("the base's correlation was dropped by an entry that supplied its own context: %#v", got.Context)
	}

	// The entry still WINS a genuine collision. That is an override the caller
	// wrote and can see, unlike a member that vanishes.
	raw = `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
		`,"context":{"args":{"query":"base"},"correlation":{"x-session-id":"s-base"}}` +
		`,"evaluations":[{"resource":` + okResource +
		`,"context":{"args":{"query":"entry"},"correlation":{"x-session-id":"s-entry"}}}]}}`
	env, err = contract.DecodeAuthZENEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("the fixture does not decode: %v", err)
	}
	mapped, mapErr = mapEnvelope(env)
	if mapErr != nil {
		t.Fatalf("the envelope was refused: %v", mapErr)
	}
	if mapped[0].request.Query != "entry" {
		t.Errorf("query %q, want the entry to win its own collision", mapped[0].request.Query)
	}
	if mapped[0].request.Context["x-session-id"] != "s-entry" {
		t.Errorf("correlation %#v, want the entry to win its own collision", mapped[0].request.Context)
	}
}

// TestAMergedContextCannotSmuggleAnythingPastTheRefusals is the safety half of
// the merge above.
//
// A per-key merge is only safe if it cannot assemble a bag that neither half
// was allowed to send. Two facts make it so and both are asserted here: the
// base is validated BEFORE any merging, and mapOne re-validates the MERGED
// entry. The second is what a future deeper merge would rely on, so it is
// pinned now rather than assumed.
func TestAMergedContextCannotSmuggleAnythingPastTheRefusals(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{
			// The base carries a correlation key this deployment records
			// nowhere, and the entry supplies a context of its own - the exact
			// shape that used to discard the base's context wholesale, and with
			// it the refusal that key was owed.
			name: "an unrecorded correlation key in the base beside an entry context",
			raw: `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
				`,"context":{"correlation":{"x-not-recorded-anywhere":"v"}}` +
				`,"evaluations":[{"resource":` + okResource + `,"context":{"args":{"query":"q"}}}]}}`,
		},
		{
			name: "an unevaluable base member beside an entry context",
			raw: `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
				`,"context":{"department":"legal"}` +
				`,"evaluations":[{"resource":` + okResource + `,"context":{"args":{"query":"q"}}}]}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, err := contract.DecodeAuthZENEnvelope([]byte(tc.raw))
			if err != nil {
				t.Fatalf("the fixture does not decode: %v", err)
			}
			if _, mapErr := mapEnvelope(env); mapErr == nil {
				t.Fatal("the merge carried a base member the refusals should have caught")
			}
		})
	}
}

// TestAuthZENPluralEnvelopeMeetsRatherThanFansOut pins the combining rule.
func TestAuthZENPluralEnvelopeMeetsRatherThanFansOut(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body := `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
		`,"context":` + okContext + `,"evaluations":[` +
		`{"resource":{"type":"llm","id":"llm"}},` +
		`{"resource":{"type":"llm","id":"llm"}}]}}`
	rr := authzenForTest(t, body, negotiated())
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", rr.Code, rr.Body.String())
	}
	// One decision, never a list: the entries are preconditions of one
	// operation, so a caller must not be handed the entry it liked.
	var asList []any
	if err := json.Unmarshal(rr.Body.Bytes(), &asList); err == nil {
		t.Fatalf("the plural envelope returned a list: %s", rr.Body.String())
	}
	var resp contract.AuthZENResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Context == nil {
		t.Fatal("no profile context")
	}
}

// TestMeetStatesIsLeastPermissive pins the combining order directly, over every
// pair, rather than through whichever pair a fixture happens to produce.
func TestMeetStatesIsLeastPermissive(t *testing.T) {
	all := contract.AllOperationalStates()
	for _, a := range all {
		for _, b := range all {
			got, err := meetStates([]contract.OperationalState{a, b})
			if err != nil {
				t.Fatalf("meeting %s and %s: %v", a, b, err)
			}
			// The meet must never be more permissive than either input.
			if authzenMeetPrecedence[got] > authzenMeetPrecedence[a] ||
				authzenMeetPrecedence[got] > authzenMeetPrecedence[b] {
				t.Errorf("meet(%s,%s) = %s, which is more permissive than an input", a, b, got)
			}
			// ...and it must be one of them, not a third state invented by the
			// combination.
			if got != a && got != b {
				t.Errorf("meet(%s,%s) = %s, which is neither input", a, b, got)
			}
		}
	}
	// A single denied entry denies the operation, whatever it is meeting.
	for _, s := range all {
		if got, _ := meetStates([]contract.OperationalState{contract.StateDeny, s}); got != contract.StateDeny {
			t.Errorf("meet(DENY,%s) = %s", s, got)
		}
	}
	// An empty set is an error rather than an ALLOW. "The list was empty" is
	// the worst possible reason to permit an operation.
	if _, err := meetStates(nil); err == nil {
		t.Error("an empty state set was met without error")
	}
	// An unranked state fails loudly rather than becoming the zero rank.
	if _, err := meetStates([]contract.OperationalState{"MAYBE"}); err == nil {
		t.Error("an undeclared state was ordered")
	}
}

// TestAuthZENStateMappingIsTotalAndFailsSafe pins the verdict translation.
func TestAuthZENStateMappingIsTotalAndFailsSafe(t *testing.T) {
	for verdict, want := range map[string]contract.OperationalState{
		VerdictAllow:         contract.StateAllow,
		VerdictDeny:          contract.StateDeny,
		VerdictNeedsApproval: contract.StateChallenge,
	} {
		if got := authzenStateFor(verdict); got != want {
			t.Errorf("verdict %q mapped to %s, want %s", verdict, got, want)
		}
	}
	// A verdict this build does not recognise is an evaluation whose meaning is
	// unknown, and the safe reading of an unknown meaning is not ALLOW.
	for _, unknown := range []string{"", "allowed", "permit", "ALLOW", "maybe"} {
		got := authzenStateFor(unknown)
		if got == contract.StateAllow {
			t.Errorf("unrecognised verdict %q became ALLOW", unknown)
		}
		if got != contract.StateError {
			t.Errorf("unrecognised verdict %q became %s, want ERROR", unknown, got)
		}
	}
	// Every state maps to a declared reason, and every reason to a declared
	// category, so no response can carry a code the schema refuses.
	for _, s := range contract.AllOperationalStates() {
		reason := authzenReasonFor(s)
		declared := false
		for _, r := range contract.AllReasonCodes() {
			if r == reason {
				declared = true
			}
		}
		if !declared {
			t.Errorf("state %s maps to undeclared reason %q", s, reason)
		}
	}
}

// TestAuthZENSurfacesAnUnmappableObligationAsUnavailable pins the obligation
// table's fail-loud rule.
//
// The table is closed, so this path is unreachable with today's evaluator. It
// is asserted anyway because "unreachable today" is the state every fail-open
// starts in: the day a second obligation type is added to the Decision API,
// this is the branch that decides whether the caller learns about it or is
// handed an allow whose conditions it never saw.
func TestAuthZENSurfacesAnUnmappableObligationAsUnavailable(t *testing.T) {
	if _, err := mapObligations([]DecisionObligation{newRedactPIIObligation("PII detected")}); err != nil {
		t.Fatalf("the known obligation did not map: %v", err)
	}
	got, err := mapObligations([]DecisionObligation{{Type: "quarantine_payload"}})
	if err == nil {
		t.Fatalf("an unmappable obligation was accepted, yielding %+v", got)
	}
	if !strings.Contains(err.Error(), "quarantine_payload") {
		t.Errorf("the error does not name the obligation: %v", err)
	}
}

// TestAuthZENRejectsNonPOST pins the defence in depth.
func TestAuthZENRejectsNonPOST(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodOptions, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, authzenHandlerPath, nil)
		rr := httptest.NewRecorder()
		handleAuthZENEvaluation(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, rr.Code)
		}
	}
}

// TestAuthZENRequiresAuthentication proves the route is behind the same
// middleware as the Decision API.
//
// The handler-level tests above call the handler directly, which is what makes
// this one necessary: without it the whole suite would be evidence about a
// function nobody can reach the way a customer reaches it.
func TestAuthZENRequiresAuthentication(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	req := httptest.NewRequest("POST", authzenHandlerPath,
		bytes.NewBufferString(singularEnvelope(t, okSubject, okAction, okResource, okContext)))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header.
	rr := httptest.NewRecorder()
	apiAuthMiddleware(http.HandlerFunc(handleAuthZENEvaluation)).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401; body=%s", rr.Code, rr.Body.String())
	}
}

// TestAuthZENBodyIsBounded pins the size limit. A plural envelope is a list,
// and an unbounded list is an unbounded number of policy evaluations from one
// request.
func TestAuthZENBodyIsBounded(t *testing.T) {
	huge := `{"evaluation":{"subject":{"type":"gateway","id":"` +
		strings.Repeat("a", maxAuthZENBodyBytes+1) + `"}}}`
	rr := authzenForTest(t, huge, negotiated())
	if rr.Code == http.StatusOK {
		t.Errorf("an oversized body was evaluated: %d", rr.Code)
	}
}

// TestDecisionAPIKeepsItsMembersAndLeaksNoAuthZENMember pins the additivity
// half of the release constraint.
//
// WHAT IT PROVES, EXACTLY, because the name it used to carry claimed more than
// it delivered. It asserts that a 200 response to a single Decision API request
// still carries six named members, and that none of the three AuthZEN members
// appears in it. That is a MEMBER-SET assertion, not byte stability: it does not
// pin status codes across inputs, verdict VALUES, member ORDER, or encoding, so
// it must not be cited as evidence that the response is byte-for-byte what it
// was. It catches the failure that matters here - the shared evaluation growing
// or losing a member, or an AuthZEN member leaking through the delegation - and
// a claim wider than that is a claim this test cannot support.
func TestDecisionAPIKeepsItsMembersAndLeaksNoAuthZENMember(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "llm-gateway-01"},
		Target:         DecisionTarget{Type: "llm", Provider: "openai", Model: "gpt-4o"},
		Query:          "what is the weather",
	})
	rr := decideForTest(t, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	// The members a PEP built against 10.2.0 reads. Their PRESENCE is the
	// contract; their values vary with policy.
	for _, member := range []string{"verdict", "decision_id", "trace_id", "obligations", "evaluated_policies", "expires_at"} {
		if _, ok := got[member]; !ok {
			t.Errorf("the Decision API response lost the member %q: %s", member, rr.Body.String())
		}
	}
	// And no AuthZEN member leaked into it.
	for _, member := range []string{"decision", "context", "profile"} {
		if _, ok := got[member]; ok {
			t.Errorf("an AuthZEN member %q leaked into the Decision API response: %s", member, rr.Body.String())
		}
	}
}

// TestAuthZENRecordsItsOwnAuditPlane pins constraint 4 of the release ruling:
// this route is a PLANE.
//
// It exists because the constant was decorative when it was first written. The
// handler declared PlaneAccessEvaluation, documented why folding AuthZEN
// traffic into `decision` would make adoption unmeasurable, and then delegated
// to a handler that stamped `decision` on every row -- a declared-but-never-
// emitted value whose own comment described behaviour the code did not have.
// Only a live audit row disclosed it.
//
// The two directions are asserted together: the delegated call must carry the
// AuthZEN plane, and a DIRECT call must still carry the Decision API's, because
// a fix that stamped the new plane on both would silently rewrite the meaning of
// every existing /api/v1/decide audit row.
func TestAuthZENRecordsItsOwnAuditPlane(t *testing.T) {
	if PlaneAccessEvaluation == PlaneDecision {
		t.Fatal("the two planes are the same value; the surface would be unmeasurable")
	}

	// A context with no override is a direct Decision API call.
	if got := decisionPlaneFromContext(context.Background()); got != PlaneDecision {
		t.Errorf("a direct call records plane %q, want %q", got, PlaneDecision)
	}

	// ...and the delegated one carries this surface's plane.
	ctx := withDecisionPlane(context.Background(), PlaneAccessEvaluation)
	if got := decisionPlaneFromContext(ctx); got != PlaneAccessEvaluation {
		t.Errorf("a delegated call records plane %q, want %q", got, PlaneAccessEvaluation)
	}

	// An empty override must not blank the plane: an audit row with no surface
	// is worse than one with the wrong surface, because it matches no query.
	if got := decisionPlaneFromContext(withDecisionPlane(context.Background(), "")); got != PlaneDecision {
		t.Errorf("an empty override produced plane %q, want the default %q", got, PlaneDecision)
	}

	// The delegation path actually sets it. Asserting the helpers alone would
	// leave exactly the defect this test was written for: correct plumbing that
	// nothing calls.
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)
	req := httptest.NewRequest("POST", authzenHandlerPath,
		bytes.NewBufferString(singularEnvelope(t, okSubject, okAction, okResource, okContext)))
	req.Header.Set("Content-Type", "application/json")
	var seen string
	restore := decisionPlaneObserver
	decisionPlaneObserver = func(plane string) { seen = plane }
	t.Cleanup(func() { decisionPlaneObserver = restore })

	rr := httptest.NewRecorder()
	handleAuthZENEvaluation(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", rr.Code, rr.Body.String())
	}
	if seen != PlaneAccessEvaluation {
		t.Errorf("the delegated evaluation recorded plane %q, want %q", seen, PlaneAccessEvaluation)
	}
}

// TestEveryDecidePlaneWritesAConstraintValidVerdict pins the defect a live
// database found and no unit test could.
//
// audit_logs.policy_decision carries a CHECK constraint. writeDecisionAuditLog
// canonicalizes the wire verdict (`allow` -> `allowed`) only for an ALLOW-LIST
// of planes, so a plane added without touching that list writes the raw wire
// value, violates the constraint, and loses its audit row -- silently, because
// the insert is deliberately non-fatal and the caller still gets its 200. That
// is exactly what happened when this route first recorded its own plane.
//
// sqlmock has no constraints, so every existing unit test stayed green. This
// asserts the property directly instead: for every plane that routes through
// handleDecide, every verdict it can emit must canonicalize to something the
// column can hold.
func TestEveryDecidePlaneWritesAConstraintValidVerdict(t *testing.T) {
	// The values the CHECK constraint admits. Restated here on purpose: this is
	// the DATABASE's contract, and a test that read it from the same helper the
	// writer uses would agree with the writer by construction.
	constraintValid := map[string]bool{
		"allowed": true, "blocked": true, "redacted": true,
		"needs_approval": true, "error": true, "override_lifecycle": true,
	}

	// The WRITER's own predicate is called, with the plane, not the
	// canonicalizer underneath it. An earlier version of this test iterated
	// planes and then called canonicalAuditVerdict directly -- the plane
	// appeared only in the failure message -- so it passed with the allow-list
	// mutated, which is the exact defect it exists to prevent.
	for _, plane := range []string{PlaneDecision, PlaneOpenAICompat, PlaneAccessEvaluation} {
		for _, verdict := range []string{VerdictAllow, VerdictDeny, VerdictNeedsApproval, AuditVerdictError} {
			got := auditPolicyDecisionFor(plane, verdict)
			if !constraintValid[got] {
				t.Errorf("plane %s, verdict %q is written as %q, which audit_logs cannot hold",
					plane, verdict, got)
			}
		}
		// An unrecognised verdict must still land on a value the column accepts.
		for _, junk := range []string{"", "permit", "ALLOW", "yes"} {
			if got := auditPolicyDecisionFor(plane, junk); !constraintValid[got] {
				t.Errorf("plane %s, unrecognised verdict %q is written as %q, which audit_logs cannot hold",
					plane, junk, got)
			}
		}
	}

	// The raw wire verdicts are NOT constraint-valid. Without this the loop
	// above would pass over a predicate that returned its input unchanged.
	for _, wire := range []string{VerdictAllow, VerdictDeny} {
		if constraintValid[wire] {
			t.Fatalf("the wire verdict %q is constraint-valid, so this test cannot detect a missing canonicalization", wire)
		}
	}

	// ...and the predicate really is plane-dependent: a plane OUTSIDE the
	// allow-list passes the verdict through untouched. This is what makes the
	// loop above a test of the allow-list rather than of canonicalAuditVerdict.
	// The MCP planes are excluded deliberately (#2643) because they already emit
	// the canonical vocabulary, and because override_lifecycle -- constraint
	// valid, and not a verdict -- would be rewritten to `error`.
	if got := auditPolicyDecisionFor(PlaneMCP, VerdictAllow); got != VerdictAllow {
		t.Errorf("plane %s canonicalized %q to %q; the allow-list is not being consulted",
			PlaneMCP, VerdictAllow, got)
	}
	if got := auditPolicyDecisionFor(PlaneMCP, "override_lifecycle"); got != "override_lifecycle" {
		t.Errorf("plane %s rewrote override_lifecycle to %q; canonicalizing unconditionally would corrupt it",
			PlaneMCP, got)
	}
}

func TestAuthZENRefusesUnevaluableDataInTheSharedBase(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	// In each case the BASE carries something unevaluable and EVERY entry
	// overrides that member, so merging discards it unread.
	for _, tc := range []struct {
		name    string
		body    string
		code    contract.AuthZENErrorCode
		pointer string
	}{
		{
			name: "a subject property in the base, overridden by the entry",
			body: `{"evaluations":{"subject":{"type":"gateway","id":"g","properties":{"clearance":"secret"}},` +
				`"action":` + okAction + `,"context":` + okContext + `,` +
				`"evaluations":[{"subject":{"type":"gateway","id":"g2"},"resource":` + okResource + `}]}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/subject/properties",
		},
		{
			name: "an action property in the base, overridden by the entry",
			body: `{"evaluations":{"subject":` + okSubject + `,"action":{"name":"llm.completion","properties":{"urgency":"high"}},` +
				`"context":` + okContext + `,` +
				`"evaluations":[{"action":` + okAction + `,"resource":` + okResource + `}]}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/action/properties",
		},
		{
			name: "a resource property in the base, overridden by the entry",
			body: `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction + `,` +
				`"resource":{"type":"llm","id":"llm","properties":{"tier":"gold"}},` +
				`"context":` + okContext + `,"evaluations":[{"resource":` + okResource + `}]}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/resource/properties",
		},
		{
			name: "an unrecognised context member in the base, overridden by the entry",
			body: `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction + `,` +
				`"context":{"args":{"query":"q"},"department":"legal"},` +
				`"evaluations":[{"resource":` + okResource + `,"context":` + okContext + `}]}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/context/department",
		},
		{
			name: "an end-user subject in the base, overridden by the entry",
			body: `{"evaluations":{"subject":{"type":"identity","id":"alice@example.com"},` +
				`"action":` + okAction + `,"context":` + okContext + `,` +
				`"evaluations":[{"subject":` + okSubject + `,"resource":` + okResource + `}]}}`,
			code:    contract.ErrUnsupportedSubject,
			pointer: "/evaluations/subject/type",
		},
		// ...and the same data in an ENTRY of a plural envelope, which the
		// singular-only suite also never covered.
		{
			name: "a subject property in a plural ENTRY",
			body: `{"evaluations":{"action":` + okAction + `,"context":` + okContext + `,` +
				`"evaluations":[{"subject":{"type":"gateway","id":"g","properties":{"clearance":"secret"}},"resource":` + okResource + `}]}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/evaluations/0/subject/properties",
		},
		{
			name: "unevaluable data in the SECOND entry only",
			body: `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction + `,"context":` + okContext + `,` +
				`"evaluations":[{"resource":` + okResource + `},` +
				`{"resource":{"type":"llm","id":"anthropic/claude-sonnet-4","properties":{"tier":"gold"}}}]}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/evaluations/1/resource/properties",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := authzenForTest(t, tc.body, negotiated())
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422; body=%s", rr.Code, rr.Body.String())
			}
			e := decodeRefusal(t, rr)
			if e.Code != tc.code {
				t.Errorf("code %q, want %q", e.Code, tc.code)
			}
			if e.Pointer != tc.pointer {
				t.Errorf("pointer %q, want %q", e.Pointer, tc.pointer)
			}
		})
	}

	// The control: a plural envelope carrying nothing unevaluable must still be
	// evaluated, or the fix above would be "refuse all bulk requests".
	ok := `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction + `,"context":` + okContext +
		`,"evaluations":[{"resource":` + okResource + `},{"resource":{"type":"llm","id":"llm"}}]}}`
	if rr := authzenForTest(t, ok, negotiated()); rr.Code != http.StatusOK {
		t.Errorf("a clean plural envelope was refused: %d %s", rr.Code, rr.Body.String())
	}
}

// TestObligationsAreValidAndDischargeable pins the two rules that make an
// obligation on this surface usable rather than merely present.
//
// The first version of mapObligations emitted a disclosure transform with NO
// target -- which the contract's own Validate rejects -- and dropped the
// Fulfillment block entirely. Both shipped green: nothing called Validate, and
// no test drove an obligation through. A caller would have been told
// "field_redact, mandatory" with no target field, no endpoint and no method,
// while ADR-056 forbids client-side redaction. That is an allow the caller
// cannot lawfully act on.
func TestObligationsAreValidAndDischargeable(t *testing.T) {
	legacy := newRedactPIIObligation("SSN detected")

	got, err := mapObligations([]DecisionObligation{legacy})
	if err != nil {
		t.Fatalf("the known obligation did not map: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one obligation, got %d", len(got))
	}
	ob := got[0]

	// The contract's OWN validator, not a restatement of it. This is the check
	// whose absence let the invalid shape ship.
	if err := ob.Validate(); err != nil {
		t.Errorf("the emitted obligation is invalid under the contract: %v", err)
	}
	if ob.Target == "" {
		t.Error("a disclosure transform was emitted with no target field path")
	}

	// The PEP must be able to discharge it. An obligation it cannot discharge
	// is one the contract says must deny, so emitting it as a plain allow
	// condition would be worse than not emitting it.
	for _, k := range []string{"fulfillment_endpoint", "fulfillment_method", "fulfillment_phase"} {
		if ob.Params[k] == "" {
			t.Errorf("the emitted obligation carries no %s; the caller cannot discharge it", k)
		}
	}
	if ob.Params["fulfillment_endpoint"] != legacy.Fulfillment.Endpoint {
		t.Errorf("endpoint %q, want %q", ob.Params["fulfillment_endpoint"], legacy.Fulfillment.Endpoint)
	}
	if ob.Params["detail"] != "SSN detected" {
		t.Errorf("the human-readable detail was dropped: %q", ob.Params["detail"])
	}

	// It must also satisfy the PUBLISHED schema, which is what every generated
	// SDK validates against.
	raw, err := json.Marshal(ob)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if err := contract.ValidateAgainstSchema(contract.SchemaObligation, doc); err != nil {
		t.Errorf("the emitted obligation does not satisfy the published schema: %v\n%s", err, raw)
	}

	// An obligation with NO fulfillment block is refused rather than rendered
	// undischargeable. This is the branch that turns a lossy render into a
	// loud one.
	if _, err := mapObligations([]DecisionObligation{{Type: ObligationRedactPII}}); err == nil {
		t.Error("an obligation with no fulfillment block was rendered as a mandatory one")
	}
}

// TestAuthZENRefusesInputTheEvaluatorWouldSilentlyDrop covers the two members
// that were accepted and then discarded further down.
//
// Both are the same class as a caller-supplied property: the caller sends
// something, gets a 200, and the thing it sent reaches nothing. The difference
// is only WHERE the drop happened -- inside the evaluator's context allowlist,
// or in an audit row that names no caller.
func TestAuthZENRefusesInputTheEvaluatorWouldSilentlyDrop(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	for _, tc := range []struct {
		name    string
		body    string
		code    contract.AuthZENErrorCode
		pointer string
	}{
		{
			// canonicalizeRequestContext keeps only the deployment's allowlist
			// and drops the rest, so this key would have reached no audit row.
			name:    "a correlation key this deployment does not record",
			body:    singularEnvelope(t, okSubject, okAction, okResource, `{"args":{"query":"q"},"correlation":{"case_id":"C-1"}}`),
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluation/context/correlation/case_id",
		},
		{
			name:    "an empty subject id",
			body:    singularEnvelope(t, `{"type":"gateway","id":""}`, okAction, okResource, okContext),
			code:    contract.ErrIncompleteEvaluation,
			pointer: "/evaluation/subject/id",
		},
		{
			name:    "a whitespace-only subject id",
			body:    singularEnvelope(t, `{"type":"gateway","id":"   "}`, okAction, okResource, okContext),
			code:    contract.ErrIncompleteEvaluation,
			pointer: "/evaluation/subject/id",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := authzenForTest(t, tc.body, negotiated())
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422; body=%s", rr.Code, rr.Body.String())
			}
			e := decodeRefusal(t, rr)
			if e.Code != tc.code {
				t.Errorf("code %q, want %q", e.Code, tc.code)
			}
			if e.Pointer != tc.pointer {
				t.Errorf("pointer %q, want %q", e.Pointer, tc.pointer)
			}
		})
	}

	// The control: a key the deployment DOES record must still be accepted, or
	// the fix above is "refuse all correlation".
	ok := singularEnvelope(t, okSubject, okAction, okResource,
		`{"args":{"query":"q"},"correlation":{"x-session-id":"s-1"}}`)
	if rr := authzenForTest(t, ok, negotiated()); rr.Code != http.StatusOK {
		t.Errorf("a recorded correlation key was refused: %d %s", rr.Code, rr.Body.String())
	}

	// ...and the allowlist is genuinely consulted rather than hardcoded: a
	// deployment that widens it widens what this surface accepts.
	t.Setenv("AXONFLOW_DECISION_CONTEXT_ALLOWLIST", "case-id,x-session-id")
	widened := singularEnvelope(t, okSubject, okAction, okResource,
		`{"args":{"query":"q"},"correlation":{"case_id":"C-1"}}`)
	if rr := authzenForTest(t, widened, negotiated()); rr.Code != http.StatusOK {
		t.Errorf("a key the deployment was configured to record was still refused: %d %s", rr.Code, rr.Body.String())
	}
}

// TestTheBaseIsValidatedLikeAnEntry is the round-2 regression: the first fix
// covered a LIST of members, not the class.
//
// refuseUnevaluableMembers originally checked seven things - three properties
// bags, the subject type, the action name, the resource type, and top-level
// context keys. Everything it omitted stayed reachable through the shared base
// of a plural envelope, and every case below was verified to return 200 with a
// decision before this test existed, while the byte-identical SINGULAR request
// was correctly refused.
//
// The fix is structural rather than another list: the base and every merged
// entry now run through the SAME validator, and the only thing that differs is
// completeness. That is why this test asserts the singular and plural forms
// give the same answer, rather than enumerating a longer list of members.
func TestTheBaseIsValidatedLikeAnEntry(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	// Each case is a member written into the SHARED BASE that every entry then
	// overrides, so merging discards it unread.
	for _, tc := range []struct {
		name    string
		base    string
		code    contract.AuthZENErrorCode
		pointer string
	}{
		{
			name:    "an argument beside the query",
			base:    `"context":{"args":{"query":"q","amount_cents":9000}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/context/args/amount_cents",
		},
		{
			name:    "a correlation key this deployment does not record",
			base:    `"context":{"args":{"query":"q"},"correlation":{"case_id":"C-1"}}`,
			code:    contract.ErrUnevaluableAttribute,
			pointer: "/evaluations/context/correlation/case_id",
		},
		{
			name:    "a query that is not a string",
			base:    `"context":{"args":{"query":12345}}`,
			code:    contract.ErrMissingEvaluableContent,
			pointer: "/evaluations/context/args/query",
		},
		{
			name:    "a resource id naming a provider nothing reads",
			base:    `"resource":{"type":"llm","id":"openai/gpt-4o"},"context":` + okContext,
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluations/resource/id",
		},
		{
			name:    "an action and a resource describing different operations",
			base:    `"action":{"name":"llm.completion"},"resource":{"type":"tool","id":"jira/create"},"context":` + okContext,
			code:    contract.ErrUnsupportedResource,
			pointer: "/evaluations/resource/type",
		},
		{
			name:    "a blank subject id",
			base:    `"subject":{"type":"gateway","id":"   "},"context":` + okContext,
			code:    contract.ErrIncompleteEvaluation,
			pointer: "/evaluations/subject/id",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Every entry supplies its own subject, action and resource, so the
			// base's members are discarded by the merge.
			body := `{"evaluations":{` + tc.base + `,"evaluations":[{` +
				`"subject":` + okSubject + `,"action":` + okAction +
				`,"resource":` + okResource + `,"context":` + okContext + `}]}}`
			rr := authzenForTest(t, body, negotiated())
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422; body=%s", rr.Code, rr.Body.String())
			}
			e := decodeRefusal(t, rr)
			if e.Code != tc.code {
				t.Errorf("code %q, want %q", e.Code, tc.code)
			}
			if e.Pointer != tc.pointer {
				t.Errorf("pointer %q, want %q", e.Pointer, tc.pointer)
			}
		})
	}
}

// TestCorrelationRefusalUsesTheEvaluatorsOwnMatcher pins the round-2 finding
// that the refusal reintroduced the harm it was added to prevent.
//
// The first version reimplemented the allowlist rule and folded "." along with
// "-" and "_", which the evaluator's rule does not. So `x.ai.agent`, `xaiagent`
// and `x-ai.agent` were ACCEPTED here and DROPPED there - told captured, not
// captured. It now calls matchContextAllowlist directly.
func TestCorrelationRefusalUsesTheEvaluatorsOwnMatcher(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	allowed := decisionContextAllowlist()
	// Spellings that a "-", "_" AND "." folding rule would accept but the real
	// rule refuses. Asserting against matchContextAllowlist is the point: the
	// adapter's answer must be the evaluator's answer, whatever that is.
	for _, k := range []string{"x.ai.agent", "xaiagent", "x-ai.agent", "x--ai--agent"} {
		if matchContextAllowlist(k, allowed) {
			t.Fatalf("fixture %q is recorded by this deployment; it cannot demonstrate the disagreement", k)
		}
		body := singularEnvelope(t, okSubject, okAction, okResource,
			`{"args":{"query":"q"},"correlation":{"`+k+`":"v"}}`)
		rr := authzenForTest(t, body, negotiated())
		if rr.Code != http.StatusUnprocessableEntity {
			t.Errorf("the correlation key %q was accepted (%d) but the evaluator would drop it: %s",
				k, rr.Code, rr.Body.String())
		}
	}

	// The surplus-key cap: the evaluator keeps at most maxContextKeys and
	// truncates the rest, and which keys survive is not the caller's choice.
	var keys []string
	for i := 0; i < maxContextKeys+2; i++ {
		keys = append(keys, fmt.Sprintf(`"x-tenant-%d":"v"`, i))
	}
	t.Setenv("AXONFLOW_DECISION_CONTEXT_ALLOWLIST", "x-tenant-*")
	body := singularEnvelope(t, okSubject, okAction, okResource,
		`{"args":{"query":"q"},"correlation":{`+strings.Join(keys, ",")+`}}`)
	rr := authzenForTest(t, body, negotiated())
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("%d correlation keys were accepted (%d) but only %d are recorded: %s",
			len(keys), rr.Code, maxContextKeys, rr.Body.String())
	}
}
