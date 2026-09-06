package agent

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// newAuthZENRequest and serveAuthZEN exist because authzenForTest takes a
// map[string]string and therefore cannot express a REPEATED header - which is
// the one input the test below is about.
func newAuthZENRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", authzenHandlerPath, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func serveAuthZEN(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handleAuthZENEvaluation(rr, req)
	return rr
}

// TestTheHandshakeReachesTheEvaluatorThroughTheAuthZENSurface.
//
// THE CONTROL THAT HAD TO ASSERT A REFUSAL, NOT AN ALLOW.
//
// delegateToDecide copies request headers onto the synthetic inner request BY
// NAME. A header missing from that list is not "not forwarded" - it is SILENTLY
// STRIPPED, so the evaluator sees the absent case and takes the unchanged path.
// Every capability refusal, every identity binding and every over-advertising
// check would then be inert on this plane, with no error and no counter, and a
// test that presented a VALID handshake and asserted an allow would pass
// against exactly that build - because a stripped header produces the same
// allow.
//
// So the fixture is a MALFORMED handshake, whose only correct outcome is a
// refusal that could not have come from anywhere else.
//
// MUTANT: remove contract.PEPHandshakeHeader from the copy list in
// delegateToDecide (authzen_handler.go) -> this dies.
func TestTheHandshakeReachesTheEvaluatorThroughTheAuthZENSurface(t *testing.T) {
	envelope := singularEnvelope(t, okSubject, okAction, okResource, okContext)

	// The CONTROL first: the identical envelope with NO handshake must not
	// produce this refusal, so a 400 below cannot be blamed on the envelope.
	clean := authzenForTest(t, envelope, negotiated())
	if clean.Code == http.StatusBadRequest && strings.Contains(clean.Body.String(), contract.PEPHandshakeHeader) {
		t.Fatalf("control failed: the handshake-free envelope already produced a handshake refusal: %s", clean.Body.String())
	}

	headers := negotiated()
	headers[contract.PEPHandshakeHeader] = "!!! not base64 !!!"
	rr := authzenForTest(t, envelope, headers)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400. A malformed handshake presented on %s was not refused, which is what a header "+
			"STRIPPED by delegateToDecide's by-name copy list looks like: the evaluator saw the absent case and took "+
			"the unchanged path.\nbody: %s", rr.Code, authzenHandlerPath, rr.Body.String())
	}

	refusal := decodeRefusal(t, rr)
	// The CODE is the surface's existing one - no new reason-code set - so the
	// DETAIL is the only thing that distinguishes a malformed handshake HEADER
	// from a malformed body ENVELOPE. It must name the header.
	if !strings.Contains(refusal.Message, contract.PEPHandshakeHeader) {
		t.Errorf("the AuthZEN refusal does not name %s, so a reader of this surface will take it to mean the body envelope was malformed: %+v",
			contract.PEPHandshakeHeader, refusal)
	}
	if refusal.Code != contract.ErrIncompleteEvaluation {
		t.Errorf("code = %q, want %q: this surface renders a 4xx from the delegated evaluator through one branch, "+
			"and the design document must state that rather than a code the code cannot produce",
			refusal.Code, contract.ErrIncompleteEvaluation)
	}
}

// TestARepeatedHandshakeHeaderSurvivesTheAuthZENDelegationAsARepeat.
//
// The copy list uses Header.Values and Header.Add, not Get and Set: a repeated
// header must reach the evaluator AS a repeat so it is refused there, rather
// than being silently collapsed to its first value on the way through - which
// would make one of two conflicting declarations authoritative for reasons
// nobody wrote down.
//
// MUTANT: change the copy loop back to `Get`/`Set` -> this dies.
func TestARepeatedHandshakeHeaderSurvivesTheAuthZENDelegationAsARepeat(t *testing.T) {
	first, refusal := contract.PEPHandshake{
		ProfileVersion: contract.PEPHandshakeProfileV1, PEPID: "sdk-a", Audience: "aud",
		Capabilities: []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}},
	}.Encode()
	if refusal != nil {
		t.Fatal(refusal)
	}
	second, refusal := contract.PEPHandshake{
		ProfileVersion: contract.PEPHandshakeProfileV1, PEPID: "sdk-b", Audience: "aud",
		Capabilities: []contract.Capability{},
	}.Encode()
	if refusal != nil {
		t.Fatal(refusal)
	}

	// authzenForTest sets headers, so the repeat is added directly.
	req := newAuthZENRequest(t, singularEnvelope(t, okSubject, okAction, okResource, okContext))
	req.Header.Set(authzenProfileHeader, string(contract.AuthZENProfileV1))
	req.Header.Add(contract.PEPHandshakeHeader, first)
	req.Header.Add(contract.PEPHandshakeHeader, second)

	rr := serveAuthZEN(req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a repeated declaration must reach the evaluator as a repeat and be refused there, "+
			"not be collapsed to its first value in transit.\nbody: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), contract.PEPHandshakeHeader) {
		t.Errorf("the refusal does not name the header: %s", rr.Body.String())
	}
}

// TestAPresentButEmptyHandshakeIsNotStrippedByTheAuthZENForwardLoop.
//
// The AuthZEN twin of TestPresentButEmptyHeaderIsNotAbsent, and it exists
// because the first version of the forward loop filtered `v != ""` for every
// header. That filter is right for the four attribution headers, where empty
// means "nothing to attribute". For the handshake it DROPPED a present
// declaration, so the evaluator saw the absent case and answered 200 on the
// unchanged path — a degrade-to-legacy reintroduced one frame above the
// resolver written to refuse it, and invisible to the repeat test because both
// of that test's values are non-empty.
//
// MUTANT: restore `if v != "" { ... }` unconditionally in delegateToDecide ->
// this dies.
func TestAPresentButEmptyHandshakeIsNotStrippedByTheAuthZENForwardLoop(t *testing.T) {
	envelope := singularEnvelope(t, okSubject, okAction, okResource, okContext)

	req := newAuthZENRequest(t, envelope)
	req.Header.Set(authzenProfileHeader, string(contract.AuthZENProfileV1))
	req.Header.Add(contract.PEPHandshakeHeader, "")

	rr := serveAuthZEN(req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a present-but-empty handshake was STRIPPED by the by-name forward loop's "+
			"emptiness filter, so the evaluator saw the absent case and took the unchanged path.\nbody: %s",
			rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), contract.PEPHandshakeHeader) {
		t.Errorf("the refusal does not name the header: %s", rr.Body.String())
	}
}

// TestAnEmptyLineCannotCollapseARepeatOnTheAuthZENPlane.
//
// The second half of the same defect: with the emptiness filter applied to the
// handshake, `["", <valid>]` reached the evaluator as ONE header line and was
// ACCEPTED — a repeat silently resolved in favour of whichever line survived
// the filter. The repeat test could not see it, because both its values are
// non-empty.
func TestAnEmptyLineCannotCollapseARepeatOnTheAuthZENPlane(t *testing.T) {
	valid, refusal := contract.PEPHandshake{
		ProfileVersion: contract.PEPHandshakeProfileV1, PEPID: "sdk-go", Audience: "aud",
		Capabilities: []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}},
	}.Encode()
	if refusal != nil {
		t.Fatal(refusal)
	}

	req := newAuthZENRequest(t, singularEnvelope(t, okSubject, okAction, okResource, okContext))
	req.Header.Set(authzenProfileHeader, string(contract.AuthZENProfileV1))
	req.Header.Add(contract.PEPHandshakeHeader, "")
	req.Header.Add(contract.PEPHandshakeHeader, valid)

	rr := serveAuthZEN(req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: an empty line collapsed a REPEAT into a single accepted declaration.\nbody: %s",
			rr.Code, rr.Body.String())
	}
}

// TestAPluralEnvelopeCountsTheHandshakeOnceNotOncePerEntry.
//
// The adoption counter is what #3564's per-plane cutover reads its ratio off.
// Resolving per delegated entry made that ratio a function of a number the
// CALLER chooses: one request with 64 entries wrote 64 increments. The skew is
// also directional — a malformed handshake short-circuits the entry loop after
// one increment while absent and accepted multiply — so the malformed rate was
// understated on exactly the plane where the header is most fragile.
//
// MUTANT: move the resolution back inside handleDecide unconditionally (drop
// the context reuse in resolveAndRecordPEPHandshakeOnce) -> this dies.
func TestAPluralEnvelopeCountsTheHandshakeOnceNotOncePerEntry(t *testing.T) {
	valid, refusal := contract.PEPHandshake{
		ProfileVersion: contract.PEPHandshakeProfileV1, PEPID: "sdk-go", Audience: "aud",
		Capabilities: []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}},
	}.Encode()
	if refusal != nil {
		t.Fatal(refusal)
	}

	const entries = 8
	var b strings.Builder
	b.WriteString(`{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
		`,"resource":` + okResource + `,"context":` + okContext + `,"evaluations":[`)
	for i := 0; i < entries; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("{}")
	}
	b.WriteString(`]}}`)

	// The package's existing counterValue helper (segment_policy_gate_test.go),
	// not a second one: it reads the CounterVec directly rather than parsing the
	// text exposition, and a second reader would be a second thing to drift.
	before := counterValue(t, pepHandshakeOutcomes, pepHandshakeAccepted, PlaneAccessEvaluation)

	req := newAuthZENRequest(t, b.String())
	req.Header.Set(authzenProfileHeader, string(contract.AuthZENProfileV1))
	req.Header.Set(contract.PEPHandshakeHeader, valid)
	// The test harness posts straight at the handler, so the identity
	// apiAuthMiddleware would have stamped has to be supplied here. Without it
	// the handshake is correctly refused as unbindable and the counter under
	// test never reaches the `accepted` series - a fixture that would have
	// "passed" by measuring nothing.
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyClientID, "acme"))
	rr := serveAuthZEN(req)
	if rr.Code != http.StatusOK {
		t.Fatalf("fixture invalid: the plural envelope was not evaluated (status %d): %s", rr.Code, rr.Body.String())
	}

	after := counterValue(t, pepHandshakeOutcomes, pepHandshakeAccepted, PlaneAccessEvaluation)
	delta := after - before
	if delta != 1 {
		t.Fatalf("a single HTTP request carrying ONE header wrote %v increments across %d entries; the adoption "+
			"counter must not be a function of the entry count the caller chose", delta, entries)
	}
}
