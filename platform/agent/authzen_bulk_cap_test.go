package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// bulkEnvelopeOfEmptyEntries builds the exact shape the amplification finding
// described: a base carrying subject, action, resource and context, and n
// entries of `{}` — every one of which is a fully valid evaluation, because
// mergeEntry fills everything an entry omits from the shared base.
func bulkEnvelopeOfEmptyEntries(n int) string {
	entries := make([]string, n)
	for i := range entries {
		entries[i] = "{}"
	}
	return `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
		`,"resource":{"type":"llm","id":"llm"},"context":` + okContext +
		`,"evaluations":[` + strings.Join(entries, ",") + `]}}`
}

// TestAuthZENBulkEntryCountIsBounded pins the entry cap. The 1 MiB body cap's
// own comment says an unbounded list is an unbounded number of policy
// evaluations from one request — and bounds bytes, not entries, so ~350,000
// `{}` entries fit under it. This test is the missing half: one over the cap
// is refused with a typed 413 BEFORE anything is evaluated, and the refusal
// names the member to shrink.
func TestAuthZENBulkEntryCountIsBounded(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	rr := authzenForTest(t, bulkEnvelopeOfEmptyEntries(maxAuthZENBulkEntries+1), negotiated())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413; body=%s", rr.Code, rr.Body.String())
	}
	var refusal contract.AuthZENError
	if err := json.Unmarshal(rr.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("the refusal is not a typed AuthZENError: %v; body=%s", err, rr.Body.String())
	}
	if refusal.Code != contract.ErrMalformedEnvelope {
		t.Errorf("code = %q, want %q", refusal.Code, contract.ErrMalformedEnvelope)
	}
	if refusal.Pointer != "/evaluations" {
		t.Errorf("pointer = %q, want /evaluations — the caller must be told which member to shrink", refusal.Pointer)
	}
	// The message must carry both numbers IN THE RIGHT ROLES — the count sent
	// before "at most", the cap after it — so the caller can size a retry
	// without reading our source, and an arg-swap mutant cannot survive on a
	// bare Contains check.
	sent, cap := "65", "64"
	i, j := strings.Index(refusal.Message, sent), strings.Index(refusal.Message, "at most "+cap)
	if i < 0 || j < 0 || i > j {
		t.Errorf("refusal message %q must carry the sent count %s before %q", refusal.Message, sent, "at most "+cap)
	}
}

// TestAuthZENBulkAtTheCapStillEvaluates is the positive control: exactly
// maxAuthZENBulkEntries entries evaluate normally. Without it, the refusal
// test above would also pass if the route refused every plural envelope.
func TestAuthZENBulkAtTheCapStillEvaluates(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	rr := authzenForTest(t, bulkEnvelopeOfEmptyEntries(maxAuthZENBulkEntries), negotiated())
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d at exactly the cap, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp contract.AuthZENResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Context == nil {
		t.Fatal("no profile context on a negotiated at-cap evaluation")
	}
}

// TestAuthZENSingularEnvelopeIsNotEntryCapped — the cap is about the plural
// list; a singular envelope has no list to bound and must be untouched.
func TestAuthZENSingularEnvelopeIsNotEntryCapped(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	body := `{"evaluation":{"subject":` + okSubject + `,"action":` + okAction +
		`,"resource":{"type":"llm","id":"llm"},"context":` + okContext + `}}`
	rr := authzenForTest(t, body, negotiated())
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

// TestAuthZENEntryCapRunsBeforeMapping pins the ORDERING, which the PR claims
// in three places and which no other test can see: externally, 413 looks the
// same wherever the cap sits. The probe makes the order observable — entry 0
// carries subject.properties, a member mapEnvelope refuses with 422
// unevaluable_attribute. Cap-first answers 413 (the length check never looks
// inside an entry); mapping-first answers 422. So moving the cap after
// mapEnvelope — the mutant that survived the whole suite before this test —
// flips this exact assertion. The ordering matters because mapping is O(n)
// per-entry work (member walks, merged-struct allocation) that an over-cap
// envelope must not be able to buy with one length check's price.
func TestAuthZENEntryCapRunsBeforeMapping(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	entries := make([]string, maxAuthZENBulkEntries+1)
	for i := range entries {
		entries[i] = "{}"
	}
	entries[0] = `{"subject":{"type":"gateway","id":"x","properties":{"k":"v"}}}`
	body := `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
		`,"resource":{"type":"llm","id":"llm"},"context":` + okContext +
		`,"evaluations":[` + strings.Join(entries, ",") + `]}}`

	rr := authzenForTest(t, body, negotiated())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413 — a 422 here means the unevaluable member in entry 0 was "+
			"inspected, i.e. mapping ran BEFORE the cap and an over-cap envelope buys per-entry work; "+
			"body=%s", rr.Code, rr.Body.String())
	}
}

// TestAuthZENStopsEvaluatingWhenTheCallerIsGone pins the ctx.Err() check in
// the delegation loop. A cancelled request context means the caller
// disconnected; without the check the loop finishes every remaining entry —
// full evaluations and audit INSERTs — for a response nobody reads, and the
// server has no Read/WriteTimeout to stop it either.
//
// The context is cancelled BEFORE the handler runs, which is the deterministic
// form: the loop must refuse at the first boundary rather than evaluate even
// one entry. Removing the check makes this request return 200 (the mock engine
// happily evaluates for a dead caller), which is exactly the mutant this test
// exists to kill.
func TestAuthZENStopsEvaluatingWhenTheCallerIsGone(t *testing.T) {
	installSharedEngineWithMockDB(t)
	installCircuitBreaker(t)

	req := httptest.NewRequest(http.MethodPost, authzenHandlerPath,
		strings.NewReader(bulkEnvelopeOfEmptyEntries(4)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authzenProfileHeader, string(contract.AuthZENProfileV1))
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // the caller is gone before evaluation begins
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handleAuthZENEvaluation(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d for a cancelled caller, want 502; body=%s", rr.Code, rr.Body.String())
	}
	var refusal contract.AuthZENError
	if err := json.Unmarshal(rr.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("not a typed refusal: %v", err)
	}
	if refusal.Code != contract.ErrEvaluationUnavailable {
		t.Errorf("code = %q, want %q", refusal.Code, contract.ErrEvaluationUnavailable)
	}
	if !strings.Contains(refusal.Message, "cancelled") {
		t.Errorf("message %q does not name the cancellation", refusal.Message)
	}
}
