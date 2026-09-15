// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// RedactDecided is the discharge an enforcing response pass applies for the
// anchored engine's field_redact obligations (#3564). These tests pin the
// property the seam relies on - it masks exactly what it is told to - and the
// two shapes it must refuse, beside the detector facts the pass decides from.

func redactDecidedRows() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "alice", "ssn": "123-45-6789"},
		{"name": "bob", "note": "DROP TABLE t"},
	}
}

// redactDecidedPolicies is one block row and one redact row. The block row is
// in a category no validator gates: under pii-us the SSN-shaped validator
// rejects `DROP TABLE`, so it would match nothing and neither the "whatever
// action it stores" case nor the stop-on-block case would prove anything.
func redactDecidedPolicies() []CompiledPolicy {
	return []CompiledPolicy{
		{
			ID: "1", PolicyID: "test_block", Name: "test_block",
			Category: CategorySensitiveData, Tier: "system", Severity: SeverityHigh,
			Pattern: regexp.MustCompile(`DROP\s+TABLE`), PatternStr: `DROP\s+TABLE`,
			Phase: PhaseBoth, ActionRequest: ActionBlock, ActionResponse: ActionBlock,
			Enabled: true, Priority: 100, TenantID: "test-tenant",
		},
		{
			ID: "2", PolicyID: "test_redact", Name: "test_redact",
			Category: CategoryPIIUS, Tier: "system", Severity: SeverityHigh,
			Pattern: regexp.MustCompile(`\d{3}-\d{2}-\d{4}`), PatternStr: `\d{3}-\d{2}-\d{4}`,
			Phase: PhaseBoth, ActionRequest: ActionRedact, ActionResponse: ActionRedact,
			Enabled: true, Priority: 90, TenantID: "test-tenant",
		},
	}
}

func redactDecidedOpts() EvalOptions {
	return EvalOptions{
		TenantID: "test-tenant", OrgID: "test-tenant", UserID: "alice",
	}
}

// THE DETECTOR FACTS ARE BUILT ON EVERY EVALUATION. Nothing is switched on
// here: until v11 they existed only while the decision shadow observed, and an
// enforcing seam handed nil facts reads every detector-reading control UNKNOWN.
func TestEveryEvaluationReturnsItsDetectorFacts(t *testing.T) {
	e := createTestEngine(redactDecidedPolicies())
	ctx := context.Background()
	factsByID := func(o *Observation) map[string]DetectorFact {
		t.Helper()
		if o == nil {
			t.Fatal("the evaluation returned no detector facts; an enforcing seam would decide from none")
		}
		out := map[string]DetectorFact{}
		for _, r := range o.Rows {
			out[r.PolicyID] = r
		}
		return out
	}

	t.Run("the response phase reports what ran and what matched", func(t *testing.T) {
		got := factsByID(e.EvaluateResponse(ctx, redactDecidedRows(), redactDecidedOpts()).Observation)
		if f := got["test_redact"]; !f.Ran || !f.Matched {
			t.Fatalf("test_redact ran over an SSN and reports %+v", f)
		}
	})

	t.Run("a policy after the blocking one still runs, and the block is still the first", func(t *testing.T) {
		// test_block has the higher priority and blocks. The request pass runs
		// every detector past a block, so test_redact still looked and found the
		// SSN: a detector the pass skipped would read UNKNOWN to the anchored
		// engine. The verdict a legacy reader sees is still the first block's.
		r := e.EvaluateRequest(ctx, "DROP TABLE t WHERE ssn = '123-45-6789'", redactDecidedOpts())
		got := factsByID(r.Observation)
		if f := got["test_block"]; !f.Ran || !f.Matched {
			t.Fatalf("test_block blocked the request and reports %+v", f)
		}
		if f := got["test_redact"]; !f.Ran || !f.Matched {
			t.Fatalf("test_redact reports %+v; want ran and matched, because the pass does not stop at a block", f)
		}
		if !r.Blocked || r.BlockedBy == nil || r.BlockedBy.PolicyID != "test_block" {
			t.Fatalf("blocked=%v by=%v; the first block, test_block, is still the verdict", r.Blocked, r.BlockedBy)
		}
	})

	t.Run("CONTROL: a clean request ran every detector and matched none", func(t *testing.T) {
		got := factsByID(e.EvaluateRequest(ctx, "SELECT name FROM customers", redactDecidedOpts()).Observation)
		for _, id := range []string{"test_block", "test_redact"} {
			if f := got[id]; !f.Ran || f.Matched {
				t.Fatalf("%s over clean content reports %+v; want ran and not matched", id, f)
			}
		}
	})
}

func TestRedactDecidedMasksExactlyTheNamedPolicies(t *testing.T) {
	e := createTestEngine(redactDecidedPolicies())
	ctx := context.Background()
	original := redactDecidedRows()

	t.Run("naming the redact row masks its span and leaves the other untouched", func(t *testing.T) {
		got, err := e.RedactDecided(ctx, redactDecidedRows(), PhaseResponse, redactDecidedOpts(), []string{"test_redact"})
		if err != nil {
			t.Fatal(err)
		}
		rows := got.Content.([]map[string]interface{})
		if rows[0]["ssn"] == original[0]["ssn"] || !got.Redacted {
			t.Fatalf("the ssn was not masked: %v", rows)
		}
		if rows[1]["note"] != original[1]["note"] {
			t.Fatalf("a span no named policy matched was masked: %v", rows)
		}
	})

	t.Run("a named policy is redacted whatever action its row stores", func(t *testing.T) {
		// test_block stores action block. The decision is taken elsewhere; this
		// transform resolves no action.
		got, err := e.RedactDecided(ctx, redactDecidedRows(), PhaseResponse, redactDecidedOpts(), []string{"test_block"})
		if err != nil {
			t.Fatal(err)
		}
		rows := got.Content.([]map[string]interface{})
		if rows[1]["note"] == original[1]["note"] || got.Blocked {
			t.Fatalf("the block row's span was not masked, or the transform blocked: blocked=%v rows=%v", got.Blocked, rows)
		}
		if rows[0]["ssn"] != original[0]["ssn"] {
			t.Fatalf("the ssn was masked although test_redact was not named: %v", rows)
		}
	})

	t.Run("naming nothing leaves the content exactly as it was", func(t *testing.T) {
		got, err := e.RedactDecided(ctx, redactDecidedRows(), PhaseResponse, redactDecidedOpts(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.Redacted || !reflect.DeepEqual(got.Content, original) {
			t.Fatalf("an empty redaction set changed the content: redacted=%v content=%v", got.Redacted, got.Content)
		}
	})
}

func TestRedactDecidedRefusesAPolicyTheResponsePhaseDidNotLoad(t *testing.T) {
	e := createTestEngine(redactDecidedPolicies())
	_, err := e.RedactDecided(context.Background(), redactDecidedRows(), PhaseResponse, redactDecidedOpts(), []string{"test_redact", "never_loaded"})
	if err == nil || !strings.Contains(err.Error(), "never_loaded") {
		t.Fatalf("a decision naming a policy the content was never scanned by returned %v; want a refusal naming it", err)
	}
}

// TestRedactDecidedRefusesATransformTheCapWouldMakePartial: the cap discards
// plans, and a discarded plan leaves content unmasked exactly when no kept plan
// shares its pattern - the redactor masks every occurrence of a kept pattern.
func TestRedactDecidedRefusesATransformTheCapWouldMakePartial(t *testing.T) {
	e := createTestEngine(redactDecidedPolicies())
	ctx := context.Background()

	t.Run("two patterns under a limit of one leave the second unmasked, and are refused", func(t *testing.T) {
		opts := redactDecidedOpts()
		opts.MaxRedactions = 1
		_, err := e.RedactDecided(ctx, redactDecidedRows(), PhaseResponse, opts, []string{"test_redact", "test_block"})
		if err == nil {
			t.Fatal("two policies with different patterns under a limit of one were redacted partially and reported as discharged")
		}
	})

	t.Run("CONTROL: two spans of one pattern under a limit of one are both masked", func(t *testing.T) {
		rows := []map[string]interface{}{{"ssn": "123-45-6789"}, {"ssn": "234-56-7890"}}
		opts := redactDecidedOpts()
		opts.MaxRedactions = 1
		got, err := e.RedactDecided(ctx, rows, PhaseResponse, opts, []string{"test_redact"})
		if err != nil {
			t.Fatalf("both spans share the kept pattern, so nothing is left unmasked, and the transform refused: %v", err)
		}
		masked := got.Content.([]map[string]interface{})
		if masked[0]["ssn"] == "123-45-6789" || masked[1]["ssn"] == "234-56-7890" {
			t.Fatalf("a span of the kept pattern was left unmasked: %v", masked)
		}
	})
}

// TestRedactDecidedMasksTheStatedPhase: the phase is the pass's, and it is load
// bearing. The MCP request pass masks the statement it hands back with rows its
// phase loads, which may be request-only; the same row named on the response
// phase is a detector that phase never ran, so the transform refuses it.
func TestRedactDecidedMasksTheStatedPhase(t *testing.T) {
	requestOnly := CompiledPolicy{
		ID: "3", PolicyID: "test_request_only", Name: "test_request_only",
		Category: CategoryPIIUS, Tier: "system", Severity: SeverityHigh,
		Pattern: regexp.MustCompile(`\d{3}-\d{2}-\d{4}`), PatternStr: `\d{3}-\d{2}-\d{4}`,
		Phase: PhaseRequest, ActionRequest: ActionRedact,
		Enabled: true, Priority: 90, TenantID: "test-tenant",
	}
	e := createTestEngine([]CompiledPolicy{requestOnly})
	ctx := context.Background()
	statement := func() []map[string]interface{} {
		return []map[string]interface{}{{"statement": "SELECT name FROM customers WHERE ssn = '123-45-6789'"}}
	}

	t.Run("a request-only row masks the statement on the request phase", func(t *testing.T) {
		got, err := e.RedactDecided(ctx, statement(), PhaseRequest, redactDecidedOpts(), []string{"test_request_only"})
		if err != nil {
			t.Fatal(err)
		}
		masked := got.Content.([]map[string]interface{})[0]["statement"].(string)
		if !got.Redacted || strings.Contains(masked, "123-45-6789") || !strings.Contains(masked, "SELECT name FROM customers") {
			t.Fatalf("redacted=%v statement=%q; want the ssn masked and the rest of the statement kept", got.Redacted, masked)
		}
		if len(got.MatchedPolicies) == 0 || got.MatchedPolicies[0].StoredAction != ActionRedact {
			t.Fatalf("matched %+v; want the row's REQUEST action recorded as the stored action", got.MatchedPolicies)
		}
	})

	t.Run("CONTROL: the same row named on the response phase is refused, naming it", func(t *testing.T) {
		_, err := e.RedactDecided(ctx, statement(), PhaseResponse, redactDecidedOpts(), []string{"test_request_only"})
		if err == nil || !strings.Contains(err.Error(), "test_request_only") || !strings.Contains(err.Error(), "response phase") {
			t.Fatalf("a request-only row named on the response phase returned %v; want a refusal naming the row and the phase", err)
		}
	})

	t.Run("a phase that names no content to mask is refused rather than guessed", func(t *testing.T) {
		if _, err := e.RedactDecided(ctx, statement(), PhaseBoth, redactDecidedOpts(), []string{"test_request_only"}); err == nil {
			t.Fatal("RedactDecided accepted PhaseBoth; a transform must be told whose content it masks")
		}
	})
}
