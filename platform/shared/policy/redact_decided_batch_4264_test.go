// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"reflect"
	"testing"
)

// TestRedactDecidedBatchLoadsOnceAndMasksEachContentOnItsOwn (#4264): the MCP
// request pass masks its statement and each parameter's scan text by one
// decision, so the batch form loads and filters the policies ONCE for all of
// them (a per-text reload could see a different policy set between two), masks
// each content exactly as RedactDecided masks it alone, and masks only with the
// named policies.
func TestRedactDecidedBatchLoadsOnceAndMasksEachContentOnItsOwn(t *testing.T) {
	e := createTestEngine(redactDecidedPolicies())
	ctx := context.Background()
	contents := []interface{}{
		redactDecidedRows(),
		"card holder ssn 123-45-6789 on file",
		"nothing sensitive here",
	}

	before := e.cache.GetStats().CacheHits
	got, err := e.RedactDecidedBatch(ctx, contents, PhaseResponse, redactDecidedOpts(), []string{"test_redact"})
	if err != nil {
		t.Fatal(err)
	}
	if loads := e.cache.GetStats().CacheHits - before; loads != 1 {
		t.Fatalf("the batch loaded the policies %d times for %d contents; want once", loads, len(contents))
	}
	if len(got) != len(contents) {
		t.Fatalf("the batch returned %d results for %d contents", len(got), len(contents))
	}

	for i, c := range contents {
		alone, err := e.RedactDecided(ctx, c, PhaseResponse, redactDecidedOpts(), []string{"test_redact"})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got[i].Content, alone.Content) || got[i].Redacted != alone.Redacted {
			t.Fatalf("content %d: the batch masked %v (redacted %v), alone %v (redacted %v)", i, got[i].Content, got[i].Redacted, alone.Content, alone.Redacted)
		}
	}
	if s, _ := got[1].Content.(string); s == contents[1] || !got[1].Redacted {
		t.Fatalf("the text with an SSN came back unmasked: %q", s)
	}
	if s, _ := got[2].Content.(string); s != contents[2] || got[2].Redacted {
		t.Fatalf("a clean text was changed: %q", s)
	}

	// Only the named policies mask: the rows' note matches test_block, which is
	// not named, so it is handed back as it was.
	rows := got[0].Content.([]map[string]interface{})
	if rows[1]["note"] != redactDecidedRows()[1]["note"] {
		t.Fatalf("a span only an unnamed policy matches was masked: %v", rows)
	}
}
