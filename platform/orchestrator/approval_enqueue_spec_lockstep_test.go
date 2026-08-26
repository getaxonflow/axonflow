// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/agent/hitl/queue"
)

// TestApprovalEnqueueEnumMatchesTheSpec keeps the `approval_enqueue` vocabulary
// in lockstep between the Go constants and docs/api/orchestrator-api.yaml.
//
// WHY A BESPOKE TEST RATHER THAN A bindings.yaml ENTRY. The repo's enum drift
// guard (scripts/contract-guards/enum_differ.py, #3460) binds a SPEC PROPERTY
// to a GO STRUCT FIELD. `StepGateResponse.ApprovalEnqueue` is a plain `string`
// - workflow_control must not import platform/agent/hitl/queue, which would
// invert the dependency - so there is no typed field for that guard to read,
// and an entry there would have nothing to compare. The vocabulary is declared
// as queue.Outcome constants instead, and this compares those directly.
//
// Its scope block also only makes regulator-pack enums mandatory, so this enum
// would have been silently unbound. Recording the reason here rather than
// leaving the omission to be rediscovered.
func TestApprovalEnqueueEnumMatchesTheSpec(t *testing.T) {
	// The Go side, read from the SOURCE of the const block rather than from a
	// list retyped here.
	//
	// R3 round 2: the first version hardcoded the five values inside the test,
	// so adding a SIXTH queue.Outcome in Go left it green - it guarded
	// spec-to-test drift only, which is not the drift it is named for. A
	// source census is the repo's own answer to this (#3514's M6 mutant made
	// the same point about a build-tagged constant).
	goValues := outcomeConstantsFromSource(t)
	sort.Strings(goValues)

	// The census must ALSO agree with the compiled constants, or a rename that
	// broke the parse would go unnoticed.
	compiled := map[string]bool{
		string(queue.OutcomeCreated): true, string(queue.OutcomeReused): true,
		string(queue.OutcomeCapReached): true, string(queue.OutcomeTierDisabled): true,
		string(queue.OutcomeError): true,
	}
	for _, v := range goValues {
		if !compiled[v] {
			t.Errorf("source census found %q, which is not a compiled queue.Outcome - "+
				"the parse is reading something else", v)
		}
	}

	blob, err := os.ReadFile("../../docs/api/orchestrator-api.yaml")
	if err != nil {
		t.Fatalf("read the orchestrator spec: %v", err)
	}
	// The `approval_enqueue` property's enum line. Anchored on the property
	// name so a second enum elsewhere in the file cannot satisfy it.
	re := regexp.MustCompile(`(?m)^\s*approval_enqueue:\n\s*type: string\n\s*enum: \[([^\]]*)\]`)
	m := re.FindSubmatch(blob)
	if m == nil {
		t.Fatal("no `approval_enqueue: {type: string, enum: [...]}` found in the orchestrator spec; " +
			"either the property moved or its enum was dropped, and this test would otherwise pass vacuously")
	}
	var specValues []string
	for _, v := range strings.Split(string(m[1]), ",") {
		if v = strings.TrimSpace(v); v != "" {
			specValues = append(specValues, v)
		}
	}
	sort.Strings(specValues)

	if strings.Join(goValues, ",") != strings.Join(specValues, ",") {
		t.Errorf("approval_enqueue vocabulary drifted:\n  Go   (queue.Outcome): %v\n  spec (orchestrator-api.yaml): %v",
			goValues, specValues)
	}

	// Positive control: the comparison must be over a NON-EMPTY set. An empty
	// spec enum and an empty Go list would compare equal and pass while
	// asserting nothing.
	if len(specValues) == 0 || len(goValues) == 0 {
		t.Fatalf("one side is empty (go=%d spec=%d) - the comparison is vacuous", len(goValues), len(specValues))
	}
}

// outcomeConstantsFromSource reads every `Outcome = "..."` declaration out of
// the queue package's source.
//
// Deliberately textual rather than reflective: Go has no enum, so there is
// nothing to enumerate at runtime, and a hand-kept list in the test is exactly
// what this replaces. A parse that finds nothing is a hard failure, not an
// empty set - an empty set is what "everything matches" looks like.
func outcomeConstantsFromSource(t *testing.T) []string {
	t.Helper()
	blob, err := os.ReadFile("../agent/hitl/queue/enqueuer.go")
	if err != nil {
		t.Fatalf("read the queue package source: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*Outcome\w+\s+Outcome\s*=\s*"([^"]+)"`)
	ms := re.FindAllSubmatch(blob, -1)
	if len(ms) == 0 {
		t.Fatal("no `OutcomeX Outcome = \"...\"` declarations found in enqueuer.go; " +
			"the const block moved or changed shape, and this test would otherwise " +
			"compare two empty sets and pass")
	}
	var out []string
	for _, m := range ms {
		out = append(out, string(m[1]))
	}
	return out
}
