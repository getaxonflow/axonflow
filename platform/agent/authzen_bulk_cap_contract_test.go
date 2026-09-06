package agent

import (
	"encoding/json"
	"os"
	"testing"
)

// TestBulkEntryCapMatchesThePublishedContract pins the server's entry cap to
// the JSON Schema's maxItems in BOTH directions, so the two cannot drift: a
// server that enforces a cap the contract does not declare surprises every
// spec-generated client, and a contract that declares a cap the server does
// not enforce is a promise nothing keeps. The schema is the canonical
// contract artifact the five SDKs vendor; docs/api/agent-api.yaml restates
// the same bound and is reconciled by review (its lockstep test is
// name-level only - see #3639).
func TestBulkEntryCapMatchesThePublishedContract(t *testing.T) {
	raw, err := os.ReadFile("../decision/contract/schema/contract-2026-08-29.schema.json")
	if err != nil {
		t.Fatalf("read the contract schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	defs, _ := doc["$defs"].(map[string]any)
	bulk, ok := defs["authzen_bulk"].(map[string]any)
	if !ok {
		t.Fatal("authzen_bulk missing from $defs - the schema changed shape and this pin is reading nothing")
	}
	props, _ := bulk["properties"].(map[string]any)
	ev, ok := props["evaluations"].(map[string]any)
	if !ok {
		t.Fatal("authzen_bulk.evaluations missing - same vacuity concern")
	}
	mi, ok := ev["maxItems"].(float64)
	if !ok {
		t.Fatalf("the schema declares no maxItems on the bulk evaluations array, but the server refuses above %d - the contract must carry the bound the server enforces", maxAuthZENBulkEntries)
	}
	if int(mi) != maxAuthZENBulkEntries {
		t.Fatalf("schema maxItems = %d, server cap = %d - the published contract and the enforced bound have drifted", int(mi), maxAuthZENBulkEntries)
	}
}
