// Copyright 2026 AxonFlow
package agent

import (
	"reflect"
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

// findDecisionEnum digs the list_recent_decisions tool's `decision` filter enum
// out of its InputSchema (map[string]interface{}). Returns nil if any hop is
// missing so the assertions below fail loudly rather than panic.
func findDecisionEnum(t *testing.T) []string {
	t.Helper()
	for _, tool := range getMCPTools() {
		if tool.Name != "list_recent_decisions" {
			continue
		}
		schema, ok := tool.InputSchema.(map[string]interface{})
		if !ok {
			t.Fatalf("list_recent_decisions InputSchema is %T, want map", tool.InputSchema)
		}
		props, ok := schema["properties"].(map[string]interface{})
		if !ok {
			t.Fatalf("InputSchema.properties is %T, want map", schema["properties"])
		}
		decision, ok := props["decision"].(map[string]interface{})
		if !ok {
			t.Fatalf("properties.decision is %T, want map", props["decision"])
		}
		enum, ok := decision["enum"].([]string)
		if !ok {
			t.Fatalf("decision.enum is %T, want []string", decision["enum"])
		}
		return enum
	}
	t.Fatal("list_recent_decisions tool not found in getMCPTools()")
	return nil
}

// TestListRecentDecisionsEnumIsCanonical guards the fix for the MCP
// list_recent_decisions filter enum. The tool forwards `decision` verbatim to
// GET /api/v1/decisions, whose ?decision= filter rejects anything that is not a
// canonical audit verdict with a 400 (decisions_list_handler.go: !audit.IsCanonical).
// Advertising the legacy allow/deny/require_approval spellings therefore made
// every host-supplied filter value 400 after the #2638/#2653 canonical cutover.
//
// Red-on-revert: restoring []string{"allow", "deny", "require_approval"} fails
// both assertions below.
func TestListRecentDecisionsEnumIsCanonical(t *testing.T) {
	enum := findDecisionEnum(t)

	if want := sharedaudit.All(); !reflect.DeepEqual(enum, want) {
		t.Errorf("list_recent_decisions decision enum = %v, want canonical %v", enum, want)
	}

	// Every advertised value must survive the same canonicality gate the
	// decisions endpoint applies, so a host that picks any enum value never
	// gets a 400.
	for _, v := range enum {
		if !sharedaudit.IsCanonical(v) {
			t.Errorf("enum value %q is not canonical — GET /api/v1/decisions would reject it with 400", v)
		}
	}

	// Explicitly forbid the pre-canonical wire spellings the bug advertised.
	for _, legacy := range []string{"allow", "deny", "require_approval"} {
		for _, v := range enum {
			if v == legacy {
				t.Errorf("enum still advertises legacy spelling %q (now 400s downstream)", legacy)
			}
		}
	}
}
