package legacycompile

import (
	"encoding/json"
	"testing"
)

// col renders a value as a captured column.
func col(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling fixture column: %v", err)
	}
	return b
}

// staticRow builds a complete static_policies capture row, then applies the
// overrides. Building from a COMPLETE row and overriding is deliberate: a
// fixture that lists only the columns a case cares about would trip the
// capture-incomplete arm and every test would assert the same thing.
func staticRow(t *testing.T, policyID string, overrides map[string]any) RawRow {
	t.Helper()
	base := map[string]any{
		"id":        "00000000-0000-0000-0000-0000000000" + policyIDSuffix(policyID),
		"policy_id": policyID, "name": policyID, "category": "pii-us",
		"pattern": `\d{3}-\d{2}-\d{4}`, "severity": "high",
		"tier": "system", "tenant_id": "global", "org_id": "global",
		"priority": 100, "enabled": true,
		"phase": "both", "action_request": "block", "action_response": "redact",
		"action":     "block",
		"segment_id": nil, "version": 1, "metadata": map[string]any{},
		"deleted_at": nil, "created_at": "2026-01-01T00:00:00Z",
		"updated_at": "2026-01-01T00:00:00Z",
	}
	for k, v := range overrides {
		base[k] = v
	}
	cols := map[string]json.RawMessage{}
	for k, v := range base {
		cols[k] = col(t, v)
	}
	return RawRow{Table: "static_policies", OrgScope: "global", Columns: cols}
}

func dynamicRow(t *testing.T, policyID string, overrides map[string]any) RawRow {
	t.Helper()
	base := map[string]any{
		"id":        "11111111-1111-1111-1111-1111111111" + policyIDSuffix(policyID),
		"policy_id": policyID, "name": policyID, "policy_type": "context_aware",
		"category": "dynamic-role-access",
		"tier":     "tenant", "tenant_id": "acme", "org_id": "acme",
		"priority": 50, "enabled": true, "risk_threshold": nil,
		"conditions": []map[string]any{{"field": "user.role", "operator": "equals", "value": "intern"}},
		"actions":    []map[string]any{{"type": "block", "config": map[string]any{"reason": "interns cannot"}}},
		"segment_id": nil, "metadata": map[string]any{},
		"created_at":  "2026-01-01T00:00:00Z",
		"version":     1,
		"description": "fixture row",
	}
	for k, v := range overrides {
		base[k] = v
	}
	cols := map[string]json.RawMessage{}
	for k, v := range base {
		cols[k] = col(t, v)
	}
	return RawRow{Table: "dynamic_policies", OrgScope: "acme", Columns: cols}
}

func policyIDSuffix(policyID string) string {
	if len(policyID) >= 2 {
		s := policyID[len(policyID)-2:]
		out := make([]byte, 0, 2)
		for i := 0; i < len(s); i++ {
			c := s[i]
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
				out = append(out, c)
			default:
				out = append(out, 'a')
			}
		}
		return string(out)
	}
	return "00"
}

// testOptions are compilation options with every supplied input present, so a
// test asserting an uncompilable arm is asserting the arm and not a missing
// option.
func testOptions() Options {
	return Options{
		ApprovalPools: map[string]ApprovalPool{
			"*": {Quorum: 1, Eligible: []string{"Group::legacy_segment:approvers"}},
		},
	}
}

func recordFor(t *testing.T, rep *Report, policyID string) Record {
	t.Helper()
	for _, r := range rep.Records {
		if r.Source.PolicyID == policyID {
			return r
		}
	}
	t.Fatalf("no record for policy %q; the one-record-per-row invariant says there must be exactly one", policyID)
	return Record{}
}
