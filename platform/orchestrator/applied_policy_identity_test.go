// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3365: orchestrator LLM-plane blocked writers must stamp the shared
// reader's identity keys (policy_ids + policy_names) from the
// evaluation-time AppliedPoliciesDetail, and the override_used lifecycle
// writer must carry the display names it has in hand.

import (
	"encoding/json"
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

func TestWithAppliedPolicyIdentity_StampsNamesNotUUIDs(t *testing.T) {
	details := withAppliedPolicyIdentity(map[string]interface{}{"x": 1}, []AppliedPolicyDetail{
		{PolicyID: "550e8400-e29b-41d4-a716-446655440000", PolicyName: "High Risk Block"},
		{PolicyID: "550e8400-e29b-41d4-a716-446655440000", PolicyName: "High Risk Block"}, // dup dropped
		{PolicyID: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},                                // no name -> nothing
		{PolicyID: "", PolicyName: "Orphan Rule"},                                         // no id, name still counts
	})
	names, _ := details["policy_names"].([]string)
	if len(names) != 2 || names[0] != "High Risk Block" || names[1] != "Orphan Rule" {
		t.Fatalf("policy_names: %v", details["policy_names"])
	}
	// The dynamic-policy UUID must NEVER become the row's resolved identity:
	// the shared chain reads policy_ids[0] before policy_names[0], so a
	// stamped UUID would land in the single Policy column of every SEBI/OJK
	// export row instead of the human-readable name.
	if _, has := details["policy_ids"]; has {
		t.Fatalf("policy_ids must not be stamped on this plane (UUID identity would beat the readable name): %v", details["policy_ids"])
	}
}

func TestWithAppliedPolicyIdentity_ResolvesReadableIdentityForExporters(t *testing.T) {
	details := withAppliedPolicyIdentity(map[string]interface{}{
		"applied_policies": []string{"High Risk Block"},
	}, []AppliedPolicyDetail{
		{PolicyID: "550e8400-e29b-41d4-a716-446655440000", PolicyName: "High Risk Block"},
	})
	b, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	id, _ := sharedaudit.ExtractPolicyIdentity(b)
	if id != "High Risk Block" {
		t.Fatalf("the shared reader must resolve the readable name as this row's identity, got %q", id)
	}
	// And a blocked row now resolves SOMETHING, so the exporters stop
	// rendering the false pre-9.16.1 placeholder on a freshly-written row.
	if got := sharedaudit.PolicyOrPlaceholder(id, sharedaudit.DecisionBlocked, ""); got == sharedaudit.PolicyNotRecordedPlaceholder {
		t.Fatalf("a freshly-written blocked row must not render the pre-9.16.1 placeholder")
	}
}

func TestWithAppliedPolicyIdentity_NoDetail_NoChange(t *testing.T) {
	details := withAppliedPolicyIdentity(map[string]interface{}{"applied_policies": []string{"a"}}, nil)
	if _, has := details["policy_ids"]; has {
		t.Fatalf("no structured detail must leave the legacy shape untouched")
	}
}

func TestNonEmptyStrings(t *testing.T) {
	if got := nonEmptyStrings([]string{" ", "", "keep"}); len(got) != 1 || got[0] != "keep" {
		t.Fatalf("got %v", got)
	}
	if nonEmptyStrings(nil) != nil {
		t.Fatalf("nil in, nil out")
	}
}
