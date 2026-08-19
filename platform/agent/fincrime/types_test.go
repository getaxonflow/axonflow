// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Untagged: these tests pin the cross-build surface (context metadata and the
// audit-detail merge) under BOTH the community and enterprise builds.

package fincrime

import (
	"context"
	"testing"
)

func TestDecisionMetaRoundTrip(t *testing.T) {
	ctx := WithDecisionMeta(context.Background(), "mcp", "dec-7")
	meta := DecisionMetaFromContext(ctx)
	if meta == nil || meta.Plane != "mcp" || meta.DecisionID != "dec-7" {
		t.Fatalf("meta = %+v", meta)
	}
	if DecisionMetaFromContext(context.Background()) != nil {
		t.Fatal("no meta expected on a bare context")
	}
}

func TestMergeAuditDetails_NoStampIsUntouched(t *testing.T) {
	details := map[string]interface{}{"policy_ids": []string{"existing"}}
	out := MergeAuditDetails(context.Background(), details)
	ids, _ := out["policy_ids"].([]string)
	if len(ids) != 1 || ids[0] != "existing" {
		t.Fatalf("details changed without a stamp: %v", out)
	}
	if _, present := out["risk_score"]; present {
		t.Fatal("risk_score must not appear without a stamp")
	}
	// A stamped context whose seam recorded nothing is also untouched.
	ctx := WithDecisionMeta(context.Background(), "decide", "d1")
	out = MergeAuditDetails(ctx, details)
	if _, present := out["ml_inference_layer_status"]; present {
		t.Fatal("no merge expected for an empty stamp")
	}
}

func TestMergeAuditDetails_AppendsAndDedupes(t *testing.T) {
	ctx := WithDecisionMeta(context.Background(), "decide", "d1")
	stampResult(ctx, &Result{
		PolicyIDs:      []string{PolicyIDMLFraudScore, "existing"},
		PolicyNames:    []string{"FinCrime ML Fraud Score", "Existing"},
		PolicyVersions: map[string]string{PolicyIDMLFraudScore: "1.2.0"},
		RiskScore:      map[string]interface{}{"overall": 0.9},
		MLStatus:       MLStatusScored,
	})
	details := map[string]interface{}{
		"policy_ids":   []string{"existing"},
		"policy_names": []string{"Existing"},
	}
	out := MergeAuditDetails(ctx, details)

	ids, _ := out["policy_ids"].([]string)
	if len(ids) != 2 || ids[0] != "existing" || ids[1] != PolicyIDMLFraudScore {
		t.Fatalf("policy_ids merge wrong (must append after existing, deduped): %v", ids)
	}
	names, _ := out["policy_names"].([]string)
	if len(names) != 2 {
		t.Fatalf("policy_names merge wrong: %v", names)
	}
	versions, _ := out["policy_versions"].(map[string]interface{})
	if versions[PolicyIDMLFraudScore] != "1.2.0" {
		t.Fatalf("policy_versions merge wrong: %v", versions)
	}
	if out["ml_inference_layer_status"] != MLStatusScored {
		t.Fatalf("ml status missing: %v", out)
	}
	rs, _ := out["risk_score"].(map[string]interface{})
	if rs["overall"] != 0.9 {
		t.Fatalf("risk_score missing: %v", out)
	}
}

func TestMergeAuditDetails_PreservesExistingVersionTypes(t *testing.T) {
	ctx := WithDecisionMeta(context.Background(), "mcp", "d2")
	stampResult(ctx, &Result{
		PolicyIDs:      []string{PolicyIDMandatoryFields},
		PolicyVersions: map[string]string{PolicyIDMandatoryFields: "1"},
	})
	// The MCP explainable writer stamps map[string]int; the merge must keep
	// those entries and their values.
	details := map[string]interface{}{
		"policy_versions": map[string]int{"sys_pii_ssn": 3},
	}
	out := MergeAuditDetails(ctx, details)
	versions, _ := out["policy_versions"].(map[string]interface{})
	if versions["sys_pii_ssn"] != 3 {
		t.Fatalf("existing int version lost: %v", versions)
	}
	if versions[PolicyIDMandatoryFields] != "1" {
		t.Fatalf("fincrime version missing: %v", versions)
	}
}

func TestMergeAuditDetails_ExistingEntryWins(t *testing.T) {
	ctx := WithDecisionMeta(context.Background(), "mcp", "d3")
	stampResult(ctx, &Result{
		PolicyIDs:      []string{"p1"},
		PolicyVersions: map[string]string{"p1": "9"},
	})
	details := map[string]interface{}{
		"policy_versions": map[string]interface{}{"p1": 4},
	}
	out := MergeAuditDetails(ctx, details)
	versions, _ := out["policy_versions"].(map[string]interface{})
	if versions["p1"] != 4 {
		t.Fatalf("a version stamped by the primary writer must not be overwritten: %v", versions)
	}
}

func TestMergeAuditDetails_ToleratesInterfaceSlices(t *testing.T) {
	ctx := WithDecisionMeta(context.Background(), "decide", "d4")
	stampResult(ctx, &Result{PolicyIDs: []string{"p2"}})
	details := map[string]interface{}{
		"policy_ids": []interface{}{"p1", 42},
	}
	out := MergeAuditDetails(ctx, details)
	ids, _ := out["policy_ids"].([]string)
	if len(ids) != 2 || ids[0] != "p1" || ids[1] != "p2" {
		t.Fatalf("interface-slice normalization wrong: %v", ids)
	}
}

func TestMergeAuditDetails_NilDetails(t *testing.T) {
	ctx := WithDecisionMeta(context.Background(), "decide", "d5")
	stampResult(ctx, &Result{PolicyIDs: []string{"p"}})
	if out := MergeAuditDetails(ctx, nil); out != nil {
		t.Fatalf("nil details must stay nil, got %v", out)
	}
}
