// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"testing"
	"time"
)

// The precedence cases below port the coverage of the now-deleted
// agent.PolicyOverrideRepository.GetEffectiveAction (formerly
// platform/agent/policy_override_repository_test.go:336-470,
// TestGetEffectiveAction), whose four table cases mapped 1:1 onto
// EffectiveOverride's tenant-beats-org-beats-none contract:
//   - "tenant override takes precedence" (a tenant row and an org row both
//     exist; tenant wins)
//   - "org override when no tenant override" (only an org row exists)
//   - "no override" (no rows at all)
//   - "expired override ignored" — GetEffectiveAction filtered this in SQL
//     (`expires_at IS NULL OR expires_at > NOW()`); EffectiveOverride takes
//     already-filtered rows (see OverrideRow's doc comment), so the
//     equivalent case here is "the caller never includes an expired row",
//     which collapses to the empty-rows case.

func boolPtr(b bool) *bool { return &b }

func TestEffectiveOverride_TenantBeatsOrg(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-1", RowID: "org-row", Scope: OverrideScopeOrg, Action: "log"},
		{PolicyID: "policy-1", RowID: "tenant-row", Scope: OverrideScopeTenant, Action: "warn"},
	}
	res := EffectiveOverride("policy-1", "", rows)
	if !res.HasOverride || !res.HasAction {
		t.Fatal("expected an override to apply")
	}
	if res.Action != "warn" {
		t.Errorf("action = %q, want tenant-level %q", res.Action, "warn")
	}
}

func TestEffectiveOverride_OrgWhenNoTenant(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-1", RowID: "org-row", Scope: OverrideScopeOrg, Action: "log"},
	}
	res := EffectiveOverride("policy-1", "", rows)
	if !res.HasOverride || !res.HasAction {
		t.Fatal("expected an override to apply")
	}
	if res.Action != "log" {
		t.Errorf("action = %q, want org-level %q", res.Action, "log")
	}
}

func TestEffectiveOverride_NoOverride(t *testing.T) {
	res := EffectiveOverride("policy-1", "", nil)
	if res.HasOverride {
		t.Fatalf("expected no override, got %+v", res)
	}
	if res.Action != "" {
		t.Errorf("action = %q, want empty", res.Action)
	}
}

func TestEffectiveOverride_EmptyRowsIgnored(t *testing.T) {
	// Mirrors "expired override ignored": the caller simply omits the
	// expired/filtered row, leaving the rows slice empty for this policy.
	res := EffectiveOverride("policy-1", "", []OverrideRow{})
	if res.HasOverride {
		t.Fatalf("expected no override for empty rows, got %+v", res)
	}
}

func TestEffectiveOverride_UnknownPolicyID(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-other", Scope: OverrideScopeTenant, Action: "block"},
	}
	res := EffectiveOverride("policy-1", "", rows)
	if res.HasOverride {
		t.Fatalf("expected no override for a policy id absent from rows, got %+v", res)
	}
}

func TestEffectiveOverride_EmptyPolicyID(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "", Scope: OverrideScopeTenant, Action: "block"},
	}
	res := EffectiveOverride("", "", rows)
	if res.HasOverride {
		t.Fatalf("expected no override for an empty policy id, even if a row matches it, got %+v", res)
	}
}

// TestEffectiveOverride_SegmentScopedNeverOverridable is the Mechanism-A
// counterpart of static_policy_repository.go's
// `if o, ok := overrides[policy.ID]; ok && policy.SegmentID == nil` gate: a
// segment-scoped policy must return no override unconditionally, even when a
// tenant-level row exists that would otherwise win outright.
func TestEffectiveOverride_SegmentScopedNeverOverridable(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-1", Scope: OverrideScopeTenant, Action: "log"},
		{PolicyID: "policy-1", Scope: OverrideScopeOrg, Action: "log"},
	}
	res := EffectiveOverride("policy-1", "seg-finance", rows)
	if res.HasOverride {
		t.Fatalf("segment-scoped policy must never be overridable via EffectiveOverride, got %+v", res)
	}
}

func TestEffectiveOverride_SegmentScopedNoOverrideRowsEitherWay(t *testing.T) {
	res := EffectiveOverride("policy-1", "seg-finance", nil)
	if res.HasOverride {
		t.Fatalf("expected no override for a segment-scoped policy with no rows, got %+v", res)
	}
}

// TestEffectiveOverride_ConflictingRowsAtSameScope covers two rows at the
// SAME scope for the same policy (not supposed to happen given
// PolicyOverrideRepository.Create's duplicate-scope check, but not
// schema-enforced): the LAST row in the input slice wins — i.e. the most
// recently created one, since callers pass rows in created_at ASC order —
// regardless of which action is more or less restrictive.
func TestEffectiveOverride_ConflictingRowsAtSameScope(t *testing.T) {
	t.Run("tenant scope, later row wins (warn then block)", func(t *testing.T) {
		rows := []OverrideRow{
			{PolicyID: "policy-1", RowID: "r1", Scope: OverrideScopeTenant, Action: "warn"},
			{PolicyID: "policy-1", RowID: "r2", Scope: OverrideScopeTenant, Action: "block"},
		}
		res := EffectiveOverride("policy-1", "", rows)
		if !res.HasOverride || res.Action != "block" {
			t.Fatalf("got %+v, want the LAST (most recent) row's action %q", res, "block")
		}
	})
	t.Run("tenant scope, later row wins (block then warn)", func(t *testing.T) {
		rows := []OverrideRow{
			{PolicyID: "policy-1", RowID: "r1", Scope: OverrideScopeTenant, Action: "block"},
			{PolicyID: "policy-1", RowID: "r2", Scope: OverrideScopeTenant, Action: "warn"},
		}
		res := EffectiveOverride("policy-1", "", rows)
		if !res.HasOverride || res.Action != "warn" {
			t.Fatalf("got %+v, want the LAST (most recent) row's action %q — recency, not restrictiveness, breaks a same-scope tie", res, "warn")
		}
	})
	t.Run("org scope, later row wins (log then require_approval)", func(t *testing.T) {
		rows := []OverrideRow{
			{PolicyID: "policy-1", RowID: "r1", Scope: OverrideScopeOrg, Action: "log"},
			{PolicyID: "policy-1", RowID: "r2", Scope: OverrideScopeOrg, Action: "require_approval"},
		}
		res := EffectiveOverride("policy-1", "", rows)
		if !res.HasOverride || res.Action != "require_approval" {
			t.Fatalf("got %+v, want the LAST (most recent) row's action %q", res, "require_approval")
		}
	})
}

func TestEffectiveOverride_RowsForOtherPoliciesIgnored(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-other", Scope: OverrideScopeTenant, Action: "block"},
		{PolicyID: "policy-1", Scope: OverrideScopeOrg, Action: "warn"},
	}
	res := EffectiveOverride("policy-1", "", rows)
	if !res.HasOverride || res.Action != "warn" {
		t.Fatalf("got %+v, want only policy-1's org row (%q) to be considered", res, "warn")
	}
}

func TestEffectiveOverride_RowWithEmptyActionIgnored(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-1", Scope: OverrideScopeTenant, Action: ""},
	}
	res := EffectiveOverride("policy-1", "", rows)
	if res.HasOverride {
		t.Fatalf("a row with an empty Action and a nil Enabled must not be treated as an override, got %+v", res)
	}
}

// --- Fix 1 (#3320 review) coverage: per-attribute resolution -------------

// TestEffectiveOverride_DisableOnlyRowRegisters is the disable-only
// regression: action_override NULL, enabled_override=false must still set
// HasOverride and resolve Enabled=false, even though no row has an opinion
// on Action.
func TestEffectiveOverride_DisableOnlyRowRegisters(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-1", RowID: "disable-row", Scope: OverrideScopeTenant, Enabled: boolPtr(false), Reason: "BI false positives"},
	}
	res := EffectiveOverride("policy-1", "", rows)
	if !res.HasOverride {
		t.Fatal("a disable-only row must set HasOverride")
	}
	if res.HasAction {
		t.Errorf("no row had an opinion on action, HasAction should be false, got action=%q", res.Action)
	}
	if !res.HasEnabled || res.Enabled != false {
		t.Errorf("expected resolved Enabled=false, got HasEnabled=%v Enabled=%v", res.HasEnabled, res.Enabled)
	}
	if len(res.Contributions) != 1 || res.Contributions[0].RowID != "disable-row" {
		t.Errorf("expected exactly one contribution from disable-row, got %+v", res.Contributions)
	}
}

// TestEffectiveOverride_OrgActionSurvivesActionlessTenantRow is the worked
// example from the #3320 review: a system policy has an org-level "warn"
// action override and a DIFFERENT tenant-level disable-only override. Both
// must resolve: HasOverride=true, Enabled=false (tenant's only opinion),
// Action="warn" (org's only opinion, since the tenant row has none) — the
// action-less tenant row must not discard the org's valid action.
func TestEffectiveOverride_OrgActionSurvivesActionlessTenantRow(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "sys_sqli_or_true", RowID: "org-tuning", Scope: OverrideScopeOrg, Action: "warn", Reason: "tuning"},
		{PolicyID: "sys_sqli_or_true", RowID: "tenant-disable", Scope: OverrideScopeTenant, Enabled: boolPtr(false), Reason: "BI FPs"},
	}
	res := EffectiveOverride("sys_sqli_or_true", "", rows)
	if !res.HasOverride {
		t.Fatal("expected HasOverride=true")
	}
	if !res.HasAction || res.Action != "warn" {
		t.Errorf("expected the org row's action %q to survive, got HasAction=%v Action=%q", "warn", res.HasAction, res.Action)
	}
	if !res.HasEnabled || res.Enabled != false {
		t.Errorf("expected the tenant row's disable to resolve, got HasEnabled=%v Enabled=%v", res.HasEnabled, res.Enabled)
	}
	if len(res.Contributions) != 2 {
		t.Fatalf("expected both rows attributed, got %d contributions: %+v", len(res.Contributions), res.Contributions)
	}
	var sawOrg, sawTenant bool
	for _, c := range res.Contributions {
		switch c.RowID {
		case "org-tuning":
			sawOrg = true
			if !c.HasAction || c.Action != "warn" || c.HasEnabled {
				t.Errorf("org-tuning contribution malformed: %+v", c)
			}
			if c.Reason != "tuning" {
				t.Errorf("org-tuning reason = %q, want %q", c.Reason, "tuning")
			}
		case "tenant-disable":
			sawTenant = true
			if !c.HasEnabled || c.Enabled != false || c.HasAction {
				t.Errorf("tenant-disable contribution malformed: %+v", c)
			}
			if c.Reason != "BI FPs" {
				t.Errorf("tenant-disable reason = %q, want %q", c.Reason, "BI FPs")
			}
		}
	}
	if !sawOrg || !sawTenant {
		t.Fatalf("expected contributions from both org-tuning and tenant-disable, got %+v", res.Contributions)
	}
}

// TestEffectiveOverride_SingleRowBothAttributes covers one row that opines
// on BOTH action and enabled: it must appear as exactly ONE contribution
// carrying both, never split into two.
func TestEffectiveOverride_SingleRowBothAttributes(t *testing.T) {
	rows := []OverrideRow{
		{PolicyID: "policy-1", RowID: "both", Scope: OverrideScopeTenant, Action: "redact", Enabled: boolPtr(true), Reason: "one row, two attributes"},
	}
	res := EffectiveOverride("policy-1", "", rows)
	if !res.HasAction || res.Action != "redact" {
		t.Errorf("expected action %q, got HasAction=%v Action=%q", "redact", res.HasAction, res.Action)
	}
	if !res.HasEnabled || res.Enabled != true {
		t.Errorf("expected enabled=true, got HasEnabled=%v Enabled=%v", res.HasEnabled, res.Enabled)
	}
	if len(res.Contributions) != 1 {
		t.Fatalf("expected exactly one contribution (same row supplies both attributes), got %+v", res.Contributions)
	}
	c := res.Contributions[0]
	if !c.HasAction || !c.HasEnabled || c.Action != "redact" || c.Enabled != true {
		t.Errorf("contribution should carry both attributes: %+v", c)
	}
}

// TestEffectiveOverride_ExpiryIsUpstreamOfThisFunction pins that
// EffectiveOverride treats each row's contribution independently of any
// OTHER row's expiry: passing only the still-live row (as the caller would
// once the other row's expires_at <= NOW() and it drops out of the SQL
// result) must resolve exactly as it did when both rows were live.
func TestEffectiveOverride_ExpiryIsUpstreamOfThisFunction(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	both := []OverrideRow{
		{PolicyID: "policy-1", RowID: "action-row", Scope: OverrideScopeOrg, Action: "warn", ExpiresAt: &future},
		{PolicyID: "policy-1", RowID: "enabled-row", Scope: OverrideScopeTenant, Enabled: boolPtr(false)},
	}
	onlyEnabled := []OverrideRow{
		{PolicyID: "policy-1", RowID: "enabled-row", Scope: OverrideScopeTenant, Enabled: boolPtr(false)},
	}

	resBoth := EffectiveOverride("policy-1", "", both)
	resAfterActionExpires := EffectiveOverride("policy-1", "", onlyEnabled)

	if !resBoth.HasEnabled || resBoth.Enabled != false {
		t.Fatalf("sanity: expected enabled=false with both rows live, got %+v", resBoth)
	}
	if !resAfterActionExpires.HasEnabled || resAfterActionExpires.Enabled != false {
		t.Errorf("the enabled-row's contribution must be unaffected by the action-row's expiry, got %+v", resAfterActionExpires)
	}
	if resAfterActionExpires.HasAction {
		t.Errorf("once the action-row is filtered out upstream, no row has an opinion on action, got %+v", resAfterActionExpires)
	}
}

// IsOverrideEligible ports the coverage of the identical eligibility gate
// previously duplicated in orchestrator.ApplyOverrideToResult,
// orchestrator.SelectOverridablePolicy, and
// agent.applyOverrideToCheckInputBlock (see override_enforcement_test.go's
// TestSelectOverridablePolicy_* and TestApplyOverrideToResult_AllCriticalNoOp
// for the pre-consolidation equivalents, which now exercise this function
// indirectly through the two live adapters).

func TestIsOverrideEligible_CriticalNeverEligible(t *testing.T) {
	if IsOverrideEligible("critical", true) {
		t.Error("critical-risk policy must never be eligible, even with allow_override=true")
	}
}

func TestIsOverrideEligible_NonCriticalEchoesAllowOverride(t *testing.T) {
	cases := []struct {
		risk          string
		allowOverride bool
		want          bool
	}{
		{"high", true, true},
		{"high", false, false},
		{"medium", true, true},
		{"medium", false, false},
		{"low", true, true},
		{"low", false, false},
		{"", true, true},
	}
	for _, tc := range cases {
		if got := IsOverrideEligible(tc.risk, tc.allowOverride); got != tc.want {
			t.Errorf("IsOverrideEligible(%q, %v) = %v, want %v", tc.risk, tc.allowOverride, got, tc.want)
		}
	}
}
