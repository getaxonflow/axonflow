// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

func TestConvertSharedResultToStatic_Nil(t *testing.T) {
	result := convertSharedResultToStatic(nil)
	if result == nil {
		t.Fatal("Expected non-nil result for nil input")
	}
	if result.Blocked {
		t.Error("Expected Blocked=false for nil input")
	}
	if len(result.TriggeredPolicies) != 0 {
		t.Error("Expected empty TriggeredPolicies for nil input")
	}
	if len(result.ChecksPerformed) == 0 || result.ChecksPerformed[0] != "shared_policy_engine" {
		t.Error("Expected ChecksPerformed to contain 'shared_policy_engine'")
	}
}

func TestConvertSharedResultToStatic_Blocked(t *testing.T) {
	blockedPolicy := &sharedpolicy.CompiledPolicy{
		PolicyID: "sqli_001",
		Severity: sharedpolicy.SeverityCritical,
	}

	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           true,
		BlockedBy:         blockedPolicy,
		BlockReason:       "SQL injection detected",
		PoliciesEvaluated: 150,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "sqli_001",
				Action:   sharedpolicy.ActionBlock,
				Category: sharedpolicy.CategorySecuritySQLi,
				Severity: sharedpolicy.SeverityCritical,
			},
		},
		ProcessingTimeMs: 2,
	})

	if !result.Blocked {
		t.Error("Expected Blocked=true")
	}
	if result.Reason != "SQL injection detected" {
		t.Errorf("Expected reason 'SQL injection detected', got '%s'", result.Reason)
	}
	if result.Severity != string(sharedpolicy.SeverityCritical) {
		t.Errorf("Expected severity 'critical', got '%s'", result.Severity)
	}
	if len(result.TriggeredPolicies) != 1 || result.TriggeredPolicies[0] != "sqli_001" {
		t.Errorf("Expected triggered policy 'sqli_001', got %v", result.TriggeredPolicies)
	}
	if result.ProcessingTimeMs != 2 {
		t.Errorf("Expected ProcessingTimeMs=2, got %d", result.ProcessingTimeMs)
	}
	if result.RequiresRedaction {
		t.Error("Blocked result should not require redaction")
	}
}

func TestConvertSharedResultToStatic_PIIRedaction(t *testing.T) {
	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 50,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "pii_ssn",
				Action:   sharedpolicy.ActionRedact,
				Category: sharedpolicy.CategoryPIIUS,
				Severity: sharedpolicy.SeverityCritical,
			},
			{
				PolicyID: "pii_email",
				Action:   sharedpolicy.ActionRedact,
				Category: sharedpolicy.CategoryPIIGlobal,
				Severity: sharedpolicy.SeverityMedium,
			},
		},
	})

	if result.Blocked {
		t.Error("Expected Blocked=false for PII redaction")
	}
	if !result.RequiresRedaction {
		t.Error("Expected RequiresRedaction=true for PII matches")
	}
	if len(result.TriggeredPolicies) != 2 {
		t.Errorf("Expected 2 triggered policies, got %d", len(result.TriggeredPolicies))
	}
}

func TestConvertSharedResultToStatic_RequiresApproval(t *testing.T) {
	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "hitl_credit_scoring",
				Action:   sharedpolicy.ActionRequireApproval,
				Category: sharedpolicy.CategorySensitiveData,
				Severity: sharedpolicy.SeverityCritical,
			},
		},
	})

	if result.Blocked {
		t.Error("Expected Blocked=false for require_approval")
	}
	if !result.RequiresApproval {
		t.Error("Expected RequiresApproval=true for ActionRequireApproval")
	}
}

func TestConvertSharedResultToStatic_EmptyResult(t *testing.T) {
	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 150,
		MatchedPolicies:   []sharedpolicy.PolicyMatch{},
	})

	if result.Blocked {
		t.Error("Expected Blocked=false")
	}
	if result.RequiresRedaction {
		t.Error("Expected RequiresRedaction=false for no matches")
	}
	if result.RequiresApproval {
		t.Error("Expected RequiresApproval=false for no matches")
	}
}

// TestPlaneWhitelistsCoverAllPII is the #2965 R3 guard for the sibling planes:
// the proxy, openai-compat, and gateway pre-check category whitelists must
// evaluate EVERY canonical pii-* category. The original bug was pii-indonesia
// missing from these hand lists, so the KTP policy was filtered out before
// evaluation and Indonesian PII was silently ungoverned on those planes. All
// lists now spread sharedpolicy.AllTextPIICategories(); this test fails if a
// future edit drops a PII category from a whitelist.
//
// NOTE: this test alone is SELF-REFERENTIAL — the whitelists spread the same
// AllTextPIICategories() it checks against, so deleting a category from that
// function would leave this green. TestAllTextPIICategories_CoversStaticCategories
// below is the independent cross-check that actually bites.
func TestPlaneWhitelistsCoverAllPII(t *testing.T) {
	whitelists := map[string][]sharedpolicy.PolicyCategory{
		"proxyPolicyCategories":           proxyPolicyCategories,
		"openaiCompatPolicyCategories":    openaiCompatPolicyCategories,
		"gatewayPreCheckPolicyCategories": gatewayPreCheckPolicyCategories,
	}
	for name, list := range whitelists {
		present := make(map[sharedpolicy.PolicyCategory]bool, len(list))
		for _, c := range list {
			present[c] = true
		}
		for _, pii := range sharedpolicy.AllTextPIICategories() {
			if !present[pii] {
				t.Errorf("%s omits PII category %q — a matching policy would be filtered out before evaluation (silent allow, #2965)", name, pii)
			}
		}
	}
}

// TestAllTextPIICategories_CoversStaticCategories is the INDEPENDENT cross-check
// (#2965 R3 MED-1). StaticPolicyCategories() is this package's canonical category
// enum — a list maintained separately from sharedpolicy.AllTextPIICategories(),
// which the plane whitelists spread. Every pii-* category the agent knows about
// (per StaticPolicyCategories) MUST appear in AllTextPIICategories, or a plane
// whitelist would silently stop evaluating it. Because the two lists are
// independent, this guard actually fails when AllTextPIICategories drops a
// category — unlike TestPlaneWhitelistsCoverAllPII, which is self-referential.
func TestAllTextPIICategories_CoversStaticCategories(t *testing.T) {
	covered := make(map[string]bool)
	for _, c := range sharedpolicy.AllTextPIICategories() {
		covered[string(c)] = true
	}
	found := 0
	for _, c := range StaticPolicyCategories() {
		s := string(c)
		if !strings.HasPrefix(s, "pii-") {
			continue
		}
		found++
		if !covered[s] {
			t.Errorf("StaticPolicyCategories() has pii-* category %q not covered by sharedpolicy.AllTextPIICategories() — a plane whitelist would silently stop evaluating it (#2965)", s)
		}
	}
	// Guard the guard: if StaticPolicyCategories ever stops listing pii-*
	// categories, this cross-check would vacuously pass.
	if found == 0 {
		t.Fatal("no pii-* categories found in StaticPolicyCategories() — cross-check is vacuous")
	}
}

// TestConvertSharedResultToStatic_Indonesia_ActionAware is the direct #2965
// regression: pii-indonesia (KTP/NIK) must produce the SAME governance signal
// as pii-singapore (NRIC) under every resolved action. Before the fix the
// agent-local isPIICategory switch omitted pii-indonesia, so a non-blocking KTP
// match set neither RequiresRedaction nor an advisory reason and fell through
// to a bare allow. Both categories are driven table-wise so any divergence
// between them fails.
func TestConvertSharedResultToStatic_Indonesia_ActionAware(t *testing.T) {
	// The engine has already applied the per-category PII_ACTION override onto
	// match.Action by the time convert sees it, so `action` here is the RESOLVED
	// action for each of the four postures.
	//
	//   block is represented by Blocked=true (engine short-circuits on it);
	//   redact/warn/log ride a non-blocking match.
	cases := []struct {
		posture       string
		action        sharedpolicy.Action
		blocked       bool
		wantRedaction bool
		wantAdvisory  bool
	}{
		{"redact", sharedpolicy.ActionRedact, false, true, false},
		{"warn", sharedpolicy.ActionWarn, false, false, true},
		{"log", sharedpolicy.ActionLog, false, false, true},
		{"block", sharedpolicy.ActionBlock, true, false, false},
	}

	categories := []struct {
		name     string
		category sharedpolicy.PolicyCategory
		policyID string
	}{
		{"indonesia_ktp", sharedpolicy.CategoryPIIIndonesia, "sys_pii_indonesia_ktp"},
		{"singapore_nric", sharedpolicy.CategoryPIISingapore, "sys_pii_singapore_nric"},
	}

	for _, cat := range categories {
		for _, tc := range cases {
			t.Run(cat.name+"/"+tc.posture, func(t *testing.T) {
				rr := &sharedpolicy.RequestResult{
					Blocked: tc.blocked,
					MatchedPolicies: []sharedpolicy.PolicyMatch{{
						PolicyID: cat.policyID,
						Action:   tc.action,
						Category: cat.category,
						Severity: sharedpolicy.SeverityCritical,
					}},
				}
				if tc.blocked {
					rr.BlockReason = "blocked by policy"
				}
				got := convertSharedResultToStatic(rr)

				if got.RequiresRedaction != tc.wantRedaction {
					t.Errorf("RequiresRedaction = %v, want %v", got.RequiresRedaction, tc.wantRedaction)
				}
				hasAdvisory := len(got.AdvisoryReasons) > 0
				if hasAdvisory != tc.wantAdvisory {
					t.Errorf("advisory reasons present = %v (%v), want %v", hasAdvisory, got.AdvisoryReasons, tc.wantAdvisory)
				}
				if tc.wantAdvisory {
					// The advisory reason must name the policy so the match is
					// self-documenting (not a bare allow).
					if !strings.Contains(got.AdvisoryReasons[0], cat.policyID) {
						t.Errorf("advisory reason %q does not name policy %q", got.AdvisoryReasons[0], cat.policyID)
					}
				}
			})
		}
	}
}

// TestConvertSharedResultToStatic_WarnLogNoRedaction pins the sibling bug fix
// (#2965): before making the mapping action-aware, ANY non-blocking PII match
// set RequiresRedaction regardless of resolved action, so warn/log postures
// silently emitted redact_pii. A warn/log match must NOT require redaction.
func TestConvertSharedResultToStatic_WarnLogNoRedaction(t *testing.T) {
	for _, action := range []sharedpolicy.Action{sharedpolicy.ActionWarn, sharedpolicy.ActionLog} {
		got := convertSharedResultToStatic(&sharedpolicy.RequestResult{
			Blocked: false,
			MatchedPolicies: []sharedpolicy.PolicyMatch{{
				PolicyID: "sys_pii_us_ssn",
				Action:   action,
				Category: sharedpolicy.CategoryPIIUS,
				Severity: sharedpolicy.SeverityCritical,
			}},
		})
		if got.RequiresRedaction {
			t.Errorf("action=%s: RequiresRedaction=true, want false (warn/log must not redact)", action)
		}
		if len(got.AdvisoryReasons) == 0 {
			t.Errorf("action=%s: expected an advisory reason so the match is not a silent allow", action)
		}
	}
}
