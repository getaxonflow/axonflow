// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

// Real-engine before/after proof for #2705: a system sensitive-data policy with
// NULL phase columns (action_request/action_response empty — the migration-035
// shape) resolves to a hardcoded 'log' via GetActionForPhase's category fallback
// UNLESS the caller supplies an ActionOverrides entry for the category. Before
// the fix, platform/agent/detection_config.go BuildActionOverrides omitted
// CategorySensitiveData, so the override was never present and the documented
// warn(default)/block(strict) posture was inert. This test exercises the REAL
// UnifiedPolicyEngine (no mocked evaluation) to prove the three states:
//
//	BEFORE (no override)         -> action = log,   not blocked
//	AFTER, default profile (warn)-> action = warn,  not blocked
//	AFTER, strict profile (block)-> action = block, BLOCKED
//
// The agent-side wiring (BuildActionOverrides now emits the warn/block override
// per profile) is proven by TestBuildActionOverrides_SensitiveDataLever_* in
// platform/agent.

import (
	"context"
	"regexp"
	"testing"
)

func sensitiveDataSystemPolicy() CompiledPolicy {
	// Mirrors a migration-035 system sensitive-data row: NULL phase columns
	// (ActionRequest/ActionResponse empty), so the engine must fall back to
	// GetActionForPhase's category default (log) when no override is supplied.
	return CompiledPolicy{
		ID:             "00000000-0000-0000-0000-0000000005ec",
		PolicyID:       "sys_sensitive_password",
		Name:           "Password Detection",
		Category:       CategorySensitiveData,
		Tier:           "system",
		Severity:       SeverityHigh,
		Pattern:        regexp.MustCompile(`(?i)password\s*=`),
		PatternStr:     `(?i)password\s*=`,
		Phase:          PhaseRequest,
		ActionRequest:  "", // NULL in DB
		ActionResponse: "", // NULL in DB
		Enabled:        true,
		Priority:       80,
		TenantID:       "test-tenant",
	}
}

func TestEngine_SensitiveDataActionOverride_BeforeAfter(t *testing.T) {
	engine := createTestEngine([]CompiledPolicy{sensitiveDataSystemPolicy()})
	const input = "password = hunter2"
	cats := []PolicyCategory{CategorySensitiveData}

	eval := func(t *testing.T, overrides map[PolicyCategory]Action) *RequestResult {
		t.Helper()
		r := engine.EvaluateRequest(context.Background(), input, EvalOptions{
			TenantID:        "test-tenant",
			Categories:      cats,
			ActionOverrides: overrides,
		})
		if len(r.MatchedPolicies) != 1 {
			t.Fatalf("expected exactly 1 matched policy, got %d", len(r.MatchedPolicies))
		}
		return r
	}

	t.Run("before_no_override_falls_back_to_log", func(t *testing.T) {
		r := eval(t, nil)
		if got := r.MatchedPolicies[0].Action; got != ActionLog {
			t.Errorf("without an override the sensitive-data action = %q, want %q (GetActionForPhase fallback)", got, ActionLog)
		}
		if r.Blocked {
			t.Error("sensitive-data must NOT block without a block override")
		}
	})

	t.Run("after_default_profile_warn", func(t *testing.T) {
		r := eval(t, map[PolicyCategory]Action{CategorySensitiveData: ActionWarn})
		if got := r.MatchedPolicies[0].Action; got != ActionWarn {
			t.Errorf("default-profile override: sensitive-data action = %q, want %q", got, ActionWarn)
		}
		if r.Blocked {
			t.Error("warn must not block")
		}
	})

	t.Run("after_strict_profile_block", func(t *testing.T) {
		r := eval(t, map[PolicyCategory]Action{CategorySensitiveData: ActionBlock})
		if got := r.MatchedPolicies[0].Action; got != ActionBlock {
			t.Errorf("strict-profile override: sensitive-data action = %q, want %q", got, ActionBlock)
		}
		if !r.Blocked {
			t.Error("strict profile (block override) MUST block the sensitive-data request — this is the #2705 fix")
		}
	})
}
