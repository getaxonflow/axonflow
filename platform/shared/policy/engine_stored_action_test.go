// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

// #3360: the engine must record the ROW-resolved action (StoredAction) beside
// the posture-resolved one (Action) on every match, so consumers can see when
// an ActionOverrides posture lever displaced a stored action instead of the
// discard being silent. Exercises the REAL UnifiedPolicyEngine on the exact
// reported shape: a pii-category system row storing action_request=block
// (migration 116's sys_pii_indonesia_ktp) evaluated under a redact posture.

import (
	"context"
	"regexp"
	"testing"
)

func ktpBlockSystemPolicy() CompiledPolicy {
	return CompiledPolicy{
		ID:            "00000000-0000-0000-0000-000000000116",
		PolicyID:      "sys_pii_indonesia_ktp",
		Name:          "Indonesian KTP Detection",
		Category:      CategoryPIIIndonesia,
		Tier:          "system",
		Severity:      SeverityCritical,
		Pattern:       regexp.MustCompile(`(?i)ktp[\s:#=]*[0-9][0-9.\s-]{14,22}[0-9]`),
		PatternStr:    `(?i)ktp[\s:#=]*[0-9][0-9.\s-]{14,22}[0-9]`,
		Phase:         PhaseRequest,
		ActionRequest: ActionBlock, // the stored row value the lever displaces
		Enabled:       true,
		Priority:      100,
		TenantID:      "test-tenant",
	}
}

func TestEngine_StoredActionRecordedBesideResolvedAction(t *testing.T) {
	engine := createTestEngine([]CompiledPolicy{ktpBlockSystemPolicy()})
	const input = "pelanggan no KTP 3174.0123.0467.0001 konfirmasi"
	cats := []PolicyCategory{CategoryPIIIndonesia}

	t.Run("lever displaces stored block to redact: both recorded, no deny", func(t *testing.T) {
		r := engine.EvaluateRequest(context.Background(), input, EvalOptions{
			TenantID:   "test-tenant",
			Categories: cats,
			ActionOverrides: map[PolicyCategory]Action{
				CategoryPIIIndonesia: ActionRedact,
			},
		})
		if r.Blocked {
			t.Fatalf("redact posture must not deny (lever-wins design): %+v", r)
		}
		if len(r.MatchedPolicies) != 1 {
			t.Fatalf("expected 1 match, got %d", len(r.MatchedPolicies))
		}
		m := r.MatchedPolicies[0]
		if m.Action != ActionRedact {
			t.Fatalf("resolved action must be the lever's: got %q", m.Action)
		}
		if m.StoredAction != ActionBlock {
			t.Fatalf("StoredAction must carry the row's action_request=block: got %q", m.StoredAction)
		}
	})

	t.Run("no override: StoredAction equals Action and the row blocks", func(t *testing.T) {
		r := engine.EvaluateRequest(context.Background(), input, EvalOptions{
			TenantID:   "test-tenant",
			Categories: cats,
		})
		if !r.Blocked {
			t.Fatalf("without a lever entry the stored block must deny")
		}
		m := r.MatchedPolicies[len(r.MatchedPolicies)-1]
		if m.StoredAction != ActionBlock || m.Action != ActionBlock {
			t.Fatalf("stored/resolved must both be block: (%q, %q)", m.StoredAction, m.Action)
		}
	})
}

// A row storing NULL for the evaluated phase resolves its action through
// GetActionForPhase's CATEGORY FALLBACK (pii -> redact), which is not a stored
// value: StoredAction must stay EMPTY so consumers never report a fallback as
// a displaced stored action. Without this rule every default-profile (warn)
// deployment would emit a displacement advisory on every match of the many
// seeded pii rows whose phase columns are NULL.
func TestEngine_NullPhaseColumn_StoredActionEmpty(t *testing.T) {
	p := ktpBlockSystemPolicy()
	p.ActionRequest = "" // NULL in the DB
	engine := createTestEngine([]CompiledPolicy{p})

	r := engine.EvaluateRequest(context.Background(), "pelanggan no KTP 3174.0123.0467.0001 konfirmasi", EvalOptions{
		TenantID:   "test-tenant",
		Categories: []PolicyCategory{CategoryPIIIndonesia},
		ActionOverrides: map[PolicyCategory]Action{
			CategoryPIIIndonesia: ActionWarn,
		},
	})
	if len(r.MatchedPolicies) != 1 {
		t.Fatalf("expected 1 match, got %d", len(r.MatchedPolicies))
	}
	m := r.MatchedPolicies[0]
	if m.StoredAction != "" {
		t.Fatalf("a NULL phase column must leave StoredAction empty (category fallback is not a stored value): got %q", m.StoredAction)
	}
	if m.Action != ActionWarn {
		t.Fatalf("resolved action must be the lever's: got %q", m.Action)
	}
}
