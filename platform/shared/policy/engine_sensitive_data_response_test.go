// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

// Response-plane proof for #2705. The request-plane half is proven in
// engine_sensitive_data_override_test.go; this proves the SAME lever now reaches
// the RESPONSE plane: a credential-shaped response is warn-recorded (default) or
// BLOCKED/withheld (strict/compliance) once the sensitive-data category is folded
// into the evaluated set. Also proves EnabledSensitiveDataCategories gates the
// category by enablement (the helper the request/response callsites use to fold
// it in without the empty-Categories whitelist footgun).

import (
	"context"
	"testing"
)

func sensitiveDataResponsePolicy() CompiledPolicy {
	p := sensitiveDataSystemPolicy()
	p.Phase = PhaseBoth // applies to request AND response
	return p
}

func TestEngine_SensitiveDataResponse_BlockWarnLog(t *testing.T) {
	engine := createTestEngine([]CompiledPolicy{sensitiveDataResponsePolicy()})
	content := []map[string]interface{}{{"statement": "password = hunter2"}}
	cats := []PolicyCategory{CategorySensitiveData}

	eval := func(overrides map[PolicyCategory]Action) *ResponseResult {
		return engine.EvaluateResponse(context.Background(), content, EvalOptions{
			TenantID:        "test-tenant",
			Categories:      cats,
			ActionOverrides: overrides,
			MaxRedactions:   100,
		})
	}

	t.Run("no_override_not_blocked", func(t *testing.T) {
		if eval(nil).Blocked {
			t.Error("sensitive-data must NOT block on response without a block override")
		}
	})
	t.Run("default_warn_not_blocked", func(t *testing.T) {
		if eval(map[PolicyCategory]Action{CategorySensitiveData: ActionWarn}).Blocked {
			t.Error("warn must not block the response")
		}
	})
	t.Run("strict_block_withholds", func(t *testing.T) {
		// The #2705 response-plane fix: a block override (strict/compliance) must
		// make the engine flag the credential-shaped response as Blocked, which the
		// orchestrator wiring turns into a withheld + canonical-blocked response.
		if !eval(map[PolicyCategory]Action{CategorySensitiveData: ActionBlock}).Blocked {
			t.Fatal("strict (block override) MUST block a credential-shaped response — #2705 response plane")
		}
	})
}

func TestEnabledSensitiveDataCategories(t *testing.T) {
	t.Run("enabled_returns_category", func(t *testing.T) {
		engine := createTestEngine([]CompiledPolicy{sensitiveDataResponsePolicy()})
		got := engine.EnabledSensitiveDataCategories(context.Background(), "test-tenant", nil, PhaseResponse)
		if len(got) != 1 || got[0] != CategorySensitiveData {
			t.Fatalf("enabled sensitive-data → %v, want [sensitive-data]", got)
		}
	})
	t.Run("disabled_returns_nil", func(t *testing.T) {
		p := sensitiveDataResponsePolicy()
		p.Enabled = false
		engine := createTestEngine([]CompiledPolicy{p})
		if got := engine.EnabledSensitiveDataCategories(context.Background(), "test-tenant", nil, PhaseResponse); got != nil {
			t.Fatalf("disabled sensitive-data → %v, want nil (whitelist-footgun guard)", got)
		}
	})
	t.Run("absent_returns_nil", func(t *testing.T) {
		pii := sensitiveDataResponsePolicy()
		pii.Category = CategoryPIIUS
		engine := createTestEngine([]CompiledPolicy{pii})
		if got := engine.EnabledSensitiveDataCategories(context.Background(), "test-tenant", nil, PhaseResponse); got != nil {
			t.Fatalf("no sensitive-data policy → %v, want nil", got)
		}
	})
}
