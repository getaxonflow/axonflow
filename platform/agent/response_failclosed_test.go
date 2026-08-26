// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #2820: agent response-plane redactors must fail CLOSED when the policy
// engine cannot LOAD policies (transient degradation) — a couldn't-scan must
// not be indistinguishable from scanned-clean, which would forward/store raw
// PII. Trigger: a real engine with a nil DB and an empty cache — every
// GetPolicies is a cache miss → load error.

import (
	"context"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// installLoadErroringEngine swaps the global engine for one that errors on
// every policy load (nil DB + empty cache), with MCP detection enabled so the
// response redactors actually reach the load. Restores prior state on cleanup.
func installLoadErroringEngine(t *testing.T) {
	t.Helper()
	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	cfg.GracefulDegradation = true // the agent's default — the fail-open regime under test
	engine := sharedpolicy.NewUnifiedPolicyEngine(nil, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)

	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: DetectionActionRedact}
	detectionConfigMu.Unlock()

	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() {
		sharedpolicy.SetGlobalEngine(origEngine)
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
	})
}

// Plane: check-output / query / execute (evaluateOutputPolicies).
func TestEvaluateOutputPolicies_FailsClosedOnLoadError(t *testing.T) {
	installLoadErroringEngine(t)
	rows := []map[string]interface{}{{"email": "andi@example.com", "note": "customer record"}}
	out := evaluateOutputPolicies(context.Background(), "unseeded-tenant", "", "u1",
		"gw.test", "gw.test", rows, "", nil, len(rows), false, true /* isGateway (check-output) */, nil)

	if out.StaticResult == nil || !out.StaticResult.Blocked {
		t.Fatal("load error must fail closed (blocked/withheld), not forward the rows")
	}
	if !out.StaticResult.EvaluationError {
		t.Error("the withheld outcome must carry EvaluationError so audit records could-not-govern, not a policy verdict")
	}
	if out.RedactedRows != nil {
		t.Error("no rows should be forwarded on a couldn't-scan")
	}
}

// Plane: request-phase redact-obligation fulfillment (redactInputStatement).
// A load error must report evaluated=false so the PEP fails closed (#2563 B1),
// not evaluated=true/redacted=false ("ran, nothing to mask") which forwards raw.
func TestRedactInputStatement_FailsClosedOnLoadError(t *testing.T) {
	installLoadErroringEngine(t)
	masked, redacted, evaluated := redactInputStatement(context.Background(), "unseeded-tenant", "u1", "gw.test", "ping andi@example.com")
	if evaluated {
		t.Error("load error must report evaluated=false so the PEP fails closed")
	}
	if redacted || masked != "" {
		t.Errorf("no masking can be claimed on a couldn't-scan; got masked=%q redacted=%v", masked, redacted)
	}
}
