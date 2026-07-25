// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// #2865: check-output must report whether the response redaction pipeline RAN,
// so a response-phase PEP can tell "scanned, nothing to mask" from "not scanned"
// and fail closed on the latter. Previously the field never appeared on the
// wire, so a strict PEP could not trust an un-redacted response.

// installMCPDetection forces the cached MCP detection config on/off for a test.
// When enabled, it also wires a REAL policy engine backed by an empty-policy
// sqlmock (so PoliciesLoadable succeeds and RedactionEvaluated must be true);
// pass wantEngine=false to leave the engine nil and prove the engine-nil guard.
func installMCPDetection(t *testing.T, enabled, wantEngine bool) {
	t.Helper()
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: enabled, PIIAction: DetectionActionRedact}
	detectionConfigMu.Unlock()
	origEngine := sharedpolicy.GetGlobalEngine()

	if wantEngine {
		mockDB, mockSQL, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		t.Cleanup(func() { _ = mockDB.Close() })
		mockSQL.MatchExpectationsInOrder(false)
		// #3048: a load with ZERO system-tier policies now fails CLOSED, so
		// the "engine present, no PII policies" premise is expressed with a
		// benign never-matching non-PII system row instead of an empty set.
		for i := 0; i < 8; i++ {
			mockSQL.ExpectQuery("SELECT").WillReturnRows(
				policytest.SystemPolicyRow(sqlmock.NewRows(policytest.LoaderCols()),
				"00000000-0000-0000-0000-00000000f0f0", "sys_test_never_matches",
				"security-sqli", "ZZ_NEVER_MATCHES_ZZ", "low", "request", "block", 1),
			)
		}
		policytest.ScopedTxPlumbing(mockSQL, 8)
		cfg := sharedpolicy.DefaultEngineConfig()
		cfg.RefreshInterval = 0
		cfg.EnableMetrics = false
		engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, cfg, &sharedpolicy.NoOpAuditQueue{})
		t.Cleanup(engine.Stop)
		sharedpolicy.SetGlobalEngine(engine)
	} else {
		sharedpolicy.SetGlobalEngine(nil)
	}

	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
		sharedpolicy.SetGlobalEngine(origEngine)
	})
}

// Detection enabled + a live engine: the redaction pipeline ran, so
// RedactionEvaluated must be true even on a clean response with nothing to mask.
func TestEvaluateOutputPolicies_RedactionEvaluated_TrueWhenScanned(t *testing.T) {
	installMCPDetection(t, true /* enabled */, true /* engine */)
	out := evaluateOutputPolicies(context.Background(), "t1", "u1", "gw.test", "gw.test",
		nil, "nothing sensitive here", nil, 0, false, true /* isGateway */)
	if !out.RedactionEvaluated {
		t.Error("detection on + live engine → RedactionEvaluated must be true, even on a clean response")
	}
	if out.WasRedacted() {
		t.Error("a clean response must not report a redaction")
	}
}

// Detection disabled: nothing scanned the response, so RedactionEvaluated must
// be false — a strict PEP then fails closed.
func TestEvaluateOutputPolicies_RedactionEvaluated_FalseWhenDetectionOff(t *testing.T) {
	installMCPDetection(t, false /* disabled */, false)
	out := evaluateOutputPolicies(context.Background(), "t1", "u1", "gw.test", "gw.test",
		nil, "contact bob@example.com", nil, 0, false, true /* isGateway */)
	if out.RedactionEvaluated {
		t.Error("detection disabled → RedactionEvaluated must be false so a PEP fails closed")
	}
}

// Detection ON but engine NIL: the static PII pass is skipped (only the
// Indonesia checksum masker runs, which cannot clear generic PII), so claiming
// "evaluated" would be a fail-open. Must be false — faithful to the input plane.
func TestEvaluateOutputPolicies_RedactionEvaluated_FalseWhenEngineNil(t *testing.T) {
	installMCPDetection(t, true /* enabled */, false /* nil engine */)
	out := evaluateOutputPolicies(context.Background(), "t1", "u1", "gw.test", "gw.test",
		nil, "contact bob@example.com", nil, 0, false, true /* isGateway */)
	if out.RedactionEvaluated {
		t.Error("detection on but engine nil → generic PII not scanned → RedactionEvaluated must be false (no fail-open)")
	}
}

// The wire contract: RedactionEvaluated=true serializes redaction_evaluated:true;
// false is omitted (omitempty) so a strict PEP defaults to fail-closed, and the
// pre-#2865 byte shape is preserved for callers that never scanned.
func TestMCPCheckOutputResponse_RedactionEvaluatedWireShape(t *testing.T) {
	on, _ := json.Marshal(MCPCheckOutputResponse{Allowed: true, RedactionEvaluated: true})
	if !strings.Contains(string(on), `"redaction_evaluated":true`) {
		t.Errorf("evaluated response must emit redaction_evaluated:true; got %s", on)
	}
	off, _ := json.Marshal(MCPCheckOutputResponse{Allowed: true, RedactionEvaluated: false})
	if strings.Contains(string(off), "redaction_evaluated") {
		t.Errorf("un-evaluated response must OMIT redaction_evaluated (omitempty → PEP fail-closed); got %s", off)
	}
}
