// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// withMCPPIIAction sets the cached MCP detection config to a given PII action for
// the duration of a test (isolated; restored via the returned cleanup). The
// static engine is also nil'd so only the Indonesia response step runs.
func withMCPPIIAction(t *testing.T, action DetectionAction) {
	t.Helper()
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: action}
	detectionConfigMu.Unlock()
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
		sharedpolicy.SetGlobalEngine(origEngine)
	})
}

const validNIKResponse = "Pelanggan NIK 3174042506780001 terdaftar"

// Under PII_ACTION=warn/log the Indonesia response step must DETECT but NOT
// modify content — parity with the static engine + orchestrator, which never
// mutate on warn/log. (Master R3 round-2 required fix.)
func TestEvaluateOutputPolicies_IndonesiaWarnNoMask(t *testing.T) {
	for _, action := range []DetectionAction{DetectionActionWarn, DetectionActionLog} {
		t.Run(string(action), func(t *testing.T) {
			withMCPPIIAction(t, action)
			out := evaluateOutputPolicies(context.Background(), "t1", "u1", "gw.test", "gw.test",
				nil, validNIKResponse, nil, 0, false, true /* isGateway */)
			if out.StaticResult != nil && out.StaticResult.Blocked {
				t.Errorf("%s must not block", action)
			}
			if out.RedactedMessage != "" {
				t.Errorf("%s must NOT mask (detect-don't-modify); got RedactedMessage=%q", action, out.RedactedMessage)
			}
			if out.WasRedacted() {
				t.Errorf("%s must not report a redaction", action)
			}
		})
	}
}

// Under PII_ACTION=redact the Indonesia response step masks the NIK.
func TestEvaluateOutputPolicies_IndonesiaRedactMasks(t *testing.T) {
	withMCPPIIAction(t, DetectionActionRedact)
	out := evaluateOutputPolicies(context.Background(), "t1", "u1", "gw.test", "gw.test",
		nil, validNIKResponse, nil, 0, false, true /* isGateway */)
	if out.RedactedMessage == "" {
		t.Fatal("redact must mask the NIK on the response")
	}
	if strings.Contains(out.RedactedMessage, "3174042506780001") {
		t.Errorf("raw NIK leaked through redaction: %q", out.RedactedMessage)
	}
	if !out.WasRedacted() {
		t.Error("redact must report a redaction")
	}
}

// Under PII_ACTION=block a critical NIK is blocked (not masked) on the response.
func TestEvaluateOutputPolicies_IndonesiaBlock(t *testing.T) {
	withMCPPIIAction(t, DetectionActionBlock)
	out := evaluateOutputPolicies(context.Background(), "t1", "u1", "gw.test", "gw.test",
		nil, validNIKResponse, nil, 0, false, true /* isGateway */)
	if out.StaticResult == nil || !out.StaticResult.Blocked {
		t.Fatal("block mode must block a critical NIK on the response")
	}
}

// Regression lock for the #2563 round-2 leak: an Indonesia-ONLY redaction sets
// RedactedRows/RedactedMessage but leaves StaticResult nil. Every redaction
// surface (MCP-tool response, client body, audit) must gate on WasRedacted, not
// StaticResult — otherwise the masked data is dropped (forwarding the unmasked
// original) or the redaction signal is lost.
func TestOutputPolicyOutcome_WasRedacted_IndonesiaOnly(t *testing.T) {
	// Indonesia-only message redaction, StaticResult nil.
	msgOnly := OutputPolicyOutcome{RedactedMessage: "NIK 31**********0001", IndonesiaRedactedTypes: []string{"nik"}}
	if !msgOnly.WasRedacted() {
		t.Error("WasRedacted must be true for an Indonesia-only message redaction (StaticResult nil) — the leak gate")
	}
	if got := msgOnly.RedactedFieldNames(); len(got) != 1 || got[0] != "nik" {
		t.Errorf("RedactedFieldNames = %v, want [nik]", got)
	}

	// Indonesia-only row redaction, StaticResult nil.
	rowsOnly := OutputPolicyOutcome{
		RedactedRows:           []map[string]interface{}{{"ktp": "31**********0001"}},
		IndonesiaRedactedTypes: []string{"nik"},
	}
	if !rowsOnly.WasRedacted() {
		t.Error("WasRedacted must be true for an Indonesia-only row redaction (StaticResult nil)")
	}

	// Static-engine redaction (no Indonesia) still counts.
	staticOnly := OutputPolicyOutcome{StaticResult: &sharedpolicy.ResponseResult{Redacted: true}}
	if !staticOnly.WasRedacted() {
		t.Error("WasRedacted must be true for a static-engine redaction")
	}

	// No redaction → false.
	if (OutputPolicyOutcome{}).WasRedacted() {
		t.Error("empty outcome must report WasRedacted=false")
	}
}

// The Indonesia detector must govern a checksum-valid NIK on RESPONSE text, not
// only on requests — the asymmetry #2563 closes. checkIndonesiaResponsePII reuses
// the same text-based detector as the request path.
func TestCheckIndonesiaResponsePII_NIK(t *testing.T) {
	const validNIK = "3174042506780001" // checksum-valid (shared with 2478 + runtime-e2e)

	// Block mode: critical NIK on a response must recommend a block.
	got := checkIndonesiaResponsePII("Pelanggan NIK "+validNIK+" terdaftar", true)
	if got == nil || !got.HasPII || !got.CriticalPII {
		t.Fatalf("expected critical Indonesia PII on response text, got %+v", got)
	}
	if !got.BlockRecommended {
		t.Error("block mode: a critical NIK on the response must recommend a block (NIK leaked on output)")
	}

	// Redact mode: still detected, but no block recommended.
	red := checkIndonesiaResponsePII("Pelanggan NIK "+validNIK+" terdaftar", false)
	if red == nil || !red.HasPII {
		t.Fatalf("expected Indonesia PII detected in redact mode, got %+v", red)
	}
	if red.BlockRecommended {
		t.Error("redact mode must not recommend a block")
	}

	// An invalid NIK (bad month) must NOT be detected — proves checksum gating.
	if bad := checkIndonesiaResponsePII("NIK 3174012345678901 x", true); bad != nil && bad.CriticalPII {
		t.Error("an invalid NIK must not be detected as critical PII")
	}
}

// redactIndonesiaPIIInString masks checksum-validated Indonesia PII in place.
// This is the masker the request-phase check-input redactor (redactInputStatement,
// #2571) now uses, so a /decide redact_pii obligation naming check-input is
// actually fulfillable. The static engine does NOT carry checksum NIK, so this
// primitive is what closes the request-path NIK leak — it must be pinned in
// normal CI, not only the license-gated runtime-e2e.
func TestRedactIndonesiaPIIInString(t *testing.T) {
	const validNIK = "3174042506780001" // checksum-valid (province 31, DD 25, MM 06)

	// NIK is masked to the canonical first-2 + middle-mask + last-4 form.
	masked, changed := redactIndonesiaPIIInString("NIK " + validNIK)
	if !changed {
		t.Fatal("expected NIK to be masked")
	}
	if masked != "NIK 31**********0001" {
		t.Errorf("NIK masking: got %q, want %q", masked, "NIK 31**********0001")
	}
	if strings.Contains(masked, validNIK) {
		t.Errorf("raw NIK still present after masking: %q", masked)
	}

	// NPWP is masked too (the other critical Indonesia identifier).
	npwpMasked, npwpChanged := redactIndonesiaPIIInString("NPWP 01.234.567.8-901.234")
	if !npwpChanged {
		t.Error("expected NPWP to be masked")
	}
	if strings.Contains(npwpMasked, "01.234.567.8-901.234") {
		t.Errorf("raw NPWP still present after masking: %q", npwpMasked)
	}

	// An invalid 16-digit number (fails the NIK checksum: province/date) must
	// NOT be masked — proves checksum gating, so the masker doesn't redact
	// arbitrary 16-digit strings (e.g. a credit card or order id).
	if out, changed := redactIndonesiaPIIInString("number 9999999999999999"); changed || out != "number 9999999999999999" {
		t.Errorf("invalid 16-digit must NOT be masked, got %q changed=%v", out, changed)
	}

	// Clean text unchanged.
	if out, changed := redactIndonesiaPIIInString("favorite color blue"); changed || out != "favorite color blue" {
		t.Errorf("clean text must be unchanged, got %q changed=%v", out, changed)
	}
}

// #2801 regression lock (R3 round-2 F1): capability scoping must NEVER touch
// Indonesia PII response governance — a NIK in a Jira document is still a
// leak. Unlike the tests above, the shared engine is REAL (DB-less, graceful
// degradation) so the capability classifier is actually active and positively
// classifies the identity as text-document; redact/block per posture must
// behave exactly as for any other identity.
func TestEvaluateOutputPolicies_IndonesiaNIKUnaffectedByCapabilityScope(t *testing.T) {
	const jiraTool = "claude_code.mcp__atlassian__getJiraIssue"

	install := func(t *testing.T, action DetectionAction) {
		t.Helper()
		withMCPPIIAction(t, action) // sets posture, nils engine, registers restore
		// #2820: a DB-backed engine that LOADS successfully with an empty policy
		// set. A nil-DB engine now errors on GetPolicies (couldn't-scan), which
		// the response plane fails CLOSED on — that would mask this test's real
		// intent (Indonesia checksum detector, engine-independent, still governs
		// NIK on a text-document tool).
		mockDB, mockSQL, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		t.Cleanup(func() { _ = mockDB.Close() })
		mockSQL.MatchExpectationsInOrder(false)
		// #3048: zero-system-set loads fail CLOSED — serve a benign
		// never-matching non-PII system row instead of an empty set.
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
		sharedpolicy.SetGlobalEngine(engine) // withMCPPIIAction's cleanup restores the original
		if !engine.IsTextDocumentTool(jiraTool) {
			t.Fatalf("%s must classify text-document — test would be vacuous", jiraTool)
		}
	}

	t.Run("redact still masks NIK", func(t *testing.T) {
		install(t, DetectionActionRedact)
		out := evaluateOutputPolicies(context.Background(), "t1", "u1", jiraTool, jiraTool,
			nil, validNIKResponse, nil, 0, false, true /* isGateway */)
		if out.RedactedMessage == "" {
			t.Fatal("NIK via a text-document tool must still redact")
		}
		if strings.Contains(out.RedactedMessage, "3174042506780001") {
			t.Errorf("raw NIK leaked through redaction: %q", out.RedactedMessage)
		}
	})

	t.Run("block still blocks NIK", func(t *testing.T) {
		install(t, DetectionActionBlock)
		out := evaluateOutputPolicies(context.Background(), "t1", "u1", jiraTool, jiraTool,
			nil, validNIKResponse, nil, 0, false, true /* isGateway */)
		if out.StaticResult == nil || !out.StaticResult.Blocked {
			t.Fatal("block posture must block a critical NIK even via a text-document tool")
		}
	})
}
