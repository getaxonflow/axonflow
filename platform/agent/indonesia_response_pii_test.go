// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// withMCPPIIAction pins the cached MCP detection config's PIIAction - the slot
// an organization's recorded pii override fills; "" = no override - for the
// duration of a test (isolated; restored in t.Cleanup). An organization with no
// recorded override resolves to the pinned slot. The shared engine is the
// migrated database's, whose shipped rows match nothing these tests send, so
// the Indonesia response step is the only detector that acts.
func withMCPPIIAction(t *testing.T, action DetectionAction) {
	t.Helper()
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: action}
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
	})
}

const validNIKResponse = "Pelanggan NIK 3174042506780001 terdaftar"

// Under a pii=warn/log override the Indonesia response step must DETECT but NOT
// modify content — parity with the static engine + orchestrator, which never
// mutate on warn/log. (Master R3 round-2 required fix.) With NO override the
// code-backed detector has no action to take either (#3961), so it too detects
// and neither masks nor blocks.
func TestEvaluateOutputPolicies_IndonesiaWarnNoMask(t *testing.T) {
	for _, action := range []DetectionAction{DetectionActionWarn, DetectionActionLog, ""} {
		name := string(action)
		if action == "" {
			name = "no override"
		}
		t.Run(name, func(t *testing.T) {
			withMCPPIIAction(t, action)
			out := evaluateOutputPolicies(responseRouteContext("o1"), "t1", "o1", "u1", "gw.test", "gw.test",
				nil, validNIKResponse, nil, 0, false, true /* isGateway */)
			if out.StaticResult != nil && out.StaticResult.Blocked {
				t.Errorf("%s must not block", name)
			}
			if out.RedactedMessage != "" {
				t.Errorf("%s must NOT mask (detect-don't-modify); got RedactedMessage=%q", name, out.RedactedMessage)
			}
			if out.WasRedacted() {
				t.Errorf("%s must not report a redaction", name)
			}
		})
	}
}

// Under a pii=redact override the Indonesia response step masks the NIK.
func TestEvaluateOutputPolicies_IndonesiaRedactMasks(t *testing.T) {
	withMCPPIIAction(t, DetectionActionRedact)
	out := evaluateOutputPolicies(responseRouteContext("o1"), "t1", "o1", "u1", "gw.test", "gw.test",
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
	if out.StaticResult != nil && out.StaticResult.Blocked {
		t.Errorf("a masked response is released, not withheld; got %+v", out.StaticResult)
	}
}

// Under a pii=block override a critical NIK is blocked (not masked) on the response.
func TestEvaluateOutputPolicies_IndonesiaBlock(t *testing.T) {
	withMCPPIIAction(t, DetectionActionBlock)
	out := evaluateOutputPolicies(responseRouteContext("o1"), "t1", "o1", "u1", "gw.test", "gw.test",
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
// This is the masker the MCP request pass's checksum validator step
// (maskIndonesiaBeforeTheRequestPass, #2571) masks with under the organization's
// pii=redact posture. The static engine does NOT carry checksum NIK, so this
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
// leak. The shared engine's capability classifier positively classifies the
// identity as text-document; redact/block per pii override must behave exactly
// as for any other identity.
func TestEvaluateOutputPolicies_IndonesiaNIKUnaffectedByCapabilityScope(t *testing.T) {
	const jiraTool = "claude_code.mcp__atlassian__getJiraIssue"

	install := func(t *testing.T, action DetectionAction) {
		t.Helper()
		withMCPPIIAction(t, action)
		if !sharedpolicy.GetGlobalEngine().IsTextDocumentTool(jiraTool) {
			t.Fatalf("%s must classify text-document — test would be vacuous", jiraTool)
		}
	}

	t.Run("redact still masks NIK", func(t *testing.T) {
		install(t, DetectionActionRedact)
		out := evaluateOutputPolicies(responseRouteContext("o1"), "t1", "o1", "u1", jiraTool, jiraTool,
			nil, validNIKResponse, nil, 0, false, true /* isGateway */)
		if out.RedactedMessage == "" {
			t.Fatal("NIK via a text-document tool must still redact")
		}
		if strings.Contains(out.RedactedMessage, "3174042506780001") {
			t.Errorf("raw NIK leaked through redaction: %q", out.RedactedMessage)
		}
		if out.StaticResult != nil && out.StaticResult.Blocked {
			t.Errorf("a masked response is released, not withheld; got %+v", out.StaticResult)
		}
	})

	t.Run("block still blocks NIK", func(t *testing.T) {
		install(t, DetectionActionBlock)
		out := evaluateOutputPolicies(responseRouteContext("o1"), "t1", "o1", "u1", jiraTool, jiraTool,
			nil, validNIKResponse, nil, 0, false, true /* isGateway */)
		if out.StaticResult == nil || !out.StaticResult.Blocked {
			t.Fatal("a pii=block override must block a critical NIK even via a text-document tool")
		}
	})
}
