// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// BuildActionOverrides must map pii-indonesia to PII_ACTION like every other
// text PII category — otherwise NIK keeps its DB action_response (redact) and
// won't BLOCK under PII_ACTION=block (the partner-critical hard-deny). media-pii
// must NOT be mapped (no agent text-engine match to apply it to).
func TestBuildActionOverrides_IndonesiaHonorsPIIAction(t *testing.T) {
	cfg := &ModeDetectionConfig{PIIAction: DetectionActionBlock}
	ov := cfg.BuildActionOverrides()

	want := cfg.PIIAction.ToPolicyAction()
	for _, cat := range []sharedpolicy.PolicyCategory{
		sharedpolicy.CategoryPIIGlobal,
		sharedpolicy.CategoryPIIUS,
		sharedpolicy.CategoryPIIIndia,
		sharedpolicy.CategoryPIIEU,
		sharedpolicy.CategoryPIISingapore,
		sharedpolicy.CategoryPIIIndonesia, // the fix
	} {
		got, ok := ov[cat]
		if !ok {
			t.Errorf("BuildActionOverrides missing PII category %q (PII_ACTION would not apply)", cat)
			continue
		}
		if got != want {
			t.Errorf("override[%q] = %q, want %q (PII_ACTION lever)", cat, got, want)
		}
	}

	// media-pii is intentionally NOT mapped — it's the orchestrator OCR
	// subsystem; mapping it here would falsely imply agent-side media coverage.
	if _, ok := ov[sharedpolicy.CategoryMediaPII]; ok {
		t.Error("BuildActionOverrides must NOT map media-pii (no agent text-engine match)")
	}
}
