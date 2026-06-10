// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent"
)

// Per-org posture on the ORCHESTRATOR response plane (#2612).
//
// These drive the live ProcessResponse path with the shared engine disabled, so
// only the (DB-free) Indonesia checksum-NIK governance runs — deterministic. The
// deployment-global PII_ACTION is held at ONE value while two orgs get DIFFERENT
// outcomes purely from their per-org override row. Reverting the per-org
// skipRedaction layering in ProcessResponse turns these red.

const perOrgNIK = orchValidNIK // checksum-valid NIK, shared with the Indonesia tests

func nikContent() *LLMResponse {
	return &LLMResponse{Content: "Customer NIK is " + perOrgNIK + " on file"}
}

// Direction 1 (the leak the brief cares about): deployment-global is warn
// (detect-don't-modify), but an org that overrides PII→redact must have its NIK
// MASKED. Pre-fix, the global-warn skipRedaction reverts the masking → the org's
// NIK leaks. RED ON REVERT.
func TestProcessResponse_PerOrgRedact_OverridesGlobalWarn(t *testing.T) {
	t.Setenv("PII_ACTION", "warn")
	rp := withLegacyProcessor(t)
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]agent.DetectionAction{
			"org-redact": {agent.DetectionCategoryPII: agent.DetectionActionRedact},
		},
	}, time.Minute)

	out, info := rp.ProcessResponse(context.Background(), UserContext{OrgID: "org-redact"}, nikContent())
	if strings.Contains(fmt.Sprint(out), perOrgNIK) {
		t.Fatalf("org-redact (override) must MASK the NIK even though global=warn; leaked: %v", out)
	}
	if info == nil || !info.HasRedactions {
		t.Fatalf("redaction not recorded for org-redact: %+v", info)
	}

	// Control: an org WITHOUT an override under the same global=warn keeps the
	// deployment behavior (detect-don't-modify) → NIK stays.
	outDefault, _ := rp.ProcessResponse(context.Background(), UserContext{OrgID: "org-default"}, nikContent())
	if !strings.Contains(fmt.Sprint(outDefault), perOrgNIK) {
		t.Fatalf("org-default must follow global=warn (no modify); NIK was masked: %v", outDefault)
	}
}

// Direction 2: deployment-global is redact, but an org that overrides PII→warn
// must NOT have its content modified (detect-don't-modify honored per-org).
// Pre-fix, the global-redact skipRedaction=false keeps the masking → the org's
// warn posture is ignored. RED ON REVERT.
func TestProcessResponse_PerOrgWarn_OverridesGlobalRedact(t *testing.T) {
	t.Setenv("PII_ACTION", "redact")
	rp := withLegacyProcessor(t)
	installTestOverrideCache(t, &fakeOverrideReader{
		data: map[string]map[string]agent.DetectionAction{
			"org-warn": {agent.DetectionCategoryPII: agent.DetectionActionWarn},
		},
	}, time.Minute)

	out, _ := rp.ProcessResponse(context.Background(), UserContext{OrgID: "org-warn"}, nikContent())
	if !strings.Contains(fmt.Sprint(out), perOrgNIK) {
		t.Fatalf("org-warn (override) must NOT modify content even though global=redact; NIK masked: %v", out)
	}

	// Control: an org WITHOUT an override under global=redact gets the NIK masked.
	outDefault, info := rp.ProcessResponse(context.Background(), UserContext{OrgID: "org-default"}, nikContent())
	if strings.Contains(fmt.Sprint(outDefault), perOrgNIK) {
		t.Fatalf("org-default must follow global=redact; NIK leaked: %v", outDefault)
	}
	if info == nil || !info.HasRedactions {
		t.Fatalf("redaction not recorded for org-default: %+v", info)
	}
}

// Byte-identical guard: with NO override cache wired (community / no-DB), the
// response plane behaves exactly as the deployment-global PII_ACTION dictates —
// no per-org machinery changes the global-only outcome.
func TestProcessResponse_NoCache_GlobalUnchanged(t *testing.T) {
	ResetDetectionOverrideCacheForTest()

	t.Run("global warn → not modified", func(t *testing.T) {
		t.Setenv("PII_ACTION", "warn")
		rp := withLegacyProcessor(t)
		out, _ := rp.ProcessResponse(context.Background(), UserContext{OrgID: "any-org"}, nikContent())
		if !strings.Contains(fmt.Sprint(out), perOrgNIK) {
			t.Fatalf("global warn (no cache) must not modify; NIK masked: %v", out)
		}
	})
	t.Run("global redact → masked", func(t *testing.T) {
		t.Setenv("PII_ACTION", "redact")
		rp := withLegacyProcessor(t)
		out, info := rp.ProcessResponse(context.Background(), UserContext{OrgID: "any-org"}, nikContent())
		if strings.Contains(fmt.Sprint(out), perOrgNIK) {
			t.Fatalf("global redact (no cache) must mask; NIK leaked: %v", out)
		}
		if info == nil || !info.HasRedactions {
			t.Fatalf("redaction not recorded: %+v", info)
		}
	})
}
