// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

const orchValidNIK = "3174042506780001" // checksum-valid (shared with 2478 + agent #2565)

// withLegacyProcessor returns a ResponseProcessor with the shared engine
// disabled (global engine nil'd) so the Indonesia response step is exercised
// without a DB-backed shared engine.
func withLegacyProcessor(t *testing.T) *ResponseProcessor {
	t.Helper()
	orig := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(orig) })
	return NewResponseProcessor()
}

// #2566: NIK must be governed on the orchestrator/LLM-gateway response path. The
// shared engine + EnhancedPIIDetector have no NIK checksum detector, so the EE
// Indonesia detector must run here. Under redact, the NIK is masked.
func TestProcessResponse_IndonesiaNIKRedacted(t *testing.T) {
	t.Setenv("PII_ACTION", "redact")
	rp := withLegacyProcessor(t)

	out, info := rp.ProcessResponse(context.Background(), UserContext{TenantID: "t1"},
		&LLMResponse{Content: "Customer NIK is " + orchValidNIK + " on file"})

	outStr := fmt.Sprint(out)
	if strings.Contains(outStr, orchValidNIK) {
		t.Fatalf("NIK leaked on the orchestrator response path: %q", outStr)
	}
	if info == nil || !info.HasRedactions {
		t.Fatalf("redaction not recorded in RedactionInfo: %+v", info)
	}
}

// Under warn/log the orchestrator must detect-don't-modify (parity with the
// agent fix). The NIK stays in the returned content.
func TestProcessResponse_IndonesiaNIKWarnNoRedact(t *testing.T) {
	for _, action := range []string{"warn", "log"} {
		t.Run(action, func(t *testing.T) {
			t.Setenv("PII_ACTION", action)
			rp := withLegacyProcessor(t)

			out, _ := rp.ProcessResponse(context.Background(), UserContext{TenantID: "t1"},
				&LLMResponse{Content: "Customer NIK is " + orchValidNIK + " on file"})

			if !strings.Contains(fmt.Sprint(out), orchValidNIK) {
				t.Errorf("%s must NOT modify the response (detect-don't-modify); NIK was masked", action)
			}
		})
	}
}

// Negative control: clean text (no Indonesia PII) must pass through unchanged
// with no redaction — the Indonesia step must not over-mask.
func TestProcessResponse_CleanTextNoRedact(t *testing.T) {
	t.Setenv("PII_ACTION", "redact")
	rp := withLegacyProcessor(t)
	const clean = "Favorite color is blue and the order status is active"
	out, info := rp.ProcessResponse(context.Background(), UserContext{TenantID: "t1"},
		&LLMResponse{Content: clean})
	if !strings.Contains(fmt.Sprint(out), "blue") {
		t.Errorf("clean text was altered: %v", out)
	}
	if info != nil && info.HasRedactions {
		t.Errorf("clean text must not report redactions: %+v", info)
	}
}

// withSharedEngineProcessor returns a ResponseProcessor backed by a real shared
// engine with an empty cache (nil DB) — it returns response content UNCHANGED
// (no redaction plans). This is the production path, and the one where the input
// to the Indonesia step aliases the caller's original responseData. Regression
// surface for the in-place-mutation aliasing bug.
func withSharedEngineProcessor(t *testing.T) *ResponseProcessor {
	t.Helper()
	eng := sharedpolicy.NewUnifiedPolicyEngine(nil, sharedpolicy.DefaultEngineConfig(), nil)
	orig := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(eng)
	t.Cleanup(func() {
		sharedpolicy.SetGlobalEngine(orig)
		eng.Stop()
	})
	rp := NewResponseProcessor()
	if !rp.IsUsingSharedEngine() {
		t.Fatal("expected shared-engine path to be active")
	}
	return rp
}

// Regression lock for the round-1 HIGH: under warn, a JSON-OBJECT response on the
// SHARED-ENGINE path must be returned UNMODIFIED (detect-don't-modify). Pre-fix,
// maskIndonesiaPIIDeep mutated the map in place, which aliased the original that
// the skipRedaction revert restores → NIK was silently masked under warn. This
// test would FAIL pre-fix.
func TestProcessResponse_SharedEngineJSONObject_WarnNoMutate(t *testing.T) {
	t.Setenv("PII_ACTION", "warn")
	rp := withSharedEngineProcessor(t)

	out, _ := rp.ProcessResponse(context.Background(), UserContext{TenantID: "t1"},
		&LLMResponse{Content: `{"answer":"NIK ` + orchValidNIK + `"}`})

	if !strings.Contains(fmt.Sprint(out), orchValidNIK) {
		t.Fatalf("warn must NOT mutate a JSON-object response on the shared-engine path (aliasing regression); got %v", out)
	}
}

// Companion: under redact, the JSON-object NIK IS masked on the shared-engine path.
func TestProcessResponse_SharedEngineJSONObject_RedactMasks(t *testing.T) {
	t.Setenv("PII_ACTION", "redact")
	rp := withSharedEngineProcessor(t)

	out, info := rp.ProcessResponse(context.Background(), UserContext{TenantID: "t1"},
		&LLMResponse{Content: `{"answer":"NIK ` + orchValidNIK + `"}`})

	if strings.Contains(fmt.Sprint(out), orchValidNIK) {
		t.Fatalf("redact must mask the JSON-object NIK on the shared-engine path; got %v", out)
	}
	if info == nil || !info.HasRedactions {
		t.Fatalf("redaction not recorded: %+v", info)
	}
}

// maskIndonesiaPIIDeep masks string leaves recursively across JSON shapes
// (object + array), not just top-level strings.
func TestMaskIndonesiaPIIDeep_Nested(t *testing.T) {
	d := getOrchestratorIndonesiaDetector()
	if d == nil {
		t.Skip("Indonesia detector disabled")
	}
	in := map[string]interface{}{
		"customer": map[string]interface{}{"nik": "NIK " + orchValidNIK},
		"notes":    []interface{}{"clean note", "another " + orchValidNIK},
		"count":    42, // non-string leaf untouched
	}
	out, types := maskIndonesiaPIIDeep(d, in)
	if len(types) == 0 {
		t.Fatal("expected detected types in nested structure")
	}
	if strings.Contains(fmt.Sprint(out), orchValidNIK) {
		t.Errorf("nested NIK not fully masked: %v", out)
	}
	// Non-string leaf preserved.
	if m, ok := out.(map[string]interface{}); !ok || m["count"] != 42 {
		t.Error("non-string leaf must be preserved")
	}
}
