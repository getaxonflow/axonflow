// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Unit tests for the request-phase redaction helper (ADR-056 / #2563).
//
// These cover the deterministic guard branches that decide WHETHER the engine
// runs. The actual masking success path (engine returns a masked statement) is
// exercised end-to-end against a live, policy-seeded stack in
// runtime-e2e/2563_obligation_pep/ — the same division the rest of
// decision_handler_test.go uses for live-engine detection.

import (
	"context"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

func TestRedactInputStatement_EmptyStatement(t *testing.T) {
	out, did, _ := redactInputStatement(context.Background(), "tenant", "user", "gateway", "")
	if did || out != "" {
		t.Fatalf("empty statement: out=%q did=%v want (\"\", false)", out, did)
	}
}

func TestRedactInputStatement_NilEngine_NoRedaction(t *testing.T) {
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })

	out, did, evaluated := redactInputStatement(context.Background(), "tenant", "user", "gateway", "my id is 3174012509900001")
	if did || out != "" {
		t.Fatalf("nil engine must not redact: out=%q did=%v", out, did)
	}
	if evaluated {
		t.Fatal("nil engine must report evaluated=false so the PEP fails closed (#2563 B1)")
	}
}

func TestRequestRedactionDetectorFor(t *testing.T) {
	// Empty content-type defaults to the built-in text detector.
	if d, ok := requestRedactionDetectorFor(""); !ok || d.ContentType() != contentTypeText {
		t.Fatalf("empty content-type should resolve to text detector, got ok=%v", ok)
	}
	if d, ok := requestRedactionDetectorFor(contentTypeText); !ok || d == nil {
		t.Fatalf("text/plain detector must be registered")
	}
	// An unregistered (media) mime returns not-found so the endpoint fails closed.
	if _, ok := requestRedactionDetectorFor("image/png"); ok {
		t.Fatal("image/png must NOT have a detector yet (media is a future plug-in)")
	}
}

func TestRequestRedactionContentTypes_AdvertisesText(t *testing.T) {
	cts := requestRedactionContentTypes()
	found := false
	for _, c := range cts {
		if c == contentTypeText {
			found = true
		}
	}
	if !found {
		t.Fatalf("content types %v must advertise %s", cts, contentTypeText)
	}
}

// TestRegisterRequestRedactionDetector_PluggableSeam proves a media detector
// can be registered without any contract change — the addendum's requirement.
func TestRegisterRequestRedactionDetector_PluggableSeam(t *testing.T) {
	const mime = "image/test-only"
	if _, ok := requestRedactionDetectorFor(mime); ok {
		t.Fatal("precondition: mime should be unregistered")
	}
	RegisterRequestRedactionDetector(stubDetector{mime: mime})
	t.Cleanup(func() { delete(requestRedactionDetectors, mime) })
	d, ok := requestRedactionDetectorFor(mime)
	if !ok || d.ContentType() != mime {
		t.Fatalf("detector not registered via seam: ok=%v", ok)
	}
}

type stubDetector struct{ mime string }

func (s stubDetector) ContentType() string { return s.mime }
func (s stubDetector) Redact(ctx context.Context, in RedactionInput) RedactionOutput {
	return RedactionOutput{Redacted: false, Text: in.Text}
}

// TestIndonesiaFollowsPIIConvention guards the core #2563 finding now that the
// request-redaction path is policy-derived: redactInputStatement scopes via
// Session A's EnabledPIICategories (#2565), which keys on the `pii-*` naming
// convention. So NIK is auto-covered iff pii-indonesia follows that convention.
// (A's TestEnabledPIICategories owns the convention∩enabled behaviour itself.)
func TestIndonesiaFollowsPIIConvention(t *testing.T) {
	if !strings.HasPrefix(string(sharedpolicy.CategoryPIIIndonesia), "pii-") {
		t.Fatalf("CategoryPIIIndonesia=%q breaks the pii-* convention EnabledPIICategories keys on — NIK would be invisible on the redaction path (#2563)", sharedpolicy.CategoryPIIIndonesia)
	}
}
