// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package policy

import (
	"context"
	"sort"
	"testing"
)

// isPIIPolicyCategory is convention-driven (pii-* prefix, TEXT only). This pins
// the contract: every pii-* category is PII (so a future pii-* is auto-covered),
// media-pii is NOT (its detector is the orchestrator OCR subsystem, not the text
// engine), and non-PII categories are excluded.
func TestIsPIIPolicyCategory_Convention(t *testing.T) {
	pii := []PolicyCategory{
		CategoryPIIGlobal, CategoryPIIUS, CategoryPIIIndia,
		CategoryPIIEU, CategoryPIISingapore, CategoryPIIIndonesia,
		PolicyCategory("pii-future-locale"), // forward-compat: any pii-* is covered
	}
	for _, c := range pii {
		if !isPIIPolicyCategory(c) {
			t.Errorf("expected %q to be a PII category", c)
		}
	}
	notPII := []PolicyCategory{
		CategoryMediaPII, // OCR subsystem, not the text engine
		CategorySecuritySQLi, CategorySecurityDangerous,
		CategoryComplianceRBI, PolicyCategory("sensitive-data"), PolicyCategory(""),
	}
	for _, c := range notPII {
		if isPIIPolicyCategory(c) {
			t.Errorf("expected %q NOT to be a PII category", c)
		}
	}
}

// EnabledPIICategories derives the distinct PII categories from the enabled
// policies — the policy-derived coverage that auto-includes pii-indonesia and
// excludes non-PII / media-pii. Returns nil when none are enabled (the
// load-bearing empty-set guard: callers must skip rather than evaluate ALL).
func TestEnabledPIICategories(t *testing.T) {
	policies := []CompiledPolicy{
		{PolicyID: "p_id", Category: CategoryPIIIndonesia, Phase: PhaseBoth, Enabled: true},
		{PolicyID: "p_us", Category: CategoryPIIUS, Phase: PhaseBoth, Enabled: true},
		{PolicyID: "p_g1", Category: CategoryPIIGlobal, Phase: PhaseBoth, Enabled: true},
		{PolicyID: "p_g2", Category: CategoryPIIGlobal, Phase: PhaseBoth, Enabled: true},      // dup category → distinct
		{PolicyID: "p_sqli", Category: CategorySecuritySQLi, Phase: PhaseBoth, Enabled: true}, // non-PII → excluded
		{PolicyID: "p_media", Category: CategoryMediaPII, Phase: PhaseBoth, Enabled: true},    // media → excluded
	}
	engine := createTestEngine(policies)
	defer engine.Stop()

	got := engine.EnabledPIICategories(context.Background(), "test-tenant", nil, PhaseResponse)
	gotStr := make([]string, 0, len(got))
	for _, c := range got {
		gotStr = append(gotStr, string(c))
	}
	sort.Strings(gotStr)
	want := []string{"pii-global", "pii-indonesia", "pii-us"} // distinct PII only; no sqli, no media
	if len(gotStr) != len(want) {
		t.Fatalf("derived categories = %v, want %v", gotStr, want)
	}
	for i := range want {
		if gotStr[i] != want[i] {
			t.Fatalf("derived categories = %v, want %v", gotStr, want)
		}
	}

	// Empty-set guard: a tenant with no enabled PII policies returns nil (NOT an
	// empty slice that EvaluateResponse would treat as "all policies").
	if got := engine.EnabledPIICategories(context.Background(), "no-such-tenant", nil, PhaseResponse); got != nil {
		t.Fatalf("expected nil for a tenant with no PII policies, got %v", got)
	}
}
