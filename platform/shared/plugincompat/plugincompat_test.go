// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package plugincompat

import "testing"

// TestPinnedToReleaseTrain makes a version bump a deliberate, reviewed edit in
// one place. It is the successor to the orchestrator-side pin test, which
// guarded only one of the two former copies.
func TestPinnedToReleaseTrain(t *testing.T) {
	wantMin := map[string]string{
		"openclaw": "2.4.0", "claude-code": "1.4.0", "cursor": "1.4.0",
		"codex": "1.4.0", "claude-desktop": "0.2.0",
	}
	wantRecommended := map[string]string{
		"openclaw": "2.8.6", "claude-code": "1.11.0", "cursor": "1.7.0",
		"codex": "1.7.0", "claude-desktop": "0.3.2",
	}
	for id, want := range wantMin {
		if got := MinVersions()[id]; got != want {
			t.Errorf("MinVersions()[%q] = %q; want %q", id, got, want)
		}
	}
	for id, want := range wantRecommended {
		if got := RecommendedVersions()[id]; got != want {
			t.Errorf("RecommendedVersions()[%q] = %q; want %q", id, got, want)
		}
	}
	if len(MinVersions()) != len(wantMin) || len(RecommendedVersions()) != len(wantRecommended) {
		t.Errorf("entry counts drifted: min=%d recommended=%d", len(MinVersions()), len(RecommendedVersions()))
	}
	if len(IDs()) != len(wantRecommended) {
		t.Errorf("IDs() returned %d ids, want %d", len(IDs()), len(wantRecommended))
	}
}

// TestCopyOfEmptyIsNotNil pins that an empty source yields {} and never null on
// the wire.
func TestCopyOfEmptyIsNotNil(t *testing.T) {
	got := copyOf(map[string]string{})
	if got == nil {
		t.Fatal("copyOf returned nil for an empty source; the JSON shape would change from {} to null")
	}
	if len(got) != 0 {
		t.Errorf("expected an empty map, got %d entries", len(got))
	}
}
