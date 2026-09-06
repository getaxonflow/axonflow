// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"axonflow/platform/shared/plugincompat"
	"axonflow/platform/shared/sdkcompat"
	"os"
	"strings"
	"testing"

	"axonflow/platform/shared/version"
)

// TestPluginCompatComesFromTheSharedSourceOfTruth pins that this plane serves
// exactly what platform/shared/plugincompat holds.
//
// Successor to TestPluginCompatibilityPinnedToReleaseTrain, which hardcoded the
// values here. That was right while the orchestrator held its own copy — it is
// the test that caught one-sided drift — but now that both planes read one map,
// a second hardcoded list would be a third place to forget on a bump. The values
// are pinned once, in plugincompat's own test; this asserts the wiring.
func TestPluginCompatComesFromTheSharedSourceOfTruth(t *testing.T) {
	got := getPluginCompatibility()

	for name, pair := range map[string][2]map[string]string{
		"MinPluginVersion":         {got.MinPluginVersion, plugincompat.MinVersions()},
		"RecommendedPluginVersion": {got.RecommendedPluginVersion, plugincompat.RecommendedVersions()},
	} {
		served, canonical := pair[0], pair[1]
		if len(canonical) == 0 {
			t.Fatalf("%s: plugincompat returned an empty map — comparing two empty maps would pass", name)
		}
		if len(served) != len(canonical) {
			t.Errorf("%s: served %d entries, plugincompat holds %d", name, len(served), len(canonical))
		}
		for id, want := range canonical {
			if served[id] != want {
				t.Errorf("%s[%q] = %q; plugincompat holds %q", name, id, served[id], want)
			}
		}
		for id := range served {
			if _, ok := canonical[id]; !ok {
				t.Errorf("%s has key %q that plugincompat does not", name, id)
			}
		}
	}
}

// TestSDKFloorCommentAttribution guards the historical-attribution narrative
// for the SDK floors. The SDK major bump v7 -> v8 landed during the v7.9.0
// release-train (#2016 + #2102), not the v8.0.0 platform bump (#2308). PR #2311
// fixed the equivalent plugin-floor narrative; this test stops the SDK-floor
// narrative drifting back to the wrong framing on a future edit.
//
// It reads platform/shared/sdkcompat, not this package: the two duplicated map
// literals were replaced by that single source of truth (#3712), and the
// narrative moved with the values it explains. Pointing this guard at the old
// location would have meant retiring it because its subject moved -- which is
// exactly how the attribution was lost the first two times. The sibling plane
// has the mirror of this test and both now read the same file.
func TestSDKFloorCommentAttribution(t *testing.T) {
	const narrativePath = "../shared/sdkcompat/sdkcompat.go"
	src, err := os.ReadFile(narrativePath)
	if err != nil {
		t.Fatalf("read %s: %v", narrativePath, err)
	}
	// Isolate the doc comment ATTACHED TO the floor map. The predecessor of this
	// test read only getSDKCompatibility()'s body, which bound the citation to
	// the values it explains; searching the whole file would keep both plane
	// guards green with the sentence anywhere in it - including in a paragraph
	// about something else - which is how an attribution goes missing without
	// any test noticing.
	whole := string(src)
	s, isolated := sdkFloorDocBlock(whole)
	if !isolated {
		t.Fatalf("%s: could not isolate the doc comment attached to the floor map; this guard is about "+
			"that comment and must not silently fall back to searching the whole file", narrativePath)
	}
	// The isolation has to be observable HERE, not only in the helper's own
	// test: a mutant that bypasses the helper (`s := whole`) leaves that test
	// passing, because it exercises the predicate rather than this call site.
	// `package sdkcompat` is always outside the block by construction, so its
	// absence is a property of the isolation and not of the text.
	if strings.Contains(s, "package sdkcompat") || !strings.Contains(s, "minVersion is the floor") {
		t.Fatalf("%s: the text being searched is not the floor map's doc block - it reaches the package "+
			"clause, so this guard is searching the whole file and no longer binds the citation to the "+
			"values it explains", narrativePath)
	}

	// Required attribution: the v7.9.0 release-train is the historically
	// correct location of the SDK v7 -> v8 floor bump.
	if !strings.Contains(s, "v7.9.0 release-train") {
		t.Errorf("%s must cite the v7.9.0 release-train as the location of the SDK v7->v8 floor bump (per axonflow-docs/docs/releases/v7-9-0.md and PR #2016+#2102)", narrativePath)
	}
	// Required PR citation: an explicit #2016 removes ambiguity about WHICH PR
	// landed the floor values.
	if !strings.Contains(s, "#2016") {
		t.Errorf("%s must cite #2016 (the pre-emptive SDK floor bump PR)", narrativePath)
	}
	// Banned attribution: the old comment claimed the bump happened with "the
	// v8.0.0 release-train", which is historically wrong -- v8.0.0 is the
	// PLATFORM bump (#2308) and did NOT change the SDK floor.
	// The banned phrase is checked over the WHOLE file, deliberately, while the
	// required citations are checked in the block. The two scopes answer
	// different questions: a citation has to sit WITH the values it explains,
	// or it drifts away from them; a historically false sentence is wrong
	// anywhere in the file, and the file's own comment tells the next editor
	// not to quote it even to forbid it. Narrowing this to the block would make
	// that comment false, and it is the sentence a reviewer would cite as
	// evidence the file is protected.
	if strings.Contains(whole, "With the v8.0.0 release-train") {
		t.Errorf("%s must not attribute the SDK v7->v8 floor bump to the v8.0.0 platform release-train anywhere in the file; it landed during v7.9.0 (#2016 + #2102)", narrativePath)
	}
}

// TestSDKFloorDocIsolationRejectsTextOutsideTheBlock is the survivor for the
// isolation above. Without it, reverting `s := whole[i:j]` to `s := whole`
// leaves every assertion passing, because the citations ARE in the file - just
// not necessarily beside the values. That revert is a plausible "simplify", and
// nothing else would notice it.
//
// Mirrored in the sibling plane for the same reason the guards themselves are.
func TestSDKFloorDocIsolationRejectsTextOutsideTheBlock(t *testing.T) {
	const src = `package sdkcompat

// somethingElse is documented here, and this paragraph cites the v7.9.0
// release-train and #2016 while explaining something unrelated.
var somethingElse = 1

// minVersion is the floor each client must meet.
var minVersion = map[string]string{
	"go": "8.0.0",
}
`
	block, ok := sdkFloorDocBlock(src)
	if !ok {
		t.Fatal("the isolator could not find the floor doc block in a source that contains it")
	}
	if strings.Contains(block, "#2016") || strings.Contains(block, "v7.9.0 release-train") {
		t.Errorf("the isolated block reaches text that belongs to another declaration:\n%s", block)
	}
	if !strings.Contains(block, "minVersion is the floor") {
		t.Errorf("the isolated block does not contain the floor map's own doc comment:\n%s", block)
	}
	// And it must refuse rather than silently return the whole file.
	if _, ok := sdkFloorDocBlock("package p\n\nvar x = 1\n"); ok {
		t.Error("the isolator reported success on a source with no floor map; a failed isolation must fail loudly, not fall back to the whole file")
	}
}

// sdkFloorDocBlock returns the doc comment attached to sdkcompat's floor map.
func sdkFloorDocBlock(whole string) (string, bool) {
	const blockStart = "// minVersion is the floor"
	const blockEnd = "var minVersion = map[string]string{"
	i, j := strings.Index(whole, blockStart), strings.Index(whole, blockEnd)
	if i == -1 || j == -1 || j <= i {
		return "", false
	}
	return whole[i:j], true
}

// TestSDKCompatComesFromTheSharedSourceOfTruth pins that this plane serves
// exactly what platform/shared/sdkcompat holds.
//
// Successor to the pair of guards #3712 retired: an orchestrator-side test that
// hardcoded the values beside the literal, and an agent-side source-parity test
// that parsed both plane files and compared their literals. Neither could see
// the shape where both copies are equal and both are stale, which is the shape
// that actually shipped for the plugin maps. The values are pinned once, in
// sdkcompat's own test; this asserts the wiring.
func TestSDKCompatComesFromTheSharedSourceOfTruth(t *testing.T) {
	got := getSDKCompatibility()

	for name, pair := range map[string][2]map[string]string{
		"MinSDKVersion":         {got.MinSDKVersion, sdkcompat.MinVersions()},
		"RecommendedSDKVersion": {got.RecommendedSDKVersion, sdkcompat.RecommendedVersions()},
	} {
		served, canonical := pair[0], pair[1]
		if len(canonical) == 0 {
			t.Fatalf("%s: sdkcompat returned an empty map -- comparing two empty maps would pass", name)
		}
		if len(served) != len(canonical) {
			t.Errorf("%s: served %d entries, sdkcompat holds %d", name, len(served), len(canonical))
		}
		for id, want := range canonical {
			if served[id] != want {
				t.Errorf("%s[%q] = %q; sdkcompat holds %q", name, id, served[id], want)
			}
		}
		for id := range served {
			if _, ok := canonical[id]; !ok {
				t.Errorf("%s has key %q that sdkcompat does not", name, id)
			}
		}
	}
}

// TestPluginFloorCommentAttribution guards the historical-attribution narrative
// for the plugin floors. The plugin v1.4.0 / v2.4.0 floor + recommended-version
// bump landed during the v7.9.0 release-train (#2102 on 2026-05-09), not the
// v8.0.0 platform bump (#2308). PR #2311 fixed the MinPluginVersion narrative;
// the structurally-identical RecommendedPluginVersion narrative directly below it
// was missed twice. This test catches both at once.
//
// It reads platform/shared/plugincompat, not this package: the two duplicated map
// literals were replaced by that single source of truth, and the narrative moved
// with the values it explains. Pointing this guard at the old location would have
// meant retiring it because its subject moved — which is exactly how the
// attribution was lost the first two times. The orchestrator has the mirror of
// this test and both now read the same file.
func TestPluginFloorCommentAttribution(t *testing.T) {
	const narrativePath = "../shared/plugincompat/plugincompat.go"
	src, err := os.ReadFile(narrativePath)
	if err != nil {
		t.Fatalf("read %s: %v", narrativePath, err)
	}
	// Block-scoped for the same reason the SDK guard above is (#3712, R3): a
	// file-wide search is satisfied by the citation sitting anywhere, including
	// in a paragraph about something else, so it stops binding the attribution
	// to the values it explains. This twin carried that defect while the SDK
	// half was being fixed forty lines above it - the fix had been a census of
	// the named instance rather than of the class.
	pluginBlock, isolatedPlugin := pluginFloorDocBlock(string(src))
	if !isolatedPlugin {
		t.Fatalf("%s: could not isolate the doc comment attached to the plugin floor map; this guard is "+
			"about that comment and must not silently fall back to searching the whole file", narrativePath)
	}

	// Required PR citation: #2102 (the v7.9.0 release-train PR that
	// landed both the plugin floor + recommended bump) must appear at
	// least twice — once in MinPluginVersion, once in
	// RecommendedPluginVersion.
	prCount := strings.Count(pluginBlock, "#2102")
	if prCount < 2 {
		t.Errorf("getPluginCompatibility() must cite #2102 in BOTH the MinPluginVersion and RecommendedPluginVersion comment blocks (found %d, want ≥2). Got:\n%s", prCount, pluginBlock)
	}

	if strings.Contains(pluginBlock, "alongside the SDK v8.0.0 release-train") {
		t.Errorf("getPluginCompatibility() comment must NOT say 'alongside the SDK v8.0.0 release-train' — that is historically false (plugin tags shipped at v7.9.0 release-train, #2102). Got:\n%s", pluginBlock)
	}
}

// TestGetPlatformVersionBakedWinsOverEnv is the #2662 anti-spoof guard at the
// orchestrator /health reader level: a version baked into the binary must win
// over a conflicting AXONFLOW_VERSION env var, so /health reports the true
// shipped binary version and cannot be overridden at runtime.
func TestGetPlatformVersionBakedWinsOverEnv(t *testing.T) {
	prev := version.Version
	version.Version = "8.7.0"
	t.Cleanup(func() { version.Version = prev })
	t.Setenv("AXONFLOW_VERSION", "1.2.3-spoofed")

	if got := getPlatformVersion(); got != "8.7.0" {
		t.Errorf("getPlatformVersion() = %q, want baked 8.7.0 (env must NOT win)", got)
	}
}

// TestGetPlatformVersionEnvFallbackWhenUnbaked covers the dev path: with no
// baked version, the env var is used; an invalid env value falls to the default.
func TestGetPlatformVersionEnvFallbackWhenUnbaked(t *testing.T) {
	prev := version.Version
	version.Version = ""
	t.Cleanup(func() { version.Version = prev })

	t.Setenv("AXONFLOW_VERSION", "4.8.0")
	if got := getPlatformVersion(); got != "4.8.0" {
		t.Errorf("getPlatformVersion() = %q, want env fallback 4.8.0", got)
	}

	t.Setenv("AXONFLOW_VERSION", "not-a-semver")
	if got := getPlatformVersion(); got != "1.0.0" {
		t.Errorf("getPlatformVersion() = %q, want default 1.0.0 for invalid env", got)
	}
}

// pluginFloorDocBlock returns the doc comment attached to plugincompat's floor
// map, plus the recommended map's own doc comment - the guard below requires the
// #2102 attribution in BOTH, because the structurally identical recommended
// block was the one missed twice.
func pluginFloorDocBlock(whole string) (string, bool) {
	const minStart = "// minVersion is the floor"
	const recEnd = "var recommendedVersion = map[string]string{"
	i, j := strings.Index(whole, minStart), strings.Index(whole, recEnd)
	if i == -1 || j == -1 || j <= i {
		return "", false
	}
	return whole[i:j], true
}
