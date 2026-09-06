// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/plugincompat"
	"axonflow/platform/shared/sdkcompat"
)

func TestGetCapabilities(t *testing.T) {
	caps := getCapabilities()
	if len(caps) == 0 {
		t.Fatal("expected non-empty capabilities list")
	}

	for i, cap := range caps {
		if cap.Name == "" {
			t.Errorf("capability %d has empty name", i)
		}
		if cap.Since == "" {
			t.Errorf("capability %d (%s) has empty since", i, cap.Name)
		}
		if cap.Description == "" {
			t.Errorf("capability %d (%s) has empty description", i, cap.Name)
		}
	}
}

func TestGetCapabilitiesContainsVersionDiscovery(t *testing.T) {
	caps := getCapabilities()
	found := false
	for _, cap := range caps {
		if cap.Name == "version_discovery" {
			found = true
			if cap.Since != "4.8.0" {
				t.Errorf("version_discovery since = %q, want %q", cap.Since, "4.8.0")
			}
			break
		}
	}
	if !found {
		t.Error("expected version_discovery capability to be present")
	}
}

func TestGetSDKCompatibility(t *testing.T) {
	compat := getSDKCompatibility()
	if len(compat.MinSDKVersion) == 0 {
		t.Error("expected non-empty MinSDKVersion")
	}
	if len(compat.RecommendedSDKVersion) == 0 {
		t.Error("expected non-empty RecommendedSDKVersion")
	}
	for _, lang := range []string{"python", "typescript", "go", "java", "rust"} {
		if compat.MinSDKVersion[lang] == "" {
			t.Errorf("expected MinSDKVersion for %q", lang)
		}
		if compat.RecommendedSDKVersion[lang] == "" {
			t.Errorf("expected RecommendedSDKVersion for %q", lang)
		}
	}
}

func TestGetPluginCompatibility(t *testing.T) {
	compat := getPluginCompatibility()
	if len(compat.MinPluginVersion) == 0 {
		t.Error("expected non-empty MinPluginVersion")
	}
	if len(compat.RecommendedPluginVersion) == 0 {
		t.Error("expected non-empty RecommendedPluginVersion")
	}
	// Every plugin id the agent's integration_activation.go knows about
	// must have an entry here. A future plugin id added there without
	// mirrored entries here trips this test.
	for _, id := range []string{"openclaw", "claude-code", "cursor", "codex", "claude-desktop"} {
		if compat.MinPluginVersion[id] == "" {
			t.Errorf("expected MinPluginVersion for %q", id)
		}
		if compat.RecommendedPluginVersion[id] == "" {
			t.Errorf("expected RecommendedPluginVersion for %q", id)
		}
	}
}

// TestPluginCompatibilityKeysMatchKnownIntegrations is the alignment
// guard between capabilities.go and integration_activation.go. The two
// must use the same canonical plugin IDs — if integration_activation.go
// uses "claude-code" and capabilities.go uses "claude", a plugin querying
// /health for its own ID gets one answer in one place and another answer
// elsewhere. This test fails if the key sets drift apart in either
// direction.
func TestPluginCompatibilityKeysMatchKnownIntegrations(t *testing.T) {
	compat := getPluginCompatibility()

	knownIDs := make(map[string]bool, len(knownIntegrations))
	for _, k := range knownIntegrations {
		knownIDs[k.ID] = true
	}

	for id := range compat.MinPluginVersion {
		if !knownIDs[id] {
			t.Errorf("MinPluginVersion has key %q that's not in knownIntegrations", id)
		}
	}
	for id := range compat.RecommendedPluginVersion {
		if !knownIDs[id] {
			t.Errorf("RecommendedPluginVersion has key %q that's not in knownIntegrations", id)
		}
	}
	for id := range knownIDs {
		if compat.MinPluginVersion[id] == "" {
			t.Errorf("knownIntegrations id %q missing from MinPluginVersion", id)
		}
		if compat.RecommendedPluginVersion[id] == "" {
			t.Errorf("knownIntegrations id %q missing from RecommendedPluginVersion", id)
		}
	}

	// Both inner maps must have the same key set as each other (a min
	// without a recommended or vice versa is structural drift).
	if len(compat.MinPluginVersion) != len(compat.RecommendedPluginVersion) {
		t.Errorf(
			"MinPluginVersion has %d keys, RecommendedPluginVersion has %d — "+
				"every plugin must have both a min and a recommended entry",
			len(compat.MinPluginVersion),
			len(compat.RecommendedPluginVersion),
		)
	}
	for id := range compat.MinPluginVersion {
		if compat.RecommendedPluginVersion[id] == "" {
			t.Errorf("MinPluginVersion[%q] has no matching RecommendedPluginVersion", id)
		}
	}
}

// TestGetCapabilitiesContainsPluginCompatibility pins the new
// `plugin_compatibility` capability so a future cleanup that drops it
// from the list trips the test instead of silently telling clients the
// platform doesn't advertise plugin version info.
func TestGetCapabilitiesContainsPluginCompatibility(t *testing.T) {
	caps := getCapabilities()
	for _, cap := range caps {
		if cap.Name == "plugin_compatibility" {
			if cap.Since != "7.5.0" {
				t.Errorf("plugin_compatibility since = %q, want %q", cap.Since, "7.5.0")
			}
			return
		}
	}
	t.Error("expected plugin_compatibility capability to be present")
}

// TestGetCapabilitiesContainsClientVersionTelemetry pins the 9.7.0
// `client_version_telemetry` capability (per-client version-distribution
// telemetry, #2860/#2863) so a future cleanup that drops it from the list
// trips the test instead of silently telling clients the platform doesn't
// record client-version distribution.
func TestGetCapabilitiesContainsClientVersionTelemetry(t *testing.T) {
	caps := getCapabilities()
	for _, cap := range caps {
		if cap.Name == "client_version_telemetry" {
			if cap.Since != "9.7.0" {
				t.Errorf("client_version_telemetry since = %q, want %q", cap.Since, "9.7.0")
			}
			return
		}
	}
	t.Error("expected client_version_telemetry capability to be present")
}

// TestGetCapabilitiesContainsAuthZENEvaluation pins the 10.3.0
// `authzen_evaluation` capability (#3611), the AuthZEN-native authorization
// surface all five SDKs call.
//
// It is deliberately stronger than the two pins above, which compare a name and
// a Since to hand-written literals and would therefore keep passing if the
// route moved or the profile header were renamed. This one checks the
// description against the SAME constants the handler registers and negotiates
// with: authzenHandlerPath, authzenProfileHeader and contract.AuthZENProfileV1.
// So the failure it catches is not only "someone deleted the entry" but
// "someone changed the wire and left /health advertising the old one", which is
// the class of drift a hand-maintained discovery list exists to produce.
//
// What it does NOT assert, so nobody reads more into a green run than is there:
// that the route is reachable. This is a unit test over a literal list; the
// registration is exercised by authzen_handler_test.go and the live suite.
//
// The prose claims were UNPINNED until an R3 mutant proved it: a description
// keeping all three constants while asserting the exact opposite of the truth
// ("this route IS the ADR-065 Policy Decision Point, NOT an adapter") passed a
// green run. Naming the constants only proves they APPEAR. The adapter-vs-PDP
// sentence is the most consequential claim in the entry - it is what tells a
// customer whether their decisions are being made by the engine they have
// authorised policy against - so it is pinned below by phrase, not by constant.
func TestGetCapabilitiesContainsAuthZENEvaluation(t *testing.T) {
	caps := getCapabilities()
	var found *PlatformCapability
	for i := range caps {
		if caps[i].Name == "authzen_evaluation" {
			found = &caps[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected authzen_evaluation capability to be present: POST " +
			authzenHandlerPath + " is registered unconditionally and all five SDKs call it")
	}
	if found.Since != "10.3.0" {
		t.Errorf("authzen_evaluation since = %q, want %q", found.Since, "10.3.0")
	}
	for _, want := range []string{
		authzenHandlerPath,
		authzenProfileHeader,
		string(contract.AuthZENProfileV1),
		// The load-bearing claim, pinned as a phrase because no constant
		// carries it. Inverting it is the mutant that survived the
		// constants-only version of this test.
		"is an ADAPTER over the evaluation POST " + decisionHandlerPath,
		"NOT the ADR-065 Policy Decision Point",
	} {
		if !strings.Contains(found.Description, want) {
			t.Errorf("authzen_evaluation description does not name %q; /health would advertise a contract the handler does not speak.\ngot: %s",
				want, found.Description)
		}
	}
}

func TestGetPlatformVersion(t *testing.T) {
	// Without env var, should return default
	t.Setenv("AXONFLOW_VERSION", "")
	v := GetPlatformVersion()
	if v != defaultVersion {
		t.Errorf("got %q, want %q", v, defaultVersion)
	}

	// With valid env var
	t.Setenv("AXONFLOW_VERSION", "4.8.0")
	v = GetPlatformVersion()
	if v != "4.8.0" {
		t.Errorf("got %q, want %q", v, "4.8.0")
	}

	// With invalid env var, should fall back to default
	t.Setenv("AXONFLOW_VERSION", "invalid-version")
	v = GetPlatformVersion()
	if v != defaultVersion {
		t.Errorf("got %q, want %q", v, defaultVersion)
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
	// least twice — once in the MinPluginVersion comment block, once
	// in the RecommendedPluginVersion comment block. Both blocks are
	// adjacent-class historical-attribution sites and both need the
	// explicit citation so a future "refresh the comment" edit can't
	// drop the attribution from either half.
	prCount := strings.Count(pluginBlock, "#2102")
	if prCount < 2 {
		t.Errorf("getPluginCompatibility() must cite #2102 in BOTH the MinPluginVersion and RecommendedPluginVersion comment blocks (found %d, want ≥2). The plugin tags shipped at the v7.9.0 release-train, #2102. Got:\n%s", prCount, pluginBlock)
	}

	// Banned attribution: the old comment claimed the bump happened
	// "alongside the SDK v8.0.0 release-train". That's historically false
	// (the plugin tags shipped at the v7.9.0 platform release-train) AND
	// muddles the SDK/plugin/platform layers. Catch regression to this
	// wording. NOTE the assertion is on the RecommendedPluginVersion
	// block phrasing specifically — the MinPluginVersion block uses
	// "alongside the v8.0.0 release-train" (different prefix) and was
	// already fixed by PR #2311.
	if strings.Contains(pluginBlock, "alongside the SDK v8.0.0 release-train") {
		t.Errorf("getPluginCompatibility() comment must NOT say 'alongside the SDK v8.0.0 release-train' — that is historically false (plugin tags shipped at v7.9.0 release-train, #2102). Got:\n%s", pluginBlock)
	}

	// Banned stale framing: pre-2026-05-09 the comment said "Plugin tags
	// + registry publish are held pending explicit per-version
	// authorization ... until the tags ship". The tags ARE shipped now
	// (openclaw 2.4.0 on npm, claude/cursor/codex 1.4.0 on ClawHub).
	// Catch regression to the pending/unshipped framing.
	if strings.Contains(pluginBlock, "until the tags ship") {
		t.Errorf("getPluginCompatibility() comment must NOT say 'until the tags ship' — plugin tags are live on their registries. Got:\n%s", pluginBlock)
	}
}

// TestPluginCompatComesFromTheSharedSourceOfTruth pins that this plane serves
// exactly what platform/shared/plugincompat holds — not a copy of it.
//
// This replaces a test that compared the two capabilities.go files as SOURCE
// TEXT. That test was defeated by four shapes that compile cleanly, the worst
// being a decoy `PluginCompatInfo` literal earlier in the same function: the
// parser matched the decoy, reported agreement, and the value actually served
// was different. It also could not see the shape that caused #2962 in the first
// place — NEITHER file being touched — because two maps that agree at a stale
// value agree.
//
// Comparing the compiled result removes both problems: there is one set of
// values, and this asserts the wiring to it. It says nothing about whether those
// values are current relative to npm/ClawHub; that is a fact about a registry
// and belongs to the release runbook.
func TestPluginCompatComesFromTheSharedSourceOfTruth(t *testing.T) {
	got := getPluginCompatibility()

	for name, pair := range map[string][2]map[string]string{
		"MinPluginVersion":         {got.MinPluginVersion, plugincompat.MinVersions()},
		"RecommendedPluginVersion": {got.RecommendedPluginVersion, plugincompat.RecommendedVersions()},
	} {
		served, canonical := pair[0], pair[1]
		if len(canonical) == 0 {
			t.Fatalf("%s: plugincompat returned an empty map — the source of truth is broken, and comparing two empty maps would pass", name)
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

// TestPluginCompatMapsAreNotAliased guards the copy-on-read contract. Handing
// out the package-level map would let any consumer mutate the source of truth
// for the whole process.
func TestPluginCompatMapsAreNotAliased(t *testing.T) {
	first := getPluginCompatibility()
	first.RecommendedPluginVersion["openclaw"] = "0.0.0-mutated"
	first.MinPluginVersion["openclaw"] = "0.0.0-mutated"

	second := getPluginCompatibility()
	if second.RecommendedPluginVersion["openclaw"] == "0.0.0-mutated" {
		t.Error("RecommendedPluginVersion is aliased: mutating one caller's map changed the next caller's")
	}
	if second.MinPluginVersion["openclaw"] == "0.0.0-mutated" {
		t.Error("MinPluginVersion is aliased: mutating one caller's map changed the next caller's")
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
