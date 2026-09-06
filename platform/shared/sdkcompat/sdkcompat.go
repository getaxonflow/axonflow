// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package sdkcompat is the single source of truth for the SDK version floors
// and recommendations both planes advertise on /health.
//
// # Why this package exists
//
// The two maps used to be duplicated literals in platform/agent/capabilities.go
// and platform/orchestrator/capabilities.go, and BOTH are served on /health --
// the agent on 8080, the orchestrator on 8081. A client asking one port which
// SDK version it needs got an answer that had no structural reason to match the
// other port's.
//
// This is the SAME defect that the plugin maps four lines below the SDK maps had
// already been root-caused and fixed for (#3229, platform/shared/plugincompat).
// The plugin fix left the SDK maps alone; #3712 is that omission. Read
// plugincompat's package doc for the two incidents that drove it: one-sided
// drift (claude-code 1.8.0 on one plane, 1.9.0 on the other) and a train where
// NEITHER copy moved, so released versions were advertised nowhere.
//
// A test comparing the two copies was tried for the plugin maps first and is not
// sufficient, and the SDK maps had ended up with the same insufficient guard: a
// source-parsing parity test that reads both literals and compares them. It
// cannot see the second shape at all -- two files that agree at a stale value
// agree -- so it is the wrong instrument no matter how carefully it parses. The
// only durable answer is to stop having two copies, which is what this package
// does: the two planes now return this map by construction, so they cannot
// disagree.
//
// # What this package does NOT solve
//
// It makes the two planes agree by construction. It does NOT and cannot tell
// anyone that a value has gone stale relative to what is actually published on
// PyPI / npm / the Go module proxy / Maven Central / crates.io -- that is a fact
// about a registry, not about this repository, and no in-repo test can observe
// it. That check belongs to the release runbook, which re-derives every value
// from `gh release list` per SDK repo when a train opens.
package sdkcompat

// minVersion is the floor of the current major line for each SDK. A caller below
// it is told, on /health, that it should upgrade; the value moves only on a
// deliberate compatibility break.
//
// The SDK major bumped from v7 to v8 during the **v7.9.0 release-train** (#2016,
// the pre-emptive floor bump on 2026-05-08, folded into the v7.9.0 community
// sync at #2102 on 2026-05-09). The v8.0.0 PLATFORM bump (#2308) did NOT change
// the SDK floor -- it stayed at 8.0.0. Callers below 8.0.0 lack the typed 429
// RateLimitError upgrade-envelope handling and the list_decisions method
// (#1982). Note that Go's major bump also changes the import path
// (axonflow-sdk-go/v7 -> /v8) per Go modules v2+ rules.
//
// The attribution matters and is test-guarded (TestSDKFloorCommentAttribution,
// which both planes run against THIS file). Attributing the bump to the v8.0.0
// platform release-train rather than to v7.9.0 is historically false and is
// banned by substring. Do not restate the banned wording here even to forbid it
// -- the guard is a substring check over this file, so quoting the phrase trips
// it. Describe the property instead, as this paragraph does.
//
// rust joined the compat maps in the 9.7.0 release-train. Its 0.x preview line is
// versioned independently of the 8.x SDKs; the floor is 0.7.0, the first rust
// release that speaks the current Decision Mode PEP contract (decide -> fulfill
// -> forward, engine-only fulfill, fail-closed on a missing verdict; epic #2563).
// The 0.5 and 0.6 previews predate that contract.
var minVersion = map[string]string{
	"python":     "8.0.0",
	"typescript": "8.0.0",
	"go":         "8.0.0",
	"java":       "8.0.0",
	"rust":       "0.7.0",
}

// recommendedVersion is the latest tag of each SDK that this platform was tested
// against. A client below it keeps working and receives an upgrade hint; the
// minVersion floor above is what actually gates.
//
// Release-train history, newest first:
//
//   - the 10.4.0 train moves python/typescript/go/java 9.2.0 -> 9.3.0 and rust
//     0.9.0 -> 0.10.0: the tags carrying the SDK read-path identity surface
//     (#3651, merged in all five on 2026-09-03 and unpublished since) and, in
//     python, the per-call `extra_headers` attach point the PEP capability
//     handshake needs (sdk-python#243). The versions are the ones #3657's
//     Versions section commits the train to, and Step 3 of
//     RUNBOOK_RELEASE_PREP.md owns the bump in each SDK repository; the tags
//     themselves are cut in the release phase, AFTER the community platform
//     release, per that runbook's ordering.
//   - the 10.3.0 train moved python/typescript/go/java 9.1.x -> 9.2.0 and rust
//     0.8.2 -> 0.9.0 (#3650): those are the tags carrying the AuthZEN-native
//     surface, and they were published as part of the v10.3.0 cut itself.
//   - java bumped 8.5.0 -> 8.5.1 in the 9.1.1 security patch (2026-06-16):
//     8.5.1 adds a production guard around the opt-in insecure-TLS dev hatch
//     plus dependency CVE clears.
//   - python/typescript/go bumped 8.5.0 -> 8.5.1 in the 9.7.0 release-train
//     (epic #2861, the SDK hostile sweep): go 8.5.1 fails closed on 4xx auth
//     errors instead of silently allowing, python 8.5.1 bridges sync
//     interceptors onto a persistent event loop and detects AsyncOpenAI
//     clients, typescript 8.5.1 sends auth on getPlanStatus.
//   - rust entered at 0.8.1 (execute_plan status fix, plus the 9.7.0 train's
//     examples baseline).
//
// Nothing in this repository validates a recommended value against the registry
// it names, so when an SDK publishes, move this map in the same round.
var recommendedVersion = map[string]string{
	"python":     "9.3.0",
	"typescript": "9.3.0",
	"go":         "9.3.0",
	"java":       "9.3.0",
	"rust":       "0.10.0",
}

// MinVersions returns the floor map.
//
// A copy, not the map itself: a map is a reference, so handing out the original
// would let any caller -- including a JSON encoder's consumer or a future
// handler that "normalises" its input -- mutate the source of truth for the
// whole process. The two callers serve it on /health and do not currently write
// to it; that is not a property to depend on.
func MinVersions() map[string]string { return copyOf(minVersion) }

// RecommendedVersions returns the recommendation map, copied for the same reason
// as MinVersions.
func RecommendedVersions() map[string]string { return copyOf(recommendedVersion) }

// IDs returns the SDK ids both maps carry. Callers that need to cross-check
// against their own list of languages use this rather than ranging over one of
// the maps, so the check does not silently depend on which map was picked.
func IDs() []string {
	out := make([]string, 0, len(recommendedVersion))
	for id := range recommendedVersion {
		out = append(out, id)
	}
	return out
}

func copyOf(src map[string]string) map[string]string {
	// make+copy rather than a nil-appended literal: an empty source must yield
	// an empty map, never nil, or the JSON shape changes from {} to null
	// depending on the contents.
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
