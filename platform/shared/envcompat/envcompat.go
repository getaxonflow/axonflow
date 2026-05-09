// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package envcompat reads environment variables with optional fallback
// to a deprecated name, enabling rolling migrations without atomic
// env+image cutovers.
//
// Use envcompat instead of raw os.Getenv when reading config that may
// undergo a future rename. The helper:
//
//   - Reads the primary name first; if non-empty, uses that value.
//   - Falls back to the deprecated name if the primary is unset.
//   - Logs a one-time WARNING when the fallback fires, telling the
//     operator to migrate to the primary name.
//
// The fallback path enables Pattern B from the deploy-patterns runbook:
// ship the new image (which reads the primary name, falls back to the
// deprecated name) before flipping the env var, so rollback is just
// "redeploy the previous image" rather than "rebuild + reapply CFN."
//
// Without envcompat, code that does raw `os.Getenv("NEW_NAME")` locks
// the cutover-flexibility decision at code-write time — Pattern A
// (atomic env+image) becomes the only option. envcompat moves that
// decision to deploy time.
//
// Use envcompat for configuration: integration URLs, feature flag
// names, region overrides, anything that might be renamed in a future
// release. Use secretenv (not envcompat) for secrets — it has
// different defensive semantics around whitespace trimming.
//
// See axonflow-internal-docs/engineering/RUNBOOK_DEPLOY_PATTERNS.md
// for the full rollout-pattern decision matrix.
package envcompat

import (
	"log"
	"os"
	"sync"
)

// warnedPairs ensures the deprecation warning fires at most once per
// (primary, deprecated) pair per process lifetime. Without this, a
// hot-loop reader of the deprecated name would spam logs.
var warnedPairs sync.Map

// Get returns the value of the primary env var if set to a non-empty
// string, otherwise the value of the deprecated env var if set to a
// non-empty string, otherwise the empty string.
//
// When the deprecated name is the source of the value, logs a one-time
// WARNING per (primary, deprecated) pair telling the operator to
// migrate. The primary name takes precedence when both are set.
//
// Empty-string values are treated as unset (matching os.Getenv
// semantics for missing variables).
//
// Use Lookup if you need to distinguish "primary set" from "deprecated
// set" or "neither set" — for example, when the deprecated value
// requires format conversion that the primary doesn't.
func Get(primary, deprecated string) string {
	value, _, _ := Lookup(primary, deprecated)
	return value
}

// Lookup is the same as Get but also returns:
//
//   - source: "primary" if the primary name was the source, "deprecated"
//     if the fallback fired, or "" if neither name was set.
//   - ok: true if either name was set to a non-empty value.
//
// The deprecation warning fires (at most once per pair per process)
// only when source == "deprecated".
//
// Callers that need different parsing logic for the primary vs the
// deprecated value (e.g. a deprecated boolean that the primary
// expresses as an enum) should branch on source.
func Lookup(primary, deprecated string) (value, source string, ok bool) {
	if v := os.Getenv(primary); v != "" {
		return v, "primary", true
	}
	if v := os.Getenv(deprecated); v != "" {
		key := primary + "\x00" + deprecated
		if _, alreadyWarned := warnedPairs.LoadOrStore(key, struct{}{}); !alreadyWarned {
			log.Printf("[envcompat] WARNING: %s is deprecated; please migrate to %s. "+
				"Both names are honored during the migration window; the new name takes "+
				"precedence when both are set.", deprecated, primary)
		}
		return v, "deprecated", true
	}
	return "", "", false
}

// resetWarnedPairsForTest clears the once-per-pair warning cache.
// Test-only — not part of the package's public API.
func resetWarnedPairsForTest() {
	warnedPairs.Range(func(k, _ any) bool {
		warnedPairs.Delete(k)
		return true
	})
}
