// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package capability holds the canonical AxonFlow capability registry: one
// versioned, machine-readable statement of every capability the platform
// ships, what edition it needs, how it is protected, and what it exposes.
//
// # Why this package exists
//
// Before it, the same facts were stated in several places that could not
// disagree loudly. `getCapabilities()` on each of the two /health planes was a
// hand-maintained Go literal; `technical-docs/COMMUNITY_ENTERPRISE_FEATURE_MATRIX.md`
// was prose; the edition boundary itself was spread across build tags, `ee/`
// placement, mirror-sync exclusions and runtime licence checks. Nothing
// compared them, so the /health list went four releases without an entry
// (#3618) and nobody noticed, and the matrix accumulated rows that disagree
// with the code (#3590).
//
// ADR-066 decision 1 requires one canonical capability registry. This is it.
//
// # What is derived and what is declared
//
// The registry is DATA, in registry.json. Everything that can be derived from
// the tree is checked against the tree rather than trusted:
//
//   - routes are derived by PARSING the Go source with go/ast (Derive), not by
//     grepping it. Nineteen route registrations on main name a constant rather
//     than a string literal — including POST /api/v1/decide and the AuthZEN
//     route — so a literal-only scanner misses the two most important surfaces
//     on the platform. Every derived route must be covered by a registry entry;
//     an uncovered route fails.
//   - the enterprise build tag is read from the same parse, so an entry that
//     claims `build_tag: enterprise` is checked against the files it names.
//   - the /health list served by both planes is PROJECTED from the registry,
//     so it cannot go stale independently. Adding a capability with a health
//     block is the only way to add a /health entry.
//
// What cannot be derived is declared and validated for internal consistency:
// the minimum edition, the ADR-066 source classification, the owning test, the
// family, and the availability score.
//
// # What this package is NOT
//
// It is not an entitlement mechanism. Nothing here is consulted at request
// time to decide what a caller may do: the runtime licence checks in
// platform/agent/license and the build-tag/`ee/` source separation are
// unchanged and remain the enforcement. ADR-066 decision 1 says the registry
// "is configuration and metadata; it does not contain policy truth or replace
// license signature validation", and #3590's acceptance criterion is that no
// entitlement behaviour changes. The registry DESCRIBES the boundary so that
// drift is visible; it does not DECIDE it.
//
// The one runtime consumer is the /health capability list, which is discovery
// metadata and was already served from a hand-maintained literal.
package capability
