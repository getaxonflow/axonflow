// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package policypath is the single source of truth for the policy API's
// path rename (#1431): the wire paths still say "static"/"dynamic" while every
// other surface - the portal UI, the public docs, the tier vocabulary and the
// database's own tier column - says "system"/"tenant".
//
// # What this package is
//
// One table (Families) and one lookup (SuccessorOf). Every plane that registers,
// proxies, gates or documents these route families reads its answer from here.
//
// # Why it is a package and not four string literals
//
// The rename touches four registration surfaces that a reader would not guess
// from the issue text:
//
//   - the AGENT serves /api/v1/static-policies itself (13 routes, OAuth2 client
//     credentials, apiAuthMiddleware);
//   - the ORCHESTRATOR serves /api/v1/dynamic-policies itself (8 routes, behind
//     requireInternalProxyAuth);
//   - the AGENT also REVERSE-PROXIES /api/v1/dynamic-policies to the
//     orchestrator, because ADR-026 makes the agent the single entry point - so
//     the tenant-policy family has a registration on a plane that does not
//     implement it;
//   - the PORTAL serves /api/v1/static-policies from its own session-authed
//     handlers AND forwards /api/v1/dynamic-policies through its orchestrator
//     catch-all, with permission gates that are keyed on the path literal.
//
// Four surfaces means four chances for one of them to spell the mapping
// differently, and the portal's gates are the dangerous one: its catch-all
// authenticates but does not authorize (#3012), so a policy-mutating path the
// gate list does not name is an UNGATED WRITE, not a 404. A shared table makes
// "which paths are the policy families" answerable in one place by every plane
// that has to enumerate them.
//
// # Deprecation signalling
//
// The legacy paths keep working and are stamped with RFC 8594 Deprecation and
// RFC 8288 Link headers by DeprecateLegacy. There is deliberately NO Sunset
// header: a Sunset date is a promise that the path disappears on that day, and
// whether v10 removes these paths at all is an open decision. Emitting a date
// nobody has agreed to would be worse than emitting nothing.
package policypath

import (
	"net/http"
	"strings"
)

// The four path families. Legacy* are the paths shipped since ADR-018/ADR-026;
// the unprefixed names are the successors #1431 introduces.
const (
	// LegacySystemPolicies is the pattern-based, platform-authored policy
	// family: what the tier vocabulary and the docs call SYSTEM policies.
	LegacySystemPolicies = "/api/v1/static-policies"
	// SystemPolicies is LegacySystemPolicies' successor.
	SystemPolicies = "/api/v1/system-policies"

	// LegacyTenantPolicies is the customer-authored, tenant-scoped policy
	// family: what the tier vocabulary and the docs call TENANT policies.
	// "dynamic" reads as "changes by itself", which is not what it means.
	LegacyTenantPolicies = "/api/v1/dynamic-policies"
	// TenantPolicies is LegacyTenantPolicies' successor.
	TenantPolicies = "/api/v1/tenant-policies"
)

// Pair is one legacy family and the successor that aliases it.
type Pair struct {
	// Legacy is the deprecated path prefix, without a trailing slash.
	Legacy string
	// Successor is the path prefix that replaces it, without a trailing slash.
	Successor string
}

// pairs is the complete rename table.
//
// It is unexported, and Families() hands out a COPY, because this slice is
// read on every request that passes through DeprecateLegacy on four planes.
// An exported slice is writable by any importer - `policypath.Pairs[0] =
// ...` compiles - and a package whose whole job is to be the single source of
// truth should not be able to be edited at a distance by one of the four
// planes that trusts it.
var pairs = []Pair{
	{Legacy: LegacySystemPolicies, Successor: SystemPolicies},
	{Legacy: LegacyTenantPolicies, Successor: TenantPolicies},
}

// Families returns the rename table. Iterate this rather than writing the
// constants out again: a plane that enumerates route families (the portal's
// permission gates, the proxy's IsProxiedPath, a census test) stays correct
// when a third family is added to the table.
//
// The returned slice is a copy, so a caller that mutates it changes nothing
// for anybody else.
func Families() []Pair {
	out := make([]Pair, len(pairs))
	copy(out, pairs)
	return out
}

// SuccessorOf maps a request path under a legacy family to the same path under
// its successor, preserving the suffix:
//
//	/api/v1/static-policies             -> /api/v1/system-policies, true
//	/api/v1/static-policies/{id}/override -> /api/v1/system-policies/{id}/override, true
//	/api/v1/system-policies             -> "", false   (already the successor)
//	/api/v1/static-policies-archive     -> "", false   (not a segment boundary)
//
// The segment-boundary check is load-bearing. A bare strings.HasPrefix would
// treat "/api/v1/static-policies-archive" as a member of the family and stamp
// a deprecation header pointing at a successor that does not exist.
func SuccessorOf(path string) (string, bool) {
	for _, p := range pairs {
		if suffix, ok := underPrefix(path, p.Legacy); ok {
			return p.Successor + suffix, true
		}
	}
	return "", false
}

// IsLegacy reports whether path is in one of the deprecated families.
func IsLegacy(path string) bool {
	_, ok := SuccessorOf(path)
	return ok
}

// IsSuccessor reports whether path is in one of the successor families. It is
// the assertion the "deprecation header must not leak onto the new names" test
// is written against, so it lives beside SuccessorOf rather than being spelled
// out at the test.
func IsSuccessor(path string) bool {
	for _, p := range pairs {
		if _, ok := underPrefix(path, p.Successor); ok {
			return true
		}
	}
	return false
}

// underPrefix reports whether path is prefix itself or a descendant of it,
// matching only on a "/" segment boundary, and returns the remainder.
func underPrefix(path, prefix string) (string, bool) {
	if path == prefix {
		return "", true
	}
	if strings.HasPrefix(path, prefix+"/") {
		return path[len(prefix):], true
	}
	return "", false
}

// Deprecation header names and the fixed Deprecation value (RFC 8594).
const (
	HeaderDeprecation = "Deprecation"
	HeaderLink        = "Link"
	// DeprecationValue is the RFC 8594 boolean form. RFC 9745 later replaced
	// this with a structured @date; "true" is what #1431 specified and what an
	// existing client's deprecation tooling recognises, and switching to a date
	// would again be promising a timeline nobody has agreed.
	DeprecationValue = "true"
)

// LinkSuccessor renders the RFC 8288 Link header value naming successor as the
// replacement for the path that served the response.
func LinkSuccessor(successor string) string {
	return "<" + successor + ">; rel=\"successor-version\""
}

// StampDeprecation writes the deprecation signal for a response served from a
// legacy path. It is a no-op - and reports false - for any path that is not
// legacy, so a caller cannot stamp a successor path by mistake.
//
// Headers are set on the header map, so this must run BEFORE the handler calls
// WriteHeader. That is why DeprecateLegacy wraps rather than defers.
func StampDeprecation(h http.Header, path string) bool {
	successor, ok := SuccessorOf(path)
	if !ok {
		return false
	}
	h.Set(HeaderDeprecation, DeprecationValue)
	h.Set(HeaderLink, LinkSuccessor(successor))
	return true
}

// DeprecateLegacy wraps next so that a response served from a legacy policy
// path carries the deprecation signal, and a response served from anywhere
// else is byte-identical to what next would have produced.
//
// It derives the successor from the request path rather than taking it as a
// parameter ON PURPOSE. A per-call-site successor argument is a second place
// for the mapping to be written down, and the whole reason this package exists
// is that there is exactly one.
//
// Safe to mount on a router that also carries successor routes: SuccessorOf
// returns false for them, so the header cannot leak onto the new names.
func DeprecateLegacy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		StampDeprecation(w.Header(), r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// DeprecateLegacyFunc is DeprecateLegacy for a bare HandlerFunc, which is the
// shape gorilla/mux's HandleFunc and the portal's sessionPermGate both use.
func DeprecateLegacyFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		StampDeprecation(w.Header(), r.URL.Path)
		next(w, r)
	}
}
