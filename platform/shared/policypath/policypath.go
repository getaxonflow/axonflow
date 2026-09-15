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
//     orchestrator, because ADR-024 makes the agent the single entry point - so
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
// # Deprecation signalling (v11, PRD §1.11)
//
// In v11 the whole legacy policy surface is a read-only, deprecated export
// surface: both #1431 spellings of the system and tenant families, the
// orchestrator's /api/v1/policies and /api/v1/templates, and the agent's
// /api/v1/policy-overrides alias. Writes answer 409 through
// platform/shared/legacyfreeze; reads keep working so an organization can see
// and export its own legacy rows after upgrading, and four SDKs still call
// them. Every response from these families carries the signal StampDeprecation
// writes: an RFC 8594 Deprecation header, an RFC 8288 Link naming the typed
// authoring route as the successor, and HeaderRemovedIn naming the release
// that removes them.
//
// The #1431 successors are deprecated as well. The rename (static -> system,
// dynamic -> tenant) was a v10 vocabulary change inside the legacy model; v11
// replaces the model, so pointing a caller from one legacy spelling at the
// other would send it to a route that is itself going away.
//
// There is deliberately NO Sunset header: RFC 8594 makes Sunset a DATE, and the
// removal is tied to a release, not a day. Emitting a date nobody has agreed to
// would be worse than naming the release.
package policypath

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"axonflow/platform/shared/legacyfreeze"
)

// The four path families. Legacy* are the paths shipped since ADR-017/ADR-024;
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

// The two orchestrator families that #1431 never renamed. They are named here,
// beside the renamed ones, because the v11 deprecation covers all of them and a
// family missing from DeprecatedFamilies is a family that answers unstamped.
const (
	// Policies is the orchestrator's original policy CRUD, test, version,
	// import/export and simulation family.
	Policies = "/api/v1/policies"
	// Templates is the orchestrator's legacy policy-template catalogue.
	Templates = "/api/v1/templates"
	// PolicyOverrides is the agent's canonical alias of the system family's
	// /overrides list.
	PolicyOverrides = "/api/v1/policy-overrides"
)

// RBIPolicyTemplates is the RBI vertical's read-only policy-template catalogue
// (platform/orchestrator/rbi). The vertical ships as typed policy packs in v11
// (PRD v11 §1 item 9), so the catalogue's two reads are on the deprecated export
// surface beside the families above and carry the same signal.
const RBIPolicyTemplates = "/api/v1/rbi/policies/templates"

// deprecatedFamilies is the v11 deprecated export surface (PRD §1.11): every
// legacy policy path prefix, in both #1431 spellings. Unexported for the same
// reason as pairs; DeprecatedFamilies hands out a copy.
var deprecatedFamilies = []string{
	LegacySystemPolicies, SystemPolicies,
	LegacyTenantPolicies, TenantPolicies,
	Policies, Templates, PolicyOverrides,
	RBIPolicyTemplates,
}

// DeprecatedFamilies returns the path prefixes of the v11 deprecated export
// surface. A census that enumerates legacy policy routes iterates this rather
// than writing the prefixes out again.
func DeprecatedFamilies() []string {
	out := make([]string, len(deprecatedFamilies))
	copy(out, deprecatedFamilies)
	return out
}

// IsDeprecated reports whether path is in the v11 deprecated export surface,
// on a "/" segment boundary: /api/v1/policies-archive and /api/v1/typed-policies
// are not members.
func IsDeprecated(path string) bool {
	for _, prefix := range deprecatedFamilies {
		if _, ok := underPrefix(path, prefix); ok {
			return true
		}
	}
	return false
}

// The deprecation signal: three headers, and why each has the form it has.
//
//   - Deprecation (RFC 9745, which obsoletes the draft's `Deprecation: true`):
//     a structured-field date, `@<unix seconds>`, the moment the deprecation
//     took effect - the v11.0.0 tag. Do not "fix" it back to `true`: that is the
//     pre-RFC form #1431 shipped, and RFC 9745 clients read it as malformed.
//   - Link (RFC 8288) with rel="successor-version": the typed authoring route.
//   - HeaderRemovedIn: the release that removes the surface. No registered
//     header carries a RELEASE: RFC 8594's Sunset is a DATE after which the
//     resource may stop answering, and v11.1 has no agreed date. When it has
//     one, Sunset is added beside this header from one more constant.
const (
	HeaderDeprecation = "Deprecation"
	HeaderLink        = "Link"
	HeaderRemovedIn   = "X-AxonFlow-Removed-In"

	// Successor is the route that replaces every deprecated family: policies
	// are read, authored and activated through the typed authoring route. It
	// is legacyfreeze's constant, so the 409 on a write and the Link on a read
	// name the same route by construction.
	Successor = legacyfreeze.TypedAuthoringRoute
	// RemovalRelease is the release that removes the deprecated surface, once
	// the SDK train has moved its callers to the typed route (PRD §1.11).
	RemovalRelease = "v11.1"

	// DeprecatedInRelease is the release that deprecates the surface, in the
	// form the repository's VERSION file carries.
	DeprecatedInRelease = "11.0.0"
	// DeprecatedSince is the UTC date (YYYY-MM-DD) DeprecatedInRelease was
	// tagged, and the only input to the Deprecation header's value.
	//
	// IT IS EMPTY UNTIL RELEASE PREP SETS IT, and while it is empty the
	// Deprecation header is OMITTED rather than guessed: a date on the wire is
	// a claim about when the change took effect, and a guessed one is a false
	// claim. HeaderRemovedIn and Link carry the signal meanwhile.
	// TestDeprecatedSinceIsSetOnceVERSIONReachesTheDeprecatingRelease reds the
	// moment VERSION moves to DeprecatedInRelease or later with this still
	// empty or unparseable, which is the release-prep step that sets it.
	DeprecatedSince = "2026-09-15"
)

// DeprecationHeaders lists every header StampDeprecation can write. None of
// them is CORS-safelisted, so each plane's ExposedHeaders must carry all of
// them or a browser client reads the signal as null; the CORS tests iterate
// this list.
func DeprecationHeaders() []string {
	return []string{HeaderDeprecation, HeaderLink, HeaderRemovedIn}
}

// LinkSuccessor renders the RFC 8288 Link header value naming successor as the
// replacement for the path that served the response.
func LinkSuccessor(successor string) string {
	return "<" + successor + ">; rel=\"successor-version\""
}

// DeprecationValue renders an RFC 9745 Deprecation value for a YYYY-MM-DD UTC
// date, and reports false for an empty or unparseable one.
func DeprecationValue(since string) (string, bool) {
	if since == "" {
		return "", false
	}
	t, err := time.Parse(time.DateOnly, since)
	if err != nil {
		return "", false
	}
	return "@" + strconv.FormatInt(t.Unix(), 10), true
}

// StampDeprecation writes the deprecation signal for a response served from
// the deprecated export surface. It is a no-op - and reports false - for any
// other path, so a caller cannot stamp the typed route by mistake.
//
// Set, not Add: a stamp applied on two hops reaches the client once.
//
// Headers are set on the header map, so this must run BEFORE the handler calls
// WriteHeader. That is why DeprecateLegacy wraps rather than defers.
func StampDeprecation(h http.Header, path string) bool {
	return stamp(h, path, DeprecatedSince)
}

// stamp is StampDeprecation with the deprecation date as a parameter, so the
// tests pin the header's FORMAT against a fixed date rather than a real one.
func stamp(h http.Header, path, since string) bool {
	if !IsDeprecated(path) {
		return false
	}
	if v, ok := DeprecationValue(since); ok {
		h.Set(HeaderDeprecation, v)
	}
	h.Set(HeaderLink, LinkSuccessor(Successor))
	h.Set(HeaderRemovedIn, RemovalRelease)
	return true
}

// DeprecateLegacy wraps next so that a response served from the deprecated
// export surface carries the deprecation signal, and a response served from
// anywhere else is byte-identical to what next would have produced.
//
// It is keyed on the request path rather than applied unconditionally ON
// PURPOSE: a route mounted under this middleware whose path is not in
// DeprecatedFamilies answers unstamped, and the registrar census in each
// binary reds on it, so a new legacy family cannot be stamped without being
// named here first.
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
