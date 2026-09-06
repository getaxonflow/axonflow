// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package corspolicy resolves the browser cross-origin policy for every
// AxonFlow HTTP surface from one place.
//
// #3096 established the policy; #3161 established that having it twice was not
// enough. The agent and the orchestrator each carried a byte-identical copy of
// the resolution logic, and the customer-portal carried a THIRD, unrelated one:
// a hardcoded allowlist with AllowCredentials: true naming, among other things,
// a bare IPv4 address in the eu-central-1 EC2 pool. On a partner's own stack
// that advertised credentialed cross-origin access to an origin the partner
// neither controls nor can remove without rebuilding the image.
//
// A duplicated policy is a policy that drifts, and the portal is the proof. So
// the resolution lives here once and every surface reads it:
//
//	platform/agent/cors.go              -> Resolve()
//	platform/orchestrator/cors.go       -> Resolve()
//	ee/platform/customer-portal/main.go -> ResolveWithCommunityFallback(...)
//
// # The policy
//
//	| AXONFLOW_CORS_ALLOWED_ORIGINS | DEPLOYMENT_MODE | Policy                            |
//	|-------------------------------|-----------------|-----------------------------------|
//	| set to exact origins          | any             | those origins, credentials ON     |
//	| set, an entry contains "*"    | any             | those entries, credentials OFF    |
//	| set, an entry IS "*"          | any             | "*", credentials OFF (+ warning)  |
//	| unset                         | community       | the caller's community fallback   |
//	| unset                         | anything else   | deny all cross-origin             |
//
// Credentials are enabled only for a list of EXACT origins, which is the only
// combination the Fetch specification permits and the only one where the set of
// admitted origins is a set somebody actually wrote down. `*` with credentials
// is never emitted on any branch — that pairing is what #3096 removed, and the
// obvious "fix" for it (reflecting the Origin header while credentials stay on)
// is a live cross-origin read of authenticated responses from ANY site.
//
// The pattern row is not a hypothetical. rs/cors does NOT treat entries as
// exact strings: it splits an entry on the first `*` and matches prefix +
// suffix (cors.go:181-185). So `https://*.example.com` admits every subdomain,
// while every piece of documentation this project ships says entries are exact
// and that there is no suffix matching. Before #3161's review that combination
// resolved to credentials ON, which handed an unenumerated set of origins a
// credentialed read of an authenticated API — the same shape as the `*` rule,
// only narrower and therefore easier to miss.
//
// # Two rs/cors behaviours this package depends on
//
// Both verified against github.com/rs/cors@v1.11.1, not assumed:
//
//  1. For AllowedOrigins: []string{"*"} rs/cors emits a LITERAL
//     `Access-Control-Allow-Origin: *` (cors.go:374-378, :432-436). It does not
//     reflect the request Origin. Allow() mirrors that exactly so a handler
//     writing its own preflight headers cannot diverge from the middleware.
//
//  2. Setting AllowedOrigins to an EMPTY slice does not deny anything. rs/cors
//     reads a zero-length AllowedOrigins as "allow all" (cors.go:163-167), so
//     the intuitive lockdown is a silent no-op that looks exactly like a fix.
//     Denial has to be expressed as an AllowOriginFunc that returns false,
//     which is what Apply's default branch does.
package corspolicy

import (
	"os"
	"strings"

	"github.com/rs/cors"

	"axonflow/platform/shared/deploymode"
)

// AllowedOriginsEnv configures the browser origins allowed to make cross-origin
// requests to an AxonFlow HTTP surface. Comma-separated, EXACT origins (scheme
// + host + optional port), e.g.
//
//	AXONFLOW_CORS_ALLOWED_ORIGINS=https://portal.example.com,https://app.example.com
//
// Unset is a supported posture, not a missing one — see Resolve.
const AllowedOriginsEnv = "AXONFLOW_CORS_ALLOWED_ORIGINS"

// Policy is a resolved origin policy, separated from the two ways it gets
// applied: as rs/cors options on a router (Apply), and as headers written by a
// handler that answers its own OPTIONS request (Allow).
//
// Keeping the resolution separate from the application is the point. Before
// #3117 M4 the agent's MCP server handler answered its preflight with
//
//	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
//
// unconditionally — a second origin policy that reflected ANY origin, including
// under the deny-all default. One resolution, several consumers.
type Policy struct {
	// Wildcard emits a literal "*". Never paired with Credentials.
	Wildcard bool
	// Origins is the exact allowlist, consulted only when Wildcard is false.
	Origins []string
	// Credentials advertises Access-Control-Allow-Credentials.
	Credentials bool
	// Notice is an operator log line for the caller to emit ONCE at startup.
	// Resolve never logs by itself: it is called on the request path by
	// handlers that write their own preflight headers, and a per-request log
	// line for a denied preflight is a free remote log-flood.
	Notice string
}

// Resolve reads the configuration and returns the policy, using the default
// Community fallback: a literal "*" WITHOUT credentials. That keeps local
// development frictionless for surfaces whose clients do not send credentials.
//
// A surface whose clients DO send credentials (a cookie-session API such as the
// customer-portal) cannot use that fallback — `*` and credentials cannot be
// combined — and must call ResolveWithCommunityFallback with a named localhost
// allowlist instead.
func Resolve() Policy {
	return ResolveWithCommunityFallback(Policy{Wildcard: true, Credentials: false})
}

// ResolveWithCommunityFallback is Resolve with a caller-supplied policy for the
// one branch that legitimately differs between surfaces: DEPLOYMENT_MODE is the
// Community posture AND the operator has configured nothing.
//
// The fallback applies ONLY to that branch. It cannot widen a configured
// deployment, it cannot re-enable credentials on a wildcard, and it is never
// reached outside Community mode — where the default stays deny-all.
func ResolveWithCommunityFallback(communityFallback Policy) Policy {
	origins := ParseAllowedOrigins(os.Getenv(AllowedOriginsEnv))

	switch {
	case ContainsWildcardOrigin(origins):
		// An operator asked for "*" explicitly. Honour it, but never with
		// credentials — that pairing is invalid per the Fetch spec and is the
		// exact combination #3096 exists to remove.
		return Policy{
			Wildcard:    true,
			Credentials: false,
			Notice: "⚠️ [CORS] " + AllowedOriginsEnv + " contains \"*\": allowing all origins WITHOUT credentials. " +
				"List explicit origins instead if you need credentialed cross-origin requests.",
		}

	case containsPatternOrigin(origins):
		// An entry like `https://*.example.com`. Every piece of documentation
		// this project ships says entries are EXACT and that there is no suffix
		// matching — but rs/cors disagrees: it splits an entry on the first `*`
		// and does prefix/suffix matching (cors.go:181-185, wildcard.match). So
		// the entry is honoured, and an operator who believed the documentation
		// would have handed `https://<anything>.example.com` a credentialed
		// cross-origin read of an authenticated API.
		//
		// The list is passed through rather than dropped — silently ignoring a
		// configured origin is its own failure mode, and rs/cors's behaviour is
		// what an operator writing that entry evidently wanted. What is refused
		// is CREDENTIALS: a pattern names a set of origins nobody enumerated,
		// which is precisely the shape the `*`-with-credentials rule exists to
		// forbid, only narrower. The operator is told, once, at startup.
		return Policy{
			Origins:     origins,
			Credentials: false,
			Notice: "⚠️ [CORS] " + AllowedOriginsEnv + " contains a wildcard PATTERN (e.g. https://*.example.com). " +
				"Such an entry does match — prefix/suffix, not exactly — so it is honoured, but credentials " +
				"are NOT advertised for any origin in this list. List exact origins if you need credentialed " +
				"cross-origin requests.",
		}

	case len(origins) > 0:
		return Policy{Origins: origins, Credentials: true}

	// The Community-posture branch. The DEFINITION lives in
	// platform/shared/deploymode (#3713); this package used to carry its own
	// copy, and the comment justifying that copy is worth recording because it
	// was TRUE and reached the wrong conclusion:
	//
	//	"duplicated rather than imported because those live in the two
	//	 binaries' own packages, and importing either from here would make
	//	 this package depend on a binary."
	//
	// Both halves are still true. What it missed is that the answer did not
	// have to come from either binary - a shared package that neither imports
	// is the third option, and platform/shared/deploymode had already shipped
	// (#3602) when the comment was written. A justification that rules out two
	// options and never considers a third defends the duplication better than
	// no comment at all, because the next reader stops at it.
	//
	// The contract - exactly one token, no trim, no case-fold, unset fails
	// closed - is stated once, on deploymode.IsCommunityPosture. It matters
	// here for the same reason it matters there: every widening of the
	// accepting set WIDENS cross-origin access, so " community" and "Community"
	// land in the deny branch below, which is the direction a malformed value
	// should fail in.
	case deploymode.CurrentIsCommunityPosture():
		// The fallback comes from the caller, so it has been through none of
		// the checks above. Put it through the same one that matters: a caller
		// whose fallback list carries a `*` — bare or as a pattern — would
		// otherwise get credentials on a set nobody enumerated, which is the
		// invariant this whole function exists to hold. No shipped caller does
		// this today; an invariant with no guard is one line from being false.
		if ContainsWildcardOrigin(communityFallback.Origins) || containsPatternOrigin(communityFallback.Origins) {
			communityFallback.Credentials = false
			if communityFallback.Notice == "" {
				communityFallback.Notice = "⚠️ [CORS] the Community-mode fallback origin list contains a wildcard; " +
					"credentials are NOT advertised for it."
			}
		}
		return communityFallback

	default:
		return Policy{
			Credentials: false,
			Notice: "[CORS] " + AllowedOriginsEnv + " is not set and " + deploymode.EnvDeploymentMode + " is not community: " +
				"cross-origin browser requests are denied. Set " + AllowedOriginsEnv +
				" if a browser on another origin must call this API.",
		}
	}
}

// Apply writes the origin decision onto a caller-supplied cors.Options,
// leaving every other field (methods, headers, exposed headers, max-age) alone.
// Each surface keeps its own request-shaping configuration; only the origin
// policy is shared.
//
// Every origin-deciding field is overwritten, not merged. That includes the two
// rs/cors consults BEFORE the ones this package sets — AllowOriginRequestFunc
// and AllowOriginVaryRequestFunc (cors.go:153-159), which rs/cors documents as
// overriding "the contents of AllowedOrigins, AllowOriginFunc". A caller that
// left either in its base options would otherwise defeat the deny-all branch
// entirely: a second, drifting origin policy, which is the thing this package
// exists to make impossible. AllowCredentials is overwritten for the same
// reason. Note where that is actually load-bearing: the deny and wildcard
// branches re-clear the field themselves, so the assignment at the top only
// matters for a NAMED list whose policy resolved to Credentials=false — the
// pattern branch. That is the case the test pins.
//
// The result therefore has exactly one origin decision in it, and it is this
// one.
func (p Policy) Apply(opts cors.Options) cors.Options {
	opts.AllowCredentials = p.Credentials
	opts.AllowedOrigins = nil
	opts.AllowOriginFunc = nil
	// staticcheck SA1019: AllowOriginRequestFunc is deprecated upstream, and
	// clearing it is precisely why this line exists. rs/cors consults it BEFORE
	// AllowOriginFunc and AllowedOrigins (cors.go:153-159, verified in the
	// module source), so a caller that left a value there would override the
	// decision this function just made — including the deny-all branch. Not
	// naming the field is not an option: the field still exists and still wins.
	// This suppresses a deprecation notice on a defensive clear, not a finding.
	opts.AllowOriginRequestFunc = nil //nolint:staticcheck // clearing a deprecated field that still takes precedence
	opts.AllowOriginVaryRequestFunc = nil

	switch {
	case p.Wildcard:
		opts.AllowedOrigins = []string{"*"}
		opts.AllowCredentials = false
	case len(p.Origins) > 0:
		opts.AllowedOrigins = p.Origins
	default:
		// Deny every cross-origin request. Expressed as a func, NOT as an empty
		// AllowedOrigins slice, which rs/cors reads as "allow all" — see the
		// package doc.
		opts.AllowOriginFunc = func(string) bool { return false }
		opts.AllowCredentials = false
	}

	return opts
}

// Allow reports the Access-Control-Allow-Origin value to emit for origin, and
// whether credentials may be advertised alongside it. ok is false when the
// origin is refused, in which case NO ACAO header must be written at all —
// writing an empty one is not the same thing.
//
// This is for handlers that answer their own OPTIONS instead of delegating to
// the rs/cors middleware — currently only the agent's MCP server handler. It
// resolves from the SAME Policy the middleware is built from, so the two cannot
// disagree about configuration. They can still differ in matching, in exactly
// two ways, and both are worth stating because "they cannot diverge" would be
// false:
//
//   - Case. Origin comparison here folds case (EqualFold), which is what
//     rs/cors does — it lowercases both the configured list (cors.go:174) and
//     the request Origin (cors.go:469). Without the fold, an operator who wrote
//     `https://Portal.Example.com` would be admitted by the middleware and
//     refused here.
//   - Patterns. An entry containing `*` is prefix/suffix-matched by rs/cors but
//     matched EXACTLY here, so this refuses origins the middleware would admit.
//     That divergence is deliberate and one-directional: it can only ever deny
//     more, never allow more. Credentials are already off for a pattern list
//     (see ResolveWithCommunityFallback), so nothing here can leak them.
func (p Policy) Allow(origin string) (value string, credentials, ok bool) {
	if origin == "" {
		return "", false, false
	}
	if p.Wildcard {
		// Deliberately the literal "*", matching what rs/cors emits for the
		// same policy, and never paired with credentials.
		return "*", false, true
	}
	for _, o := range p.Origins {
		if strings.EqualFold(o, origin) {
			return origin, p.Credentials, true
		}
	}
	return "", false, false
}

// ParseAllowedOrigins splits the comma-separated env value, trimming each entry
// and dropping empties so that a trailing comma or a stray space cannot produce
// an "" origin (which rs/cors would never match, but which would silently make
// the list non-empty and so suppress the community fallback).
func ParseAllowedOrigins(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if o := strings.TrimSpace(part); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// ContainsWildcardOrigin reports whether the operator explicitly listed "*".
func ContainsWildcardOrigin(origins []string) bool {
	for _, o := range origins {
		if o == "*" {
			return true
		}
	}
	return false
}

// containsPatternOrigin reports whether any entry contains a `*` WITHOUT being
// the bare `*` — `https://*.example.com`, say.
//
// This exists because rs/cors does not treat entries as exact strings. It
// splits on the first `*` and matches prefix + suffix, so such an entry admits
// an unenumerated set of origins. Every credential decision in this package
// depends on knowing whether the allowlist is a set someone actually wrote
// down, so the two cases have to be told apart before Credentials is set.
func containsPatternOrigin(origins []string) bool {
	for _, o := range origins {
		if o != "*" && strings.Contains(o, "*") {
			return true
		}
	}
	return false
}
