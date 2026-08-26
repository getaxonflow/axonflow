// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"log"
	"net/http"

	"axonflow/platform/shared/corspolicy"

	"github.com/rs/cors"
)

// corsAllowedOriginsEnv is re-exported from the shared package so this file's
// tests, and any future agent-local reference, name the variable once.
const corsAllowedOriginsEnv = corspolicy.AllowedOriginsEnv

// resolveCORSOptions builds the CORS policy for the agent's HTTP surface.
//
// #3096 part 2 introduced the policy; #3161 moved it to
// platform/shared/corspolicy so that the agent, the orchestrator and the
// customer-portal cannot drift apart — they had, and the portal's divergent
// copy is what #3161 is. The table, the rs/cors caveats and the reasoning all
// live in that package's doc comment; this file is now only the agent's
// request-shaping (methods and headers) plus the startup log line.
//
// The agent differs from the orchestrator in one respect, deliberately: it also
// exposes applyCORSPreflightHeaders, because mcp_server_handler.go answers its
// own OPTIONS and therefore needs the policy as headers rather than as
// cors.Options. The orchestrator has no equivalent — every direct
// Access-Control-Allow-Origin write there is either a credential-less literal
// `*` or guarded by a package-local allowlist map — so an unused helper there
// would be dead code.
func resolveCORSOptions() cors.Options {
	policy := corspolicy.Resolve()
	if policy.Notice != "" {
		log.Print(policy.Notice)
	}

	return policy.Apply(cors.Options{
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		// #1431. AllowedHeaders governs REQUEST headers; it does nothing for
		// response headers, and neither Deprecation nor Link is on the CORS
		// safelist. Without this a browser client gets null from
		// response.headers.get("Deprecation") - so the deprecation signal on
		// the legacy policy paths, and the Link naming the successor that the
		// public docs tell clients to follow, would be invisible to the
		// largest class of caller there is.
		ExposedHeaders: []string{"Deprecation", "Link"},
	})
}

// applyCORSPreflightHeaders writes the CORS response headers for a handler that
// answers its own OPTIONS request instead of delegating to the rs/cors
// middleware. It routes through the same policy the middleware is built from,
// so there is exactly one place that decides which origins are allowed.
//
// A refused origin gets Vary plus the method/header advertisements and NO
// Access-Control-Allow-Origin, which is how rs/cors itself denies: the browser
// then blocks the request.
func applyCORSPreflightHeaders(w http.ResponseWriter, origin, allowMethods, allowHeaders string) {
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", allowMethods)
	w.Header().Set("Access-Control-Allow-Headers", allowHeaders)

	// corspolicy.Resolve() deliberately does not log: this runs on the request
	// path, and a per-request log line for a denied preflight is a free remote
	// log-flood.
	value, credentials, ok := corspolicy.Resolve().Allow(origin)
	if !ok {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", value)
	if credentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

// parseAllowedOrigins is retained as a package-local alias of the shared
// parser. The agent's own regression tests exercise it directly, and the
// parsing rule — a trailing comma or a stray space must not create an ""
// origin, because a non-empty list suppresses the community fallback — is worth
// pinning from both sides.
func parseAllowedOrigins(raw string) []string {
	return corspolicy.ParseAllowedOrigins(raw)
}
