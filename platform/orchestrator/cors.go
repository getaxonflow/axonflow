// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"log"

	"axonflow/platform/shared/corspolicy"

	"github.com/rs/cors"
)

// corsAllowedOriginsEnv is re-exported from the shared package so this file's
// tests, and any future orchestrator-local reference, name the variable once.
const corsAllowedOriginsEnv = corspolicy.AllowedOriginsEnv

// resolveCORSOptions builds the CORS policy for the orchestrator's HTTP surface.
//
// #3096 part 2 introduced the policy; #3161 moved it to
// platform/shared/corspolicy so that the orchestrator, the agent and the
// customer-portal cannot drift apart — they had, and the portal's divergent
// copy is what #3161 is. The table, the rs/cors caveats and the reasoning all
// live in that package's doc comment; this file is now only the orchestrator's
// request-shaping (methods and headers) plus the startup log line.
//
// Failing closed for an unset variable outside community mode is safe here: the
// shipped browser client (customer-portal-ui) calls its own Next.js origin and
// is proxied server-side, so it is same-origin by construction, and since #3068
// the orchestrator has no browser-facing ALB listener at all.
func resolveCORSOptions() cors.Options {
	policy := corspolicy.Resolve()
	if policy.Notice != "" {
		log.Print(policy.Notice)
	}

	return policy.Apply(cors.Options{
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		// #1431. See the identical note on the agent: AllowedHeaders is about
		// REQUEST headers, and a response header that is not CORS-safelisted
		// is unreadable to a browser client unless it is exposed here. The
		// tenant-policy family is stamped on this plane and the header is
		// copied back through the agent's reverse proxy, so this is where its
		// visibility is decided.
		ExposedHeaders: []string{"Deprecation", "Link"},
	})
}

// parseAllowedOrigins is retained as a package-local alias of the shared
// parser. The orchestrator's own regression tests exercise it directly, and the
// parsing rule — a trailing comma or a stray space must not create an ""
// origin, because a non-empty list suppresses the community fallback — is worth
// pinning from both sides.
func parseAllowedOrigins(raw string) []string {
	return corspolicy.ParseAllowedOrigins(raw)
}
