// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package secretenv reads operator-provided secrets from environment
// variables, defensively trimming surrounding whitespace.
//
// AWS Secrets Manager (and operator copy-paste through shells, heredocs,
// and CI runners) routinely leaves trailing newline bytes on secret
// values. Most secret consumers feed those values into HTTP headers
// (Authorization: Bearer ...), HMAC inputs, or third-party SDK clients
// — all of which reject control characters and fail closed in
// confusing ways:
//
//   - Go's net/http rejects header values with control characters
//     (`net/http: invalid header field value for "Authorization"`).
//   - HMAC verification silently produces a different digest, so the
//     receiver returns a 401 with no diagnostic.
//   - Some SDKs (Stripe, Resend, Anthropic, OpenAI) construct the
//     header themselves and surface the same Go-stdlib error after
//     several frames of indirection.
//
// Use secretenv.Get instead of os.Getenv for any value treated as a
// secret (API key, signing key, password, HMAC seed). Non-secret
// configuration (URLs, hostnames, integers, booleans) should keep
// using os.Getenv — TrimSpace would silently mangle a legitimate
// space-containing value.
package secretenv

import (
	"os"
	"strings"
)

// Get returns the value of the named environment variable with
// surrounding whitespace trimmed. Equivalent to
// strings.TrimSpace(os.Getenv(key)).
//
// Values consisting only of whitespace are returned as the empty
// string, matching the os.Getenv contract for unset variables.
func Get(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
