// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package secretenv

import (
	"encoding/base64"
	"errors"
	"strings"
)

// ErrNotSet reports that the named environment variable is unset or holds
// nothing but whitespace. Callers match it with errors.Is to keep their own
// "not configured" diagnostic — which names the variable and what belongs in
// it — instead of surfacing a decode error for a value that was never there.
var ErrNotSet = errors.New("environment variable not set")

// GetBase64Seed reads the named environment variable and returns its decoded
// bytes. It is the entry point for loading the licence signing seed and the
// audit signing key out of the environment, and it exists so that "which
// base64 dialects does this deployment accept?" has one answer for those
// readers rather than one per binary.
//
// It is NOT yet the only base64-secret decoder in the repository, and the
// comment should not claim it is: a census of every base64 decode of a
// secret-shaped input (#3710) also found getPluginClaimPublicKey in both
// copies of the licence package and NewCredentialEncryptorFromKey in
// platform/connectors/config, all three still on base64.StdEncoding alone.
// Those are tracked separately; naming them here is what keeps the next
// reader from taking "single entry point" on trust.
//
// THAT CENSUS WAS BASE64-SCOPED, and its scope is stated here so a future
// reader does not mistake it for an enumeration of the class this function
// belongs to. The class is "a secret an operator pastes is consumed
// byte-exact", and it has members with no base64 in them at all - where the
// paste artefact is NOT forgiven the way base64 forgives a newline. The
// shipped counter-example is the HITL webhook HMAC signing key, read bare with
// os.Getenv in both copies of platform/agent/hitl/webhook.go and handed
// straight to hmac.New: a trailing newline there changes the key bytes and the
// receiver 401s with no diagnostic. That is the failure this package's own
// doc comment describes, and the HMAC seed is named in the rule it states
// ("use secretenv.Get instead of os.Getenv for any value treated as a
// secret"). The wider class, its sizing and a published instrument for
// re-deriving it are #3733; the umbrella is #3709.
//
// Two normalisations happen here, and both are load-bearing — but not for the
// reason #3710 originally gave:
//
//  1. Surrounding whitespace is trimmed (via Get). Note that Go's base64
//     decoder already IGNORES '\r' and '\n' at every position, leading,
//     interior and trailing, so a plain trailing newline was never the
//     failure. What the decoder rejects is a trailing SPACE or TAB
//     ("illegal base64 data at input byte 44" for a 44-character padded
//     seed), which is what `kubectl create secret`, a copied console field
//     and an editor that strips nothing actually leave behind.
//
//  2. All four common base64 dialects are accepted: standard (padded),
//     raw-standard (unpadded), URL-safe (padded) and raw-URL-safe (unpadded).
//     This is the cause that bit operators most: an UNPADDED value fails
//     under standard encoding ("illegal base64 data at input byte 40" for a
//     32-byte seed), and so does the URL-safe alphabet. Operators paste seeds
//     from `openssl rand -base64`, from a cloud console, and from in-house
//     keygen tools, and those sources do not agree on padding or on the 62/63
//     alphabet. All four spellings of one seed decode to the same bytes, so
//     rejecting three of them buys nothing.
//
// Returns ErrNotSet itself — not a wrapping of it, so errors.Is and == both
// match — when the variable is unset or all-whitespace, so a caller can
// distinguish "not configured" from "configured with something undecodable".
// On a decode failure the returned error is the standard-encoding error,
// because standard padded base64 is the documented form and its message is
// the one that describes the input the operator was told to supply.
//
// The returned length is NOT checked: callers know how many bytes their own
// key type needs and report the mismatch in their own terms.
func GetBase64Seed(key string) ([]byte, error) {
	v := Get(key)
	if v == "" {
		return nil, ErrNotSet
	}
	return DecodeBase64Tolerant(v)
}

// DecodeBase64Tolerant trims surrounding whitespace from s and decodes it
// from whichever of the four common base64 dialects accepts it: standard
// (padded), raw-standard (unpadded), URL-safe (padded), raw-URL-safe
// (unpadded). The first success wins.
//
// The trim is part of the contract, not a convenience at the call site: a
// helper whose callers each have to remember to trim first is the divergence
// this function was consolidated to end. Prefer GetBase64Seed when the value
// comes straight from an environment variable — it distinguishes "not set"
// from "set to something undecodable". This entry point is for callers that
// already hold the string (an element of a comma-separated list, say).
//
// When every dialect fails, the error returned is the one from standard
// encoding: that is the documented form, so its byte offset refers to the
// input the operator was actually asked for.
func DecodeBase64Tolerant(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return nil, err
}
