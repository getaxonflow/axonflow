// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// This file is deliberately identical apart from its build constraint between
// `platform/agent/license/testing.go` and `ee/platform/agent/license/testing.go`:
// the platform copy serves both build tags and carries no constraint; the ee
// copy sits in an enterprise-only package and must carry `//go:build
// enterprise`. The shipped enterprise image overlays the ee copy onto the
// platform one (platform/agent/Dockerfile, EDITION=enterprise), and
// tests/regression-test-required/license_pair_byte_identity_test.sh holds the two
// identical after stripping that one line.

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// OverridePublicKeysForTest replaces the embedded production public keys with
// the provided test keys. Returns a function that restores the originals.
// This is intended for use in tests only — it is not safe for concurrent use.
func OverridePublicKeysForTest(evalPub, entPub ed25519.PublicKey) func() {
	savedEval := make(ed25519.PublicKey, len(evaluationPublicKey))
	savedEnt := make(ed25519.PublicKey, len(enterprisePublicKey))
	copy(savedEval, evaluationPublicKey)
	copy(savedEnt, enterprisePublicKey)

	copy(evaluationPublicKey, evalPub)
	copy(enterprisePublicKey, entPub)

	return func() {
		copy(evaluationPublicKey, savedEval)
		copy(enterprisePublicKey, savedEnt)
	}
}

// SignPayloadForTest renders payload in the shipped wire format
// AXON-{base64url(json)}.{base64url(sig)} and signs it with priv - the format
// keygen.go writes and both build tags' validators parse; only the signer
// differs. It exists so a test can mint what the keygen REFUSES to mint (an
// expired date, a tier this build does not issue) against a keypair installed
// with OverridePublicKeysForTest, without carrying its own copy of the wire
// encoding. Intended for use in tests only.
func SignPayloadForTest(priv ed25519.PrivateKey, payload ServiceLicensePayload) string {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic("license.SignPayloadForTest: " + err.Error())
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(raw)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	return "AXON-" + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ForgeSignatureForTest is the #3709 row-1 reproduction: the payload of key
// with its signature replaced by the literal bytes NOTASIG!. The payload is
// untouched, so a reader that trusts the payload still sees whatever tier it
// names. Intended for use in tests only.
func ForgeSignatureForTest(key string) string {
	dot := strings.LastIndex(key, ".")
	if dot < 0 {
		return key
	}
	return key[:dot+1] + base64.RawURLEncoding.EncodeToString([]byte("NOTASIG!"))
}
