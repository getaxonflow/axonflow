// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import "crypto/ed25519"

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
