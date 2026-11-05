// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package checkoutbinding binds a deleted tenant's verified expired Checkout
// Session to its original attempt without retaining the raw Stripe identifiers
// in the erasure receipt.
package checkoutbinding

import (
	"crypto/sha256"
	"encoding/hex"
)

// Digest is an unambiguous digest of the tenant, attempt, and Stripe Session.
// The webhook still requires Stripe's valid signature before using it.
func Digest(tenantID, attemptID, sessionID string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + attemptID + "\x00" + sessionID))
	return hex.EncodeToString(sum[:])
}
