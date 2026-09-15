//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "testing"

// minDistinctShippedRealms is the community edition's realm count: the five
// BuiltinRealms and nothing else. oidc_realm.go is enterprise-tagged, so a
// community build has no OIDC configuration to declare a realm from and this
// is not an omission.
const minDistinctShippedRealms = 5

// editionShippedRealms contributes the realms this edition ships beyond the
// built-in five. Community ships none.
//
// It is a declared empty rather than an absent function so the census in
// realm_subject_type_singleton_test.go reads identically in both arms, and so
// the community arm states its population rather than inheriting it from a
// file that is not there.
func editionShippedRealms(t *testing.T, _ BuiltinRealmDeployment) []TrustRealm {
	t.Helper()
	return nil
}
