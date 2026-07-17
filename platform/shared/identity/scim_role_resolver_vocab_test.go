//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "testing"

// The fleet vocabulary exposed by FleetRoleNames (from the untagged knownRoles
// map) MUST equal what the enterprise resolver actually keys on:
// rolePrecedence + admin. These are two separate declarations of the same role
// set — this guards them against drift so a role added to one but not the other
// (e.g. a new 'auditor' role recognized by the resolver but rejected by the
// SCIM mapping gate, or vice versa) fails loudly here. #2963.
//
// Enterprise-tagged because rolePrecedence is defined only in the enterprise
// build (scim_role_resolver.go).
func TestFleetRoleNames_MatchesResolverPrecedence(t *testing.T) {
	want := map[string]bool{"admin": true}
	for _, r := range rolePrecedence {
		want[r] = true
	}
	got := map[string]bool{}
	for _, n := range FleetRoleNames() {
		got[n] = true
	}
	for r := range want {
		if !got[r] {
			t.Errorf("resolver role %q missing from FleetRoleNames — the SCIM mapping gate would reject a role the resolver accepts", r)
		}
	}
	for r := range got {
		if !want[r] {
			t.Errorf("FleetRoleNames has %q which is neither admin nor in rolePrecedence — the gate would accept a role the resolver drops to least-privilege", r)
		}
	}
}
