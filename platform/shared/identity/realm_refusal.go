// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// RealmRefusalCode is the single machine-readable code every identity-plane
// refusal carries, on every plane and in every rendering.
//
// IT LIVES HERE, NOT IN package agent, AND THAT WAS THE BUG. An earlier
// revision declared it beside the agent's call sites, so the SHARED choke
// point (ResolveToken) structurally could not use it - and that is the fifth
// rendering. An operator filtering on this code during an enforce rollout
// would have missed every refusal from the fleet path, which is exactly the
// conflation the constant was introduced to end.
//
// The conflation it ends: an identity-plane refusal previously shared
// "invalid_user_token" with a tampered signature, so "my realm configuration
// is wrong" and "someone is forging tokens" were indistinguishable.
const RealmRefusalCode = "identity_realm_refused"
