//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// Community stub for the enterprise OIDC realm source (#3550), mirroring the
// pattern every other Enterprise-only backend in this package uses
// (provisioning_community.go, identity_attribute_resolver_community.go): the
// SYMBOL exists in both editions so the shared boot wiring compiles
// unconditionally, and only the behaviour differs.
//
// A community build federates no IdP: there is no sso_configurations table to
// read and no OIDC verifier registered, so an OIDC token presented to a
// community deployment is never validated and never produces a realm. That is
// the correct answer, not a gap - and it is reached by the caller skipping
// ErrEnterpriseOnly exactly as it does for every other Enterprise capability,
// rather than by a silent no-op source that would report "no OIDC realm
// declared" in a build where one could never exist.

// NewOIDCRealmSource is Enterprise-only. See the enterprise file for the real
// implementation.
func NewOIDCRealmSource(_ *RealmRegistry, _ OIDCConfigProvider, _ BuiltinRealmDeployment, _ ...OIDCRealmSourceOption) (CompatRealmSource, error) {
	return nil, ErrEnterpriseOnly
}
