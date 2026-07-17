//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"database/sql"
	"time"
)

// Community stubs for the Enterprise per-user token validation backends
// (#2924, epic #2919). The interfaces, registry, and CanonicalEmail contract
// (validator.go) are untagged so community code compiles against the same
// seam; the concrete validators are Enterprise-only. Signatures match the
// enterprise files exactly so call sites compile unconditionally.

// NewHS256Validator is Enterprise-only in community builds.
func NewHS256Validator(_ []byte, _ RevocationChecker) (TokenValidator, error) {
	return nil, ErrEnterpriseOnly
}

// OIDCVerifierOption matches the enterprise option type so option-passing
// call sites compile unconditionally (the option target is opaque here —
// there is no verifier to configure in a community build).
type OIDCVerifierOption func(any)

// WithOIDCLeeway is Enterprise-only in community builds (no-op option;
// signature mirrors the enterprise variant).
func WithOIDCLeeway(_ time.Duration) OIDCVerifierOption { return func(any) {} }

// NewOIDCVerifier is Enterprise-only in community builds.
func NewOIDCVerifier(_ OIDCConfigProvider, _ RoleResolver, _ ...OIDCVerifierOption) (TokenValidator, error) {
	return nil, ErrEnterpriseOnly
}

// NewDBRevocationStore is Enterprise-only in community builds.
func NewDBRevocationStore(_ *sql.DB) (RevocationChecker, error) {
	return nil, ErrEnterpriseOnly
}

// NewDBOIDCConfigProvider is Enterprise-only in community builds.
func NewDBOIDCConfigProvider(_ *sql.DB) (OIDCConfigProvider, error) {
	return nil, ErrEnterpriseOnly
}

// NewSCIMRoleResolver is Enterprise-only in community builds.
func NewSCIMRoleResolver(_ *sql.DB) (RoleResolver, error) {
	return nil, ErrEnterpriseOnly
}
