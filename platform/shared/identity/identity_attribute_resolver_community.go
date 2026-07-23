//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
)

// Community stub for the Enterprise IdentityAttributeResolver (ADR-060,
// #2989). The type shapes here MUST mirror identity_attribute_resolver.go
// exactly (same pattern as the other Enterprise-only backends in
// provisioning_community.go) so call sites compile unconditionally in both
// editions; only NewIdentityAttributeResolver's behavior differs (Enterprise-
// only, since SCIM is Enterprise-only).

// SegmentID identifies a governance segment (ADR-060). See the enterprise
// file for the full doc; unused directly in a community build but kept
// symbol-identical so shared call sites compile unconditionally.
type SegmentID string

// ResolvedIdentity mirrors the enterprise type. See identity_attribute_
// resolver.go for the field docs.
type ResolvedIdentity struct {
	Role     string
	Segments []SegmentID
}

// IdentityAttributeResolver mirrors the enterprise interface (embeds
// RoleResolver) so a resolver value can be used directly wherever a
// RoleResolver is expected.
type IdentityAttributeResolver interface {
	RoleResolver
	Resolve(ctx context.Context, orgID, email string) (ResolvedIdentity, error)
}

// NewIdentityAttributeResolver is Enterprise-only in community builds — SCIM,
// its underlying identity source, is an Enterprise capability.
func NewIdentityAttributeResolver(_ *sql.DB) (IdentityAttributeResolver, error) {
	return nil, ErrEnterpriseOnly
}
