// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "context"

// RequestIdentity is the v9 typed identity carried through request context.
//
// See ADR-052 (v9 identity model) and ADR-053 §Step 2 (code identity
// migration). The three concepts are kept distinct so that downstream
// handlers, audit writers, and the RLS plumbing planned for Phase 7 can
// read the value they actually need instead of overloading TenantID:
//
//   - OrgID    — customer/account organization identity (RLS boundary).
//   - ClientID — authenticated API credential/app/service identity within OrgID.
//   - UserID   — human user inside the org (empty for service-to-service calls).
//
// During the v9 compatibility window, ClientID equals the legacy TenantID
// for most paths (Community-SaaS, in-VPC clients with one credential).
// Enterprise multi-credential deployments may distinguish them once
// per-row classification lands in Phase 1/2 of Epic #2230.
type RequestIdentity struct {
	OrgID    string
	ClientID string
	UserID   string
}

// RequestIdentityFromContext extracts the v9 typed identity from request
// context. Empty-string fields are normal during the compatibility window
// — for example, UserID is empty for service-to-service callers that did
// not present a user token.
func RequestIdentityFromContext(ctx context.Context) RequestIdentity {
	return RequestIdentity{
		OrgID:    OrgIDFromContext(ctx),
		ClientID: ClientIDFromContext(ctx),
		UserID:   UserIDFromContext(ctx),
	}
}

// WithRequestIdentity stores the v9 typed identity on ctx using the same
// individual keys that OrgIDFromContext / ClientIDFromContext /
// UserIDFromContext read. Stamping all three from one helper keeps tests
// and integration callers from forgetting a key.
//
// Empty-string fields are stored as-is (callers that want to preserve
// existing values should layer their own merges before calling).
func WithRequestIdentity(ctx context.Context, id RequestIdentity) context.Context {
	ctx = context.WithValue(ctx, ContextKeyOrgID, id.OrgID)
	ctx = context.WithValue(ctx, ContextKeyClientID, id.ClientID)
	ctx = context.WithValue(ctx, ContextKeyUserID, id.UserID)
	// TenantID stays a v9 compatibility alias of ClientID — see ADR-052 §5.
	// Stamping it from the same value keeps legacy TenantIDFromContext()
	// readers stable for the compatibility window.
	ctx = context.WithValue(ctx, ContextKeyTenantID, id.ClientID)
	return ctx
}

// UserIDFromContext extracts the auth-derived user ID from request
// context. Returns the empty string for service-to-service callers that
// did not present a user token.
func UserIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyUserID).(string); ok {
		return v
	}
	return ""
}
