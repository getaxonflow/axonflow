// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"
)

// TestRequestIdentityFromContext verifies the v9 typed identity helper
// reads each individual context key correctly. Empty values are valid —
// service-to-service callers leave UserID empty.
func TestRequestIdentityFromContext(t *testing.T) {
	t.Run("all three populated", func(t *testing.T) {
		ctx := context.Background()
		ctx = context.WithValue(ctx, ContextKeyOrgID, "acme-corp")
		ctx = context.WithValue(ctx, ContextKeyClientID, "acme-prod-api")
		ctx = context.WithValue(ctx, ContextKeyUserID, "1234")
		got := RequestIdentityFromContext(ctx)
		want := RequestIdentity{OrgID: "acme-corp", ClientID: "acme-prod-api", UserID: "1234"}
		if got != want {
			t.Errorf("RequestIdentityFromContext = %+v, want %+v", got, want)
		}
	})

	t.Run("empty when keys not set", func(t *testing.T) {
		got := RequestIdentityFromContext(context.Background())
		if got != (RequestIdentity{}) {
			t.Errorf("RequestIdentityFromContext on empty ctx = %+v, want zero value", got)
		}
	})

	t.Run("service-to-service has empty UserID", func(t *testing.T) {
		ctx := context.Background()
		ctx = context.WithValue(ctx, ContextKeyOrgID, "axonflow-community-saas")
		ctx = context.WithValue(ctx, ContextKeyClientID, "internal-svc")
		got := RequestIdentityFromContext(ctx)
		if got.UserID != "" {
			t.Errorf("UserID should be empty for service-to-service, got %q", got.UserID)
		}
		if got.OrgID != "axonflow-community-saas" || got.ClientID != "internal-svc" {
			t.Errorf("OrgID/ClientID misread: got %+v", got)
		}
	})
}

// TestWithRequestIdentity verifies the round-trip helper stamps all keys
// the individual readers expect — including the legacy TenantID alias
// (ADR-052 §5) so deprecated TenantIDFromContext readers don't see
// blanks during the v9 window.
func TestWithRequestIdentity(t *testing.T) {
	id := RequestIdentity{OrgID: "cs_demo", ClientID: "cs_demo", UserID: "7"}
	ctx := WithRequestIdentity(context.Background(), id)

	if got := OrgIDFromContext(ctx); got != id.OrgID {
		t.Errorf("OrgIDFromContext = %q, want %q", got, id.OrgID)
	}
	if got := ClientIDFromContext(ctx); got != id.ClientID {
		t.Errorf("ClientIDFromContext = %q, want %q", got, id.ClientID)
	}
	if got := UserIDFromContext(ctx); got != id.UserID {
		t.Errorf("UserIDFromContext = %q, want %q", got, id.UserID)
	}
	// Deprecated tenant alias must also be populated so legacy readers
	// behind the compatibility window do not break (ADR-052 §5).
	if got := TenantIDFromContext(ctx); got != id.ClientID {
		t.Errorf("TenantIDFromContext (compat alias) = %q, want %q", got, id.ClientID)
	}
}

// TestUserIDFromContext locks in the helper for v9 typed identity. The
// service-to-service case (empty user id) must return "" — that is the
// correct shape that downstream audit writers treat as "no human user".
func TestUserIDFromContext(t *testing.T) {
	t.Run("returns value when set", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyUserID, "user-42")
		if got := UserIDFromContext(ctx); got != "user-42" {
			t.Errorf("UserIDFromContext = %q, want %q", got, "user-42")
		}
	})
	t.Run("empty when not set", func(t *testing.T) {
		if got := UserIDFromContext(context.Background()); got != "" {
			t.Errorf("UserIDFromContext on empty ctx = %q, want empty", got)
		}
	})
	t.Run("empty for wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyUserID, 42)
		if got := UserIDFromContext(ctx); got != "" {
			t.Errorf("UserIDFromContext = %q, want empty for wrong type", got)
		}
	})
}

// TestTenantIDFromContext_DeprecatedAliasBehavior — the deprecated
// TenantIDFromContext continues to read ContextKeyTenantID, not
// ContextKeyClientID. This is INTENTIONAL: on the Enterprise auth path
// the two values can intentionally differ (Client.TenantID is the
// hardcoded scope tag, Client.ID is the Basic Auth username). Conflating
// them silently would break data-isolation queries; the migration is
// supposed to be explicit per-row per Epic #2230 Phase 1/2.
func TestTenantIDFromContext_DeprecatedAliasBehavior(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyClientID, "client-username")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "hardcoded-scope-tag")

	if got := ClientIDFromContext(ctx); got != "client-username" {
		t.Errorf("ClientIDFromContext = %q, want %q", got, "client-username")
	}
	// Compat alias still returns the legacy scope tag — NOT the client id.
	// Auditors of this test: if you "fix" this to read ClientID, you
	// break Enterprise multi-credential row scoping. See ADR-052 §5.
	if got := TenantIDFromContext(ctx); got != "hardcoded-scope-tag" {
		t.Errorf("TenantIDFromContext (deprecated) = %q, want %q (compat alias must preserve)",
			got, "hardcoded-scope-tag")
	}
}
