//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"net/http"
)

// PluginClaimContext is the community-edition placeholder for the enterprise
// type with the same name. Community builds never populate it; downstream
// handlers that read PluginClaimFromContext will always see nil.
type PluginClaimContext struct {
	LicenseID        string
	Tier             string
	JTI              string
	Entitlements     map[string]interface{}
	StripeCustomerID string
}

// PluginClaimFromContext is a community-edition stub that always returns
// nil. Plugin-claim is a paid Pro tier feature only available in
// enterprise / community-saas builds.
func PluginClaimFromContext(_ context.Context) *PluginClaimContext {
	return nil
}

// PluginClaimMiddleware in community builds is a no-op pass-through.
// Plugin-claim license validation requires enterprise license-validation
// primitives (Ed25519 verification + plugin_user_licenses table). Community
// self-hosted deployments don't ship with these — the middleware silently
// forwards every request to the next handler.
func PluginClaimMiddleware(_ *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}
