//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// defaultEmailClaim is used when the stored claim mapping does not name the
// identity claim. "email" is what JumpCloud/Okta/Azure AD emit for a standard
// OIDC profile+email scope.
const defaultEmailClaim = "email"

// dbOIDCConfigProvider loads per-tenant OIDC verifier configuration from
// sso_configurations (provider_type='oidc', core mig 143 columns).
type dbOIDCConfigProvider struct {
	db *sql.DB
}

// NewDBOIDCConfigProvider builds an OIDCConfigProvider over the shared
// platform database. sso_configurations is FORCE-RLS org-isolated, so reads
// run inside an org-scoped transaction.
func NewDBOIDCConfigProvider(db *sql.DB) (OIDCConfigProvider, error) {
	if db == nil {
		return nil, fmt.Errorf("identity: nil db for OIDC config provider")
	}
	return &dbOIDCConfigProvider{db: db}, nil
}

// OIDCConfigForOrg returns the org's enabled OIDC configuration, or
// ErrNotConfigured when the org has none (no row, row disabled, or row is a
// SAML config). A row that IS an enabled OIDC config but is missing any of
// issuer/audience/JWKS URI is an error, not ErrNotConfigured — a half-built
// config must fail loudly rather than let the resolver silently fall through
// to a weaker path.
func (p *dbOIDCConfigProvider) OIDCConfigForOrg(ctx context.Context, orgID string) (*OIDCConfig, error) {
	if orgID == "" {
		return nil, fmt.Errorf("identity: OIDC config lookup requires an org")
	}
	var (
		issuer, audience, jwksURI sql.NullString
		claimMapping              []byte
	)
	err := withOrgScope(ctx, p.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT oidc_issuer, oidc_audience, oidc_jwks_uri, oidc_claim_mapping
			FROM sso_configurations
			WHERE org_id = $1 AND provider_type = 'oidc' AND enabled = true
		`, orgID).Scan(&issuer, &audience, &jwksURI, &claimMapping)
	})
	if err == sql.ErrNoRows {
		return nil, ErrNotConfigured
	}
	if err != nil {
		return nil, fmt.Errorf("identity: OIDC config lookup failed: %w", err)
	}

	cfg := &OIDCConfig{
		OrgID:      orgID,
		Issuer:     strings.TrimSpace(issuer.String),
		Audience:   strings.TrimSpace(audience.String),
		JWKSURI:    strings.TrimSpace(jwksURI.String),
		EmailClaim: defaultEmailClaim,
	}
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.JWKSURI == "" {
		return nil, fmt.Errorf("identity: org %q has an enabled OIDC config with missing issuer/audience/jwks_uri", orgID)
	}
	if len(claimMapping) > 0 {
		var m map[string]string
		if err := json.Unmarshal(claimMapping, &m); err != nil {
			return nil, fmt.Errorf("identity: org %q oidc_claim_mapping is not valid JSON: %w", orgID, err)
		}
		if v := strings.TrimSpace(m["email"]); v != "" {
			cfg.EmailClaim = v
		}
	}
	return cfg, nil
}
