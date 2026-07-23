//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Empirical gate (#2991, method per #2937): a token this dev endpoint mints
// must be accepted on BOTH governance planes and resolve the role that drives
// role-scoped reads — proven against the REAL validators, not a mock. Before
// #2991 the dev token carried no iss/email/jti, so the fleet HS256 validator
// rejected it outright ("iss claim is required") and the role never reached the
// read-scope layer.

import (
	"context"
	"testing"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// notRevokedStub reports every token live — the gate only proves claim-shape
// acceptance + role resolution, not revocation (covered elsewhere).
type notRevokedStub struct{}

func (notRevokedStub) IsRevoked(ctx context.Context, orgID, jti, email string, issuedAt time.Time) (bool, error) {
	return false, nil
}

func TestDevToken_MintedTokenAcceptedByBothValidators(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key-abcdef012345")
	// Non-community so validateUserToken actually parses (community bypasses).
	t.Setenv("DEPLOYMENT_MODE", "evaluation")

	fleetValidator, err := sharedidentity.NewHS256Validator(jwtSecret, notRevokedStub{})
	if err != nil {
		t.Fatalf("build fleet HS256 validator: %v", err)
	}

	cases := []struct {
		name           string
		body           string
		wantRole       string
		wantTenantWide bool
	}{
		{"default→developer (own-rows)", "", "developer", false},
		{"admin (tenant-wide)", `{"role":"admin"}`, "admin", true},
		{"viewer (own-rows)", `{"role":"viewer"}`, "viewer", false},
		{"owner (tenant-wide)", `{"role":"owner"}`, "owner", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := mintDevToken(t, c.body, "acme-ops", "acme-org")
			if rec.Code != 200 {
				t.Fatalf("mint status = %d; body=%s", rec.Code, rec.Body.String())
			}
			resp := decodeDevTokenResp(t, rec)

			// (1) FLEET plane — this is what makes role-scoped reads work.
			vid, err := fleetValidator.Validate(context.Background(), "acme-org", resp.UserToken)
			if err != nil {
				t.Fatalf("FLEET validator REJECTED the minted token: %v", err)
			}
			if vid.Role != c.wantRole {
				t.Errorf("fleet-resolved role = %q, want %q", vid.Role, c.wantRole)
			}
			if vid.Email != resp.Email {
				t.Errorf("fleet-resolved email = %q, want %q (own-rows key)", vid.Email, resp.Email)
			}
			if got := sharedidentity.RoleCanReadTenant(vid.Role); got != c.wantTenantWide {
				t.Errorf("RoleCanReadTenant(%q) = %v, want %v (tenant-wide vs own-rows)", vid.Role, got, c.wantTenantWide)
			}
			// The minted email must NOT be a shared synthetic identity, or a
			// developer/viewer read would fail closed to zero rows.
			if sharedidentity.IsSharedSyntheticIdentity(vid.Email, false) {
				t.Errorf("minted email %q is a shared synthetic identity — own-rows would fail closed", vid.Email)
			}
			// Org binding: the same token must NOT validate for another org.
			if _, err := fleetValidator.Validate(context.Background(), "other-org", resp.UserToken); err == nil {
				t.Error("fleet validator accepted the token for the WRONG org (org binding broken)")
			}

			// (2) LEGACY body-token plane.
			user, err := validateUserToken(resp.UserToken, "acme-ops")
			if err != nil {
				t.Fatalf("LEGACY validateUserToken REJECTED the minted token: %v", err)
			}
			if user.TenantID != "acme-ops" {
				t.Errorf("legacy TenantID = %q, want acme-ops (forced to the Basic username)", user.TenantID)
			}
			if user.OrgID != "acme-org" {
				t.Errorf("legacy OrgID = %q, want acme-org", user.OrgID)
			}
			if user.Role != c.wantRole {
				t.Errorf("legacy role = %q, want %q", user.Role, c.wantRole)
			}
		})
	}
}
