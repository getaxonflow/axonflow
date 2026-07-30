// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOverrideHandlerShape_NonUUIDOrg_RealPostgres closes the reasoning-only gap
// in the #2792 fix (migration_133_org_id_text_test.go proves the migration, not
// the handler). It drives the REAL override create path (PolicyOverrideRepository
// .Create — the same call HandleCreateOverride makes) with the shape the FIXED
// handler now produces: `organization_id` NULL, `org_id` + `tenant_id` set to a
// FREE-FORM (non-UUID) org string. It then asserts that override is:
//
//	(a) applied by the REAL eval-time path StaticPolicyRepository.GetEffective —
//	    the LEFT JOIN on sp.id::text = po.policy_id::text that a policy evaluation
//	    actually resolves — so KTP block becomes warn,
//	(b) returned by GetOverrideForPolicy with organization_id STILL NULL (proving
//	    the fix left the legacy uuid column NULL rather than binding the string),
//	(c) deletable via Delete.
//
// Fidelity note (folds a round-2 review finding): production
// `policy_overrides.policy_id` is `UUID NOT NULL` (mig 030) and the portal sends
// the static policy's UUID `id` to POST /static-policies/{id}/override, so the
// override row keys on the static-policy UUID. The test declares the column UUID
// and stores that UUID (NOT the human policy_id string) so it exercises the same
// JOIN production evaluation uses — and would surface a policy_id-column UUID
// regression, the direct sibling of the organization_id class fixed in #2792.
//
// The org string is deliberately a free-form, non-UUID license id so the test
// also guards the #2792 regression class end-to-end.
func TestOverrideHandlerShape_NonUUIDOrg_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB

	const org = "acme-eval-org" // free-form, NON-UUID license id (the #2792 class)

	// #3065 (F7): the override by-id read is org-scoped and fails closed when
	// the caller org is unknown, so the context must carry the authenticated
	// org exactly as the request path supplies it.
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, org)
	const tenant = "acme-eval-org"

	// Post-133 schema: organization_id is TEXT on both policy tables; policy_id is
	// UUID (mig 030). clients is consulted by isEnterpriseLicense (Enterprise gates
	// override create). Only the columns the repositories read/write are declared.
	pc.RunMigration(t, `
		CREATE TABLE clients (
			tenant_id  varchar(255) PRIMARY KEY,
			license_tier varchar(50),
			enabled    boolean NOT NULL DEFAULT true
		);
		CREATE TABLE static_policies (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id  varchar(255) UNIQUE,
			name       varchar(255),
			category   varchar(100),
			pattern    text,
			severity   varchar(50),
			description text,
			action     varchar(50),
			tier       varchar(50),
			priority   int,
			enabled    boolean,
			organization_id text,
			tenant_id  varchar(255),
			org_id     varchar(255),
			tags       text,
			metadata   text,
			version    int,
			created_at timestamptz DEFAULT now(),
			updated_at timestamptz DEFAULT now(),
			created_by varchar(255),
			updated_by varchar(255),
			deleted_at timestamptz
		);
		CREATE TABLE policy_overrides (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id  uuid NOT NULL,            -- matches prod mig 030 (UUID NOT NULL)
			policy_type varchar(50),
			organization_id text,
			tenant_id  varchar(100),
			org_id     varchar(255) NOT NULL,
			action_override varchar(50),
			enabled_override boolean,
			override_reason text,
			expires_at timestamptz,
			created_by varchar(255),
			created_at timestamptz DEFAULT now(),
			updated_by varchar(255),
			updated_at timestamptz DEFAULT now(),
			CONSTRAINT valid_override_scope CHECK (
				(organization_id IS NOT NULL AND tenant_id IS NULL) OR (tenant_id IS NOT NULL)
			)
		);
	`)

	// Enterprise license for the tenant (DB fallback path of isEnterpriseLicense).
	_, err := db.Exec(`INSERT INTO clients (tenant_id, license_tier, enabled) VALUES ($1, 'Enterprise', true)`, tenant)
	require.NoError(t, err)

	// A SYSTEM-tier block policy — only system policies are overridable. This is
	// the KTP block the design partner overrides to warn. Capture its UUID `id`:
	// that is what the portal sends to the override endpoint and what the eval-time
	// JOIN keys on. tenant_id is '' (not NULL) for system policies to match the
	// write path (GetByID scans it into a non-nullable string).
	var staticUUID string
	require.NoError(t, db.QueryRow(`
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tier, priority, enabled, tenant_id, org_id, version)
		VALUES ('sys_pii_indonesia_ktp', 'Indonesian KTP Detection', 'pii-indonesia', 'ktp', 'critical', 'block', 'system', 100, true, '', $1, 1)
		RETURNING id
	`, org).Scan(&staticUUID))

	repo := NewPolicyOverrideRepository(db)
	staticRepo := NewStaticPolicyRepository(db)

	// ---- Drive the REAL create path in the FIXED handler's shape ----
	// organization_id NULL, org_id + tenant_id set (both to the non-UUID org),
	// policy_id = the static policy's UUID (as the portal sends it).
	tenantVal := tenant
	warn := ActionWarn
	override := &PolicyOverride{
		PolicyID:       staticUUID,
		OrganizationID: nil, // #2792: legacy uuid column left NULL
		TenantID:       &tenantVal,
		OrgID:          org, // canonical varchar org (RLS key)
		ActionOverride: &warn,
		OverrideReason: "E2E #2793: KTP block->warn on non-UUID org",
	}
	require.NoError(t, repo.Create(ctx, override, "portal-admin"),
		"override create in the fixed handler's shape must succeed on a non-UUID org")

	// (a) REAL apply path: GetEffective resolves the override via the production
	// JOIN (sp.id::text = po.policy_id::text, tenant-scoped) → block becomes warn.
	orgPtr := org
	effective, err := staticRepo.GetEffective(ctx, tenant, &orgPtr)
	require.NoError(t, err)
	var ktp *EffectiveStaticPolicy
	for i := range effective {
		if effective[i].PolicyID == "sys_pii_indonesia_ktp" {
			ktp = &effective[i]
			break
		}
	}
	require.NotNil(t, ktp, "KTP system policy must appear in the effective set")
	assert.Equal(t, "block", ktp.Action, "base action is block")
	assert.True(t, ktp.HasOverride, "GetEffective must resolve the override the handler wrote")
	assert.Equal(t, "warn", ktp.EffectiveAction(), "effective action must be warn (block overridden)")

	// (b) fetchable, and organization_id is STILL NULL (the whole point of #2792).
	got, err := repo.GetOverrideForPolicy(ctx, staticUUID, &tenantVal, &orgPtr)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.OrganizationID, "the fix must leave organization_id NULL, not bind the string org")
	require.NotNil(t, got.TenantID)
	assert.Equal(t, tenant, *got.TenantID)
	require.NotNil(t, got.ActionOverride)
	assert.Equal(t, ActionWarn, *got.ActionOverride)

	// Belt-and-braces: the raw column is genuinely NULL in Postgres.
	var orgColNull bool
	require.NoError(t, db.QueryRow(
		`SELECT organization_id IS NULL FROM policy_overrides WHERE id = $1`, got.ID).Scan(&orgColNull))
	assert.True(t, orgColNull, "policy_overrides.organization_id must be SQL NULL")

	// (c) deletable.
	require.NoError(t, repo.Delete(ctx, got.ID, "portal-admin"))
	_, err = repo.GetOverrideForPolicy(ctx, staticUUID, &tenantVal, &orgPtr)
	assert.ErrorIs(t, err, ErrOverrideNotFound, "override must be gone after delete")
}
