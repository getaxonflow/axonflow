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

	// Post-166 schema: the legacy organization_id column is GONE from both
	// policy tables (#3334), and valid_override_scope went with it - Postgres
	// drops a CHECK when a column it references is dropped, and the property
	// it guaranteed ("every override carries an organisation") is now
	// migration core/165's NOT NULL on org_id, unconditionally. policy_id is
	// UUID (mig 030).
	//
	// THIS DDL IS HAND-BUILT AND THEREFORE CANNOT PROVE ANYTHING ABOUT THE
	// MIGRATIONS. It is kept because the behaviour under test is repository
	// SQL against a real Postgres, not schema evolution - but no assertion
	// here may claim a migration ran, because the only thing such an
	// assertion would check is this literal. The migration's own effect is
	// proven in migrations/core/166 and by the runtime-e2e suite. clients is consulted by isEnterpriseLicense (Enterprise gates
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
			tenant_id  varchar(255),
			org_id     varchar(255),
			segment_id varchar(255),
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
			tenant_id  varchar(100),
			org_id     varchar(255) NOT NULL,
			action_override varchar(50),
			enabled_override boolean,
			override_reason text,
			expires_at timestamptz,
			-- #3490: the Mechanism-A override read filters revoked_at now, as
			-- the Mechanism-B matcher always has.
			revoked_at timestamptz,
			created_by varchar(255),
			created_at timestamptz DEFAULT now(),
			updated_by varchar(255),
			updated_at timestamptz DEFAULT now(),
			CONSTRAINT valid_override_scope CHECK (
				tenant_id IS NULL OR tenant_id <> ''
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
	// org_id + tenant_id set (both to the non-UUID org), policy_id = the
	// static policy's UUID (as the portal sends it).
	//
	// #3334: the OrganizationID field this literal used to set to nil is gone
	// with the column (migration core/166). The property this test exists for
	// is UNCHANGED and is now structural rather than conventional: a non-UUID
	// org must not break the override create path, and there is no longer a
	// uuid-typed column for it to break against.
	tenantVal := tenant
	warn := ActionWarn
	override := &PolicyOverride{
		PolicyID:       staticUUID,
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
	effective, err := staticRepo.GetEffective(ctx, tenant, &orgPtr, nil)
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

	// (b) fetchable, carrying the non-UUID org in the column that is meant to
	// hold it.
	//
	// #3334 changed what this leg can assert, and made it stronger. #2792's
	// original claim was "organization_id is STILL NULL" - the fix of the day
	// was to stop binding a non-UUID org into a uuid-typed column. Migration
	// core/166 removes that column, so the failure mode it guarded against is
	// now unrepresentable rather than merely avoided, and there is nothing left
	// to assert NULL about. What replaces it is the positive claim: the
	// non-UUID org round-trips through org_id, the column that has been VARCHAR
	// since core/110 and that now carries the organisation for every row.
	got, err := repo.GetOverrideForPolicy(ctx, staticUUID, &tenantVal, &orgPtr)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, org, got.OrgID, "the non-UUID org must round-trip through org_id")
	require.NotNil(t, got.TenantID)
	assert.Equal(t, tenant, *got.TenantID)
	require.NotNil(t, got.ActionOverride)
	assert.Equal(t, ActionWarn, *got.ActionOverride)

	// A "the column is gone" assertion was considered here and DELETED. This
	// test builds its own DDL a few lines up, so such an assertion would read
	// back the literal above and pass no matter what migration core/166 does -
	// a check that cannot fail. The migration's effect is asserted where the
	// migration actually runs: its own self-test block, and the runtime-e2e
	// suite against a real migrated database.

	// (c) deletable.
	require.NoError(t, repo.Delete(ctx, got.ID, "portal-admin"))
	_, err = repo.GetOverrideForPolicy(ctx, staticUUID, &tenantVal, &orgPtr)
	assert.ErrorIs(t, err, ErrOverrideNotFound, "override must be gone after delete")
}
