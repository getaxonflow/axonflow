// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres tests for StaticPolicyRepository.GetEffective's segment
// selection (ADR-060 #2989 P3, issue #3051, Decision 2 — LOCKED). sqlmock
// (the unit-test double used elsewhere in this package) cannot validate a
// real SQL WHERE clause — it returns whatever rows it is told to,
// regardless of the query's actual filtering — so the selection contract
// itself (segment_id IS NULL OR segment_id = ANY($3)) is proven here against
// a REAL Postgres instance:
//
//  1. A segment_id IS NULL policy is always selected, with or without a
//     resolved segment set (backward compatibility).
//  2. A segment-scoped policy is selected ONLY when its segment_id is in the
//     caller's resolved set — never for a non-member, never when the caller
//     resolves to a DIFFERENT segment (no cross-segment bleed).
//  3. A segment-scoped policy never carries an applied override, even when
//     an override row targets it (the override-downgrade-path exclusion).
//
// Gated on Docker (testutil.SkipIfNoDocker), independent of the
// TEST_PG_INTEGRATION env gate the migration-chain realpg tests use — this
// file builds its own minimal schema (like override_handler_shape_2792_test.go)
// rather than applying the full migration chain, so it runs fast and only
// exercises the columns GetEffective actually reads.

import (
	"context"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

func newSegmentSelectionTestDB(t *testing.T) *testutil.PostgresContainer {
	t.Helper()
	testutil.SkipIfNoDocker(t)

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
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
			policy_id  uuid NOT NULL,
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
			updated_at timestamptz DEFAULT now()
		);
	`)
	return pc
}

// TestGetEffective_RealPostgres_SegmentSelection is the core selection
// contract test: a segment-scoped row is included iff its segment_id is in
// the resolved set; a segment_id IS NULL row is always included.
func TestGetEffective_RealPostgres_SegmentSelection(t *testing.T) {
	pc := newSegmentSelectionTestDB(t)
	db := pc.DB
	ctx := context.Background()

	const tenant = "acme"
	const org = "acme"

	// A tier policy (segment_id NULL) — must ALWAYS be selected.
	_, err := db.Exec(`
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tier, priority, enabled, tenant_id, org_id, segment_id, version)
		VALUES ('tier_only', 'Tier Only', 'pii-global', 'ssn', 'high', 'warn', 'tenant', 50, true, $1, $2, NULL, 1)
	`, tenant, org)
	if err != nil {
		t.Fatalf("insert tier policy: %v", err)
	}

	// A finance-segment-scoped policy.
	_, err = db.Exec(`
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tier, priority, enabled, tenant_id, org_id, segment_id, version)
		VALUES ('finance_block', 'Finance Block', 'pii-global', 'ledger', 'critical', 'block', 'tenant', 50, true, $1, $2, 'finance', 1)
	`, tenant, org)
	if err != nil {
		t.Fatalf("insert finance segment policy: %v", err)
	}

	// An ml-platform-segment-scoped policy — used to prove no cross-segment
	// bleed: a caller resolved to "finance" must never see this one.
	_, err = db.Exec(`
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tier, priority, enabled, tenant_id, org_id, segment_id, version)
		VALUES ('ml_block', 'ML Platform Block', 'pii-global', 'model_weights', 'critical', 'block', 'tenant', 50, true, $1, $2, 'ml-platform', 1)
	`, tenant, org)
	if err != nil {
		t.Fatalf("insert ml-platform segment policy: %v", err)
	}

	repo := NewStaticPolicyRepository(db)
	orgPtr := org

	t.Run("no segments resolved: only the tier policy is selected", func(t *testing.T) {
		policies, err := repo.GetEffective(ctx, tenant, &orgPtr, nil)
		if err != nil {
			t.Fatalf("GetEffective: %v", err)
		}
		ids := policyIDSet(policies)
		if !ids["tier_only"] {
			t.Error("tier_only must always be selected")
		}
		if ids["finance_block"] || ids["ml_block"] {
			t.Errorf("no segment-scoped policy should be selected with an empty segment set, got %v", ids)
		}
	})

	t.Run("finance segment resolved: tier + finance selected, ml-platform excluded (no cross-segment bleed)", func(t *testing.T) {
		policies, err := repo.GetEffective(ctx, tenant, &orgPtr, []string{"finance"})
		if err != nil {
			t.Fatalf("GetEffective: %v", err)
		}
		ids := policyIDSet(policies)
		if !ids["tier_only"] {
			t.Error("tier_only must still be selected")
		}
		if !ids["finance_block"] {
			t.Error("finance_block must be selected for a caller resolved to segment finance")
		}
		if ids["ml_block"] {
			t.Error("ml_block must NOT be selected for a caller resolved only to segment finance — cross-segment bleed")
		}
	})

	t.Run("both segments resolved: all three selected", func(t *testing.T) {
		policies, err := repo.GetEffective(ctx, tenant, &orgPtr, []string{"finance", "ml-platform"})
		if err != nil {
			t.Fatalf("GetEffective: %v", err)
		}
		ids := policyIDSet(policies)
		if !ids["tier_only"] || !ids["finance_block"] || !ids["ml_block"] {
			t.Errorf("expected all three policies selected, got %v", ids)
		}
	})
}

// TestGetEffective_RealPostgres_SegmentNeverGetsOverride proves the
// override-downgrade-path exclusion at the SQL level: an override row
// targeting a segment-scoped policy must never be joined/applied — the JOIN
// predicate itself excludes sp.segment_id IS NOT NULL rows.
func TestGetEffective_RealPostgres_SegmentNeverGetsOverride(t *testing.T) {
	pc := newSegmentSelectionTestDB(t)
	db := pc.DB
	ctx := context.Background()

	const tenant = "acme"
	const org = "acme"

	_, err := db.Exec(`INSERT INTO clients (tenant_id, license_tier, enabled) VALUES ($1, 'Enterprise', true)`, tenant)
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}

	var policyUUID string
	err = db.QueryRow(`
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tier, priority, enabled, tenant_id, org_id, segment_id, version)
		VALUES ('finance_block', 'Finance Block', 'pii-global', 'ledger', 'critical', 'block', 'tenant', 50, true, $1, $2, 'finance', 1)
		RETURNING id
	`, tenant, org).Scan(&policyUUID)
	if err != nil {
		t.Fatalf("insert finance segment policy: %v", err)
	}

	// An override row that WOULD apply to a normal tenant-tier policy
	// (downgrading block -> warn) — must have ZERO effect on a segment row.
	_, err = db.Exec(`
		INSERT INTO policy_overrides (policy_id, policy_type, tenant_id, org_id, action_override, enabled_override, override_reason)
		VALUES ($1, 'static', $2, $2, 'warn', true, 'attempted downgrade of a segment policy')
	`, policyUUID, tenant)
	if err != nil {
		t.Fatalf("insert override: %v", err)
	}

	repo := NewStaticPolicyRepository(db)
	orgPtr := org
	policies, err := repo.GetEffective(ctx, tenant, &orgPtr, []string{"finance"})
	if err != nil {
		t.Fatalf("GetEffective: %v", err)
	}

	var found *EffectiveStaticPolicy
	for i := range policies {
		if policies[i].PolicyID == "finance_block" {
			found = &policies[i]
			break
		}
	}
	if found == nil {
		t.Fatal("finance_block must be selected")
	}
	if found.HasOverride {
		t.Errorf("a segment-scoped policy must NEVER carry an applied override, got HasOverride=true action=%s", found.EffectiveAction())
	}
	if found.EffectiveAction() != "block" {
		t.Errorf("segment policy action must remain 'block' (raw, undowngraded), got %q", found.EffectiveAction())
	}
}

func policyIDSet(policies []EffectiveStaticPolicy) map[string]bool {
	out := make(map[string]bool, len(policies))
	for _, p := range policies {
		out[p.PolicyID] = true
	}
	return out
}
