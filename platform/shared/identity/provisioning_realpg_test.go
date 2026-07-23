//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-Postgres integration for the #2924 provisioning primitives: the REAL
// migration files (enterprise/135, core/143) applied to a real database, the
// revocation store / OIDC config provider / SCIM role resolver driven
// against the resulting schema, and an RLS probe as a NON-superuser role
// (the container superuser bypasses RLS, so isolation must be proven from a
// plain role).
package identity

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

func applyMigrationFile(t *testing.T, db *sql.DB, relPath string) {
	t.Helper()
	sqlBytes, err := os.ReadFile(filepath.Join("..", "..", "..", relPath))
	if err != nil {
		t.Fatalf("read migration %s: %v", relPath, err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply migration %s: %v", relPath, err)
	}
}

func TestMigration135_RevocationStore_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB
	ctx := context.Background()

	// The REAL migration file, exactly as deployments run it.
	applyMigrationFile(t, db, "migrations/enterprise/135_user_token_revocations.sql")
	// Idempotency: re-applying must not error (CREATE IF NOT EXISTS / DROP
	// POLICY IF EXISTS guards).
	applyMigrationFile(t, db, "migrations/enterprise/135_user_token_revocations.sql")

	store, err := NewDBRevocationStore(db)
	if err != nil {
		t.Fatalf("NewDBRevocationStore: %v", err)
	}

	now := time.Now().UTC()
	seed := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// jti revocation for org-a; mass revocation for bob@org-a before now.
	seed(`INSERT INTO user_token_revocations (org_id, jti, revoked_by, reason) VALUES ('org-a', 'jti-dead', 'test-admin', 'unit')`)
	seed(`INSERT INTO user_token_revocations (org_id, user_email, issued_before, revoked_by, reason) VALUES ('org-a', 'bob@example.com', $1, 'test-admin', 'rotate')`, now)

	cases := []struct {
		name              string
		orgID, jti, email string
		issuedAt          time.Time
		want              bool
	}{
		{"revoked jti", "org-a", "jti-dead", "alice@example.com", now, true},
		{"live jti", "org-a", "jti-live", "alice@example.com", now, false},
		{"same jti other org invisible", "org-b", "jti-dead", "alice@example.com", now, false},
		{"mass-revoked (iat before watermark)", "org-a", "jti-live", "bob@example.com", now.Add(-time.Hour), true},
		{"mass revocation spares tokens minted after watermark", "org-a", "jti-live", "bob@example.com", now.Add(time.Hour), false},
		{"mass-revocation email is canonical-matched", "org-a", "jti-live", "  BOB@Example.COM ", now.Add(-time.Hour), true},
		{"zero iat matches any mass revocation (fail closed)", "org-a", "jti-live", "bob@example.com", time.Time{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.IsRevoked(ctx, tc.orgID, tc.jti, tc.email, tc.issuedAt)
			if err != nil {
				t.Fatalf("IsRevoked: %v", err)
			}
			if got != tc.want {
				t.Fatalf("IsRevoked = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("CheckRevocation reports the mass-revoke watermark", func(t *testing.T) {
		wm, ok := store.(WatermarkedRevocationChecker)
		if !ok {
			t.Fatal("dbRevocationStore must implement WatermarkedRevocationChecker")
		}
		// bob has a mass revocation at issued_before = now → watermark == now,
		// and a token minted before it is revoked.
		res, err := wm.CheckRevocation(ctx, "org-a", "jti-live", "bob@example.com", now.Add(-time.Hour))
		if err != nil {
			t.Fatalf("CheckRevocation(bob before): %v", err)
		}
		if !res.Revoked {
			t.Fatal("bob token before watermark must be revoked")
		}
		// Postgres TIMESTAMPTZ truncates to microseconds; allow a 1ms tolerance.
		if res.MassRevokeWatermark.IsZero() || res.MassRevokeWatermark.Sub(now).Abs() > time.Millisecond {
			t.Fatalf("watermark = %v, want ≈ %v (bob's issued_before)", res.MassRevokeWatermark, now)
		}
		// A token minted AFTER the watermark survives, but the watermark is
		// still reported so a cache can key on it.
		res, err = wm.CheckRevocation(ctx, "org-a", "jti-live", "bob@example.com", now.Add(time.Hour))
		if err != nil {
			t.Fatalf("CheckRevocation(bob after): %v", err)
		}
		if res.Revoked {
			t.Fatal("bob token after watermark must survive")
		}
		if res.MassRevokeWatermark.IsZero() {
			t.Fatal("watermark must still be reported for a surviving token")
		}
		// alice has no mass revocation → zero watermark, not revoked.
		res, err = wm.CheckRevocation(ctx, "org-a", "jti-live", "alice@example.com", now)
		if err != nil {
			t.Fatalf("CheckRevocation(alice): %v", err)
		}
		if res.Revoked || !res.MassRevokeWatermark.IsZero() {
			t.Fatalf("alice: revoked=%v watermark=%v, want false/zero", res.Revoked, res.MassRevokeWatermark)
		}
		// Canonical-email match: uppercased/padded input still finds bob's rows.
		res, err = wm.CheckRevocation(ctx, "org-a", "jti-live", "  BOB@Example.COM ", now.Add(-time.Hour))
		if err != nil {
			t.Fatalf("CheckRevocation(bob canonical): %v", err)
		}
		if !res.Revoked || res.MassRevokeWatermark.IsZero() {
			t.Fatalf("canonical bob: revoked=%v watermark=%v, want true/non-zero", res.Revoked, res.MassRevokeWatermark)
		}
	})

	t.Run("RLS isolates orgs for a plain role", func(t *testing.T) {
		// The container superuser bypasses RLS; prove isolation as a plain role.
		if _, err := db.Exec(`CREATE ROLE rls_probe LOGIN PASSWORD 'probe'`); err != nil {
			t.Fatalf("create probe role: %v", err)
		}
		if _, err := db.Exec(`GRANT SELECT, INSERT ON user_token_revocations TO rls_probe;
			GRANT USAGE ON SEQUENCE user_token_revocations_id_seq TO rls_probe`); err != nil {
			t.Fatalf("grant: %v", err)
		}
		probeURL := pc.URL + "" // testutil URL is for the super user; rebuild with probe creds
		probeDB, err := sql.Open("postgres", replaceCreds(t, probeURL, "rls_probe", "probe"))
		if err != nil {
			t.Fatalf("open probe conn: %v", err)
		}
		defer func() { _ = probeDB.Close() }()

		probeStore, err := NewDBRevocationStore(probeDB)
		if err != nil {
			t.Fatalf("probe store: %v", err)
		}
		// org-a's revocation is visible when scoped to org-a...
		revoked, err := probeStore.IsRevoked(ctx, "org-a", "jti-dead", "", time.Time{})
		if err != nil || !revoked {
			t.Fatalf("probe org-a: revoked=%v err=%v, want true", revoked, err)
		}
		// ...and org-b sees NOTHING of org-a's rows (RLS policy, not just the
		// WHERE clause: insert a row org-b can't see via a raw scoped count).
		var count int
		err = withOrgScope(ctx, probeDB, "org-b", func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT COUNT(*) FROM user_token_revocations`).Scan(&count)
		})
		if err != nil {
			t.Fatalf("probe org-b count: %v", err)
		}
		if count != 0 {
			t.Fatalf("RLS breach: org-b sees %d of org-a's revocation rows", count)
		}
		// A probe WITHOUT any org GUC sees nothing either (fail closed).
		var bare int
		if err := probeDB.QueryRow(`SELECT COUNT(*) FROM user_token_revocations`).Scan(&bare); err != nil {
			t.Fatalf("bare probe: %v", err)
		}
		if bare != 0 {
			t.Fatalf("RLS breach: unscoped connection sees %d rows", bare)
		}
	})

	t.Run("down migration drops cleanly", func(t *testing.T) {
		applyMigrationFile(t, db, "migrations/enterprise/135_user_token_revocations_down.sql")
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='user_token_revocations')`).Scan(&exists); err != nil {
			t.Fatalf("check: %v", err)
		}
		if exists {
			t.Fatal("down migration must drop user_token_revocations")
		}
	})
}

// replaceCreds swaps the user:password in a postgres URL
// (postgres://user:pass@host:port/db?args).
func replaceCreds(t *testing.T, url, user, pass string) string {
	t.Helper()
	rest, ok := strings.CutPrefix(url, "postgres://")
	if !ok {
		t.Fatalf("unexpected postgres URL shape: %q", url)
	}
	_, hostPart, found := strings.Cut(rest, "@")
	if !found {
		t.Fatalf("unexpected postgres URL shape (no creds): %q", url)
	}
	return "postgres://" + user + ":" + pass + "@" + hostPart
}

// minimalSSOConfigurationsDDL mirrors the columns of enterprise mig 108 +
// core mig 106 that core mig 143 and the config provider touch. The REAL 143
// file is applied on top of it.
const minimalSSOConfigurationsDDL = `
CREATE TABLE sso_configurations (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	tenant_id VARCHAR(255) NOT NULL UNIQUE,
	org_id VARCHAR(255) NOT NULL,
	provider VARCHAR(50) NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT false,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE sso_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY sso_configurations_org_id_isolation ON sso_configurations
	USING (org_id = current_setting('app.current_org_id', true))
	WITH CHECK (org_id = current_setting('app.current_org_id', true));
`

func TestMigration143_OIDCConfigProvider_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB
	ctx := context.Background()

	// Guard behavior: applying 143 BEFORE the table exists must be a no-op,
	// not an error (community deployments run core migrations without the
	// enterprise sso tables).
	applyMigrationFile(t, db, "migrations/core/143_sso_configurations_oidc.sql")

	pc.RunMigration(t, minimalSSOConfigurationsDDL)
	applyMigrationFile(t, db, "migrations/core/143_sso_configurations_oidc.sql")
	// Idempotent re-apply.
	applyMigrationFile(t, db, "migrations/core/143_sso_configurations_oidc.sql")

	seed := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(`INSERT INTO sso_configurations (tenant_id, org_id, provider, enabled, provider_type, oidc_issuer, oidc_audience, oidc_jwks_uri, oidc_claim_mapping)
	      VALUES ('org-oidc', 'org-oidc', 'oidc', true, 'oidc', 'https://issuer.test', 'axonflow', 'https://issuer.test/keys', '{"email":"preferred_username"}')`)
	seed(`INSERT INTO sso_configurations (tenant_id, org_id, provider, enabled, provider_type)
	      VALUES ('org-saml', 'org-saml', 'okta', true, 'saml')`)
	seed(`INSERT INTO sso_configurations (tenant_id, org_id, provider, enabled, provider_type, oidc_issuer, oidc_audience, oidc_jwks_uri)
	      VALUES ('org-disabled', 'org-disabled', 'oidc', false, 'oidc', 'https://x', 'y', 'https://z')`)
	seed(`INSERT INTO sso_configurations (tenant_id, org_id, provider, enabled, provider_type, oidc_issuer)
	      VALUES ('org-broken', 'org-broken', 'oidc', true, 'oidc', 'https://only-issuer')`)

	provider, err := NewDBOIDCConfigProvider(db)
	if err != nil {
		t.Fatalf("NewDBOIDCConfigProvider: %v", err)
	}

	t.Run("enabled OIDC config loads with claim mapping", func(t *testing.T) {
		cfg, err := provider.OIDCConfigForOrg(ctx, "org-oidc")
		if err != nil {
			t.Fatalf("OIDCConfigForOrg: %v", err)
		}
		if cfg.Issuer != "https://issuer.test" || cfg.Audience != "axonflow" || cfg.JWKSURI != "https://issuer.test/keys" {
			t.Fatalf("unexpected config: %+v", cfg)
		}
		if cfg.EmailClaim != "preferred_username" {
			t.Fatalf("claim mapping not honored: %q", cfg.EmailClaim)
		}
	})
	t.Run("SAML org is not configured for OIDC", func(t *testing.T) {
		if _, err := provider.OIDCConfigForOrg(ctx, "org-saml"); err != ErrNotConfigured {
			t.Fatalf("want ErrNotConfigured, got %v", err)
		}
	})
	t.Run("disabled OIDC config is not configured", func(t *testing.T) {
		if _, err := provider.OIDCConfigForOrg(ctx, "org-disabled"); err != ErrNotConfigured {
			t.Fatalf("want ErrNotConfigured, got %v", err)
		}
	})
	t.Run("unknown org is not configured", func(t *testing.T) {
		if _, err := provider.OIDCConfigForOrg(ctx, "org-none"); err != ErrNotConfigured {
			t.Fatalf("want ErrNotConfigured, got %v", err)
		}
	})
	t.Run("half-built enabled config errors loudly", func(t *testing.T) {
		_, err := provider.OIDCConfigForOrg(ctx, "org-broken")
		if err == nil || err == ErrNotConfigured {
			t.Fatalf("an enabled-but-incomplete OIDC config must be a loud error, got %v", err)
		}
	})
	t.Run("check constraint rejects junk provider_type", func(t *testing.T) {
		_, err := db.Exec(`INSERT INTO sso_configurations (tenant_id, org_id, provider, provider_type) VALUES ('org-junk','org-junk','okta','ldap')`)
		if err == nil {
			t.Fatal("provider_type CHECK must reject values outside (saml, oidc)")
		}
	})
	t.Run("down migration removes the columns", func(t *testing.T) {
		applyMigrationFile(t, db, "migrations/core/143_sso_configurations_oidc_down.sql")
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='sso_configurations' AND column_name='oidc_issuer')`).Scan(&exists); err != nil {
			t.Fatalf("check: %v", err)
		}
		if exists {
			t.Fatal("down migration must drop the OIDC columns")
		}
	})
}

func TestSCIMRoleResolver_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB
	ctx := context.Background()

	// Minimal mirror of custom_roles (mig 023, permissions JSONB) +
	// role_assignments (org_id post-mig-111).
	pc.RunMigration(t, `
		CREATE TABLE custom_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			name VARCHAR(100) NOT NULL,
			permissions JSONB NOT NULL DEFAULT '[]'::jsonb
		);
		CREATE TABLE role_assignments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			user_email VARCHAR(255) NOT NULL,
			role_id UUID NOT NULL REFERENCES custom_roles(id),
			source VARCHAR(20) DEFAULT 'scim',
			expires_at TIMESTAMPTZ,
			assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	roleID := func(name, perms string) string {
		t.Helper()
		var id string
		if err := db.QueryRow(`INSERT INTO custom_roles (org_id, name, permissions) VALUES ('org-a', $1, $2::jsonb) RETURNING id`, name, perms).Scan(&id); err != nil {
			t.Fatalf("role %s: %v", name, err)
		}
		return id
	}
	adminID := roleID("admin", `["*"]`)
	// #2993: owner is a true superset of admin — its seeded bundle carries "*".
	// The resolver must still classify it as owner (owner outranks wildcard→admin).
	ownerID := roleID("owner", `["*","sso:configure"]`)
	memberID := roleID("member", `["query"]`)
	viewerID := roleID("viewer", `["read"]`)
	customID := roleID("data_scientist", `["query","export"]`)
	developerID := roleID("developer", `["query","mcp_query"]`)

	assign := func(email, rid string, expires *time.Time) {
		t.Helper()
		mustExec(`INSERT INTO role_assignments (org_id, user_email, role_id, expires_at) VALUES ('org-a', $1, $2, $3)`, email, rid, expires)
	}
	past := time.Now().Add(-time.Hour)
	assign("wildcard@example.com", adminID, nil)
	assign("owner@example.com", ownerID, nil)
	// A user holding BOTH owner and admin resolves to owner (owner ≥ admin).
	assign("owneradmin@example.com", ownerID, nil)
	assign("owneradmin@example.com", adminID, nil)
	assign("both@example.com", viewerID, nil)
	assign("both@example.com", memberID, nil)
	assign("expired@example.com", adminID, &past)
	assign("expired@example.com", viewerID, nil)
	assign("custom@example.com", customID, nil)
	assign("MiXeD@Example.com", developerID, nil)

	resolver, err := NewSCIMRoleResolver(db)
	if err != nil {
		t.Fatalf("NewSCIMRoleResolver: %v", err)
	}

	cases := []struct {
		name, email, want string
	}{
		{"wildcard permission resolves admin", "wildcard@example.com", "admin"},
		{"owner with wildcard resolves owner, not admin (#2993 superset)", "owner@example.com", "owner"},
		{"owner + admin resolves owner (owner outranks admin)", "owneradmin@example.com", "owner"},
		// #2993 dropped "member": a still-seeded member role is now unmapped,
		// so a user assigned viewer + member falls through to viewer (the
		// highest recognized precedence among their assignments).
		{"dropped member role falls through to viewer", "both@example.com", "viewer"},
		{"expired admin assignment ignored", "expired@example.com", "viewer"},
		{"custom-only role is unmapped (least privilege)", "custom@example.com", ""},
		{"unknown identity is unmapped", "ghost@example.com", ""},
		{"stored mixed-case email still resolves", "mixed@example.com", "developer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolver.ResolveRole(ctx, "org-a", tc.email)
			if err != nil {
				t.Fatalf("ResolveRole: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ResolveRole(%q) = %q, want %q", tc.email, got, tc.want)
			}
		})
	}

	t.Run("other org sees no assignments", func(t *testing.T) {
		got, err := resolver.ResolveRole(ctx, "org-b", "wildcard@example.com")
		if err != nil {
			t.Fatalf("ResolveRole: %v", err)
		}
		if got != "" {
			t.Fatalf("org-b must not inherit org-a roles, got %q", got)
		}
	})
}

// #3030 defense-in-depth (M2): the resolver must refuse to confer a role from a
// scim_users directory row the IdP has DEACTIVATED, while remaining inert for
// principals with no directory row at all (manual/portal identities) and for
// active directory users. NOTE the sibling TestSCIMRoleResolver_RealPostgres
// runs with NO scim_users table — that is the existence-guard leg (the resolver
// must not break where enterprise mig 117 was never applied); this test is the
// table-PRESENT counterpart the live harness cannot reach (the service-side
// revoke empties the assignments before any read, so the resolver branch never
// fires there).
func TestSCIMRoleResolver_DeactivatedDirectoryUser_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB
	ctx := context.Background()

	// Minimal mirrors of custom_roles + role_assignments (as above) PLUS
	// scim_users with the columns the deactivated-check reads (mig 117:
	// tenant_id-keyed, email, active).
	pc.RunMigration(t, `
		CREATE TABLE custom_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			name VARCHAR(100) NOT NULL,
			permissions JSONB NOT NULL DEFAULT '[]'::jsonb
		);
		CREATE TABLE role_assignments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id VARCHAR(255) NOT NULL,
			user_email VARCHAR(255) NOT NULL,
			role_id UUID NOT NULL REFERENCES custom_roles(id),
			source VARCHAR(20) DEFAULT 'scim',
			expires_at TIMESTAMPTZ,
			assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE scim_users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id VARCHAR(255) NOT NULL,
			user_name VARCHAR(255),
			email VARCHAR(255) NOT NULL,
			active BOOLEAN NOT NULL DEFAULT true
		);
	`)

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var padminID string
	if err := db.QueryRow(`INSERT INTO custom_roles (org_id, name, permissions) VALUES ('org-a', 'policy_admin', '["policies:write"]'::jsonb) RETURNING id`).Scan(&padminID); err != nil {
		t.Fatalf("role: %v", err)
	}
	// All three principals hold the SAME assignment shape; only the directory
	// row differs.
	for _, email := range []string{"deactivated@example.com", "manual@example.com", "active@example.com", "sourcemanual@example.com"} {
		mustExec(`INSERT INTO role_assignments (org_id, user_email, role_id) VALUES ('org-a', $1, $2)`, email, padminID)
	}
	// The single-tenant posture: the addressing tenant == the org.
	mustExec(`INSERT INTO scim_users (tenant_id, email, active) VALUES ('org-a', 'deactivated@example.com', false)`)
	mustExec(`INSERT INTO scim_users (tenant_id, email, active) VALUES ('org-a', 'active@example.com', true)`)
	// A deactivated row whose grant is source='manual': the fleet plane still
	// refuses (blanket refusal — the IdP says this human must not act), even
	// though the grant survives in storage and the portal plane is unaffected.
	mustExec(`INSERT INTO scim_users (tenant_id, email, active) VALUES ('org-a', 'sourcemanual@example.com', false)`)
	mustExec(`UPDATE role_assignments SET source = 'manual' WHERE user_email = 'sourcemanual@example.com'`)
	// manual@example.com deliberately has NO scim_users row.

	resolver, err := NewSCIMRoleResolver(db)
	if err != nil {
		t.Fatalf("NewSCIMRoleResolver: %v", err)
	}

	cases := []struct {
		name, email, want string
	}{
		{"assignment + deactivated directory row confers nothing", "deactivated@example.com", ""},
		{"assignment + NO directory row (manual principal) still resolves", "manual@example.com", "policy_admin"},
		{"assignment + active directory row resolves", "active@example.com", "policy_admin"},
		{"deactivated refusal is blanket: even a source='manual' grant is not conferred on the fleet plane", "sourcemanual@example.com", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolver.ResolveRole(ctx, "org-a", tc.email)
			if err != nil {
				t.Fatalf("ResolveRole: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ResolveRole(%q) = %q, want %q", tc.email, got, tc.want)
			}
		})
	}

	t.Run("reactivating the directory row restores resolution", func(t *testing.T) {
		mustExec(`UPDATE scim_users SET active = true WHERE email = 'deactivated@example.com'`)
		got, err := resolver.ResolveRole(ctx, "org-a", "deactivated@example.com")
		if err != nil {
			t.Fatalf("ResolveRole: %v", err)
		}
		if got != "policy_admin" {
			t.Fatalf("reactivated directory row must resolve again, got %q", got)
		}
	})
}
