//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Proves the #2930 R3 merge-blocker fix: a per-user token minted by the
// provisioning API and REVOKED via the admin API is rejected on the
// request/decide plane's validateUserToken — not only on the fleet plane, and
// not only after exp. Drives the REAL mig-135 deny-list on real Postgres.
package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	identity "axonflow/platform/shared/identity"
	"axonflow/platform/testutil"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

func TestValidateUserToken_RevocationOnDecidePlane_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB

	// Real mig-135 deny-list.
	sqlBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations", "enterprise", "135_user_token_revocations.sql"))
	if err != nil {
		t.Fatalf("read mig 135: %v", err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply mig 135: %v", err)
	}

	// Wire the decide-plane revocation checker over the real store.
	store, err := identity.NewDBRevocationStore(db)
	if err != nil {
		t.Fatalf("NewDBRevocationStore: %v", err)
	}
	prevChecker := userTokenRevocations
	userTokenRevocations = store
	t.Cleanup(func() { userTokenRevocations = prevChecker })

	// Enterprise mode + a known secret so validateUserToken reaches JWT
	// validation (community/community-saas bypass it entirely).
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	prevSecret := jwtSecret
	jwtSecret = []byte("decide-plane-revocation-test-secret")
	t.Cleanup(func() { jwtSecret = prevSecret })

	const org = "org-decide"
	// mintLike stamps the same claim shape as the provisioning mint API.
	mintLike := func(jti string, iat time.Time) string {
		t.Helper()
		claims := jwt.MapClaims{
			"iss":       identity.UserTokenIssuer,
			"email":     "dev@example.com",
			"role":      "developer",
			"org_id":    org,
			"tenant_id": org,
			"jti":       jti,
			"iat":       jwt.NewNumericDate(iat),
			"nbf":       jwt.NewNumericDate(iat),
			"exp":       jwt.NewNumericDate(iat.Add(time.Hour)),
		}
		s, signErr := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
		if signErr != nil {
			t.Fatalf("sign: %v", signErr)
		}
		return s
	}

	now := time.Now().UTC().Truncate(time.Second)

	t.Run("minted token validates before revocation", func(t *testing.T) {
		u, err := validateUserToken(mintLike("jti-live", now), org)
		if err != nil {
			t.Fatalf("fresh token must validate: %v", err)
		}
		if u.Email != "dev@example.com" || u.Role != "developer" || u.OrgID != org {
			t.Fatalf("unexpected user: %+v", u)
		}
	})

	t.Run("jti revocation is enforced on the decide plane", func(t *testing.T) {
		tok := mintLike("jti-revoked", now)
		if _, err := validateUserToken(tok, org); err != nil {
			t.Fatalf("token must validate before it is revoked: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO user_token_revocations (org_id, jti, revoked_by, reason) VALUES ($1, 'jti-revoked', 'admin', 'test')`, org); err != nil {
			t.Fatalf("insert revocation: %v", err)
		}
		if _, err := validateUserToken(tok, org); err == nil {
			t.Fatal("a revoked token MUST be rejected on the decide plane")
		}
	})

	t.Run("mass (email) revocation is enforced on the decide plane", func(t *testing.T) {
		// Rotation semantics: a watermark in the recent past revokes every
		// token issued before it; a replacement minted at/after it survives.
		watermark := now.Add(-30 * time.Second)
		// A token minted BEFORE the watermark for this user.
		old := mintLike("jti-old", now.Add(-time.Minute))
		if _, err := validateUserToken(old, org); err != nil {
			t.Fatalf("token must validate before mass revocation: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO user_token_revocations (org_id, user_email, issued_before, revoked_by, reason) VALUES ($1, 'dev@example.com', $2, 'admin', 'rotate')`, org, watermark); err != nil {
			t.Fatalf("insert mass revocation: %v", err)
		}
		if _, err := validateUserToken(old, org); err == nil {
			t.Fatal("a mass-revoked (pre-watermark) token MUST be rejected on the decide plane")
		}
		// The replacement, minted at real-now (after the watermark), survives.
		fresh := mintLike("jti-fresh", now)
		if _, err := validateUserToken(fresh, org); err != nil {
			t.Fatalf("a token minted after the mass-revocation watermark must still validate: %v", err)
		}
	})

	t.Run("legacy jti-less token is unaffected by revocation enforcement", func(t *testing.T) {
		// generate-jwt.sh-style token: no jti, no iss requirement. It must
		// still validate — revocation is opt-in via the mint API's jti.
		claims := jwt.MapClaims{
			"email":     "legacy@example.com",
			"role":      "viewer",
			"org_id":    org,
			"tenant_id": org,
			"exp":       jwt.NewNumericDate(now.Add(time.Hour)),
		}
		legacy, signErr := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
		if signErr != nil {
			t.Fatalf("sign legacy: %v", signErr)
		}
		u, err := validateUserToken(legacy, org)
		if err != nil {
			t.Fatalf("a jti-less legacy token must still validate (revocation is jti-opt-in): %v", err)
		}
		if u.Email != "legacy@example.com" {
			t.Fatalf("unexpected legacy user: %+v", u)
		}
	})
}
