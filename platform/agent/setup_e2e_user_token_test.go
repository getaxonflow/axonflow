//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Regression coverage for #2937: scripts/setup-e2e-testing.sh's
// generate_user_token must write a token into AXONFLOW_USER_TOKEN that the
// per-user X-User-Token plane (platform/shared/identity ResolveToken -> HS256
// validator) accepts — while the SAME token still satisfies the legacy body
// `user_token` plane (validateUserToken). Before #2937 the script wrote a
// legacy tenant JWT (no iss/email/jti) into that var, which the per-user
// validator rejects on claim shape, silently breaking the plugin per-user
// flow for anyone who sourced the e2e env.
package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	sharedidentity "axonflow/platform/shared/identity"

	"github.com/golang-jwt/jwt/v5"
)

const (
	e2eTestSecret = "axonflow-local-dev-jwt-secret-do-not-use-in-production"
	e2eTestOrg    = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	e2eTestEmail  = "demo-user@axonflow.local"
)

// neverRevoked is a happy-path RevocationChecker (mirrors the DB checker when
// the token is live).
type neverRevoked struct{}

func (neverRevoked) IsRevoked(_ context.Context, _, _, _ string, _ time.Time) (bool, error) {
	return false, nil
}

// assertBothPlanesAccept runs a candidate superset token through BOTH
// governance planes and asserts each accepts it, ignoring the other plane's
// extra claims. This is the #2937 contract.
func assertBothPlanesAccept(t *testing.T, token string) {
	t.Helper()

	// validateUserToken must not bypass on community mode.
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	orig := jwtSecret
	jwtSecret = []byte(e2eTestSecret)
	t.Cleanup(func() { jwtSecret = orig })

	// Plane 1 — legacy body user_token path. The per-user claims
	// (iss=axonflow-user-token-mint, email, jti) must NOT cause rejection.
	user, err := validateUserToken(token, e2eTestOrg)
	if err != nil {
		t.Fatalf("PLANE1 validateUserToken (legacy body path) rejected the token: %v", err)
	}
	if user.TenantID != e2eTestOrg || user.OrgID != e2eTestOrg {
		t.Fatalf("PLANE1 tenant/org mismatch: tenant=%q org=%q want %q", user.TenantID, user.OrgID, e2eTestOrg)
	}
	if user.Email != e2eTestEmail {
		t.Fatalf("PLANE1 email mismatch: got %q want %q", user.Email, e2eTestEmail)
	}
	if !containsPerm(user.Permissions, "mcp_query") {
		t.Fatalf("PLANE1 permissions missing mcp_query (examples need it): %v", user.Permissions)
	}
	t.Logf("PLANE1 validateUserToken ACCEPT: email=%s tenant=%s perms=%v", user.Email, user.TenantID, user.Permissions)

	// Plane 2 — per-user X-User-Token path. The legacy claims
	// (permissions, tenant_id, region, user_id) must be ignored, not rejected.
	v, err := sharedidentity.NewHS256Validator([]byte(e2eTestSecret), neverRevoked{})
	if err != nil {
		t.Fatalf("NewHS256Validator: %v", err)
	}
	vid, err := v.Validate(context.Background(), e2eTestOrg, token)
	if err != nil {
		t.Fatalf("PLANE2 hs256Validator (per-user X-User-Token path) rejected the token: %v", err)
	}
	if vid.Email != e2eTestEmail || vid.Role != "admin" || vid.OrgID != e2eTestOrg || vid.JTI == "" {
		t.Fatalf("PLANE2 resolved identity mismatch: %+v", vid)
	}
	t.Logf("PLANE2 hs256Validator ACCEPT: email=%s role=%s org=%s jti=%s", vid.Email, vid.Role, vid.OrgID, vid.JTI)
}

func containsPerm(perms []string, want string) bool {
	for _, p := range perms {
		if p == want {
			return true
		}
	}
	return false
}

// TestSetupE2EUserToken_SupersetContract is the always-on contract guard: a
// token with the claim set generate_user_token emits validates through BOTH
// planes, and the OLD legacy tenant JWT is rejected on the per-user plane. It
// builds the tokens in-process so it runs with no external tooling.
func TestSetupE2EUserToken_SupersetContract(t *testing.T) {
	now := time.Now().UTC()
	superset := signE2E(t, jwt.MapClaims{
		"iss":         sharedidentity.UserTokenIssuer,
		"sub":         e2eTestEmail,
		"email":       e2eTestEmail,
		"user_id":     "demo-user",
		"tenant_id":   e2eTestOrg,
		"org_id":      e2eTestOrg,
		"role":        "admin",
		"region":      "local",
		"jti":         "e2e-00000000-0000-0000-0000-000000000001",
		"permissions": []string{"query", "llm", "mcp_query", "admin"},
		"iat":         jwt.NewNumericDate(now),
		"nbf":         jwt.NewNumericDate(now.Add(-time.Minute)),
		"exp":         jwt.NewNumericDate(now.Add(24 * time.Hour)),
	})
	assertBothPlanesAccept(t, superset)

	// The pre-#2937 legacy tenant JWT (no iss/email/jti) must be rejected on
	// the per-user plane — this is the exact bug the fix removes from the var.
	legacy := signE2E(t, jwt.MapClaims{
		"user_id":     "demo-user",
		"tenant_id":   e2eTestOrg,
		"role":        "admin",
		"region":      "local",
		"permissions": []string{"query", "llm", "mcp_query", "admin"},
		"iat":         jwt.NewNumericDate(now),
		"exp":         jwt.NewNumericDate(now.Add(24 * time.Hour)),
	})
	v, err := sharedidentity.NewHS256Validator([]byte(e2eTestSecret), neverRevoked{})
	if err != nil {
		t.Fatalf("NewHS256Validator: %v", err)
	}
	if _, err := v.Validate(context.Background(), e2eTestOrg, legacy); err == nil {
		t.Fatal("per-user validator ACCEPTED a legacy tenant JWT — the #2937 regression is not guarded")
	} else {
		t.Logf("per-user validator correctly REJECTS the legacy tenant JWT: %v", err)
	}
}

// TestSetupE2EUserToken_ScriptOutputValidates ties the fix to the REAL script:
// it mints a token exactly as generate_user_token does — via
// scripts/generate-jwt.sh --kind user — and asserts the actual output
// validates through both planes. Skips when jq/openssl are unavailable (the
// script needs them); CI runners have both.
func TestSetupE2EUserToken_ScriptOutputValidates(t *testing.T) {
	for _, bin := range []string{"jq", "openssl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping real-script integration", bin)
		}
	}
	script := repoScript(t, "scripts/generate-jwt.sh")

	out, err := exec.Command("bash", script,
		"--kind", "user",
		"--secret", e2eTestSecret,
		"--tenant-id", e2eTestOrg,
		"--org-id", e2eTestOrg,
		"--email", "Demo-User@Axonflow.Local", // upper-case in → lowercased out
		"--role", "admin",
		"--permissions", "query,llm,mcp_query,admin",
		"--quiet",
	).Output()
	if err != nil {
		t.Fatalf("generate-jwt.sh --kind user failed: %v", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		t.Fatal("generate-jwt.sh --kind user produced an empty token")
	}
	assertBothPlanesAccept(t, token)
}

// TestSetupE2EUserToken_EnvTokenValidates is the closing link of the
// Real-World-Path evidence chain: the evidence harness sources the generated
// env, drives the Claude Code plugin's actual header-build path
// (mcp-auth-headers.sh), extracts the X-User-Token it ships, and hands it back
// here via E2E_EVIDENCE_TOKEN. This asserts THAT exact wire value validates
// through both real server planes. Skips outside the harness.
func TestSetupE2EUserToken_EnvTokenValidates(t *testing.T) {
	token := os.Getenv("E2E_EVIDENCE_TOKEN")
	if token == "" {
		t.Skip("E2E_EVIDENCE_TOKEN not set; run scripts/verify path via the evidence harness")
	}
	assertBothPlanesAccept(t, token)
}

func signE2E(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(e2eTestSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

// repoScript resolves a repo-root-relative path from this test file's location,
// independent of the test's working directory.
func repoScript(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// platform/agent/<thisfile> -> repo root is two dirs up from platform/agent.
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	p := filepath.Join(root, rel)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected script at %s: %v", p, err)
	}
	return p
}
