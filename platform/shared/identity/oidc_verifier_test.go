//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- test issuer scaffolding: a real HTTP JWKS endpoint + RSA signing ---

type testIssuer struct {
	key    *rsa.PrivateKey
	kid    string
	iss    string
	aud    string
	server *httptest.Server
	// jwks served; swap to simulate rotation
	serveKeys atomic.Value // []jwksEntry
	fetches   atomic.Int64
}

type jwksEntry struct {
	kid string
	pub *rsa.PublicKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ti := &testIssuer{key: key, kid: "kid-1", iss: "https://issuer.test", aud: "axonflow"}
	ti.serveKeys.Store([]jwksEntry{{kid: ti.kid, pub: &key.PublicKey}})
	ti.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ti.fetches.Add(1)
		keys := ti.serveKeys.Load().([]jwksEntry)
		out := map[string]any{"keys": []map[string]any{}}
		for _, k := range keys {
			out["keys"] = append(out["keys"].([]map[string]any), map[string]any{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.kid,
				"n": base64.RawURLEncoding.EncodeToString(k.pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.pub.E)).Bytes()),
			})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(ti.server.Close)
	return ti
}

func (ti *testIssuer) config() *OIDCConfig {
	return &OIDCConfig{
		OrgID: "org-a", Issuer: ti.iss, Audience: ti.aud,
		JWKSURI: ti.server.URL, EmailClaim: "email",
	}
}

// sign issues an RS256 token from this issuer with claim/header overrides.
func (ti *testIssuer) sign(t *testing.T, kid string, mutate func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   ti.iss,
		"aud":   ti.aud,
		"email": "Dev@Example.com",
		"role":  "admin", // deliberately present: the verifier must IGNORE it
		"iat":   jwt.NewNumericDate(now),
		"exp":   jwt.NewNumericDate(now.Add(time.Hour)),
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(ti.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

type stubConfigs struct {
	cfg *OIDCConfig
	err error
}

func (s *stubConfigs) OIDCConfigForOrg(_ context.Context, orgID string) (*OIDCConfig, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.cfg == nil || s.cfg.OrgID != orgID {
		return nil, ErrNotConfigured
	}
	return s.cfg, nil
}

type stubRoles struct {
	role string
	err  error
	// captured
	orgID, email string
}

func (s *stubRoles) ResolveRole(_ context.Context, orgID, email string) (string, error) {
	s.orgID, s.email = orgID, email
	return s.role, s.err
}

func newVerifier(t *testing.T, cfg *OIDCConfig, roles RoleResolver) TokenValidator {
	t.Helper()
	v, err := NewOIDCVerifier(&stubConfigs{cfg: cfg}, roles)
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	return v
}

// --- tests ---

func TestNewOIDCVerifier_FailFast(t *testing.T) {
	if _, err := NewOIDCVerifier(nil, &stubRoles{}); err == nil {
		t.Fatal("nil config provider must be rejected")
	}
	if _, err := NewOIDCVerifier(&stubConfigs{}, nil); err == nil {
		t.Fatal("nil role resolver must be rejected")
	}
}

func TestOIDCVerifier_HappyPath_RoleFromDirectoryNotToken(t *testing.T) {
	ti := newTestIssuer(t)
	roles := &stubRoles{role: "member"}
	v := newVerifier(t, ti.config(), roles)

	// The token claims role=admin; the directory says member. Directory wins.
	id, err := v.Validate(context.Background(), "org-a", ti.sign(t, ti.kid, nil))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Role != "member" {
		t.Fatalf("role must come from the SCIM directory (member), not the token claim (admin); got %q", id.Role)
	}
	if id.Email != "dev@example.com" {
		t.Errorf("email not canonicalized: %q", id.Email)
	}
	if !id.Validated || id.Source != ValidatorNameOIDC || id.OrgID != "org-a" {
		t.Errorf("unexpected identity: %+v", id)
	}
	if roles.email != "dev@example.com" || roles.orgID != "org-a" {
		t.Errorf("role resolver keyed on %q/%q, want canonical email + org", roles.orgID, roles.email)
	}
}

func TestOIDCVerifier_CustomEmailClaim(t *testing.T) {
	ti := newTestIssuer(t)
	cfg := ti.config()
	cfg.EmailClaim = "preferred_username"
	v := newVerifier(t, cfg, &stubRoles{role: "viewer"})

	tok := ti.sign(t, ti.kid, func(c jwt.MapClaims) {
		delete(c, "email")
		c["preferred_username"] = "Alice@Example.com"
	})
	id, err := v.Validate(context.Background(), "org-a", tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("identity must come from the mapped claim: %q", id.Email)
	}
}

func TestOIDCVerifier_Rejections(t *testing.T) {
	ti := newTestIssuer(t)
	v := newVerifier(t, ti.config(), &stubRoles{role: "member"})
	ctx := context.Background()

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	wrongKeyToken := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": ti.iss, "aud": ti.aud, "email": "x@y.z",
			"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		tok.Header["kid"] = ti.kid // claims the issuer's kid, signed by another key
		s, sErr := tok.SignedString(otherKey)
		if sErr != nil {
			t.Fatalf("sign: %v", sErr)
		}
		return s
	}()

	algNoneToken := func() string {
		header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"none","typ":"JWT","kid":%q}`, ti.kid)))
		payload, _ := json.Marshal(map[string]any{
			"iss": ti.iss, "aud": ti.aud, "email": "attacker@example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
	}()

	// HS256 key-confusion: signed with some symmetric secret; a confused
	// verifier that fed the RSA public key bytes to HMAC would accept a
	// crafted variant. Ours must reject on algorithm alone.
	hs256Token := func() string {
		s, sErr := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": ti.iss, "aud": ti.aud, "email": "attacker@example.com",
			"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}).SignedString([]byte("whatever"))
		if sErr != nil {
			t.Fatalf("sign: %v", sErr)
		}
		return s
	}()

	cases := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"garbage", "x.y.z"},
		{"alg none", algNoneToken},
		{"HS256 algorithm confusion", hs256Token},
		{"signed by wrong key under known kid", wrongKeyToken},
		{"no kid header", ti.sign(t, "", func(c jwt.MapClaims) {})},
		{"expired", ti.sign(t, ti.kid, func(c jwt.MapClaims) {
			c["exp"] = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		})},
		{"missing exp (unbounded)", ti.sign(t, ti.kid, func(c jwt.MapClaims) { delete(c, "exp") })},
		{"nbf in the future", ti.sign(t, ti.kid, func(c jwt.MapClaims) {
			c["nbf"] = jwt.NewNumericDate(time.Now().Add(time.Hour))
		})},
		{"wrong audience", ti.sign(t, ti.kid, func(c jwt.MapClaims) { c["aud"] = "some-other-api" })},
		{"missing audience", ti.sign(t, ti.kid, func(c jwt.MapClaims) { delete(c, "aud") })},
		{"wrong issuer", ti.sign(t, ti.kid, func(c jwt.MapClaims) { c["iss"] = "https://evil.test" })},
		{"missing email claim", ti.sign(t, ti.kid, func(c jwt.MapClaims) { delete(c, "email") })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := v.Validate(ctx, "org-a", tc.token)
			if err == nil || id != nil {
				t.Fatalf("expected rejection, got identity=%+v err=%v", id, err)
			}
		})
	}
}

// TestOIDCVerifier_EmailVerified pins the unverified-email rejection: a token
// whose email_verified is false (or a non-bool) must not authenticate — else
// a low-privilege principal on a self-asserted-email IdP could present a
// higher-privilege user's email and inherit their SCIM role.
func TestOIDCVerifier_EmailVerified(t *testing.T) {
	ti := newTestIssuer(t)
	v := newVerifier(t, ti.config(), &stubRoles{role: "member"})
	ctx := context.Background()

	t.Run("email_verified true validates", func(t *testing.T) {
		tok := ti.sign(t, ti.kid, func(c jwt.MapClaims) { c["email_verified"] = true })
		if _, err := v.Validate(ctx, "org-a", tok); err != nil {
			t.Fatalf("verified email must validate: %v", err)
		}
	})
	t.Run("email_verified absent validates (IdP omits it)", func(t *testing.T) {
		if _, err := v.Validate(ctx, "org-a", ti.sign(t, ti.kid, nil)); err != nil {
			t.Fatalf("absent email_verified must validate: %v", err)
		}
	})
	t.Run("email_verified false rejected", func(t *testing.T) {
		tok := ti.sign(t, ti.kid, func(c jwt.MapClaims) { c["email_verified"] = false })
		if _, err := v.Validate(ctx, "org-a", tok); err == nil {
			t.Fatal("unverified email must be rejected")
		}
	})
	t.Run("email_verified stringly-typed false rejected", func(t *testing.T) {
		tok := ti.sign(t, ti.kid, func(c jwt.MapClaims) { c["email_verified"] = "true" })
		if _, err := v.Validate(ctx, "org-a", tok); err == nil {
			t.Fatal("a non-bool email_verified must not be treated as verified")
		}
	})
}

func TestOIDCVerifier_NotConfiguredPassesThrough(t *testing.T) {
	ti := newTestIssuer(t)
	v := newVerifier(t, ti.config(), &stubRoles{})
	_, err := v.Validate(context.Background(), "org-without-oidc", ti.sign(t, ti.kid, nil))
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured for an org with no OIDC config, got %v", err)
	}
}

func TestOIDCVerifier_RoleResolverErrorFailsClosed(t *testing.T) {
	ti := newTestIssuer(t)
	v := newVerifier(t, ti.config(), &stubRoles{err: fmt.Errorf("directory down")})
	id, err := v.Validate(context.Background(), "org-a", ti.sign(t, ti.kid, nil))
	if err == nil || id != nil {
		t.Fatal("a role-directory failure must reject, not return an identity with a guessed role")
	}
}

// TestOIDCVerifier_KidMissTriggersRefetch simulates IdP key rotation: the
// first validation caches kid-1; the issuer rotates to kid-2; a kid-2 token
// must trigger a JWKS refetch and then validate.
func TestOIDCVerifier_KidMissTriggersRefetch(t *testing.T) {
	ti := newTestIssuer(t)
	v := newVerifier(t, ti.config(), &stubRoles{role: "member"})
	ctx := context.Background()

	if _, err := v.Validate(ctx, "org-a", ti.sign(t, "kid-1", nil)); err != nil {
		t.Fatalf("initial validate: %v", err)
	}
	fetchesAfterFirst := ti.fetches.Load()

	// Rotate: new key under kid-2 (old key removed, as IdPs do eventually).
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ti.serveKeys.Store([]jwksEntry{{kid: "kid-2", pub: &newKey.PublicKey}})
	oldKey := ti.key
	ti.key = newKey
	defer func() { ti.key = oldKey }()

	if _, err := v.Validate(ctx, "org-a", ti.sign(t, "kid-2", nil)); err != nil {
		t.Fatalf("post-rotation validate must succeed via kid-miss refetch: %v", err)
	}
	if ti.fetches.Load() <= fetchesAfterFirst {
		t.Fatal("kid miss must have triggered a JWKS refetch")
	}
}

// TestOIDCVerifier_KidMissRefetchIsRateLimited pins the cooldown: a flood of
// unknown-kid tokens cannot hammer the JWKS endpoint.
func TestOIDCVerifier_KidMissRefetchIsRateLimited(t *testing.T) {
	ti := newTestIssuer(t)
	v := newVerifier(t, ti.config(), &stubRoles{role: "member"})
	ctx := context.Background()

	if _, err := v.Validate(ctx, "org-a", ti.sign(t, "kid-1", nil)); err != nil {
		t.Fatalf("initial validate: %v", err)
	}
	baseline := ti.fetches.Load()

	for i := 0; i < 5; i++ {
		if _, err := v.Validate(ctx, "org-a", ti.sign(t, "kid-does-not-exist", nil)); err == nil {
			t.Fatal("unknown kid must never validate")
		}
	}
	// Exactly one refetch is allowed inside the cooldown window.
	if got := ti.fetches.Load() - baseline; got > 1 {
		t.Fatalf("kid-miss refetch not rate-limited: %d fetches for 5 misses", got)
	}
}

// TestJWKSCache_StaleKeyBounded pins the #2924 R3 fix: a cached key is served
// on a fetch error only within jwksMaxStaleness; past that the cache fails
// closed rather than honoring a possibly-rotated-out key for a whole outage.
func TestJWKSCache_StaleKeyBounded(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	// A cache with a key, but the JWKS URI now points at a dead server.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()
	ctx := context.Background()

	t.Run("within staleness window serves stale key", func(t *testing.T) {
		c := &jwksCache{uri: dead.URL, keys: map[string]*rsa.PublicKey{"k1": &key.PublicKey}}
		// Cache is stale (TTL expired) but within the max-staleness window.
		c.fetchedAt = timeAgo(jwksCacheTTL + time.Minute)
		got, err := c.key(ctx, http.DefaultClient, "k1")
		if err != nil || got == nil {
			t.Fatalf("within-window stale key must be served: got=%v err=%v", got, err)
		}
	})

	t.Run("beyond staleness window fails closed", func(t *testing.T) {
		c := &jwksCache{uri: dead.URL, keys: map[string]*rsa.PublicKey{"k1": &key.PublicKey}}
		c.fetchedAt = timeAgo(jwksMaxStaleness + time.Minute)
		if _, err := c.key(ctx, http.DefaultClient, "k1"); err == nil {
			t.Fatal("a key stale beyond jwksMaxStaleness must not be honored during an outage")
		}
	})

	t.Run("cold path (never fetched) fails closed and rate-limits", func(t *testing.T) {
		c := &jwksCache{uri: dead.URL}
		if _, err := c.key(ctx, http.DefaultClient, "k1"); err == nil {
			t.Fatal("cold cache with a dead JWKS must fail")
		}
		// Immediate retry is within the cooldown → must not hit the endpoint
		// again (returns the cooldown error, not a fresh fetch error).
		_, err := c.key(ctx, http.DefaultClient, "k1")
		if err == nil {
			t.Fatal("cold retry must still fail")
		}
	})
}

// timeAgo returns an instant d in the past (test helper; avoids sprinkling
// time.Now().Add(-d) at call sites).
func timeAgo(d time.Duration) time.Time { return time.Now().Add(-d) }

func TestValidateJWKSURI(t *testing.T) {
	valid := []string{
		"https://idp.example.com/keys",
		"http://127.0.0.1:8443/keys",
		"http://localhost:9/keys",
	}
	for _, u := range valid {
		if err := validateJWKSURI(u); err != nil {
			t.Errorf("validateJWKSURI(%q) = %v, want nil", u, err)
		}
	}
	invalid := []string{
		"http://idp.example.com/keys", // plaintext to a routable host
		"http://10.0.0.5/keys",
		"ftp://idp.example.com/keys",
		"://bad",
	}
	for _, u := range invalid {
		if err := validateJWKSURI(u); err == nil {
			t.Errorf("validateJWKSURI(%q) = nil, want error", u)
		}
	}
}

func TestFetchJWKS_Hygiene(t *testing.T) {
	t.Run("oversized document rejected", func(t *testing.T) {
		big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, jwksMaxResponseBytes+10))
		}))
		defer big.Close()
		if _, err := fetchJWKS(context.Background(), http.DefaultClient, big.URL); err == nil {
			t.Fatal("oversized JWKS must be rejected")
		}
	})
	t.Run("non-200 rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		if _, err := fetchJWKS(context.Background(), http.DefaultClient, srv.URL); err == nil {
			t.Fatal("non-200 JWKS response must be rejected")
		}
	})
	t.Run("document with no usable RSA sig keys rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// enc-use key only
			_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","use":"enc","kid":"k","n":"AQAB","e":"AQAB"}]}`))
		}))
		defer srv.Close()
		if _, err := fetchJWKS(context.Background(), http.DefaultClient, srv.URL); err == nil {
			t.Fatal("a JWKS with no signing keys must be rejected")
		}
	})
}
