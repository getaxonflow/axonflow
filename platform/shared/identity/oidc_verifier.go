//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// Path B verifier hygiene constants.
const (
	// jwksMaxResponseBytes bounds a JWKS document read — a JWKS is a few KB;
	// anything near a megabyte is not a key set.
	jwksMaxResponseBytes = 1 << 20
	// jwksCacheTTL is how long a fetched key set is served without refetch.
	jwksCacheTTL = 15 * time.Minute
	// jwksKidMissCooldown rate-limits the kid-miss refetch so a flood of
	// tokens with unknown kids cannot hammer the IdP.
	jwksKidMissCooldown = 30 * time.Second
	// jwksMaxStaleness bounds how long a cached key is honored once the JWKS
	// endpoint has become unreachable. Past this, validation fails closed
	// rather than trusting a possibly-rotated-out (compromised) key for the
	// entire duration of an IdP outage.
	jwksMaxStaleness = time.Hour
	// oidcLeeway absorbs small clock skew on exp/nbf/iat checks.
	oidcLeeway = 60 * time.Second
)

// oidcVerifier validates IdP-issued OIDC bearer tokens (Path B, #2924)
// against the tenant's configured JWKS endpoint:
//
//   - RS256 ONLY (WithValidMethods + an explicit header check before any key
//     is returned) — alg:none and HS256 key-confusion tokens never reach a
//     signature check;
//   - iss exact-match, aud must contain the configured audience, exp
//     REQUIRED, nbf honored — all enforced by the parser options;
//   - JWKS fetched over HTTPS (loopback exempt, for tests and sidecar
//     issuers), cached with a TTL, kid-miss triggers a rate-limited refetch
//     (IdP key rotation);
//   - the ROLE COMES FROM THE SCIM-SYNCED DIRECTORY, never from a token
//     claim. Deliberate (#2924): an IdP token's role/groups claim shape is
//     tenant-IdP-specific and its mapping is admin-managed in AxonFlow via
//     SCIM group→role mappings; trusting an IdP-embedded role claim directly
//     would move role assignment out of the audited SCIM/admin surface and
//     make every IdP misconfiguration a privilege escalation. The token
//     proves WHO the caller is; the directory decides WHAT they may read.
type oidcVerifier struct {
	configs OIDCConfigProvider
	roles   RoleResolver
	client  *http.Client
	leeway  time.Duration

	mu     sync.Mutex
	caches map[string]*jwksCache // keyed by JWKS URI
}

// OIDCVerifierOption customizes the verifier.
type OIDCVerifierOption func(*oidcVerifier)

// WithOIDCLeeway overrides the clock-skew leeway applied to exp/nbf/iat
// checks (default 60s). Deployments with tightly-synced clocks can shrink
// it; it can never be negative (clamped to zero).
func WithOIDCLeeway(d time.Duration) OIDCVerifierOption {
	return func(v *oidcVerifier) {
		if d < 0 {
			d = 0
		}
		v.leeway = d
	}
}

// NewOIDCVerifier builds the Path B validator. Both collaborators are
// required: without a config provider there is nothing to verify against,
// and without a role resolver every identity would be unmapped.
func NewOIDCVerifier(configs OIDCConfigProvider, roles RoleResolver, opts ...OIDCVerifierOption) (TokenValidator, error) {
	if configs == nil {
		return nil, fmt.Errorf("identity: OIDC verifier requires a config provider")
	}
	if roles == nil {
		return nil, fmt.Errorf("identity: OIDC verifier requires a role resolver")
	}
	v := &oidcVerifier{
		configs: configs,
		roles:   roles,
		client:  &http.Client{Timeout: 10 * time.Second},
		leeway:  oidcLeeway,
		caches:  map[string]*jwksCache{},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

func (v *oidcVerifier) Name() string { return ValidatorNameOIDC }

func (v *oidcVerifier) Validate(ctx context.Context, orgID, token string) (*ValidatedIdentity, error) {
	if orgID == "" {
		return nil, fmt.Errorf("%w: no authenticated org", ErrTokenInvalid)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: empty token", ErrTokenInvalid)
	}

	cfg, err := v.configs.OIDCConfigForOrg(ctx, orgID)
	if err != nil {
		return nil, err // ErrNotConfigured passes through for the resolver
	}

	cache, err := v.cacheFor(cfg.JWKSURI)
	if err != nil {
		return nil, err
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Belt-and-braces algorithm pinning: WithValidMethods below already
		// rejects anything but RS256, but assert the method type BEFORE
		// resolving any key so a confusion-shaped token never selects one.
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q (only RS256 accepted)", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token has no kid header")
		}
		return cache.key(ctx, v.client, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.leeway),
	)
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected claims shape", ErrTokenInvalid)
	}
	email := CanonicalEmail(claimString(claims, cfg.EmailClaim))
	if email == "" {
		return nil, fmt.Errorf("%w: token has no %q claim to identify the user", ErrTokenInvalid, cfg.EmailClaim)
	}
	// Reject an unverified email identity. The role is resolved from the SCIM
	// directory keyed on this email, so an IdP that emits a self-asserted /
	// unverified email (multi-tenant Azure AD, or any IdP allowing the user to
	// edit their own profile email) would otherwise let a low-privilege
	// principal present the email of a higher-privilege directory user and
	// inherit their role. If the token carries email_verified, it MUST be
	// true; absent (some IdPs omit it) is allowed since there is nothing to
	// contradict — the identity still had to be signed by the trusted IdP.
	if verified, present := claimBool(claims, "email_verified"); present && !verified {
		return nil, fmt.Errorf("%w: email is not verified by the IdP", ErrTokenInvalid)
	}

	// Role from the SCIM-synced directory, never the token (see type doc).
	role, err := v.roles.ResolveRole(ctx, orgID, email)
	if err != nil {
		return nil, fmt.Errorf("identity: role resolution failed for validated OIDC identity: %w", err)
	}

	exp, _ := claims.GetExpirationTime() // presence enforced by WithExpirationRequired
	identity := &ValidatedIdentity{
		Email:     email,
		Role:      role,
		OrgID:     orgID,
		Source:    ValidatorNameOIDC,
		Validated: true,
	}
	if exp != nil {
		identity.ExpiresAt = exp.Time
	}
	return identity, nil
}

// cacheFor returns (creating on first use) the JWKS cache for a URI, after
// validating the URI's transport security.
func (v *oidcVerifier) cacheFor(jwksURI string) (*jwksCache, error) {
	if err := validateJWKSURI(jwksURI); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.caches[jwksURI]
	if !ok {
		c = &jwksCache{uri: jwksURI}
		v.caches[jwksURI] = c
	}
	return c, nil
}

// validateJWKSURI requires HTTPS for any non-loopback JWKS endpoint. Keys
// fetched over plaintext HTTP from a routable host could be swapped by an
// on-path attacker, which converts every OIDC validation into a forgery
// oracle. Loopback is exempt so local test issuers work.
func validateJWKSURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("identity: invalid JWKS URI: %w", err)
	}
	// SSRF denylist (defense in depth — the portal write path checks too, but
	// a config written directly to the DB reaches here): never fetch from an
	// internal / metadata endpoint.
	if ssrfErr := CheckOIDCEndpointSSRF(raw); ssrfErr != nil {
		return fmt.Errorf("identity: JWKS URI rejected: %w", ssrfErr)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("identity: JWKS URI %q must use https (http allowed only for loopback)", raw)
	default:
		return fmt.Errorf("identity: JWKS URI %q has unsupported scheme %q", raw, u.Scheme)
	}
}

// jwksCache holds one endpoint's RSA signing keys with TTL + rate-limited
// kid-miss refetch (IdP key rotation publishes the new kid before tokens
// signed with it arrive — a miss on a fresh cache is the rotation signal).
type jwksCache struct {
	uri string

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastMissRef time.Time
	lastColdRef time.Time
}

// key returns the RSA public key for kid, fetching or refetching the JWKS as
// needed. Unknown kid after a fresh fetch is an error (the token was not
// signed by this issuer's current key set).
//
// The per-URI mutex is held across a refetch, so during an IdP outage
// concurrent validations for that one JWKS URI serialize behind the bounded
// (10s client-timeout) fetch. Accepted deliberately: a fresh cache serves
// every validation lock-free (the common path — JWKS is cached 15m), refetch
// happens only on TTL expiry or a kid miss, and serializing avoids a
// thundering herd of concurrent fetches against a struggling IdP. If this
// ever shows up as tenant-scoped latency under an outage, a single-flight is
// the follow-up.
func (c *jwksCache) key(ctx context.Context, client *http.Client, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fresh := time.Since(c.fetchedAt) < jwksCacheTTL && c.keys != nil
	if fresh {
		if k, ok := c.keys[kid]; ok {
			return k, nil
		}
		// kid miss on a fresh cache: refetch once, rate-limited.
		if time.Since(c.lastMissRef) < jwksKidMissCooldown {
			return nil, fmt.Errorf("unknown kid %q (refetch cooling down)", kid)
		}
		c.lastMissRef = time.Now()
	} else if c.keys == nil {
		// Cold path: no successful fetch yet. Rate-limit so a flood of tokens
		// while the IdP is unreachable at first use cannot hammer the endpoint
		// or pile up blocked goroutines behind the fetch.
		if !c.lastColdRef.IsZero() && time.Since(c.lastColdRef) < jwksKidMissCooldown {
			return nil, fmt.Errorf("JWKS not yet available (fetch cooling down)")
		}
		c.lastColdRef = time.Now()
	}

	keys, err := fetchJWKS(ctx, client, c.uri)
	if err != nil {
		// Serve a stale-but-present key rather than hard-failing on a transient
		// IdP hiccup — the key material itself does not expire with the cache
		// TTL — but ONLY within the bounded staleness window. Past that, a
		// rotated-out (possibly compromised) key must not be honored for the
		// whole duration of an outage: fail closed. A kid we have never seen
		// still fails.
		if c.keys != nil && time.Since(c.fetchedAt) <= jwksMaxStaleness {
			if k, ok := c.keys[kid]; ok {
				return k, nil
			}
		}
		return nil, err
	}
	c.keys = keys
	c.fetchedAt = time.Now()

	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q after JWKS refetch from %s", kid, c.uri)
}

// fetchJWKS downloads and parses a JWKS document, keeping only RSA public
// keys usable for signature verification (use empty or "sig"; alg empty or
// RS256). EC/oct/enc keys are ignored — this verifier is RS256-only.
func fetchJWKS(ctx context.Context, client *http.Client, uri string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("identity: build JWKS request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: fetch JWKS from %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: JWKS endpoint %s returned %d", uri, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("identity: read JWKS body: %w", err)
	}
	if len(body) > jwksMaxResponseBytes {
		return nil, fmt.Errorf("identity: JWKS document from %s exceeds %d bytes", uri, jwksMaxResponseBytes)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("identity: parse JWKS document: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.KeyID == "" || !k.Valid() || !k.IsPublic() {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != "RS256" {
			continue
		}
		if pub, ok := k.Key.(*rsa.PublicKey); ok {
			keys[k.KeyID] = pub
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("identity: JWKS document from %s contains no usable RS256 signing keys", uri)
	}
	return keys, nil
}
