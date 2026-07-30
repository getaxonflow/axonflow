// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Per-user token validation contract (#2924, epic #2919).
//
// Fleet deployments authenticate every developer's plugin with one shared
// tenant credential — attribution without authorization. The fix (#2919) is a
// validated, non-forgeable per-user {identity, role} resolved from a per-user
// token. This file defines the validator-agnostic contract; two backends
// implement it:
//
//   - Path A: HS256Validator — AxonFlow-minted per-user tokens (admin mint /
//     rotate / revoke via the customer-portal admin plane), revocation-checked
//     against user_token_revocations (enterprise mig 135).
//   - Path B: OIDCVerifier — IdP-issued OIDC/JWKS bearer tokens (JumpCloud,
//     Okta, Azure AD, ...) validated against the IdP JWKS, role resolved from
//     the SCIM-synced directory (never the token's own role claim).
//
// The fleet/MCP-server plane resolver (#2920) consumes registered validators
// through RegisterValidator/RegisteredValidators. NOTE (#2920 integration):
// this registry is RBAC-2's side of the seam — the exact resolver call is
// reconciled with the #2920 foundation work at integration time.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"axonflow/platform/shared/egress"
)

// ValidatedIdentity is the outcome of a successful token validation: a
// non-forgeable per-user identity + role the read-authz layer (#2922) can key
// on. Email is always canonicalized via CanonicalEmail so the read path keys
// on exactly the value the write-attribution path stores (#2920 gap 2).
type ValidatedIdentity struct {
	// Email is the canonical per-user identity key (lower-cased, trimmed).
	Email string
	// Role is the effective authz role. For Path A it is the admin-assigned
	// role claim of the minted token; for Path B it is resolved from the
	// SCIM-synced directory. Empty means unmapped — consumers MUST treat an
	// empty role as least-privilege (fail-closed), never as admin.
	Role string
	// OrgID is the organization the token was validated against.
	OrgID string
	// JTI is the token's unique ID when the backend carries one (Path A
	// tokens always do; it is the revocation key). Empty for Path B.
	JTI string
	// ExpiresAt is the token's expiry instant (both paths require exp).
	ExpiresAt time.Time
	// Source names the validator that produced this identity (see
	// ValidatorNameHS256 / ValidatorNameOIDC) for audit attribution.
	Source string
	// Validated is always true for an identity returned by a TokenValidator —
	// it distinguishes this from the attribution-only header-derived identity
	// on the MCP-server plane, which must stay least-privilege.
	Validated bool
}

// TokenValidator is the pluggable per-user token validation backend (#2920).
// Validate MUST fail closed: any ambiguity (unparseable token, unknown key,
// revocation-store error, org mismatch, missing required claim) is an error,
// never a degraded identity.
type TokenValidator interface {
	// Name identifies the backend (stable, audit-safe).
	Name() string
	// Validate checks token for the given org and returns the validated
	// identity. orgID is the ALREADY-AUTHENTICATED tenant (from the Basic
	// credential), never a client-asserted header: a token minted or
	// configured for another org must not validate.
	Validate(ctx context.Context, orgID, token string) (*ValidatedIdentity, error)
}

// Stable validator names (ValidatedIdentity.Source values).
const (
	ValidatorNameHS256 = "hs256"
	ValidatorNameOIDC  = "oidc"
)

// UserTokenIssuer is the iss claim the Path A mint API stamps and the HS256
// validator requires. JWT_SECRET is shared with other HS256 minters (e.g. the
// dev-token endpoint); pinning iss is defense-in-depth so only tokens minted
// by the provisioning API are accepted on the fleet plane, even if a future
// same-secret token type happens to carry a jti+email+org+role+exp shape.
const UserTokenIssuer = "axonflow-user-token-mint"

// Sentinel errors. Callers branch on these with errors.Is.
var (
	// ErrTokenInvalid: the token failed signature/claim validation.
	ErrTokenInvalid = errors.New("per-user token invalid")
	// ErrTokenRevoked: the token validated cryptographically but is on the
	// revocation list.
	ErrTokenRevoked = errors.New("per-user token revoked")
	// ErrNotConfigured: this validator has no usable configuration for the
	// org (e.g. no enabled OIDC config row) — the resolver may try the next
	// backend; it must NOT treat this as a validated identity.
	ErrNotConfigured = errors.New("per-user token validator not configured for org")
	// ErrEnterpriseOnly: per-user token validation is an Enterprise
	// capability; community builds return this from every constructor.
	ErrEnterpriseOnly = errors.New("per-user token validation is an Enterprise capability")
)

// RevocationChecker answers whether a Path A token has been revoked, either
// individually (jti) or via a mass revocation (email + issued-before window).
// Implementations MUST return an error on any storage failure so the
// validator can fail closed — never a silent false.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, orgID, jti, email string, issuedAt time.Time) (bool, error)
}

// RevocationCheck is the richer result of a revocation lookup: the revoked
// verdict PLUS the caller's current mass-revocation watermark. A caching layer
// (see the /decide hot-path cache, #2931) uses the watermark to invalidate a
// user's cached not-revoked entries the instant it observes a newer mass
// revocation, instead of waiting out each entry's TTL.
type RevocationCheck struct {
	// Revoked is the fail-closed verdict for the specific token queried
	// (single-jti revocation OR a mass revocation that covers it).
	Revoked bool
	// MassRevokeWatermark is the greatest issued_before across the user's mass
	// revocation rows for the org (zero time when the user has none). Any token
	// for that user whose iat is strictly before this value is dead — a cached
	// not-revoked entry predating the watermark MUST be treated as revoked.
	MassRevokeWatermark time.Time
}

// WatermarkedRevocationChecker is an optional extension of RevocationChecker
// that reports the mass-revoke watermark alongside the verdict in a single
// round trip. The DB-backed store implements it; a caching wrapper type-asserts
// for it and degrades to plain IsRevoked (TTL-only, no early cross-token
// invalidation) when the underlying checker does not.
type WatermarkedRevocationChecker interface {
	RevocationChecker
	// CheckRevocation returns the verdict for (orgID, jti, email, issuedAt) and
	// the user's current mass-revoke watermark. It fails closed on any storage
	// error (returns a non-nil error, never a silent not-revoked).
	CheckRevocation(ctx context.Context, orgID, jti, email string, issuedAt time.Time) (RevocationCheck, error)
}

// RoleResolver resolves a validated identity to its effective authz role from
// a server-side directory (SCIM-synced group→role mappings + admin-assigned
// roles). Returns "" (with nil error) for an unmapped identity — the caller
// treats that as least-privilege. Storage failures are errors (fail closed).
type RoleResolver interface {
	ResolveRole(ctx context.Context, orgID, email string) (string, error)
}

// OIDCConfig is one tenant's OIDC verifier configuration (sso_configurations
// with provider_type='oidc', extended by core mig 143).
type OIDCConfig struct {
	OrgID    string
	Issuer   string
	Audience string
	JWKSURI  string
	// EmailClaim is the token claim carrying the identity. Defaults to
	// "email" when the stored claim mapping does not override it.
	EmailClaim string
}

// OIDCConfigProvider loads the per-tenant OIDC configuration. Returns
// ErrNotConfigured when the org has no enabled OIDC configuration.
type OIDCConfigProvider interface {
	OIDCConfigForOrg(ctx context.Context, orgID string) (*OIDCConfig, error)
}

// knownRoles is the closed authz-role vocabulary the fleet plane understands
// (kept in lockstep with the customer-portal mint allowlist and the #2921
// role model). A validated token carrying a role OUTSIDE this set is
// normalized to "" (least-privilege) by NormalizeRole — so no minting path,
// current or future, can smuggle an unrecognized-but-privileged role string
// through a validator even though JWT_SECRET is shared with the agent plane.
// The five tiers of the #2993 role model. "member" was dropped: it mapped to
// no distinct behavior (own-rows, exactly like developer/viewer minus their one
// enforced capability), so it was removed from the mint vocabulary. A legacy
// token still carrying role="member" is unknown here and NormalizeRole
// collapses it to "" (own-rows) — the same least-privilege posture it already
// had, so existing member tokens degrade safely with no runtime change.
var knownRoles = map[string]bool{
	"admin":        true,
	"owner":        true,
	"policy_admin": true,
	"developer":    true,
	"viewer":       true,
}

// NormalizeRole returns role if it is a recognized authz role, else "" — the
// least-privilege sentinel every consumer already treats as unmapped. This is
// the defense-in-depth backstop for the HS256 path: the mint API is the
// primary role gate, but a token whose role claim was tampered to an unknown
// value (or minted by some other path) resolves to least-privilege here, not
// to whatever string it carried.
func NormalizeRole(role string) string {
	if knownRoles[role] {
		return role
	}
	return ""
}

// IsFleetRole reports whether role is one of the fleet plane's recognized authz
// roles. It is the SAME closed vocabulary NormalizeRole enforces, exposed so
// upstream surfaces can REJECT an unrecognized role at the point of
// configuration rather than let it silently normalize to least-privilege
// later. #2963: the SCIM group->role mapping gate uses this — mapping a group
// to a role the resolver does not recognize would otherwise drop every member
// of that group to own-rows with no error, which reads exactly like "my IdP
// roles are being ignored".
func IsFleetRole(role string) bool {
	return knownRoles[role]
}

// FleetRoleNames returns the recognized authz role names (unordered). For
// building actionable error messages at the configuration surface.
func FleetRoleNames() []string {
	names := make([]string, 0, len(knownRoles))
	for r := range knownRoles {
		names = append(names, r)
	}
	return names
}

// CheckOIDCEndpointSSRF rejects an OIDC issuer / JWKS URL that targets an
// internal or cloud-metadata endpoint (#2930 R3). A tenant admin with
// sso:configure sets these URLs and the platform then fetches them
// server-side, so an unguarded value is an SSRF primitive: pointing
// oidc_jwks_uri at 169.254.169.254 (the cloud metadata service) or an
// RFC-1918 host reaches inside the deployment's network.
//
// When the host is an IP literal it applies egress.OIDCLiteral — the shared
// range table (#3104) — which blocks every named reserved range EXCEPT
// loopback. That is more than the ranges this comment used to list: it also
// covers 0.0.0.0/8, CGNAT, the IETF protocol-assignment and TEST-NET ranges,
// RFC 2544 benchmarking, 240.0.0.0/4, the broadcast address, the IPv6
// documentation range, and the four IPv6 encodings that wrap an IPv4 address.
// See platform/shared/egress for the authoritative list. When the host is a name, it
// blocks the internal service-discovery suffixes (.internal, .local) and the
// literal metadata hostnames. Loopback is deliberately NOT blocked — it is
// allowed elsewhere for local-dev issuers and blocking it here would diverge
// from that contract. This includes the .localhost suffix: RFC 6761 reserves
// the whole `.localhost.` zone for loopback, so `foo.localhost` resolves to
// loopback exactly like bare `localhost` — treating the two inconsistently (as
// an earlier revision did, blocking `.localhost` while allowing `localhost`)
// bought no security and only rejected legitimate local-dev issuers. A
// hostname that resolves to a private IP at fetch time (DNS rebinding) is out
// of scope for this literal-denylist guard. Returns nil for a safe URL
// (including a non-IP public hostname).
func CheckOIDCEndpointSSRF(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL %q has no host", rawURL)
	}

	// The IP-literal branch delegates to the shared egress table (#3104).
	// egress.OIDCLiteral is the only policy that exempts a range, and the range
	// it exempts is loopback — the local-dev allowance documented above. That
	// exemption used to live only in this prose; it is now a named cell that
	// TestPolicyMatrix and TestDeclaredDivergences read.
	//
	// Hardening relative to the switch this replaces: the old branch permitted
	// 0.0.0.0/8 outside the single unspecified address, CGNAT (100.64.0.0/10),
	// the IETF protocol-assignment and TEST-NET ranges, the RFC 2544
	// benchmarking range, 240.0.0.0/4, the broadcast address, the IPv6
	// documentation range, and the four IPv6 encodings that wrap an IPv4
	// address. An OIDC issuer or JWKS URI on any of those is now refused at the
	// configuration-write path.
	if ip := net.ParseIP(host); ip != nil {
		if egress.OIDCLiteral.Blocks(ip) {
			return fmt.Errorf("URL host %q is not a permitted egress target: %s",
				host, egress.OIDCLiteral.Reason(ip))
		}
		return nil
	}

	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "metadata" || lower == "metadata.google.internal" {
		return fmt.Errorf("URL host %q is a metadata endpoint", host)
	}
	// NB: .localhost is intentionally NOT in this list — it is a loopback zone
	// (RFC 6761), consistent with the bare-`localhost` and 127.0.0.1 exemptions
	// above. Adding it here would block legitimate local-dev issuers.
	for _, suffix := range []string{".internal", ".local"} {
		if strings.HasSuffix(lower, suffix) {
			return fmt.Errorf("URL host %q targets an internal domain (%s)", host, suffix)
		}
	}
	return nil
}

// CanonicalEmail is the single identity-key canonicalization used by every
// producer and consumer of a per-user identity: the mint API (stores/mints),
// both validators (compare/return), and the revocation list (match). Write
// attribution and read scoping MUST both key on this exact value or a
// developer sees zero of their own rows (#2920 gap 2).
func CanonicalEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// --- Validator registry (the #2920 resolver seam) ---

var (
	registryMu sync.RWMutex
	registry   []TokenValidator
	byName     = map[string]TokenValidator{}
)

// RegisterValidator adds a validator to the process-wide registry in
// registration order. Registering a second validator with the same Name is a
// programming error and returns an error (never silently replaces — a
// replaced validator would be an authz-relevant surprise).
func RegisterValidator(v TokenValidator) error {
	if v == nil {
		return errors.New("identity: RegisterValidator(nil)")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := byName[v.Name()]; dup {
		return errors.New("identity: validator already registered: " + v.Name())
	}
	byName[v.Name()] = v
	registry = append(registry, v)
	return nil
}

// HasRegisteredValidators reports whether the process has at least one
// registered per-user token validator. It is the cheap, allocation-free probe
// the fleet plane uses to detect the #2932 silent-disable case: a per-user
// token was presented but nothing is registered to validate it.
func HasRegisteredValidators() bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return len(registry) > 0
}

// RegisteredValidators returns the registered validators in registration
// order (a copy — callers cannot mutate the registry through it).
func RegisteredValidators() []TokenValidator {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]TokenValidator, len(registry))
	copy(out, registry)
	return out
}

// LookupValidator returns the validator registered under name, or nil.
func LookupValidator(name string) TokenValidator {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return byName[name]
}

// ResetRegistryForTest empties the registry. Test helper only.
func ResetRegistryForTest() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = nil
	byName = map[string]TokenValidator{}
}
