//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package billing implements the W4 axonflow-billing service skeleton: it
// receives Stripe checkout-session-completed webhooks and atomically:
//
//  1. Issues a plugin-claim license token via license.GeneratePluginClaimLicense
//  2. Inserts a corresponding row into plugin_user_licenses
//  3. Returns the token (caller — webhook handler — wraps it in the response
//     and / or hands it to an email sender for delivery)
//
// Why this is a separate package from the agent's HTTP middleware (PR D):
//
//   - Agent middleware is per-request, hot path, no signing keys
//   - Billing is per-checkout, cold path, holds the SIGNING key
//
// Keeping signer + verifier in different packages enforces the operational
// separation called out in ADR-049 section 1's blast-radius isolation
// rationale: a billing-service compromise can issue forged tokens, but
// cannot read or modify the agent's request-time enforcement decisions.
//
// This file ships the LIBRARY only (IssueLicense + helpers). The Stripe
// webhook HTTP handler that invokes IssueLicense lives in webhook.go.
// The Lambda packaging + deployment lives in a separate follow-up.
package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"axonflow/platform/agent/license"
)

// nowFn is the clock the issuer reads to stamp the token's IssuedAt. Default
// is time.Now; tests override it (and restore via t.Cleanup) to make the
// idempotency-replay path produce a byte-deterministic token without
// depending on the wall clock matching a fixture date.
var nowFn = time.Now

// IssueRequest collects the fields needed to mint a SaaS Plugin license +
// persist the corresponding plugin_user_licenses row. All fields are
// required; Validate enforces this.
//
// Per ADR-050 §6 the per-tier limits (retention, quota, capability gates)
// live in the typed `TierLimits` struct keyed by `Tier`, not in a JSONB
// blob on the row. The row carries identity + tier; downstream readers
// (audit_cleanup, community_saas_ratelimit) call GetTierLimits(row.Tier).
type IssueRequest struct {
	TenantID         string // cs_<uuid>; the community-saas tenant the license is bound to
	ClaimedByEmail   string // email associated with the paid claim (typically Stripe checkout email)
	StripeCustomerID string // cus_<id>; for refund / dispute / accounting reconciliation
	StripeSessionID  string // cs_<id>; the checkout session that funded this license
	// StripePaymentIntentID (pi_<id>) is the reverse-lookup key for
	// charge.refunded auto-revoke (#1895). Captured from the
	// checkout.session.completed event's payment_intent field. Stripe
	// always populates payment_intent on Checkout-driven sessions; if
	// empty (legacy / hand-crafted IssueRequest), the row is still issued
	// but won't be auto-revocable on full refund — operator falls back to
	// the manual revoke runbook.
	StripePaymentIntentID string
	Tier                  license.Tier
	ValidityDays          int // 0 = no expiry (Pro v1 one-time pricing)
}

// IssueResult carries everything the webhook handler needs to respond to
// Stripe with 200 + hand the token off to email delivery.
type IssueResult struct {
	LicenseID string    // plugin_user_licenses.license_id (UUID)
	Token     string    // signed AXON-...AXON-...
	JTI       string    // unique token id (matches the row's license_token_jti)
	IssuedAt  time.Time // wall-clock issuance time
	Tier      license.Tier
	TenantID  string
}

// ValidateRequest returns an error describing the first missing/invalid
// field. Caller (webhook handler) should reject with 400 + log + continue
// (Stripe will retry).
func (r IssueRequest) Validate() error {
	if r.TenantID == "" {
		return errors.New("TenantID is required")
	}
	if r.ClaimedByEmail == "" {
		return errors.New("ClaimedByEmail is required")
	}
	// StripeCustomerID is intentionally NOT required.
	//
	// Stripe Payment Links with customer_creation="if_required" (V1 setup)
	// don't create a Customer for one-time payments — the Checkout Session
	// arrives with `customer: null`. Empirically verified 2026-05-06
	// against a real Test purchase. We persist whatever Stripe sends
	// (empty string when null) and rely on stripe_session_id +
	// stripe_payment_intent_id for downstream lookup; the customer ID is
	// best-effort metadata for ops use only.
	if r.StripeSessionID == "" {
		return errors.New("StripeSessionID is required")
	}
	if r.Tier == "" {
		return errors.New("Tier is required")
	}
	if !license.IsSaasPluginTier(r.Tier) {
		return fmt.Errorf("Tier %q must be Pro or Premium", r.Tier)
	}
	return nil
}

// IssueLicense is the entry point for the billing service. It runs the full
// issue-and-persist sequence inside a single SERIALIZABLE transaction so:
//
//   - The plugin_user_licenses row creation is atomic with the token mint
//     (no orphan token / orphan row possible)
//   - The UNIQUE partial index from migration 078 (at-most-one-active-row
//     per tenant) is respected; if a prior active row exists for the same
//     tenant we mark it revoked_at = NOW() inside the same transaction.
//
// Returns an IssueResult on success. On any error, the transaction is rolled
// back and no token has been issued (the token mint itself is reversible
// because we only persist the public facts; the private key never gets
// network or disk).
//
// IDEMPOTENCY (GAP-2): the function is idempotent over StripeSessionID. If a
// row already exists with the requested StripeSessionID, the original token
// is re-minted byte-identical (Ed25519 deterministic signing + same
// JTI/KID/IssuedAt) and returned. Stripe's at-least-once webhook delivery
// can therefore retry the same checkout.session.completed event without
// producing additional tokens or revoking the original.
func IssueLicense(ctx context.Context, db *sql.DB, req IssueRequest) (*IssueResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid IssueRequest: %w", err)
	}
	if db == nil {
		return nil, errors.New("db is nil")
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Per-tenant serialization lock. SERIALIZABLE alone isn't enough here:
	// two concurrent webhook deliveries for the same checkout can both pass
	// the idempotency SELECT (both see snapshots from before the other's
	// commit), then T1 inserts and commits. T2 is still in flight; its UPDATE
	// step is evaluated against latest committed state for the unique-active
	// constraint, so it sees T1's row and revokes it before T2's INSERT
	// trips ON CONFLICT and falls through to re-mint. T2 returns the
	// "original" token but the row is now revoked — middleware rejects it
	// for the buyer.
	//
	// Holding a per-tenant advisory lock for the duration of the tx
	// serializes all webhook deliveries for the same tenant. T2 blocks on
	// the lock until T1 commits and releases it. T2 then sees T1's row in
	// the idempotency check and re-mints cleanly without revoking it.
	// pg_advisory_xact_lock takes a bigint key derived from tenant_id;
	// hashtext gives us a deterministic 32-bit hash with a uniform-enough
	// distribution that collisions across distinct concurrent tenants are
	// negligible (worst case: occasional spurious cross-tenant blocking,
	// not correctness loss).
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, req.TenantID); err != nil {
		return nil, fmt.Errorf("acquire per-tenant lock: %w", err)
	}

	// Idempotency check (migration 079 UNIQUE partial index on
	// stripe_session_id). If we've already issued for this session, re-mint
	// the same token and return. Tenant + email + tier come from the row,
	// not from req — defends against a malicious caller passing a different
	// tenant_id with the same session_id (would be a hijack).
	if req.StripeSessionID != "" {
		existing, err := selectExistingLicenseBySession(ctx, tx, req.StripeSessionID)
		if err != nil {
			return nil, fmt.Errorf("idempotency lookup: %w", err)
		}
		if existing != nil {
			result, err := remintFromExistingRow(existing, req)
			if err != nil {
				return nil, fmt.Errorf("re-mint existing token: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return nil, fmt.Errorf("commit (idempotent path): %w", err)
			}
			committed = true
			return result, nil
		}
	}

	// Mint the token. This is deterministic-given-inputs, so if Generate
	// fails we have not yet persisted anything.
	//
	// Capture IssuedAt explicitly so the value baked into the token matches
	// the value persisted on the row. Without this the token would carry
	// time.Now() while the row would carry the DB's NOW() (potentially a
	// different day under clock skew or test fixtures), and the re-mint
	// path on replay would produce a byte-different token. Idempotency is
	// only as durable as our IssuedAt source.
	issuedAt := nowFn()
	token, err := license.GeneratePluginClaimLicense(license.PluginClaimLicenseInput{
		TenantID:       req.TenantID,
		ClaimedByEmail: req.ClaimedByEmail,
		Tier:           req.Tier,
		ValidityDays:   req.ValidityDays,
		IssuedAt:       issuedAt,
		// JTI/KID auto-generate inside Generate
	})
	if err != nil {
		return nil, fmt.Errorf("GeneratePluginClaimLicense: %w", err)
	}

	// Decode the token to recover the JTI so we can write it as the unique
	// row-side identifier. ValidatePluginClaimToken does the parse + verify
	// pass — equivalent to "unwrap and re-verify" but we trust Generate
	// just-issued the token so the verification is belt-and-braces only.
	payload, err := license.ValidatePluginClaimToken(token)
	if err != nil {
		return nil, fmt.Errorf("self-verify newly-issued token: %w", err)
	}
	jti := payload.JTI

	// Revoke any prior active row for this tenant — required by migration
	// 078's UNIQUE partial index (at most one active row per tenant). The
	// `IS DISTINCT FROM` clause excludes any row matching the new session
	// (NULL-safe), so even if the per-tenant lock above somehow failed to
	// serialize concurrent webhook deliveries, this UPDATE can never revoke
	// the row we're about to (or just did) idempotently re-mint from. Belt
	// and braces.
	if _, err := tx.ExecContext(ctx, `
		UPDATE plugin_user_licenses
		   SET revoked_at = NOW(),
		       revocation_reason = COALESCE(revocation_reason, 'replaced_by_new_purchase')
		 WHERE tenant_id = $1
		   AND revoked_at IS NULL
		   AND (stripe_session_id IS DISTINCT FROM $2)`,
		req.TenantID, req.StripeSessionID); err != nil {
		return nil, fmt.Errorf("revoke prior active row: %w", err)
	}

	var licenseID string
	// ON CONFLICT (stripe_session_id) DO NOTHING handles the rare race where
	// two concurrent webhook deliveries for the same session both pass the
	// SELECT idempotency check above. The losing transaction sees 0 rows
	// affected via sql.ErrNoRows, falls back to re-fetching the winner's
	// row, and re-mints from that. Without DO NOTHING the losing tx would
	// fail with a duplicate-key constraint error.
	//
	// We pass `issuedAt` explicitly (rather than letting the column default
	// to NOW()) so the persisted issued_at exactly matches the value baked
	// into the token's payload. That coupling is what makes the re-mint
	// path on Stripe replay produce byte-identical tokens.
	// stripe_payment_intent_id ($8) is the reverse-lookup key for
	// charge.refunded auto-revoke (#1895). Nullable on the column
	// (migration 083) so legacy callers without payment_intent still
	// insert cleanly; when empty we pass sql.NullString{Valid:false}
	// so the row carries NULL rather than the empty string (the
	// idx_plugin_user_licenses_payment_intent partial index excludes
	// NULL → no contention with future inserts).
	var pi sql.NullString
	if strings.TrimSpace(req.StripePaymentIntentID) != "" {
		pi = sql.NullString{String: strings.TrimSpace(req.StripePaymentIntentID), Valid: true}
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO plugin_user_licenses
		  (tenant_id, claimed_by_email, tier, license_token_jti,
		   stripe_customer_id, stripe_session_id, issued_at,
		   stripe_payment_intent_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (stripe_session_id) WHERE stripe_session_id IS NOT NULL DO NOTHING
		RETURNING license_id::text, issued_at`,
		req.TenantID, req.ClaimedByEmail, string(req.Tier), jti,
		req.StripeCustomerID, req.StripeSessionID, issuedAt,
		pi,
	).Scan(&licenseID, &issuedAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Race: a concurrent webhook delivery for the same session won the
		// INSERT. Re-fetch the winner's row and re-mint to return that token.
		existing, lookupErr := selectExistingLicenseBySession(ctx, tx, req.StripeSessionID)
		if lookupErr != nil {
			return nil, fmt.Errorf("post-conflict lookup: %w", lookupErr)
		}
		if existing == nil {
			// Should be impossible — DO NOTHING would only have fired if a
			// row existed. Treat as data corruption / serializable retry.
			return nil, errors.New("INSERT conflict but no existing row found (serializable race)")
		}
		result, err := remintFromExistingRow(existing, req)
		if err != nil {
			return nil, fmt.Errorf("re-mint after conflict: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit (conflict path): %w", err)
		}
		committed = true
		return result, nil
	}
	if err != nil {
		return nil, fmt.Errorf("insert plugin_user_licenses: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	committed = true

	return &IssueResult{
		LicenseID: licenseID,
		Token:     token,
		JTI:       jti,
		IssuedAt:  issuedAt,
		Tier:      req.Tier,
		TenantID:  req.TenantID,
	}, nil
}

// existingLicenseRow carries the fields needed to re-mint a previously-issued
// token. Pulled from plugin_user_licenses by selectExistingLicenseBySession
// when the Stripe webhook handler retries for an already-handled session.
type existingLicenseRow struct {
	LicenseID      string
	TenantID       string
	ClaimedByEmail string
	Tier           string
	JTI            string
	IssuedAt       time.Time
}

// selectExistingLicenseBySession looks up a previously-issued license row by
// stripe_session_id. Returns (nil, nil) when no row exists. Used as the
// idempotency check at the top of IssueLicense.
//
// FOR UPDATE locks the row inside the SERIALIZABLE transaction so a parallel
// webhook delivery for the same session can't race past this check.
func selectExistingLicenseBySession(ctx context.Context, tx *sql.Tx, sessionID string) (*existingLicenseRow, error) {
	var row existingLicenseRow
	err := tx.QueryRowContext(ctx, `
		SELECT license_id::text, tenant_id, claimed_by_email, tier,
		       license_token_jti, issued_at
		  FROM plugin_user_licenses
		 WHERE stripe_session_id = $1
		 LIMIT 1
		   FOR UPDATE`, sessionID).Scan(
		&row.LicenseID, &row.TenantID, &row.ClaimedByEmail, &row.Tier,
		&row.JTI, &row.IssuedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// remintFromExistingRow reconstructs the original token from a stored row.
// Ed25519 is deterministic — given the same payload bytes (same JTI, KID,
// IssuedAt, Tier, TenantID, Email, OrgID) signed with the same key, the
// signature is byte-identical to the original.
//
// ValidityDays is hardcoded to 0 (Pro v1 = no expiry). The req parameter is
// intentionally NOT consulted for ValidityDays — if the caller's config
// changed between the original issuance and the replay (e.g. operator bumped
// the default), using req.ValidityDays would produce a different ExpiresAt
// in the payload and break the byte-identical guarantee. V1 is one-time
// pricing only; Premium v2 will need ValidityDays persisted on the row.
//
// Same goes for KID — package default for V1; future rotation needs row-side
// storage.
func remintFromExistingRow(row *existingLicenseRow, _ IssueRequest) (*IssueResult, error) {
	tier := license.Tier(row.Tier)
	if !license.IsSaasPluginTier(tier) {
		return nil, fmt.Errorf("stored tier %q is not a SaaS Plugin tier — refusing to re-mint", row.Tier)
	}
	token, err := license.GeneratePluginClaimLicense(license.PluginClaimLicenseInput{
		TenantID:       row.TenantID,
		ClaimedByEmail: row.ClaimedByEmail,
		Tier:           tier,
		ValidityDays:   0,            // hardcoded for V1 — see fn doc
		JTI:            row.JTI,      // KEY for determinism
		IssuedAt:       row.IssuedAt, // KEY for determinism
	})
	if err != nil {
		return nil, err
	}
	return &IssueResult{
		LicenseID: row.LicenseID,
		Token:     token,
		JTI:       row.JTI,
		IssuedAt:  row.IssuedAt,
		Tier:      tier,
		TenantID:  row.TenantID,
	}, nil
}
