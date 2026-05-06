-- Migration 079: Stripe webhook idempotency on plugin_user_licenses
-- Date: 2026-05-04
-- Context: GAP-2 (V1 paid tier security/correctness gap).
--
-- Problem before this migration:
--   The Stripe webhook handler issues a NEW token on every retry of the
--   SAME checkout.session.completed event. Stripe is at-least-once delivery
--   so a single purchase can produce multiple plugin_user_licenses rows
--   (each marking the prior row revoked) — each delivery generates a fresh
--   AXON token, the buyer's first email contains a token that will be
--   revoked seconds later by the webhook retry, and the buyer's second
--   email may arrive minutes later with the actual usable token. From the
--   buyer's perspective: random "token doesn't work" failures.
--
-- Fix:
--   UNIQUE partial index on stripe_session_id so the issuer's INSERT can
--   use ON CONFLICT (stripe_session_id) DO NOTHING and the surrounding
--   transaction can re-fetch the original row's JTI / payload / issued_at,
--   re-mint the SAME token (Ed25519 is deterministic), and return it.
--   Replays are no-ops; the buyer always gets the same token.
--
-- Partial-index on stripe_session_id IS NOT NULL because the column is
-- NULLable today (rows can be created via direct admin tooling without a
-- Stripe session — those don't need idempotency).

CREATE UNIQUE INDEX IF NOT EXISTS idx_plugin_lic_stripe_session
    ON plugin_user_licenses(stripe_session_id)
    WHERE stripe_session_id IS NOT NULL;

DO $$
BEGIN
    RAISE NOTICE 'Migration 079: UNIQUE partial index on plugin_user_licenses(stripe_session_id) — GAP-2 idempotency';
END $$;
