-- Migration 083: stripe_payment_intent_id on plugin_user_licenses (V1 SaaS Plugin Pro)
-- Date: 2026-05-05
-- Context: Issue #1895 — charge.refunded auto-revoke needs to look up the
--          originating license from a Stripe Charge. Charge.metadata is not
--          populated by our Payment Links so we can't go via session_id;
--          we extract payment_intent from the checkout.session.completed
--          event at issuance time and store it for reverse lookup at
--          refund time.
--
-- Forward-only. Nullable so existing rows (issued before this migration)
-- don't violate. Indexed because the refund handler queries on it.

ALTER TABLE plugin_user_licenses
    ADD COLUMN IF NOT EXISTS stripe_payment_intent_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_plugin_user_licenses_payment_intent
    ON plugin_user_licenses(stripe_payment_intent_id)
    WHERE stripe_payment_intent_id IS NOT NULL;

DO $$
BEGIN
    RAISE NOTICE 'Migration 083: stripe_payment_intent_id column added';
END $$;
