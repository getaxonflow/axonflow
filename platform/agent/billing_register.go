//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"strconv"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/billing"
	"axonflow/platform/shared/secretenv"
)

// proValidityDaysDefault is the default token-validity window for Pro
// purchases per PRD_TENANT_DURABILITY_AND_CLAIM "Free vs Paid Boundary"
// (locked 2026-05-05): a $9.99 purchase grants 90 days of Pro tier; at
// expiry the tenant drops to Free. Operators may override via the env
// var AXONFLOW_BILLING_PRO_VALIDITY_DAYS for time-shifted test runs.
const proValidityDaysDefault = 90

// RegisterBillingWebhook wires the Stripe webhook into the agent router.
// In enterprise / community-saas builds it delegates to the billing package;
// in community builds the symbol resolves to billing_register_community.go's
// no-op so run.go can call it unconditionally regardless of build tag.
//
// Configuration:
//
//	STRIPE_WEBHOOK_SIGNING_SECRET — whsec_... from Stripe dashboard. When
//	  unset, this function returns early without registering the route. The
//	  decision to fail-open (rather than panic) is deliberate: dev / test
//	  stacks that don't accept payments shouldn't fail to boot, and an
//	  operator running prod without the secret will see "no route" 404s
//	  in the Stripe dashboard delivery log within minutes.
//
//	AXONFLOW_BILLING_PRO_VALIDITY_DAYS — token validity window in days
//	  (default 90 per the locked Pro product). Bad values fall through
//	  to the default rather than failing boot.
//
//	RESEND_API_KEY + AXONFLOW_BILLING_FROM_EMAIL — read by
//	  NewLicenseEmailSenderFromEnv. Falls back to NoopLicenseEmailSender
//	  (logs + capture file) when RESEND_API_KEY is unset.
func RegisterBillingWebhook(router *mux.Router, db *sql.DB) {
	// secretenv.Get trims whitespace — AWS SM secrets routinely carry
	// trailing newlines and Stripe HMAC verification fails silently
	// (computed digest differs from a whitespace-padded key, no
	// diagnostic in the 401).
	secret := secretenv.Get("STRIPE_WEBHOOK_SIGNING_SECRET")
	if secret == "" {
		// Intentionally silent — dev stacks routinely run without payment
		// configuration. Operators discover this via Stripe dashboard
		// delivery failures (visible 404s, not silent drops).
		return
	}

	cfg := billing.WebhookHandlerConfig{
		SigningSecret: secret,
		ValidityDays:  proValidityDays(),
		EmailSender:   billing.NewLicenseEmailSenderFromEnv(),
	}
	billing.RegisterStripeWebhookHandler(router, db, cfg)
}

// proValidityDays reads the operator override or falls back to the locked
// 90-day default. A non-numeric or non-positive value falls through to
// the default rather than failing boot. Reads via secretenv.Get because
// SM-resolved values commonly carry trailing whitespace and strconv.Atoi
// would otherwise return "invalid syntax" on a clean integer with a
// trailing \n.
func proValidityDays() int {
	if v := secretenv.Get("AXONFLOW_BILLING_PRO_VALIDITY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return proValidityDaysDefault
}
