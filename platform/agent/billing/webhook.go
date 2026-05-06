//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/agent/license"
)

// Constants used for Stripe webhook signature verification. We implement
// signature checking ourselves rather than pulling stripe-go because the
// algorithm is small and stable, and avoiding the dep keeps the billing
// service binary footprint tight enough for a Lambda cold start.
const (
	stripeSignatureHeader = "Stripe-Signature"

	// stripeSignatureMaxAge is the freshness window for the timestamp in
	// Stripe-Signature. Stripe recommends 5 minutes; we mirror that.
	stripeSignatureMaxAge = 5 * time.Minute

	// maxRequestBodyBytes caps the inbound webhook body size. Stripe events
	// are well under 64 KiB in practice — this stops a malformed/malicious
	// request from exhausting memory.
	maxRequestBodyBytes = 1 << 16
)

// stripeEvent is the minimal subset of the Stripe Event envelope this
// webhook needs to read. We deliberately don't model the full Stripe API:
// changes to unrelated fields (line items, custom metadata) shouldn't
// require this code to recompile, and a leaner unmarshal is faster.
//
// Data.Object is held as json.RawMessage rather than a fixed type because
// different event types carry different object shapes
// (checkout.session.completed → CheckoutSession;
//  charge.refunded → Charge). Each handler unmarshals into its own typed
// struct off the raw bytes.
type stripeEvent struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Data stripeEventData `json:"data"`
}

type stripeEventData struct {
	Object json.RawMessage `json:"object"`
}

// stripeCheckoutSession is the minimal subset of a Stripe Checkout Session
// the issuer needs. tenant_id arrives via custom_fields[].text.value where
// key == "tenantid" — Stripe constrains custom_fields[].key to alphanumeric
// only, so a Dashboard label "tenant_id" sluggifies to "tenantid". V1 uses
// Stripe Payment Links exclusively (Dashboard-created); backend-driven
// Checkout Sessions (which would let us choose the key explicitly) are
// not part of V1.
//
// AmountTotal is the gross order total in the smallest currency unit (cents
// for USD). Captured here so the success log line carries the actual paid
// amount — useful for the FirstPayment alarm message context and for cross-
// referencing the issued license against the Stripe charge during refund
// reconciliation. Stripe sends this on every checkout.session.completed
// event; absence (0) is logged but not an error.
type stripeCheckoutSession struct {
	ID            string              `json:"id"`             // cs_<id>
	Customer      string              `json:"customer"`       // cus_<id>
	CustomerEmail string              `json:"customer_email"` // top-level; populated only when caller explicitly sets it on Session create. Real Payment Link checkouts leave this null and put the buyer's email in CustomerDetails.Email instead.
	CustomFields  []stripeCustomField `json:"custom_fields"`
	Mode          string              `json:"mode"`           // "payment" (one-time) or "subscription"
	PaymentStatus string              `json:"payment_status"` // "paid" required
	AmountTotal   int64               `json:"amount_total"`   // gross total in smallest currency unit (cents); 999 for $9.99 V1 Pro
	Currency      string              `json:"currency"`       // ISO 4217 lowercase (e.g. "usd")
	// CustomerDetails.Email is where Stripe writes the buyer's email for
	// Payment-Link / hosted-Checkout sessions whose customer_creation is
	// "if_required" (our V1 setup). The top-level `customer_email` is only
	// populated when the caller passes it explicitly at Session create time
	// — which V1 doesn't (the buyer types it on the Stripe-hosted form).
	// Empirically verified 2026-05-06 against a real Test buyer payload —
	// our handler initially read only `customer_email` and returned 400
	// "missing customer_email" on real Test purchases. Fix: read
	// CustomerDetails.Email first, fall back to top-level for synthetic
	// fixtures and any future caller that does set it explicitly.
	CustomerDetails *stripeCheckoutCustomerDetails `json:"customer_details"`
	// PaymentIntent (pi_<id>) is Stripe's per-charge identifier on a Checkout
	// Session. We persist it onto plugin_user_licenses.stripe_payment_intent_id
	// at issuance time so the charge.refunded handler can look the originating
	// license up by payment_intent — Charge.metadata is empty for our Payment
	// Links (verified via Stripe API on plink_1TTPnJCokRiQkpTDBXXIDmqy) so the
	// session-id-via-metadata path doesn't fire on real refunds. See #1895.
	PaymentIntent string `json:"payment_intent"`
}

// stripeCheckoutCustomerDetails is the minimal subset of Stripe's
// customer_details object the handler reads. Stripe populates this on every
// hosted-Checkout session post-payment (regardless of customer_creation
// mode). Only Email is used by the issuance flow; other fields (name,
// address, tax_ids) could be modeled later if billing wants buyer name on
// the audit row.
type stripeCheckoutCustomerDetails struct {
	Email string `json:"email"`
}

// resolveBuyerEmail returns the buyer's email from the Checkout Session,
// preferring customer_details.email (populated by every real Stripe
// hosted-Checkout payload) and falling back to the top-level
// customer_email (used by synthetic fixtures and any future caller that
// passes the email at Session create time). Trims whitespace; returns ""
// if neither path produces a value so the caller can return its existing
// "missing customer_email" 400 response.
func resolveBuyerEmail(cs stripeCheckoutSession) string {
	if cs.CustomerDetails != nil {
		if e := strings.TrimSpace(cs.CustomerDetails.Email); e != "" {
			return e
		}
	}
	return strings.TrimSpace(cs.CustomerEmail)
}

// stripeCustomField is the per-field shape Stripe sends in the
// custom_fields array on a checkout.session.completed event. Only the
// fields we need are modeled; Stripe sends more (label localization,
// numeric/dropdown variants, optional flag, type metadata) that we ignore.
//
// See: https://docs.stripe.com/api/checkout/sessions/object#checkout_session_object-custom_fields
type stripeCustomField struct {
	Key  string                `json:"key"`
	Type string                `json:"type"` // "text" | "numeric" | "dropdown"
	Text *stripeCustomFieldVal `json:"text,omitempty"`
	// Numeric/Dropdown variants intentionally omitted — V1 only uses text
	// for the tenant_id field. If we add more custom fields later, model
	// the shapes we need then.
}

type stripeCustomFieldVal struct {
	Value string `json:"value"`
}

// tenantIDCustomFieldKey is the single Stripe custom_fields[].key value the
// resolver accepts. Stripe constrains custom_fields[].key to alphanumeric
// only (no underscore/hyphen), so a Dashboard label "tenant_id" sluggifies
// to "tenantid" — that's what real Live and Test webhook deliveries carry.
// V1 ships Payment Links only; backend-driven Checkout Sessions (which
// would let us pick the key explicitly) are not part of V1.
const tenantIDCustomFieldKey = "tenantid"

// resolveTenantID extracts tenant_id from a checkout session by reading
// custom_fields[].text.value where key == "tenantid". Returns "" if not
// set. Trims whitespace (Stripe-hosted custom-field input is user-typed
// and may include trailing space from copy-paste). Error return is kept
// for API-stability with callers; current implementation never returns
// non-nil.
func resolveTenantID(cs stripeCheckoutSession) (string, error) {
	for _, cf := range cs.CustomFields {
		if cf.Key != tenantIDCustomFieldKey || cf.Type != "text" || cf.Text == nil {
			continue
		}
		return strings.TrimSpace(cf.Text.Value), nil
	}
	return "", nil
}

// =============================================================================
// Issuance-failure reason taxonomy (alarm-pattern stability)
// =============================================================================
//
// The CW alarm `LicenseIssuanceFailureMetricFilter` keys off the literal
// `event=paid_but_no_token_issued` token + the `reason=<canonical>` token.
// To keep the metric-filter pattern stable across error-string churn,
// IssueLicense errors are classified here into a SMALL fixed set rather
// than pushing the raw `err.Error()` text into the alarm-matched line.
//
// Adding a new reason value requires updating:
//
//   - this list (the canonical set is the source of truth)
//   - infrastructure/cloudformation/community-saas-alarms.yaml (the metric
//     filter pattern only matches `event=paid_but_no_token_issued`, which
//     is reason-agnostic — but the per-reason cardinality lives in the
//     log line, so any operator dashboards that group by reason need
//     updating)
//   - the unit tests below (TestClassifyIssueLicenseErr_*)
//
// Rationale for picking these specific buckets, not free-form strings:
//
//   - "tx_begin"        — db.BeginTx failed (DB unreachable, connection
//                         exhaustion, network partition)
//   - "advisory_lock"   — pg_advisory_xact_lock failed (rare; usually
//                         signals tx_begin would also fail, but separated
//                         to expose lock-acquisition starvation)
//   - "idempotency_lookup" — SELECT ... FOR UPDATE on the existing row
//                            failed (tx in flight; usually surfaces with
//                            a generic SQL error)
//   - "validation"      — IssueRequest.Validate() rejected the input
//                         (caller bug — bad TenantID, missing Tier, etc.)
//   - "signing_failed"  — license.GeneratePluginClaimLicense or self-verify
//                         failed (signing-key not loaded, malformed key,
//                         deterministic-payload bug)
//   - "db_insert"       — INSERT INTO plugin_user_licenses failed (FK
//                         violation, advisory lock contention from a
//                         non-billing path, post-conflict re-fetch failed)
//   - "commit"          — tx.Commit failed (constraint violation surfaced
//                         at commit time, network drop after INSERT)
//   - "unknown"         — fallback for unmapped error wrappers; should
//                         never fire on a stable codebase but keeps the
//                         field non-empty in the alarm log line
//
// The classifier matches the wrapping prefixes IssueLicense applies via
// fmt.Errorf("<prefix>: %w", err). If IssueLicense's wrappers change, the
// classifier must change in lockstep — that's enforced by the explicit
// per-reason unit tests below.
const (
	issueReasonTxBegin           = "tx_begin"
	issueReasonAdvisoryLock      = "advisory_lock"
	issueReasonIdempotencyLookup = "idempotency_lookup"
	issueReasonValidation        = "validation"
	issueReasonSigningFailed     = "signing_failed"
	issueReasonDBInsert          = "db_insert"
	issueReasonCommit            = "commit"
	issueReasonUnknown           = "unknown"
)

// classifyIssueLicenseErr maps an IssueLicense error to one of the canonical
// reason values above. The mapping is deterministic given the wrappers
// IssueLicense applies; see issuer.go for the source of those prefixes.
//
// Pure function (no logging side effects) so callers can include the result
// in their own log line; tests assert the classifier is closed over the full
// set of failure modes.
func classifyIssueLicenseErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "invalid IssueRequest:"):
		return issueReasonValidation
	case strings.HasPrefix(msg, "begin tx:"):
		return issueReasonTxBegin
	case strings.HasPrefix(msg, "acquire per-tenant lock:"):
		return issueReasonAdvisoryLock
	case strings.HasPrefix(msg, "idempotency lookup:"),
		strings.HasPrefix(msg, "post-conflict lookup:"):
		return issueReasonIdempotencyLookup
	case strings.HasPrefix(msg, "GeneratePluginClaimLicense:"),
		strings.HasPrefix(msg, "self-verify newly-issued token:"),
		strings.HasPrefix(msg, "re-mint existing token:"),
		strings.HasPrefix(msg, "re-mint after conflict:"):
		return issueReasonSigningFailed
	case strings.HasPrefix(msg, "revoke prior active row:"),
		strings.HasPrefix(msg, "insert plugin_user_licenses:"),
		strings.Contains(msg, "INSERT conflict but no existing row found"):
		return issueReasonDBInsert
	case strings.HasPrefix(msg, "commit:"),
		strings.HasPrefix(msg, "commit (idempotent path):"),
		strings.HasPrefix(msg, "commit (conflict path):"):
		return issueReasonCommit
	default:
		return issueReasonUnknown
	}
}

// =============================================================================
// charge.refunded — auto-revoke license on full refund (#1895)
// =============================================================================
//
// Stripe fires charge.refunded whenever a Refund is created or updated for a
// Charge. The event object is a Charge (NOT a CheckoutSession). We map the
// Charge back to the originating license via Charge.payment_intent
// (pi_<id>) — the same identifier we persist onto
// plugin_user_licenses.stripe_payment_intent_id at issuance time from the
// checkout.session.completed event. Charge.metadata is NOT used because
// Stripe Payment Links don't propagate session metadata onto the underlying
// Charge object (verified empirically against our Live + Test Payment Links;
// see issue #1895 orchestrator review for the GET /v1/payment_links/<id>
// reproduction).
//
// Full vs partial refund decision rule (per #1895):
//
//   - Full refund: charge.amount_refunded == charge.amount AND the most
//     recent refund.status == "succeeded". Revoke the license.
//   - Partial refund: amount_refunded < amount. NO-OP (logged, 200 returned).
//
// Idempotency: the UPDATE has WHERE revoked_at IS NULL, so a replayed event
// targeting an already-revoked row affects 0 rows and the handler logs the
// idempotent path. No event-dedup table needed.
//
// Re-purchase semantics: a buyer who refunds + re-purchases gets a NEW
// plugin_user_licenses row (issuer.go::IssueLicense is idempotent by
// stripe_session_id; a fresh checkout produces a fresh session ID + a fresh
// payment_intent). The refund-revoke here only revokes by the prior purchase's
// stripe_payment_intent_id, so the new license is not affected.

// stripeChargeRefundedObject is the minimal subset of the Stripe Charge
// object the refund handler needs. Fields not modeled (line_items,
// payment_method_details, billing_details, ...) are silently ignored on
// JSON unmarshal — see https://docs.stripe.com/api/charges/object.
//
// PaymentIntent is the lookup key for the originating license row. See the
// header comment above for why we don't use Metadata here.
//
// Metadata is kept on the struct for diagnostic logging only (it is empty
// on real Payment Link refunds today, but preserving the field means a
// future Stripe-side change that re-populates it lands without a code
// change here).
//
// Refunds.Data carries the per-refund records; we read the latest one to
// confirm refund.status == "succeeded" before revoking. Stripe sends the
// most recent refund first in the array.
type stripeChargeRefundedObject struct {
	ID             string                  `json:"id"`              // ch_<id>
	Amount         int64                   `json:"amount"`          // gross charge in smallest currency unit
	AmountRefunded int64                   `json:"amount_refunded"` // total refunded so far (cumulative)
	Currency       string                  `json:"currency"`
	Refunded       bool                    `json:"refunded"`       // Stripe-computed: true when fully refunded
	PaymentIntent  string                  `json:"payment_intent"` // pi_<id>; reverse-lookup key into plugin_user_licenses.stripe_payment_intent_id
	Metadata       map[string]string       `json:"metadata"`       // kept for diagnostic logging; NOT the lookup key (see header comment)
	Refunds        stripeChargeRefundsList `json:"refunds"`
}

type stripeChargeRefundsList struct {
	Data []stripeRefund `json:"data"`
}

type stripeRefund struct {
	ID     string `json:"id"`     // re_<id>
	Amount int64  `json:"amount"` // smallest currency unit
	Status string `json:"status"` // "succeeded" | "pending" | "failed" | "canceled"
}

// resolvePaymentIntentFromCharge returns the originating PaymentIntent ID
// (pi_<id>) for a Charge. Stripe always populates `payment_intent` on the
// Charge object for Charges created via Checkout (Payment Links + Sessions
// API both go through PaymentIntents).
//
// Returns "" if the field is absent (defensive — would be a Stripe-side
// payload-shape change, but we want to fall through to the canonical
// "no key, can't map" log line rather than UPDATE WHERE column = '').
func resolvePaymentIntentFromCharge(ch stripeChargeRefundedObject) string {
	return strings.TrimSpace(ch.PaymentIntent)
}

// isFullRefund returns true when the Charge has been fully refunded AND the
// latest refund status is "succeeded". Stripe sometimes fires charge.refunded
// while a refund is still pending; we only want to revoke once the funds have
// actually been returned to the buyer.
func isFullRefund(ch stripeChargeRefundedObject) bool {
	if ch.Amount <= 0 {
		return false
	}
	if ch.AmountRefunded < ch.Amount {
		return false
	}
	// AmountRefunded >= Amount → fully refunded by amount.
	// Confirm at least one refund.status == "succeeded". The Refunds.Data
	// list is sorted most-recent-first by Stripe; we walk it to be defensive
	// if Stripe ever changes the order.
	for _, r := range ch.Refunds.Data {
		if r.Status == "succeeded" {
			return true
		}
	}
	// Fallback: Stripe also sets the top-level `refunded` boolean once the
	// Charge has been fully refunded with at least one succeeded refund.
	// Trust it as a belt-and-braces signal even if Refunds.Data is empty
	// (the Refunds list is sometimes truncated for API-list-vs-event-payload
	// reasons; the boolean is authoritative for the all-or-nothing case).
	return ch.Refunded
}

// revokeReasonFullRefund is the canonical revocation_reason value written to
// plugin_user_licenses.revocation_reason for a full-refund-driven revoke.
// Stable token — used by the synthetic test + future operator dashboards.
const revokeReasonFullRefund = "full_refund"

// handleChargeRefunded auto-revokes the license issued for the originating
// PaymentIntent when the Charge has been fully refunded. Partial refunds
// are a no-op. Replays / already-revoked rows are no-op idempotent.
//
// All paths return 200 (so Stripe stops retrying). Failure modes that should
// trigger a Stripe retry — DB unreachable, malformed payload — return 5xx.
//
// Lookup key is `stripe_payment_intent_id` (persisted at issuance from
// the checkout.session.completed event's payment_intent field). The
// stripe_session_id is recovered atomically via UPDATE ... RETURNING so
// the audit row + log lines + response body keep their existing
// session-keyed shape (alarm metric filters and operator dashboards
// already key off `session=<cs_id>`).
func (h *WebhookHandler) handleChargeRefunded(w http.ResponseWriter, ctx context.Context, ev stripeEvent) {
	var ch stripeChargeRefundedObject
	if err := json.Unmarshal(ev.Data.Object, &ch); err != nil {
		log.Printf("[billing.webhook] parse charge.refunded: %v", err)
		http.Error(w, "bad charge.refunded payload", http.StatusBadRequest)
		return
	}

	paymentIntentID := resolvePaymentIntentFromCharge(ch)
	if paymentIntentID == "" {
		// No payment_intent on the charge — can't map to a license row. Still
		// 200 so Stripe doesn't retry forever; operator picks it up via this
		// log line. Would be a Stripe-side payload-shape change for any
		// charge originating from a Checkout Session / Payment Link.
		log.Printf("[billing.webhook] event=refund_no_payment_intent charge=%s amount=%d amount_refunded=%d",
			ch.ID, ch.Amount, ch.AmountRefunded)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "skipped",
			"reason": "no payment_intent on charge",
			"charge": ch.ID,
		})
		return
	}

	if !isFullRefund(ch) {
		// Partial refund — explicit V1 product decision: do nothing. Logged
		// at the canonical alarm-stable token so operators can monitor
		// partial-refund volume. The session= field is filled in from the
		// active license row so dashboards keyed off session= keep working;
		// fall back to the payment_intent if no row matches (rare — would
		// be a refund on a charge that never produced a license, e.g. a
		// hand-created Stripe charge).
		sessionID := h.lookupSessionForPaymentIntent(ctx, paymentIntentID)
		if sessionID == "" {
			sessionID = paymentIntentID
		}
		log.Printf("[billing.webhook] event=partial_refund_no_op session=%s charge=%s refund_amount=%d charge_amount=%d",
			sessionID, ch.ID, ch.AmountRefunded, ch.Amount)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":          "skipped",
			"reason":          "partial refund — license retained",
			"session":         sessionID,
			"charge":          ch.ID,
			"amount":          ch.Amount,
			"amount_refunded": ch.AmountRefunded,
		})
		return
	}

	// Full refund. Revoke the matching active license row.
	//
	// IDEMPOTENCY: WHERE revoked_at IS NULL — a replayed event (or a row
	// already revoked by another path, e.g. token expiry / replaced-by-new-
	// purchase) yields RowsAffected=0 and we log the no-op path. No event-
	// dedup table needed; the row's single-flag revoked_at IS the dedup state.
	//
	// `RETURNING stripe_session_id` recovers the session_id atomically so
	// downstream audit + log lines + response body keep their session-keyed
	// shape without a separate SELECT. Used QueryRowContext (not ExecContext)
	// because we need the returned column.
	//
	// Stripe's webhook timeout is 30s; cap the DB call so a stuck transaction
	// can't hold the connection forever.
	dbCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var sessionID string
	err := h.db.QueryRowContext(dbCtx, `
		UPDATE plugin_user_licenses
		   SET revoked_at = NOW(),
		       revocation_reason = $2
		 WHERE stripe_payment_intent_id = $1
		   AND revoked_at IS NULL
		 RETURNING stripe_session_id`,
		paymentIntentID, revokeReasonFullRefund).Scan(&sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		// Three equally-valid causes — see the original (a)/(b)/(c) taxonomy
		// in the prior implementation. Externally indistinguishable; we
		// emit the canonical `event=refund_already_revoked` token in all
		// three. The session= field is best-effort: try to look up the
		// matching (revoked) row to surface its session_id, fall back to
		// the payment_intent if no row exists at all (case (c)).
		sessionID = h.lookupSessionForPaymentIntent(ctx, paymentIntentID)
		if sessionID == "" {
			sessionID = paymentIntentID
		}
		log.Printf("[billing.webhook] event=refund_already_revoked session=%s charge=%s",
			sessionID, ch.ID)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "no_op",
			"reason":  "license already revoked or absent",
			"session": sessionID,
			"charge":  ch.ID,
		})
		return
	}
	if err != nil {
		// DB-level failure — return 500 so Stripe retries. The next delivery
		// will land on either a healthy DB (success) or the same failure
		// (operator alerting). Carry payment_intent in the log so the
		// operator can manually run the UPDATE while debugging without
		// having to walk back to the originating event.
		log.Printf("[billing.webhook] event=refund_revoke_db_error payment_intent=%s charge=%s err=%v",
			paymentIntentID, ch.ID, err)
		http.Error(w, "refund revoke failed", http.StatusInternalServerError)
		return
	}

	// Successful revoke. Audit row mirrors the AuditTypeAudit shape
	// (agent_audit_logs: client_id, action, resource, timestamp) for
	// downstream analytics + compliance retrieval. client_id stays the
	// stripe_session_id (returned by the UPDATE above) so the existing
	// audit-trail shape is preserved across the lookup-key migration.
	// Best-effort: a failed audit insert MUST NOT fail the webhook (the
	// buyer's refund completes regardless and the license IS revoked at
	// this point).
	if _, err := h.db.ExecContext(dbCtx, `
		INSERT INTO agent_audit_logs (client_id, action, resource, timestamp)
		VALUES ($1, $2, $3, NOW())`,
		sessionID,
		"license_revoked_full_refund",
		fmt.Sprintf("charge=%s amount_refunded=%d", ch.ID, ch.AmountRefunded),
	); err != nil {
		log.Printf("[billing.webhook] event=refund_audit_write_failed session=%s charge=%s err=%v",
			sessionID, ch.ID, err)
	}

	// Single-purpose alarm-stable token. Keep wording stable — the alarms
	// stack metric filter (community-saas-alarms.yaml) keys off
	// `event=license_revoked_on_refund` if/when an operator wants to alert
	// on revoke volume.
	log.Printf("[billing.webhook] event=license_revoked_on_refund session=%s charge=%s amount_refunded=%d reason=%s",
		sessionID, ch.ID, ch.AmountRefunded, revokeReasonFullRefund)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "revoked",
		"reason":          revokeReasonFullRefund,
		"session":         sessionID,
		"charge":          ch.ID,
		"amount_refunded": ch.AmountRefunded,
	})
}

// lookupSessionForPaymentIntent does a best-effort SELECT to recover the
// stripe_session_id for a payment_intent when the UPDATE didn't fire (no
// active row, partial refund, etc). Returns "" on no-match or DB error —
// callers fall back to the payment_intent for log/response context. Uses a
// short timeout because this is a non-critical-path lookup; we'd rather log
// the payment_intent and move on than hang the webhook on a slow query.
func (h *WebhookHandler) lookupSessionForPaymentIntent(ctx context.Context, paymentIntentID string) string {
	if paymentIntentID == "" {
		return ""
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var sessionID string
	if err := h.db.QueryRowContext(lookupCtx, `
		SELECT stripe_session_id
		  FROM plugin_user_licenses
		 WHERE stripe_payment_intent_id = $1
		 LIMIT 1`, paymentIntentID).Scan(&sessionID); err != nil {
		// sql.ErrNoRows + transient errors both map to "" — the caller
		// has a sensible fallback (use the payment_intent in the log line).
		return ""
	}
	return sessionID
}

// WebhookHandlerConfig holds the runtime config for the Stripe webhook
// handler. Pass to NewWebhookHandler at agent startup.
type WebhookHandlerConfig struct {
	// SigningSecret is the Stripe webhook signing secret (whsec_...).
	// In production this is fetched from AWS Secrets Manager
	// (axonflow/billing-stripe-webhook-secret).
	SigningSecret string

	// ValidityDays is the on-token validity for issued Pro tokens. Per
	// PRD_TENANT_DURABILITY_AND_CLAIM the V1 product is 90 days then the
	// tenant drops to Free. Operators wire this at startup (default 90).
	ValidityDays int

	// EmailSender delivers the issued token to the buyer's email address
	// after a successful checkout. nil is permitted — handler will fall
	// back to a NoopLicenseEmailSender so dev / test stacks don't fail
	// closed when no email transport is wired. Production wiring in
	// platform/agent/run.go passes NewLicenseEmailSenderFromEnv().
	EmailSender LicenseEmailSender
}

// WebhookHandler is the HTTP handler that receives Stripe webhook deliveries.
// Use NewWebhookHandler to construct it.
type WebhookHandler struct {
	db  *sql.DB
	cfg WebhookHandlerConfig
	now func() time.Time // injectable clock for tests
}

// NewWebhookHandler constructs a webhook handler that persists into db and
// verifies signatures with cfg.SigningSecret. If cfg.EmailSender is nil the
// handler installs a NoopLicenseEmailSender so a misconfigured deployment
// still issues + persists tokens (the buyer can recover via --recover).
func NewWebhookHandler(db *sql.DB, cfg WebhookHandlerConfig) *WebhookHandler {
	if cfg.EmailSender == nil {
		cfg.EmailSender = &NoopLicenseEmailSender{}
	}
	return &WebhookHandler{
		db:  db,
		cfg: cfg,
		now: time.Now,
	}
}

// ServeHTTP implements http.Handler. The flow is:
//
//  1. Read body (size-capped) before consuming Stripe-Signature so we have
//     both the raw bytes (for HMAC) and a copy to JSON-parse.
//  2. Verify Stripe-Signature using the configured signing secret +
//     enforce timestamp freshness (replay window).
//  3. Parse the event envelope.
//  4. Dispatch on event.type: only checkout.session.completed is handled
//     in v1; everything else returns 200 with a "skipped" log line so
//     Stripe doesn't retry forever.
//  5. Build IssueRequest from the checkout session and call IssueLicense
//     inside a SERIALIZABLE transaction.
//  6. Return 200 with a small JSON body the operator can grep for.
//
// On any error before step 5 returns successfully, we return non-200 so
// Stripe retries. After step 5 succeeds the response is always 200 even if
// the response body fails to write — the row is already persisted.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
	if err != nil {
		log.Printf("[billing.webhook] read body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > maxRequestBodyBytes {
		log.Printf("[billing.webhook] body too large: %d bytes", len(body))
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	sigHeader := r.Header.Get(stripeSignatureHeader)
	if err := verifyStripeSignature(sigHeader, body, h.cfg.SigningSecret, h.now()); err != nil {
		log.Printf("[billing.webhook] signature rejected: %v", err)
		http.Error(w, "signature invalid", http.StatusUnauthorized)
		return
	}

	var ev stripeEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		log.Printf("[billing.webhook] parse event: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	switch ev.Type {
	case "checkout.session.completed":
		h.handleCheckoutCompleted(w, r.Context(), ev)
	case "charge.refunded":
		// Auto-revoke the issued license when the buyer's charge has been
		// fully refunded. Partial refunds are explicitly a no-op (see
		// handleChargeRefunded for the full-vs-partial decision rule). Closes
		// #1895.
		h.handleChargeRefunded(w, r.Context(), ev)
	default:
		// Stripe sends many event types we don't care about. Acknowledge
		// with 200 so Stripe doesn't retry; log so operators can spot
		// unexpected event volume. Disputes / chargebacks
		// (charge.dispute.created, charge.dispute.funds_withdrawn) fall
		// here too — out of scope for V1 per #1895.
		log.Printf("[billing.webhook] event type %q ignored (id=%s)", ev.Type, ev.ID)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ignored",
			"reason": "event type not handled",
			"type":   ev.Type,
			"id":     ev.ID,
		})
	}
}

func (h *WebhookHandler) handleCheckoutCompleted(w http.ResponseWriter, ctx context.Context, ev stripeEvent) {
	var cs stripeCheckoutSession
	if err := json.Unmarshal(ev.Data.Object, &cs); err != nil {
		log.Printf("[billing.webhook] parse checkout session: %v", err)
		http.Error(w, "bad checkout session payload", http.StatusBadRequest)
		return
	}

	// Sanity checks before we hit the DB. These are validation, not
	// security — signature verification already proved Stripe sent it.
	if cs.PaymentStatus != "paid" {
		log.Printf("[billing.webhook] checkout %s not paid (status=%s); skipping", cs.ID, cs.PaymentStatus)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "skipped",
			"reason":  "payment_status not 'paid'",
			"session": cs.ID,
		})
		return
	}

	tenantID, err := resolveTenantID(cs)
	if err != nil {
		// Both metadata.tenant_id AND custom_fields[].tenant_id were set
		// to different values — refuse to guess which represents the real
		// buyer. 400 so Stripe retries (after we / the operator fix the
		// inconsistency in the checkout-creation flow).
		log.Printf("[billing.webhook] checkout %s tenant_id resolution failed: %v", cs.ID, err)
		http.Error(w, "ambiguous tenant_id (metadata vs custom_fields)", http.StatusBadRequest)
		return
	}
	if tenantID == "" {
		// Neither metadata.tenant_id nor custom_fields[].tenant_id was set.
		// The checkout creator (Stripe Payment Link with required custom
		// field, or our backend POST /billing/checkout that injects metadata)
		// MUST set one. Surface as 400 so Stripe retries; the operator fixes
		// the Payment Link config or the backend Checkout Session call.
		//
		// Also log the keys we DID see in custom_fields so the operator
		// can spot a Stripe-Dashboard label-vs-key mismatch (e.g. label
		// "tenant_id" gets sluggified to key "tenantid" — webhook then
		// rejects every delivery until the Payment Link is recreated via
		// the API with explicit key="tenant_id").
		seenKeys := make([]string, 0, len(cs.CustomFields))
		for _, cf := range cs.CustomFields {
			seenKeys = append(seenKeys, cf.Key)
		}
		log.Printf("[billing.webhook] checkout %s missing tenant_id (neither metadata nor custom_fields); custom_fields keys seen: %v", cs.ID, seenKeys)
		http.Error(w, "missing tenant_id (neither metadata nor custom_fields)", http.StatusBadRequest)
		return
	}

	email := resolveBuyerEmail(cs)
	if email == "" {
		log.Printf("[billing.webhook] checkout %s missing customer_email (neither customer_details.email nor top-level customer_email populated)", cs.ID)
		http.Error(w, "missing customer_email", http.StatusBadRequest)
		return
	}

	req := IssueRequest{
		TenantID:              tenantID,
		ClaimedByEmail:        email,
		StripeCustomerID:      cs.Customer,
		StripeSessionID:       cs.ID,
		StripePaymentIntentID: cs.PaymentIntent, // persisted for charge.refunded reverse lookup (#1895)
		Tier:                  license.TierPro,  // V1 paid product
		ValidityDays:          h.cfg.ValidityDays,
	}

	// Stripe's webhook timeout is 30s; mirror that as the upper bound for
	// our DB call so a stuck transaction can't hold the connection forever.
	issueCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := IssueLicense(issueCtx, h.db, req)
	if err != nil {
		// Two log lines on this path:
		//
		//   1. The legacy `IssueLicense failed for session=...` line — kept
		//      for backward compat with the existing CW alarm metric filter
		//      (community-saas-alarms.yaml::LicenseIssuanceFailureMetricFilter
		//      matches `IssueLicense failed`). Removing it would break the
		//      alarm on every stack still running the previous CFN template.
		//
		//   2. The new explicit `event=paid_but_no_token_issued` line — what
		//      the upgraded alarm filter keys off. Carries a CANONICAL reason
		//      (see issueReason* consts) rather than the raw err.Error(), so
		//      the alarm pattern stays stable as wrapping prefixes evolve.
		//      "Money taken without service delivered" is precisely this
		//      condition: signature verified, payment_status=="paid", but
		//      no plugin_user_licenses row got inserted.
		reason := classifyIssueLicenseErr(err)
		log.Printf("[billing.webhook] IssueLicense failed for session=%s tenant=%s: %v", cs.ID, tenantID, err)
		log.Printf("[billing.webhook] event=paid_but_no_token_issued reason=%s session=%s tenant=%s err=%v", reason, cs.ID, tenantID, err)
		http.Error(w, "license issue failed", http.StatusInternalServerError)
		return
	}

	// Two log lines on the success path:
	//
	//   1. The legacy `issued license=... jti=... tenant=... session=...`
	//      line — kept for backward compat with the existing
	//      FirstPaidLicenseMetricFilter pattern `"issued license="`. Removing
	//      it would break the first-payment alarm on stacks still running
	//      the previous CFN template.
	//
	//   2. The new explicit `event=first_paid_license_issued` line — what
	//      the upgraded alarm filter keys off. Single-purpose token (no
	//      surrounding noise) so the metric filter cannot accidentally match
	//      a future log line that shares a phrase. Carries amount_cents so
	//      the SNS notification subject can include the gross paid amount
	//      (V1 = 999 cents = $9.99 Pro).
	log.Printf("[billing.webhook] issued license=%s jti=%s tenant=%s session=%s", result.LicenseID, result.JTI, tenantID, cs.ID)
	log.Printf("[billing.webhook] event=first_paid_license_issued license=%s tenant=%s amount_cents=%d", result.LicenseID, tenantID, cs.AmountTotal)

	// Email delivery — best effort. The token is already in plugin_user_licenses
	// (it can be re-fetched by the operator if email fails), so a send failure
	// does NOT roll back the issue. We log + counter and continue with 200 so
	// Stripe doesn't retry, which would re-attempt to issue a duplicate token.
	//
	// The send timeout is independent of the IssueLicense timeout (5s vs 30s)
	// so a slow Resend can't push us past Stripe's 30s webhook deadline.
	emailCtx, emailCancel := context.WithTimeout(ctx, 5*time.Second)
	defer emailCancel()
	if err := h.cfg.EmailSender.SendLicense(emailCtx, email, result.Token); err != nil {
		log.Printf("[billing.webhook] license email failed for tenant=%s session=%s: %v", tenantID, cs.ID, err)
		licenseEmailFailuresTotal.WithLabelValues(SenderTypeLabel(h.cfg.EmailSender)).Inc()
	} else {
		licenseEmailSuccessTotal.WithLabelValues(SenderTypeLabel(h.cfg.EmailSender)).Inc()
	}

	// Token is intentionally still returned in the response body so:
	//   - Runtime-path tests can assert end-to-end without an email-fetch step.
	//   - Operators can curl the webhook and rebuild a lost token without
	//     re-triggering Stripe (e.g. after a Resend outage).
	// The header X-Sensitive-Body=token signals to log scrubbers that this
	// response should not be persisted in raw form.
	w.Header().Set("X-Sensitive-Body", "token")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "issued",
		"license_id": result.LicenseID,
		"jti":        result.JTI,
		"token":      result.Token,
		"tenant_id":  result.TenantID,
		"tier":       string(result.Tier),
		"issued_at":  result.IssuedAt.UTC().Format(time.RFC3339),
	})
}

// =============================================================================
// Prometheus counters for email delivery (mirrors W3 recovery email pattern)
// =============================================================================

// licenseEmailFailuresTotal counts post-purchase license email send failures.
// Email is the only delivery channel for the AXON- token in normal operation
// — silent failure means the buyer paid but never got their token. Suggested
// alert: rate(licenseEmailFailuresTotal[5m]) > 0 for 10m → page on-call.
var licenseEmailFailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_billing_license_email_send_failures_total",
		Help: "Total post-purchase license-token email send failures, labeled by sender type.",
	},
	[]string{"sender"},
)

// licenseEmailSuccessTotal is the success counterpart so the failure rate
// can be computed (failures / (failures + success)) — a pure failure counter
// is identical to "no traffic" during low-volume windows.
var licenseEmailSuccessTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_billing_license_email_send_success_total",
		Help: "Total post-purchase license-token emails that succeeded, labeled by sender type.",
	},
	[]string{"sender"},
)

// =============================================================================
// Stripe-Signature verification (HMAC-SHA256)
// =============================================================================

// verifyStripeSignature implements Stripe's webhook signature scheme:
//
//	header format: "t=<unix-ts>,v1=<hex-sig>[,v0=<legacy-hex-sig>]"
//	signed payload: "<unix-ts>.<raw-body>"
//	signature: HMAC_SHA256(signed_payload, signingSecret)
//
// We only check v1 signatures (v0 is the deprecated test scheme). Multiple
// v1 entries are tolerated (Stripe rotates secrets by adding a parallel
// entry); ANY one matching is sufficient.
func verifyStripeSignature(header string, body []byte, secret string, now time.Time) error {
	if secret == "" {
		return errors.New("webhook signing secret not configured")
	}
	if header == "" {
		return errors.New("missing Stripe-Signature header")
	}

	var (
		ts     int64
		v1Sigs []string
	)
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			n, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return fmt.Errorf("bad timestamp: %w", err)
			}
			ts = n
		case "v1":
			v1Sigs = append(v1Sigs, kv[1])
		}
	}
	if ts == 0 {
		return errors.New("missing t= in Stripe-Signature")
	}
	if len(v1Sigs) == 0 {
		return errors.New("missing v1= in Stripe-Signature")
	}

	signedAt := time.Unix(ts, 0)
	delta := now.Sub(signedAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > stripeSignatureMaxAge {
		return fmt.Errorf("timestamp out of tolerance: %s old", delta)
	}

	signed := fmt.Sprintf("%d.%s", ts, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	expected := hex.EncodeToString(mac.Sum(nil))

	for _, sig := range v1Sigs {
		// hmac.Equal is constant-time — important to defeat timing oracles.
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return nil
		}
	}
	return errors.New("no v1 signature matched")
}

// writeJSON is a tiny helper to keep response writing DRY across handler
// branches. Errors writing the body are logged but never returned —
// the response status is set first via WriteHeader so the client sees the
// outcome regardless.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("[billing.webhook] write response: %v", err)
	}
}
