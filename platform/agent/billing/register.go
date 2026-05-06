//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// stripeWebhookPath is the URL the Stripe Dashboard webhook endpoint posts to.
// Listed in technical-docs/architecture-decisions/ADR-049 section 7.
const stripeWebhookPath = "/api/v1/billing/stripe-webhook"

// stripeWebhookIPAllowlistEnv lets operators override (or disable) the
// built-in Stripe IP allowlist. Comma-separated CIDRs. The literal value
// "*" or a CIDR of 0.0.0.0/0 disables the allowlist (e.g. for local Docker
// compose runtime tests where Stripe-Signature is the only auth check).
const stripeWebhookIPAllowlistEnv = "AXONFLOW_STRIPE_WEBHOOK_IP_ALLOWLIST"

// stripeWebhookRateLimitEnv overrides the per-source-IP rate limit. Format
// "N" (events per minute). 0 disables the rate limit (signature is auth
// enough for trusted operators); the default is 60/min/IP which is well
// above Stripe's normal delivery rate even during a backfill.
const stripeWebhookRateLimitEnv = "AXONFLOW_STRIPE_WEBHOOK_RATE_PER_MIN"

// stripeWebhookDefaultRateLimit is per-IP requests per minute. 60/min/IP is
// 6× Stripe's typical event rate during the steady state and 2× the burst
// rate during a delivery backfill. A retry storm (Stripe re-delivering
// thousands of events after a webhook outage) shouldn't trigger this.
const stripeWebhookDefaultRateLimit = 60

// defaultStripeWebhookCIDRs is Stripe's published webhook source IP list as
// of 2026-05 (https://stripe.com/files/ips/ips_webhooks.json — IPv4 blocks).
// Operators can override via stripeWebhookIPAllowlistEnv when this list goes
// stale (Stripe updates ~quarterly per their docs).
//
// Why hardcode rather than fetch dynamically: a webhook endpoint that
// silently breaks because Stripe's IP-list endpoint is down is worse than
// one that breaks loudly when the published list shifts. Operators can
// detect "Stripe rotated IPs" via the rejection counter and update the env
// var without a redeploy.
var defaultStripeWebhookCIDRs = []string{
	"3.18.12.63/32",
	"3.130.192.231/32",
	"13.235.14.237/32",
	"13.235.122.149/32",
	"18.211.135.69/32",
	"35.154.171.200/32",
	"52.15.183.38/32",
	"54.88.130.119/32",
	"54.88.130.237/32",
	"54.187.174.169/32",
	"54.187.205.235/32",
	"54.187.216.72/32",
}

// RegisterStripeWebhookHandler mounts the Stripe webhook on router. The
// handler is intentionally NOT wrapped in apiAuthMiddleware — Stripe-Signature
// HMAC validation is the auth check. Defense in depth comes from:
//
//  1. IP allowlist (Stripe's published webhook IPs; overridable per env)
//  2. Per-source-IP rate limit (catches attempted replay floods)
//  3. Stripe-Signature HMAC + 5-minute timestamp tolerance (anti-replay)
//  4. Body size cap of 64 KiB (anti-resource-exhaustion)
//
// A request must pass (1) AND (2) AND (3) AND (4). Each layer increments a
// dedicated rejection counter so operators can see WHICH check is failing
// and adjust without flying blind.
func RegisterStripeWebhookHandler(router *mux.Router, db *sql.DB, cfg WebhookHandlerConfig) {
	allowlist := loadStripeWebhookAllowlist()
	rateLimit := loadStripeWebhookRateLimit()
	tracker := newStripeIPTracker(rateLimit)

	handler := NewWebhookHandler(db, cfg)
	wrapped := stripeWebhookGuard(handler, allowlist, tracker)

	router.Handle(stripeWebhookPath, wrapped).Methods(http.MethodPost)
	// Method probes / health checks should get 405 — explicit so the path
	// doesn't 404-mask misconfigured webhook URLs in the Stripe dashboard.
	router.HandleFunc(stripeWebhookPath, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}).Methods(http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch)

	log.Printf("[billing.webhook] registered POST %s (allowlist=%d cidrs, rate=%d/min/ip)",
		stripeWebhookPath, len(allowlist.cidrs), rateLimit)
}

// stripeWebhookGuard wraps the bare Stripe webhook handler with IP-allowlist
// + per-source rate limit checks. Order matters: IP check first (cheap),
// rate limit second (lock contention but bounded), then hand off to handler
// (DB + HMAC + parse).
func stripeWebhookGuard(h http.Handler, allowlist *stripeAllowlist, tracker *stripeIPTracker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractStripeWebhookIP(r)

		if !allowlist.allows(ip) {
			log.Printf("[billing.webhook] rejected IP %s not in allowlist", ip)
			stripeWebhookRejectsTotal.WithLabelValues("ip_not_allowed").Inc()
			http.Error(w, "source IP not allowed", http.StatusForbidden)
			return
		}

		if !tracker.allow(ip) {
			log.Printf("[billing.webhook] rate-limited IP %s", ip)
			stripeWebhookRejectsTotal.WithLabelValues("rate_limit").Inc()
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// =============================================================================
// IP allowlist
// =============================================================================

type stripeAllowlist struct {
	cidrs    []*net.IPNet
	disabled bool // env override or wildcard CIDR — bypass allowlist
}

func (a *stripeAllowlist) allows(ip string) bool {
	if a.disabled {
		return true
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, n := range a.cidrs {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

func loadStripeWebhookAllowlist() *stripeAllowlist {
	override := strings.TrimSpace(os.Getenv(stripeWebhookIPAllowlistEnv))
	if override == "*" {
		return &stripeAllowlist{disabled: true}
	}
	cidrs := defaultStripeWebhookCIDRs
	if override != "" {
		cidrs = splitAndTrim(override, ",")
	}
	out := &stripeAllowlist{}
	for _, c := range cidrs {
		if c == "0.0.0.0/0" || c == "::/0" {
			out.disabled = true
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Printf("[billing.webhook] skipping malformed CIDR %q: %v", c, err)
			continue
		}
		out.cidrs = append(out.cidrs, n)
	}
	return out
}

// extractStripeWebhookIP picks the source IP for allowlist + rate-limit
// checks. Order:
//  1. AXONFLOW_TRUST_PROXY=1 + X-Forwarded-For first hop (ALB sets this)
//  2. AXONFLOW_TRUST_PROXY=1 + X-Real-IP
//  3. r.RemoteAddr (host:port — strip port)
//
// SECURITY: X-Forwarded-For and X-Real-IP are honored ONLY when
// AXONFLOW_TRUST_PROXY=1 because both are arbitrary client-controlled
// headers. Without the gate, any attacker who can reach the agent's
// listening port directly (bypassing ALB — e.g. via VPC peering, docker
// network leak, IP-rule misconfiguration) could spoof a Stripe IP and
// pass the allowlist with `X-Real-IP: 3.18.12.63`.
//
// Operational guidance: set AXONFLOW_TRUST_PROXY=1 only when the agent is
// definitely behind an ALB / Nginx / Cloudflare that strips inbound
// X-Forwarded-For + X-Real-IP and replaces them with verified values.
// Local Docker / dev stacks have no proxy and should leave it unset.
func extractStripeWebhookIP(r *http.Request) string {
	if os.Getenv("AXONFLOW_TRUST_PROXY") == "1" {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			parts := strings.Split(xf, ",")
			return strings.TrimSpace(parts[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// =============================================================================
// per-source-IP rate limit (sliding 1-minute window)
// =============================================================================

type stripeIPTracker struct {
	mu      sync.Mutex
	limit   int // 0 = disabled
	entries map[string]*stripeIPCounter
}

type stripeIPCounter struct {
	count   int
	resetAt time.Time
}

func newStripeIPTracker(limitPerMin int) *stripeIPTracker {
	return &stripeIPTracker{
		limit:   limitPerMin,
		entries: make(map[string]*stripeIPCounter),
	}
}

// allow returns true if the IP is under its per-minute limit. limit=0
// disables (always allows). Sweeps stale entries opportunistically when the
// map crosses 1024 entries to prevent unbounded growth under attack.
func (t *stripeIPTracker) allow(ip string) bool {
	if t.limit <= 0 {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()

	if len(t.entries) > 1024 {
		for k, e := range t.entries {
			if now.After(e.resetAt) {
				delete(t.entries, k)
			}
		}
	}

	e, ok := t.entries[ip]
	if !ok || now.After(e.resetAt) {
		t.entries[ip] = &stripeIPCounter{count: 1, resetAt: now.Add(time.Minute)}
		return true
	}
	if e.count >= t.limit {
		return false
	}
	e.count++
	return true
}

func loadStripeWebhookRateLimit() int {
	override := strings.TrimSpace(os.Getenv(stripeWebhookRateLimitEnv))
	if override == "" {
		return stripeWebhookDefaultRateLimit
	}
	n, err := parseNonNegInt(override)
	if err != nil {
		log.Printf("[billing.webhook] invalid %s=%q (using default %d): %v",
			stripeWebhookRateLimitEnv, override, stripeWebhookDefaultRateLimit, err)
		return stripeWebhookDefaultRateLimit
	}
	return n
}

// =============================================================================
// rejection metric
// =============================================================================

// stripeWebhookRejectsTotal counts requests rejected at the guard layer
// (before reaching the bare webhook handler — which has its own metrics for
// signature failures + parse failures). Labels:
//
//	ip_not_allowed — source IP was not in the allowlist
//	rate_limit     — source IP exceeded the per-minute cap
//
// Operators can alert on a sudden ip_not_allowed spike (Stripe rotated IPs)
// or rate_limit spike (probable abuse).
var stripeWebhookRejectsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_billing_stripe_webhook_rejects_total",
		Help: "Stripe webhook requests rejected at the guard layer (before signature check).",
	},
	[]string{"reason"},
)

// =============================================================================
// helpers
// =============================================================================

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseNonNegInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty string")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a non-negative integer")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
