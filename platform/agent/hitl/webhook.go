// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL outbound webhook dispatcher
// Issue #2419 - notify_url callback on terminal state transition

//go:build enterprise

package hitl

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// WebhookSigningKeyEnv is the env var the dispatcher reads to obtain the
// HMAC-SHA256 signing key. Rotate by replacing the value and restarting;
// receivers must accept signatures from the prior key for the duration of
// their secret-sync cadence. Documented in axonflow-docs/docs/governance/hitl.md.
const WebhookSigningKeyEnv = "AXONFLOW_HITL_WEBHOOK_SIGNING_KEY"

// WebhookAllowPrivateEnv unlocks `notify_url` targets that resolve to
// private/reserved IP ranges (RFC 1918, loopback, link-local, ULA, IMDS).
// Default behavior REJECTS such targets at the network dialer so a tenant
// who can create a HITL row cannot drive a POST against an internal admin
// API or cloud-metadata endpoint. Set to "true" only for self-hosted
// local-dev where the receiver is intentionally on a private address.
const WebhookAllowPrivateEnv = "AXONFLOW_HITL_WEBHOOK_ALLOW_PRIVATE"

// WebhookUserAgent is sent on every outbound POST so receivers can filter
// AxonFlow traffic from other webhook sources. Version is the AxonFlow
// platform release tag; bumped in lockstep with platform/version.go.
const WebhookUserAgent = "axonflow-hitl/8.2.1"

// MinSigningKeyLength is the HMAC-SHA256 recommended floor. Shorter keys
// still produce a signature, but at less than 32 bytes the key is in brute-
// force range. We WARN-log at construction rather than refuse-to-boot so a
// development misconfiguration doesn't take the binary down — but the WARN
// line is the operator's signal to rotate.
const MinSigningKeyLength = 32

// maxConcurrentDeliveries caps the dispatcher's in-flight goroutines. A
// sustained 10 approvals/sec with the worst-case 5-minute retry tail would
// otherwise queue ~3000 sleeping goroutines. Matches the convention in
// circuitbreaker.NewNotificationService (10 in-flight notifications).
const maxConcurrentDeliveries = 32

// retryDelays is the exponential schedule per #2419. First attempt is
// immediate; subsequent attempts honor the delay.
var retryDelays = []time.Duration{
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
}

// allowPrivateOnce caches the env-gate decision once at dispatcher
// construction so tests can flip the env between dispatcher instances.
var allowPrivateRanges = func() bool {
	return strings.EqualFold(os.Getenv(WebhookAllowPrivateEnv), "true")
}

// ssrfSafeDialer rejects connections to private/reserved IP ranges so a
// tenant-supplied `notify_url` cannot reach internal services or cloud-
// metadata endpoints (e.g. 169.254.169.254 IMDSv1). Mirrors the pattern
// in platform/agent/circuitbreaker/notification.go. When
// WebhookAllowPrivateEnv=true the gate is bypassed for local-dev.
func newSSRFSafeDialer(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: 5 * time.Second}
	if allowPrivate {
		return base.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address: %w", err)
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed: %w", err)
		}
		for _, ip := range ips {
			if isPrivateIP(ip.IP) {
				return nil, fmt.Errorf("SSRF guard: connection to private/reserved IP %s blocked (set %s=true to allow for local-dev)", ip.IP, WebhookAllowPrivateEnv)
			}
		}
		return base.DialContext(ctx, network, addr)
	}
}

// isPrivateIP checks RFC 1918 + loopback + link-local + ULA + AWS IMDS +
// the unspecified / CGNAT / broadcast / multicast / benchmark / TEST-NET
// ranges. Crucially includes 0.0.0.0/8 because `http://0/` and
// `http://0.0.0.0/` both DNS-resolve + dial-routed to loopback on Linux +
// macOS — a tenant-supplied notify_url of that shape would otherwise reach
// the agent's own admin port through the bypass surfaced in R3 R2 HIGH-2.
func isPrivateIP(ip net.IP) bool {
	for _, cidr := range []string{
		// RFC 1918
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		// Loopback + unspecified (R3 R2 HIGH-2)
		"127.0.0.0/8", "0.0.0.0/8",
		// Link-local + AWS IMDSv1
		"169.254.0.0/16",
		// CGNAT
		"100.64.0.0/10",
		// Benchmark + multicast + reserved-future
		"198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		// Broadcast
		"255.255.255.255/32",
		// IPv6 loopback + ULA + link-local + unspecified
		"::1/128", "fc00::/7", "fe80::/10", "::/128",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// WebhookEnvelope is the JSON body POSTed to notify_url. Field order is
// stable so downstream signature verification can re-serialize without
// surprises. decision_envelope is a free-form bag the receiver uses to
// distinguish approve/reject/override/expire — currently mirrors the
// outer status + reviewer info so the receiver doesn't need a second
// round-trip to act on the decision.
type WebhookEnvelope struct {
	ApprovalID       string                 `json:"approval_id"`
	Status           string                 `json:"status"`
	DecidedBy        string                 `json:"decided_by,omitempty"`
	DecidedAt        time.Time              `json:"decided_at"`
	OriginalQuery    string                 `json:"original_query"`
	RequestType      string                 `json:"request_type"`
	Severity         string                 `json:"severity"`
	DecisionEnvelope map[string]interface{} `json:"decision_envelope,omitempty"`
}

// WebhookDispatcher fires outbound POSTs asynchronously with retry. One
// instance per Service; safe for concurrent Enqueue from multiple goroutines.
// In-flight deliveries are capped via the `sem` semaphore so a sustained
// approval rate against a slow receiver cannot blow up the goroutine count.
type WebhookDispatcher struct {
	httpClient *http.Client
	signingKey []byte
	sem        chan struct{}
}

// NewWebhookDispatcher reads the signing key from env and returns a ready
// dispatcher. When the key is missing, empty, or shorter than
// MinSigningKeyLength, Enqueue logs and drops the POST (so callers don't
// need an `if dispatcher != nil` guard everywhere). Production deployments
// MUST set the env var per the deploy runbook; tests inject a custom
// client via setHTTPClientForTest.
//
// SSRF posture: the outbound transport rejects DNS targets that resolve
// to RFC 1918 / loopback / link-local / ULA / 169.254.169.254. Set
// AXONFLOW_HITL_WEBHOOK_ALLOW_PRIVATE=true for self-hosted local-dev where
// the receiver is intentionally on a private address.
func NewWebhookDispatcher() *WebhookDispatcher {
	key := os.Getenv(WebhookSigningKeyEnv)
	if n := len(key); n > 0 && n < MinSigningKeyLength {
		log.Printf("[HITL.Webhook] WARN %s is %d bytes (< %d HMAC-SHA256 floor) — signatures will be weak; rotate to a longer secret",
			WebhookSigningKeyEnv, n, MinSigningKeyLength)
	}
	transport := &http.Transport{
		DialContext:         newSSRFSafeDialer(allowPrivateRanges()),
		MaxIdleConns:        20,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &WebhookDispatcher{
		httpClient: &http.Client{Transport: transport, Timeout: 10 * time.Second},
		signingKey: []byte(key),
		sem:        make(chan struct{}, maxConcurrentDeliveries),
	}
}

// setHTTPClientForTest swaps in a test http.Client. Test-only.
func (d *WebhookDispatcher) setHTTPClientForTest(c *http.Client) {
	d.httpClient = c
}

// setSigningKeyForTest swaps in a test signing key. Test-only.
func (d *WebhookDispatcher) setSigningKeyForTest(k []byte) {
	d.signingKey = k
}

// ValidateNotifyURL enforces the scheme allowlist (https + http) plus the
// shape constraints that defend against credential leak (userinfo) and
// fragment-confusion phishing. Returns the trimmed URL on success; returns
// an error suitable to surface to the API caller on failure.
//
// Bare http:// is allowed for self-hosted local-dev — but the dispatcher's
// runtime SSRF guard rejects private/reserved IP targets unless
// AXONFLOW_HITL_WEBHOOK_ALLOW_PRIVATE=true is set.
func ValidateNotifyURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("notify_url is empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("notify_url is not a valid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("notify_url scheme %q is not allowed (use https:// or http://)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("notify_url has no host")
	}
	// Reject embedded credentials. Go's http.Request honors URL userinfo
	// as Basic Auth on the outbound request, which would leak the secret
	// into receiver logs. Forcing the caller to use proper Authorization
	// headers on their receiver removes the ambiguity.
	if u.User != nil {
		return "", fmt.Errorf("notify_url must not contain userinfo (credentials in URL)")
	}
	// Reject fragments. URL fragments are never sent over the wire so
	// they cannot carry data the receiver needs — their presence almost
	// always indicates a fragment-confusion phishing attempt
	// (https://attacker.com#@victim.com/ shape).
	if u.Fragment != "" {
		return "", fmt.Errorf("notify_url must not contain a fragment")
	}
	return trimmed, nil
}

// signBody returns the lowercase hex HMAC-SHA256 of body keyed by the
// dispatcher's signing key. Receivers must verify with the same algorithm
// and a constant-time comparator (hmac.Equal).
func (d *WebhookDispatcher) signBody(body []byte) string {
	mac := hmac.New(sha256.New, d.signingKey)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Enqueue runs the deliver loop in a background goroutine. Never blocks the
// caller (the approve/reject handler's response is already on the wire by
// the time the goroutine sleeps for its first retry). Drops the POST with
// a warning log when notify_url is empty, when the signing key isn't
// configured, or when the URL fails ValidateNotifyURL (defense in depth —
// CreateApprovalRequest validates at the API boundary, but a row inserted
// via direct DB write could bypass that path).
//
// In-flight deliveries are capped at maxConcurrentDeliveries via the sem
// channel. When the cap is reached, Enqueue logs a DROP — the operator
// should rotate the slow-receiver root cause rather than let the dispatcher
// queue grow unbounded.
func (d *WebhookDispatcher) Enqueue(notifyURL string, envelope WebhookEnvelope) {
	if notifyURL == "" {
		return
	}
	if len(d.signingKey) == 0 {
		log.Printf("[HITL.Webhook] DROP %s=unset; cannot sign outbound POST for approval_id=%s", WebhookSigningKeyEnv, envelope.ApprovalID)
		return
	}
	if _, err := ValidateNotifyURL(notifyURL); err != nil {
		log.Printf("[HITL.Webhook] DROP approval_id=%s notify_url=%q invalid: %v", envelope.ApprovalID, notifyURL, err)
		return
	}
	select {
	case d.sem <- struct{}{}:
		go func() {
			defer func() { <-d.sem }()
			d.deliver(notifyURL, envelope)
		}()
	default:
		log.Printf("[HITL.Webhook] DROP approval_id=%s url=%s sem-full (cap=%d) — receiver is slow, dropping rather than queuing",
			envelope.ApprovalID, notifyURL, maxConcurrentDeliveries)
	}
}

// deliver runs the synchronous attempt loop. Returns nothing (no caller
// observes the outcome); structured log lines on each attempt give an
// operator the per-approval delivery trail.
func (d *WebhookDispatcher) deliver(notifyURL string, envelope WebhookEnvelope) {
	body, err := json.Marshal(envelope)
	if err != nil {
		log.Printf("[HITL.Webhook] marshal envelope approval_id=%s err=%v", envelope.ApprovalID, err)
		return
	}
	signature := d.signBody(body)

	for attempt := 0; attempt < len(retryDelays)+1; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelays[attempt-1])
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, notifyURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[HITL.Webhook] build request approval_id=%s attempt=%d err=%v", envelope.ApprovalID, attempt+1, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", WebhookUserAgent)
		req.Header.Set("X-AxonFlow-Signature", "sha256="+signature)
		req.Header.Set("X-AxonFlow-Request-Id", envelope.ApprovalID)
		req.Header.Set("X-AxonFlow-Delivery-Id", uuid.New().String())
		req.Header.Set("X-AxonFlow-Event", "hitl."+envelope.Status)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			log.Printf("[HITL.Webhook] attempt=%d approval_id=%s url=%s transport_err=%v", attempt+1, envelope.ApprovalID, notifyURL, err)
			continue
		}
		// Drain + close so the connection returns to pool.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[HITL.Webhook] OK approval_id=%s status=%d attempt=%d", envelope.ApprovalID, resp.StatusCode, attempt+1)
			return
		}
		// 401 / 403 / 404 / 410 are receiver-side terminal states — the
		// receiver has indicated the request shape or authn material is
		// permanently invalid. Retrying just burns the schedule. 4xx that
		// might recover (408 timeout, 429 rate-limit, 425 too-early) DO
		// stay in the retry loop. All other non-2xx (5xx + transport
		// errors) are treated as transient.
		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 || resp.StatusCode == 410 {
			log.Printf("[HITL.Webhook] terminal-4xx approval_id=%s status=%d attempt=%d — dropping without retry", envelope.ApprovalID, resp.StatusCode, attempt+1)
			return
		}
		log.Printf("[HITL.Webhook] non-2xx approval_id=%s status=%d attempt=%d", envelope.ApprovalID, resp.StatusCode, attempt+1)
	}
	log.Printf("[HITL.Webhook] GIVE-UP approval_id=%s url=%s after %d attempts", envelope.ApprovalID, notifyURL, len(retryDelays)+1)
}
