//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// WS-B (#2832/#2835) — per-tenant OTLP-ingest reject observability.
//
// Before this file, an ingest auth failure (401) fired inside apiAuthMiddleware
// BEFORE the handler, with no per-tenant log line and no counter — the only
// ingest log line ran after successful auth. A customer whose Claude Code /
// Cowork exporter was misconfigured (bad base64, embedded newline in the env
// var, wrong org) saw "zero rows, no error" and had nothing to self-diagnose
// with. This middleware wraps the /v1/logs and /v1/metrics routes OUTSIDE the
// auth middleware, observes the response status, and makes every reject
// (auth OR payload) visible: a structured log line plus a Prometheus counter
// labeled by route, tenant, and reason.
//
// The `tenant` label is the ATTEMPTED Basic-auth username (what the customer
// put before the colon in `org:license-key`) — auth failed, so no verified
// identity exists; the attempted name is exactly what an operator needs to
// match a failing exporter to a tenant. Because it is client-supplied, the
// label value set is BOUNDED (first N distinct values, then "overflow") so a
// hostile client cannot mint unbounded Prometheus series. The full unbounded
// detail always lands in the log line.
package agent

import (
	"log"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// otelIngestRejectedTotal counts OTLP ingest requests rejected (status >= 400)
// at the /v1/logs and /v1/metrics boundaries, so a customer can self-diagnose
// export failures (silent-401 gap, #2832). Scrape via /prometheus.
var otelIngestRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_otel_ingest_rejected_total",
	Help: "OTLP ingest requests rejected (status >= 400) at /v1/logs and /v1/metrics, by route, tenant (attempted Basic-auth username, bounded), and reason.",
}, []string{"route", "tenant", "reason"})

// Label-cardinality bounds: client-supplied input must not mint unbounded
// Prometheus series. Two tiers (R3 MED: a first-come-forever single set lets
// an unauthenticated attacker squat every slot with fake usernames, collapsing
// the REAL misconfigured tenant to "overflow" — defeating the diagnosis this
// exists for):
//   - authed: usernames that have completed at least one SUCCESSFUL export.
//     A licensed caller vouched for the name (note: auth validates the
//     license, not the username itself — a licensed caller could mint authed
//     labels, but the set stays bounded and such a caller is an identified
//     customer, not an anonymous attacker); they always keep their own label.
//   - failed: usernames seen only on rejects (typos, probes). Bounded; when
//     full, further unknown names collapse to "overflow". A name later seen on
//     a successful export is promoted (and frees its failed slot).
//
// The full unsanitized name always lands in the reject log line either way.
//
// Known residual (accepted, documented — #2840 review): the label is the
// ATTEMPTED username, so anyone who knows a real org id can send
// `victim-org:wrongpass` and inflate that org's reject counter (diagnostic
// noise / false "your exporter is misconfigured" signals). SUCCESS cannot be
// spoofed and cardinality stays bounded. Labeling only verified tenants would
// close the noise but blind the counter for exactly the primary use case — a
// customer whose exporter has NEVER authenticated successfully. Operators
// triaging an unexpected reject spike should corroborate with the log lines
// (they carry the user-agent) before concluding a customer-side misconfig.
const (
	maxOtelIngestAuthedLabels = 500
	maxOtelIngestFailedLabels = 100
)

var otelIngestTenantLabels = struct {
	sync.Mutex
	authed map[string]struct{}
	failed map[string]struct{}
}{authed: make(map[string]struct{}), failed: make(map[string]struct{})}

// otelIngestRejectObserver wraps an OTLP ingest route (it must be added BEFORE
// apiAuthMiddleware so it observes the middleware's own 401/400 writes) and
// emits a per-tenant log line + counter for every rejected export.
func otelIngestRejectObserver(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &otelIngestStatusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		tenant := otelIngestTenantAttempt(r)
		if sw.status < 400 {
			// A successful export proves the username is a real org — promote
			// it so its future rejects always get their own counter label.
			admitAuthedOtelTenant(sanitizeOtelTenantLabel(tenant))
			return
		}
		reason := otelIngestRejectReason(sw.status)
		otelIngestRejectedTotal.WithLabelValues(r.URL.Path, boundedOtelIngestTenantLabel(tenant), reason).Inc()
		// Length-cap the logged values: this path is pre-auth, and an unbounded
		// attacker-controlled Basic username would make each anonymous request
		// a ~1 MB log line (log-flood amplification, R3 L6).
		log.Printf("[OTELIngest] REJECTED export route=%s status=%d reason=%s tenant=%q ua=%q — the client's OTLP export did NOT land; verify the Authorization header is `Basic base64(org:license-key)` with no embedded spaces/newlines in the encoded value",
			r.URL.Path, sw.status, reason, logSanitize(capString(tenant, 256)), logSanitize(capString(r.UserAgent(), 256)))
	})
}

// admitAuthedOtelTenant records a username seen on a successful export.
func admitAuthedOtelTenant(s string) {
	otelIngestTenantLabels.Lock()
	defer otelIngestTenantLabels.Unlock()
	if _, ok := otelIngestTenantLabels.authed[s]; ok {
		return
	}
	if len(otelIngestTenantLabels.authed) >= maxOtelIngestAuthedLabels {
		return
	}
	otelIngestTenantLabels.authed[s] = struct{}{}
	delete(otelIngestTenantLabels.failed, s) // free the probation slot
}

// otelIngestTenantAttempt extracts the identity the client TRIED to
// authenticate as: the Basic-auth username (the org in `org:license-key`).
// No credential material is ever returned.
func otelIngestTenantAttempt(r *http.Request) string {
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return user
	}
	if r.Header.Get("Authorization") != "" {
		return "(malformed-auth)"
	}
	return "(no-auth)"
}

// boundedOtelIngestTenantLabel sanitizes a client-supplied tenant attempt into
// a safe, bounded Prometheus label value. Distinct raw names can fold into one
// label after sanitization (e.g. "org#1"/"org_1"), and the literals "overflow"/
// "unknown" are themselves valid usernames — acceptable for a diagnosis-only
// counter; the log line carries the (capped) raw attempt (R3 L7).
func boundedOtelIngestTenantLabel(raw string) string {
	s := sanitizeOtelTenantLabel(raw)
	otelIngestTenantLabels.Lock()
	defer otelIngestTenantLabels.Unlock()
	if _, ok := otelIngestTenantLabels.authed[s]; ok {
		return s
	}
	if _, ok := otelIngestTenantLabels.failed[s]; ok {
		return s
	}
	if len(otelIngestTenantLabels.failed) >= maxOtelIngestFailedLabels {
		return "overflow"
	}
	otelIngestTenantLabels.failed[s] = struct{}{}
	return s
}

// sanitizeOtelTenantLabel keeps org-id-shaped characters only and caps length,
// so a label value can never carry control characters or unbounded payloads.
func sanitizeOtelTenantLabel(raw string) string {
	const maxLen = 64
	if raw == "" {
		return "unknown"
	}
	b := make([]byte, 0, len(raw))
	for i := 0; i < len(raw) && len(b) < maxLen; i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ':', c == '@', c == '(', c == ')':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

// capString bounds a client-supplied string for log output.
func capString(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// otelIngestRejectReason folds an HTTP status into a low-cardinality reason label.
func otelIngestRejectReason(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusRequestEntityTooLarge:
		return "body_too_large"
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusNotImplemented:
		return "not_implemented"
	case http.StatusServiceUnavailable:
		return "storage_unavailable"
	default:
		if status >= 500 {
			return "server_error"
		}
		return "client_error"
	}
}

// otelIngestStatusWriter captures the response status code for observation.
type otelIngestStatusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *otelIngestStatusWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *otelIngestStatusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Flush forwards streaming support when the underlying writer has it (latent
// trap otherwise if anything streaming is ever mounted under this subrouter).
func (w *otelIngestStatusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
