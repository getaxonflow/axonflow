//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// resetOtelTenantLabels snapshots + restores the bounded tenant-label sets so
// tests that fill them do not poison later tests in the same process.
func resetOtelTenantLabels(t *testing.T) {
	t.Helper()
	otelIngestTenantLabels.Lock()
	origAuthed, origFailed := otelIngestTenantLabels.authed, otelIngestTenantLabels.failed
	otelIngestTenantLabels.authed = make(map[string]struct{})
	otelIngestTenantLabels.failed = make(map[string]struct{})
	otelIngestTenantLabels.Unlock()
	t.Cleanup(func() {
		otelIngestTenantLabels.Lock()
		otelIngestTenantLabels.authed, otelIngestTenantLabels.failed = origAuthed, origFailed
		otelIngestTenantLabels.Unlock()
	})
}

func rejectCount(route, tenant, reason string) float64 {
	return testutil.ToFloat64(otelIngestRejectedTotal.WithLabelValues(route, tenant, reason))
}

// The silent-401 gap (#2832): an auth reject written by the wrapped middleware
// is COUNTED per tenant (attempted Basic-auth username) + logged — the customer
// can now self-diagnose a failing exporter.
func TestOtelIngestRejectObserver_CountsAuthReject(t *testing.T) {
	resetOtelTenantLabels(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, "Invalid or expired license", http.StatusUnauthorized)
	})
	h := otelIngestRejectObserver(inner)

	r := httptest.NewRequest(http.MethodPost, coworkOTELLogsPath, strings.NewReader("x"))
	r.SetBasicAuth("observer-test-org", "wrong-license")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401 (observer must not alter the response)", w.Code)
	}
	if got := rejectCount(coworkOTELLogsPath, "observer-test-org", "unauthorized"); got != 1 {
		t.Errorf("reject counter: got %v want 1", got)
	}
}

// Applies to the metrics route too, and to payload rejects (400).
func TestOtelIngestRejectObserver_CountsMetricsBadRequest(t *testing.T) {
	resetOtelTenantLabels(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, "invalid OTLP metrics payload", http.StatusBadRequest)
	})
	h := otelIngestRejectObserver(inner)

	r := httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, strings.NewReader("x"))
	r.SetBasicAuth("observer-test-org2", "lic")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := rejectCount(coworkOTELMetricsPath, "observer-test-org2", "bad_request"); got != 1 {
		t.Errorf("reject counter: got %v want 1", got)
	}
}

// A successful export increments nothing.
func TestOtelIngestRejectObserver_SuccessNotCounted(t *testing.T) {
	resetOtelTenantLabels(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})
	h := otelIngestRejectObserver(inner)

	r := httptest.NewRequest(http.MethodPost, coworkOTELLogsPath, strings.NewReader("x"))
	r.SetBasicAuth("observer-test-ok", "lic")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := rejectCount(coworkOTELLogsPath, "observer-test-ok", "unauthorized"); got != 0 {
		t.Errorf("success must not count: got %v", got)
	}
}

// Missing / malformed Authorization headers get stable placeholder labels —
// the request is still visible, attributed as unauthenticated.
func TestOtelIngestTenantAttempt_Placeholders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, coworkOTELLogsPath, nil)
	if got := otelIngestTenantAttempt(r); got != "(no-auth)" {
		t.Errorf("no auth: got %q", got)
	}
	r.Header.Set("Authorization", "Bearer not-basic")
	if got := otelIngestTenantAttempt(r); got != "(malformed-auth)" {
		t.Errorf("non-basic auth: got %q", got)
	}
	r.SetBasicAuth("org-x", "lic")
	if got := otelIngestTenantAttempt(r); got != "org-x" {
		t.Errorf("basic auth: got %q", got)
	}
}

// Client-supplied tenant values are sanitized and BOUNDED — a hostile client
// cannot mint unbounded Prometheus series.
func TestBoundedOtelIngestTenantLabel_SanitizesAndBounds(t *testing.T) {
	resetOtelTenantLabels(t)

	if got := boundedOtelIngestTenantLabel("evil\norg\x00; DROP TABLE"); strings.ContainsAny(got, "\n\x00;") {
		t.Errorf("label not sanitized: %q", got)
	}
	if got := boundedOtelIngestTenantLabel(""); got != "unknown" {
		t.Errorf("empty: got %q", got)
	}
	if got := boundedOtelIngestTenantLabel(strings.Repeat("a", 500)); len(got) != 64 {
		t.Errorf("length cap: got %d", len(got))
	}

	// Fill the failed-tier bound; the next distinct value collapses to "overflow".
	for i := 0; i < maxOtelIngestFailedLabels+10; i++ {
		boundedOtelIngestTenantLabel("tenant-" + strings.Repeat("z", i%50) + string(rune('a'+i%26)))
	}
	if got := boundedOtelIngestTenantLabel("definitely-new-tenant-xyz"); got != "overflow" {
		t.Errorf("over the bound: got %q want overflow", got)
	}
	// An already-seen value keeps resolving to itself even after the bound.
	if got := boundedOtelIngestTenantLabel(""); got != "unknown" {
		t.Errorf("seen value after bound: got %q want unknown", got)
	}
}

// R3 MED: an attacker filling the failed tier with fake usernames must NOT be
// able to collapse a REAL org's rejects to "overflow". A username seen on one
// successful export is promoted to the authed tier and always keeps its label.
func TestOtelIngestTenantLabels_AuthedTenantSurvivesSquatting(t *testing.T) {
	resetOtelTenantLabels(t)

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	reject := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, "bad license", http.StatusUnauthorized)
	})

	// The real org completes one successful export first.
	r := httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, strings.NewReader("x"))
	r.SetBasicAuth("real-partner-org", "valid-license")
	otelIngestRejectObserver(ok).ServeHTTP(httptest.NewRecorder(), r)

	// Attacker squats every failed-tier slot with distinct fake usernames.
	for i := 0; i < maxOtelIngestFailedLabels+20; i++ {
		fr := httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, strings.NewReader("x"))
		fr.SetBasicAuth("squat-"+strings.Repeat("q", i%40)+string(rune('a'+i%26)), "bogus")
		otelIngestRejectObserver(reject).ServeHTTP(httptest.NewRecorder(), fr)
	}

	// The real org later misconfigures its exporter: its reject must still be
	// attributed to ITS label, not "overflow".
	r2 := httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, strings.NewReader("x"))
	r2.SetBasicAuth("real-partner-org", "now-wrong-license")
	otelIngestRejectObserver(reject).ServeHTTP(httptest.NewRecorder(), r2)

	if got := rejectCount(coworkOTELMetricsPath, "real-partner-org", "unauthorized"); got != 1 {
		t.Errorf("authed tenant reject count: got %v want 1 (squatting must not evict a real org)", got)
	}
}

func TestOtelIngestRejectReason_Mapping(t *testing.T) {
	cases := map[int]string{
		400: "bad_request", 401: "unauthorized", 403: "forbidden",
		413: "body_too_large", 415: "unsupported_media_type", 429: "rate_limited",
		501: "not_implemented", 503: "storage_unavailable", 500: "server_error",
		418: "client_error",
	}
	for status, want := range cases {
		if got := otelIngestRejectReason(status); got != want {
			t.Errorf("reason(%d)=%q want %q", status, got, want)
		}
	}
}

// End-to-end through the REAL mount: registerCoworkOTELIngest wires the
// observer OUTSIDE apiAuthMiddleware, so the middleware's own 401 (bad license,
// enterprise mode) is counted — the exact silent reject the design partner hit.
func TestOtelIngestRejectObserver_WiredThroughRealMount(t *testing.T) {
	resetOtelTenantLabels(t)
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")

	router := mux.NewRouter()
	registerCoworkOTELIngest(router)

	for _, path := range []string{coworkOTELLogsPath, coworkOTELMetricsPath} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("x"))
		r.Header.Set("Content-Type", contentTypeProtobuf)
		r.SetBasicAuth("mount-test-org", "AXON-invalid-license")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status got %d want 401 (auth middleware should reject the bad license)", path, w.Code)
		}
		if got := rejectCount(path, "mount-test-org", "unauthorized"); got != 1 {
			t.Errorf("%s: reject counter got %v want 1", path, got)
		}
	}
}
