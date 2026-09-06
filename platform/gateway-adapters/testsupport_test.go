// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakePDP is a programmable in-process AxonFlow engine for unit tests. It
// serves the three endpoints the adapters call and records the last request
// each received (body + auth + identity headers) for assertions.
type fakePDP struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex

	decideStatus int
	decideBody   map[string]interface{}

	checkInputStatus int
	checkInputBody   map[string]interface{}

	checkOutputStatus int
	checkOutputBody   map[string]interface{}

	lastDecide      map[string]interface{}
	lastCheckInput  map[string]interface{}
	lastCheckOutput map[string]interface{}

	lastDecideBasicUser string
	lastDecideHdrs      http.Header
	lastCheckOutputHdrs http.Header

	// seamCapabilityAware models the >=9.11.0 PDP contract (#2958): when the
	// caller advertises a non-empty fulfillment_capabilities set that does NOT
	// include request_body_redaction, a conforming PDP does not emit a
	// request-phase redact_pii obligation to it — it applies the org's
	// obligation-fallback posture instead.
	//
	// Defaults to TRUE so every adapter test runs against a PDP that behaves
	// like the real one. Set it FALSE to simulate a STALE (<=9.11.0) PDP that
	// ignores the field and hands the obligation over anyway — the only case in
	// which the adapter's never-fires backstop can fire.
	seamCapabilityAware bool
	// fallbackVerdict is what the simulated PDP returns when it suppresses an
	// obligation: "allow" models the default log posture (allow, no obligation),
	// "deny" models an org whose obligation-fallback posture is block.
	fallbackVerdict string
}

func newFakePDP(t *testing.T) *fakePDP {
	f := &fakePDP{
		t:                   t,
		seamCapabilityAware: true,
		fallbackVerdict:     "allow",
		decideStatus:        http.StatusOK,
		decideBody: map[string]interface{}{
			"verdict":            "allow",
			"decision_id":        "dec-allow",
			"trace_id":           "trace-1",
			"obligations":        []interface{}{},
			"evaluated_policies": []interface{}{},
		},
		checkInputStatus: http.StatusOK,
		checkInputBody: map[string]interface{}{
			"allowed": true, "redaction_evaluated": true,
		},
		checkOutputStatus: http.StatusOK,
		checkOutputBody: map[string]interface{}{
			"allowed": true, "redaction_evaluated": true,
			"policies_evaluated": 1, "decision_id": "dec-out",
		},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePDP) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var body map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&body)

	var status int
	var resp map[string]interface{}
	switch r.URL.Path {
	case "/api/v1/decide":
		f.lastDecide = body
		user, _, _ := r.BasicAuth()
		f.lastDecideBasicUser = user
		f.lastDecideHdrs = r.Header.Clone()
		status, resp = f.decideStatus, f.applySeamCapabilitiesLocked(body, f.decideBody)
	case "/api/v1/mcp/check-input":
		f.lastCheckInput = body
		status, resp = f.checkInputStatus, f.checkInputBody
	case "/api/v1/mcp/check-output":
		f.lastCheckOutput = body
		f.lastCheckOutputHdrs = r.Header.Clone()
		status, resp = f.checkOutputStatus, f.checkOutputBody
	default:
		f.t.Errorf("fakePDP: unexpected path %s", r.URL.Path)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// applySeamCapabilitiesLocked reproduces the PDP-side seam-capability gate
// (#2958) over the canned decide response, so the adapters are tested against a
// PDP that behaves like the real one instead of one that hands out obligations
// no matter who asked. Mirrors platform/agent's applySeamCapabilityObligations:
// a request-phase redact_pii obligation survives only if the caller advertised
// request_body_redaction; otherwise it is dropped and the fallback posture
// (fallbackVerdict) decides. Caller must hold f.mu.
func (f *fakePDP) applySeamCapabilitiesLocked(req, resp map[string]interface{}) map[string]interface{} {
	if !f.seamCapabilityAware {
		return resp // stale-PDP simulation: the field did not exist yet
	}
	advertised, _ := req["fulfillment_capabilities"].([]interface{})
	if len(advertised) == 0 {
		return resp // legacy caller: emit obligations as-is
	}
	capable := false
	for _, c := range advertised {
		if s, ok := c.(string); ok && s == "request_body_redaction" {
			capable = true
		}
	}
	if capable {
		return resp
	}

	kept := []interface{}{}
	suppressed := false
	for _, o := range asSlice(resp["obligations"]) {
		if m, ok := o.(map[string]interface{}); ok && m["type"] == "redact_pii" {
			if ful, ok := m["fulfillment"].(map[string]interface{}); ok && ful["phase"] == "request" {
				suppressed = true
				continue
			}
		}
		kept = append(kept, o)
	}
	if !suppressed {
		return resp
	}

	out := map[string]interface{}{}
	for k, v := range resp {
		out[k] = v
	}
	out["obligations"] = kept
	out["verdict"] = f.fallbackVerdict
	if f.fallbackVerdict == "deny" {
		out["obligations"] = []interface{}{}
		out["reasons"] = []string{"denied per the organization's obligation-fallback posture (block)"}
	} else {
		out["reasons"] = []string{"request-body redaction suppressed; recorded for audit (log)"}
	}
	return out
}

// asSlice coerces a decoded JSON array field to []interface{} (nil-safe).
func asSlice(v interface{}) []interface{} {
	s, _ := v.([]interface{})
	return s
}

// lastDecideCapabilities returns the fulfillment_capabilities the adapter
// advertised on its most recent decide call.
func (f *fakePDP) lastDecideCapabilities() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, c := range asSlice(f.lastDecide["fulfillment_capabilities"]) {
		if s, ok := c.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// set mutates a response definition under the lock.
func (f *fakePDP) set(fn func(*fakePDP)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// last returns a recorded request under the lock.
func (f *fakePDP) last(get func(*fakePDP) map[string]interface{}) map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return get(f)
}

// setDecideVerdict swaps the decide verdict (with optional reasons).
func (f *fakePDP) setDecideVerdict(verdict string, reasons ...string) {
	f.set(func(f *fakePDP) {
		f.decideBody = map[string]interface{}{
			"verdict":            verdict,
			"decision_id":        "dec-" + verdict,
			"trace_id":           "trace-1",
			"reasons":            reasons,
			"obligations":        []interface{}{},
			"evaluated_policies": []interface{}{},
		}
	})
}

// setDecideRedactionObligation makes decide return allow + a request-phase
// redact_pii obligation, and check-input return redactedStatement.
func (f *fakePDP) setDecideRedactionObligation(redactedStatement string) {
	f.set(func(f *fakePDP) {
		f.decideBody = map[string]interface{}{
			"verdict":     "allow",
			"decision_id": "dec-redact",
			"trace_id":    "trace-1",
			"obligations": []interface{}{map[string]interface{}{
				"type":   "redact_pii",
				"detail": "PII detected",
				"fulfillment": map[string]interface{}{
					"endpoint":      "/api/v1/mcp/check-input",
					"method":        "POST",
					"phase":         "request",
					"content_types": []string{"text/plain"},
				},
			}},
			"evaluated_policies": []interface{}{},
		}
		f.checkInputBody = map[string]interface{}{
			"allowed": true, "redacted": true,
			"redacted_statement": redactedStatement, "redaction_evaluated": true,
		}
	})
}

// testConfig returns a Config wired to the fake PDP with a breaker threshold
// high enough not to interfere.
func testConfig(pdp *fakePDP) Config {
	return Config{
		ListenAddr:       "127.0.0.1:0",
		AxonFlowEndpoint: pdp.srv.URL,
		OrgID:            "org-1",
		LicenseKey:       "lic-1",
		TenantID:         "tenant-1",
		GatewayID:        "agw-test",
		ConnectorTag:     "agentgateway",
		DefaultStage:     StageLLM,
		FailMode:         FailModeClosed,
		RequestTimeout:   2 * time.Second,
		MaxBodyBytes:     1 << 20,
		BreakerThreshold: 100,
		BreakerCooldown:  time.Second,
	}
}

// newTestPDPFacade builds the PDP facade for cfg, failing the test on error.
func newTestPDPFacade(t *testing.T, cfg Config) *PDP {
	t.Helper()
	pdp, err := NewPDP(cfg)
	if err != nil {
		t.Fatalf("NewPDP: %v", err)
	}
	return pdp
}
