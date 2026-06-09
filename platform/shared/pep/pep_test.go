// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pep

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// newTestClient points a Client at a test server.
func newTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	c, err := New(Config{Endpoint: endpoint, OrgID: "acme", LicenseKey: "lic-123", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew_Validation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"missing endpoint", Config{OrgID: "o", LicenseKey: "l"}, true},
		{"only org", Config{Endpoint: "http://x", OrgID: "o"}, true},
		{"only license", Config{Endpoint: "http://x", LicenseKey: "l"}, true},
		{"both creds", Config{Endpoint: "http://x", OrgID: "o", LicenseKey: "l"}, false},
		{"no creds (community)", Config{Endpoint: "http://x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New(%+v) err=%v wantErr=%v", tc.cfg, err, tc.wantErr)
			}
		})
	}
}

func TestNew_DefaultsConnectorTag(t *testing.T) {
	c, err := New(Config{Endpoint: "http://x/"})
	if err != nil {
		t.Fatal(err)
	}
	if c.connectorTag != "gateway" {
		t.Fatalf("connectorTag=%q want gateway", c.connectorTag)
	}
	if c.endpoint != "http://x" {
		t.Fatalf("endpoint not trimmed: %q", c.endpoint)
	}
}

func TestDecide_Verdicts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth is sent (decide-mode auth is org:license).
		user, pass, ok := r.BasicAuth()
		if !ok || user != "acme" || pass != "lic-123" {
			t.Errorf("missing/wrong Basic auth: ok=%v user=%q", ok, user)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictAllow, DecisionID: "d1", TraceID: "t1", Obligations: []Obligation{}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	resp, err := c.Decide(context.Background(), DecideRequest{Stage: "llm", Query: "hi"}, "")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if resp.Verdict != VerdictAllow || resp.DecisionID != "d1" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func TestDecide_4xxRejected_5xxUnavailable(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr error
	}{
		{http.StatusForbidden, ErrDecisionRejected},
		{http.StatusUnauthorized, ErrDecisionRejected},
		{http.StatusServiceUnavailable, ErrPDPUnavailable},
		{http.StatusBadGateway, ErrPDPUnavailable},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"error":"x","verdict":"deny"}`))
		}))
		c := newTestClient(t, srv.URL)
		_, err := c.Decide(context.Background(), DecideRequest{Stage: "llm", Query: "q"}, "")
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("status %d: err=%v want %v", tc.status, err, tc.wantErr)
		}
		srv.Close()
	}
}

func TestDecide_TransportError_Unavailable(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0") // unroutable
	_, err := c.Decide(context.Background(), DecideRequest{Stage: "llm", Query: "q"}, "")
	if !errors.Is(err, ErrPDPUnavailable) {
		t.Fatalf("err=%v want ErrPDPUnavailable", err)
	}
}

// fulfillTestServer returns a server that serves /api/v1/decide with the given
// obligations and /api/v1/mcp/check-input with engine-redacted content. It
// records how many times the redaction endpoint was hit.
func fulfillTestServer(t *testing.T, obligations []Obligation, redactedStatement string) (*httptest.Server, *int32) {
	t.Helper()
	var redactHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case decidePath:
			_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictAllow, DecisionID: "d", TraceID: "t", Obligations: obligations})
		case requestRedactionPath:
			atomic.AddInt32(&redactHits, 1)
			var in checkInputRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			out := checkInputResponse{Allowed: true, RedactionEvaluated: true}
			if redactedStatement != "" {
				out.Redacted = true
				out.RedactedStatement = redactedStatement
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, &redactHits
}

func reqObligation() Obligation {
	return Obligation{
		Type:        ObligationRedactPII,
		Detail:      "NIK detected",
		Fulfillment: &ObligationFulfillment{Endpoint: requestRedactionPath, Method: http.MethodPost, Phase: PhaseRequest},
	}
}

func TestFulfillRequest_NoObligations_Passthrough(t *testing.T) {
	srv, hits := fulfillTestServer(t, []Obligation{}, "")
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	dec, _ := c.Decide(context.Background(), DecideRequest{Stage: "llm", Query: "clean"}, "")
	out, did, err := c.FulfillRequest(context.Background(), dec, "clean")
	if err != nil || did || out != "clean" {
		t.Fatalf("out=%q did=%v err=%v", out, did, err)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatalf("redaction endpoint hit %d times for clean request", *hits)
	}
}

func TestFulfillRequest_RedactsViaEngine(t *testing.T) {
	srv, hits := fulfillTestServer(t, []Obligation{reqObligation()}, "my NIK is [REDACTED]")
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	dec, _ := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "my NIK is 3174012509900001"}, "")
	out, did, err := c.FulfillRequest(context.Background(), dec, "my NIK is 3174012509900001")
	if err != nil {
		t.Fatalf("FulfillRequest: %v", err)
	}
	if !did || out != "my NIK is [REDACTED]" {
		t.Fatalf("out=%q did=%v want engine-redacted", out, did)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("expected exactly 1 engine call, got %d", *hits)
	}
}

// TestFulfillRequest_NoLocalRedaction is the load-bearing guarantee: the helper
// has no way to produce redacted content WITHOUT calling the engine. When the
// engine endpoint is unreachable, fulfillment must error (fail closed), never
// silently mask or forward unredacted.
func TestFulfillRequest_EngineUnreachable_FailsClosed(t *testing.T) {
	// decide succeeds, but the redaction endpoint 500s.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == decidePath {
			_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{reqObligation()}})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	dec, _ := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "secret 3174012509900001"}, "")
	out, did, err := c.FulfillRequest(context.Background(), dec, "secret 3174012509900001")
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err=%v want ErrObligationNotFulfillable", err)
	}
	if did {
		t.Fatalf("did=true — helper claimed redaction without engine success")
	}
	// Critically: the returned content is the ORIGINAL (caller must fail
	// closed), never a locally-masked variant.
	if out != "secret 3174012509900001" {
		t.Fatalf("out=%q — helper must not fabricate redacted content", out)
	}
}

// TestFulfillRequest_RedactorNotEvaluated_FailsClosed is the #2563 B1 guard:
// when check-input returns 200 but the redactor did NOT run (redaction_evaluated
// absent/false — e.g. the obligation was issued under the Gateway config but the
// MCP redactor is disabled), the PEP must FAIL CLOSED, not forward the original
// statement. This is the cross-config fail-open the master R3 flagged.
func TestFulfillRequest_RedactorNotEvaluated_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case decidePath:
			_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{reqObligation()}})
		case requestRedactionPath:
			// 200, allowed, but redactor did NOT run (no redaction_evaluated).
			_ = json.NewEncoder(w).Encode(checkInputResponse{Allowed: true, Redacted: false})
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	dec, _ := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "NIK 3174012509900001"}, "")
	out, did, err := c.FulfillRequest(context.Background(), dec, "NIK 3174012509900001")
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err=%v want ErrObligationNotFulfillable (redactor not evaluated)", err)
	}
	if did || out != "NIK 3174012509900001" {
		t.Fatalf("must not claim redaction / must not fabricate: out=%q did=%v", out, did)
	}
}

func TestFulfillRequest_MissingFulfillment_FailsClosed(t *testing.T) {
	c := newTestClient(t, "http://x")
	dec := &DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{{Type: ObligationRedactPII}}}
	_, did, err := c.FulfillRequest(context.Background(), dec, "data")
	if !errors.Is(err, ErrObligationNotFulfillable) || did {
		t.Fatalf("err=%v did=%v want not-fulfillable", err, did)
	}
}

func TestFulfillRequest_DisallowedEndpoint_FailsClosed(t *testing.T) {
	c := newTestClient(t, "http://x")
	dec := &DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{{
		Type:        ObligationRedactPII,
		Fulfillment: &ObligationFulfillment{Endpoint: "/evil/redact", Method: "POST", Phase: PhaseRequest},
	}}}
	_, _, err := c.FulfillRequest(context.Background(), dec, "data")
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err=%v want ErrObligationNotFulfillable for disallowed endpoint", err)
	}
}

func TestFulfillRequest_ResponsePhaseObligation_NotDischargedHere(t *testing.T) {
	// A response-phase obligation must not be discharged by FulfillRequest; it
	// is fail-closed because the request path cannot satisfy it.
	c := newTestClient(t, "http://x")
	dec := &DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{{
		Type:        ObligationRedactPII,
		Fulfillment: &ObligationFulfillment{Endpoint: responseRedactionPath, Method: "POST", Phase: PhaseResponse},
	}}}
	_, _, err := c.FulfillRequest(context.Background(), dec, "data")
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err=%v want not-fulfillable for response-phase obligation on request path", err)
	}
}

func TestDecideAndFulfill_BlessedPath(t *testing.T) {
	srv, hits := fulfillTestServer(t, []Obligation{reqObligation()}, "email [REDACTED]")
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	verdict, content, dec, err := c.DecideAndFulfill(context.Background(),
		DecideRequest{Stage: "llm", Query: "email a@b.com"}, "")
	if err != nil {
		t.Fatalf("DecideAndFulfill: %v", err)
	}
	if verdict != VerdictAllow || content != "email [REDACTED]" {
		t.Fatalf("verdict=%q content=%q", verdict, content)
	}
	if dec == nil || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("engine not called exactly once (hits=%d)", *hits)
	}
}

func TestDecideAndFulfill_Deny_NoEngineCall(t *testing.T) {
	var redactHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == decidePath {
			_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictDeny, Reasons: []string{"sqli"}, Obligations: []Obligation{}})
			return
		}
		atomic.AddInt32(&redactHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	verdict, content, _, err := c.DecideAndFulfill(context.Background(), DecideRequest{Stage: "tool", Query: "drop table"}, "")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if verdict != VerdictDeny || content != "drop table" {
		t.Fatalf("verdict=%q content=%q", verdict, content)
	}
	if atomic.LoadInt32(&redactHits) != 0 {
		t.Fatalf("engine called on deny verdict")
	}
}

func TestIsAllowedFulfillmentEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{requestRedactionPath, true},
		{"https://pdp.internal:8443/api/v1/mcp/check-input", true},
		{"https://pdp.internal/api/v1/mcp/check-input?x=1", true},
		{"/api/v1/mcp/check-output", false},
		{"/evil", false},
		{"", false},
		{"https://evil.com/api/v1/decide", false},
	}
	for _, tc := range cases {
		if got := isAllowedFulfillmentEndpoint(tc.in, requestRedactionPath); got != tc.want {
			t.Errorf("isAllowedFulfillmentEndpoint(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestDecide_StampsConfiguredIdentity(t *testing.T) {
	var got DecideRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	_, _ = c.Decide(context.Background(), DecideRequest{Stage: "llm", Query: "q"}, "")
	if got.CallerIdentity.TenantID != "tenant-a" || got.CallerIdentity.OrgID != "acme" {
		t.Fatalf("identity not stamped: %+v", got.CallerIdentity)
	}
}

func TestDecide_ForwardsTraceparent(t *testing.T) {
	want := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("traceparent"); got != want {
			t.Errorf("traceparent=%q want %q", got, want)
		}
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{}})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	_, _ = c.Decide(context.Background(), DecideRequest{Stage: "llm", Query: "q"}, want)
}

// Ensure the connector tag travels to the engine on fulfillment.
func TestFulfillRequest_SendsConnectorTag(t *testing.T) {
	var gotTag string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == requestRedactionPath {
			var in checkInputRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			gotTag = in.ConnectorType
			_ = json.NewEncoder(w).Encode(checkInputResponse{Allowed: true, RedactionEvaluated: true, Redacted: true, RedactedStatement: "x"})
			return
		}
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{reqObligation()}})
	}))
	defer srv.Close()
	c, _ := New(Config{Endpoint: srv.URL, OrgID: "o", LicenseKey: "l", TenantID: "t", ConnectorTag: "claude_desktop.hostA"})
	dec, _ := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "q"}, "")
	if _, _, err := c.FulfillRequest(context.Background(), dec, "q"); err != nil {
		t.Fatal(err)
	}
	if gotTag != "claude_desktop.hostA" {
		t.Fatalf("connector tag=%q want claude_desktop.hostA", gotTag)
	}
}

func TestHasRequestRedaction(t *testing.T) {
	if HasRequestRedaction(nil) {
		t.Error("nil obligations should be false")
	}
	if HasRequestRedaction([]Obligation{{Type: "other"}}) {
		t.Error("non-redact obligation should be false")
	}
	if HasRequestRedaction([]Obligation{{Type: ObligationRedactPII}}) {
		t.Error("redact obligation with no fulfillment should be false")
	}
	if !HasRequestRedaction([]Obligation{reqObligation()}) {
		t.Error("request-phase redact obligation should be true")
	}
	resp := Obligation{Type: ObligationRedactPII, Fulfillment: &ObligationFulfillment{Phase: PhaseResponse}}
	if HasRequestRedaction([]Obligation{resp}) {
		t.Error("response-phase obligation should be false for request check")
	}
}

func TestFulfillRequest_UnsupportedContentType_FailsClosed(t *testing.T) {
	c := newTestClient(t, "http://x")
	dec := &DecideResponse{Verdict: VerdictAllow, Obligations: []Obligation{{
		Type: ObligationRedactPII,
		Fulfillment: &ObligationFulfillment{
			Endpoint: requestRedactionPath, Method: "POST", Phase: PhaseRequest,
			ContentTypes: []string{"image/png"}, // text not advertised
		},
	}}}
	out, did, err := c.FulfillRequest(context.Background(), dec, "secret")
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("err=%v want ErrObligationNotFulfillable", err)
	}
	if did || out != "secret" {
		t.Fatalf("must not fabricate redaction: out=%q did=%v", out, did)
	}
}

func TestFulfillRequest_TextAdvertised_OK(t *testing.T) {
	srv, hits := fulfillTestServer(t, []Obligation{reqObligation()}, "[masked]")
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	dec, _ := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "pii here"}, "")
	out, did, err := c.FulfillRequest(context.Background(), dec, "pii here")
	if err != nil || !did || out != "[masked]" {
		t.Fatalf("out=%q did=%v err=%v", out, did, err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("hits=%d", *hits)
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b"}, "b") {
		t.Error("should find b")
	}
	if containsString([]string{"a"}, "z") {
		t.Error("should not find z")
	}
}

func TestObligation_WireShape(t *testing.T) {
	// The obligation a PEP receives MUST carry a fulfillment block with an
	// endpoint — that is the whole #2563 contract. Marshal/round-trip it.
	ob := reqObligation()
	b, _ := json.Marshal(ob)
	s := string(b)
	for _, want := range []string{`"type":"redact_pii"`, `"fulfillment"`, `"endpoint":"/api/v1/mcp/check-input"`, `"phase":"request"`} {
		if !strings.Contains(s, want) {
			t.Errorf("obligation JSON %s missing %s", s, want)
		}
	}
}
