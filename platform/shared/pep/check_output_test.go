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
	"testing"
)

// newCheckOutputClient builds a client against a test PDP.
func newCheckOutputClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	c, err := New(Config{
		Endpoint:     endpoint,
		OrgID:        "org-1",
		LicenseKey:   "lic-1",
		TenantID:     "tenant-1",
		ConnectorTag: "test-gateway",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestCheckOutputAllowedClean(t *testing.T) {
	var gotBody checkOutputWireRequest
	var gotAuthOK bool
	var gotEmail, gotSession, gotTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mcp/check-output" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		gotAuthOK = ok && user == "org-1" && pass == "lic-1"
		gotEmail = r.Header.Get("X-User-Email")
		gotSession = r.Header.Get("X-Session-Id")
		gotTraceparent = r.Header.Get("traceparent")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed": true, "policies_evaluated": 2,
			"decision_id": "dec-1", "redaction_evaluated": true,
		})
	}))
	defer srv.Close()

	c := newCheckOutputClient(t, srv.URL)
	res, err := c.CheckOutput(context.Background(), CheckOutputRequest{
		Message:   `{"result":"clean"}`,
		UserToken: "jwt-abc",
		UserEmail: "dev@example.com",
		SessionID: "sess-9",
	}, "00-abc-def-01")
	if err != nil {
		t.Fatalf("CheckOutput: %v", err)
	}
	if res.Redacted || res.RedactedMessage != "" {
		t.Fatalf("expected clean pass, got %+v", res)
	}
	if res.DecisionID != "dec-1" || res.PoliciesEvaluated != 2 {
		t.Fatalf("decision fields not propagated: %+v", res)
	}
	if !gotAuthOK {
		t.Fatal("expected Basic org:license auth on check-output")
	}
	if gotBody.ClientID != "org-1" || gotBody.TenantID != "tenant-1" || gotBody.ConnectorType != "test-gateway" {
		t.Fatalf("wire identity wrong: %+v", gotBody)
	}
	if gotBody.UserToken != "jwt-abc" || gotEmail != "dev@example.com" || gotSession != "sess-9" {
		t.Fatalf("end-user identity not propagated: token=%q email=%q session=%q", gotBody.UserToken, gotEmail, gotSession)
	}
	if gotTraceparent != "00-abc-def-01" {
		t.Fatalf("traceparent not forwarded: %q", gotTraceparent)
	}
}

func TestCheckOutputRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed": true, "redacted_data": `{"result":"[REDACTED-NIK]"}`,
			"policies_evaluated": 3, "decision_id": "dec-2", "redaction_evaluated": true,
		})
	}))
	defer srv.Close()

	res, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: `{"result":"3175064209870001"}`}, "")
	if err != nil {
		t.Fatalf("CheckOutput: %v", err)
	}
	if !res.Redacted || res.RedactedMessage != `{"result":"[REDACTED-NIK]"}` {
		t.Fatalf("expected engine-redacted message, got %+v", res)
	}
}

func TestCheckOutputFailsClosedWhenRedactorDidNotRun(t *testing.T) {
	// #2866: allowed:true WITHOUT redaction_evaluated means the redactor was
	// not looking — the PEP must not forward.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed": true, "policies_evaluated": 0, "decision_id": "dec-3",
		})
	}))
	defer srv.Close()

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "hello"}, "")
	if !errors.Is(err, ErrObligationNotFulfillable) {
		t.Fatalf("expected ErrObligationNotFulfillable, got %v", err)
	}
}

func TestCheckOutputPolicyBlock403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed": false, "block_reason": "critical PII in response", "decision_id": "dec-4",
		})
	}))
	defer srv.Close()

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "blocked"}, "")
	if !errors.Is(err, ErrOutputBlocked) {
		t.Fatalf("expected ErrOutputBlocked, got %v", err)
	}
	var be *OutputBlockedError
	if !errors.As(err, &be) || be.Reason != "critical PII in response" || be.DecisionID != "dec-4" {
		t.Fatalf("block context not propagated: %v", err)
	}
}

func TestCheckOutputDefensiveBlockOn200AllowedFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed": false, "block_reason": "exfiltration", "decision_id": "dec-5",
		})
	}))
	defer srv.Close()

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "x"}, "")
	if !errors.Is(err, ErrOutputBlocked) {
		t.Fatalf("expected ErrOutputBlocked on 200 allowed:false, got %v", err)
	}
}

func TestCheckOutputAuthRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "x"}, "")
	if !errors.Is(err, ErrDecisionRejected) {
		t.Fatalf("expected ErrDecisionRejected on 401, got %v", err)
	}
}

func TestCheckOutputEngine5xxUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "x"}, "")
	if !errors.Is(err, ErrPDPUnavailable) {
		t.Fatalf("expected ErrPDPUnavailable on 500, got %v", err)
	}
}

func TestCheckOutputTransportErrorUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // dead endpoint

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "x"}, "")
	if !errors.Is(err, ErrPDPUnavailable) {
		t.Fatalf("expected ErrPDPUnavailable on transport error, got %v", err)
	}
}

func TestCheckOutputNonStringRedactedDataFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed": true, "redaction_evaluated": true,
			"redacted_data": []map[string]interface{}{{"row": 1}},
		})
	}))
	defer srv.Close()

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "x"}, "")
	if err == nil || !strings.Contains(err.Error(), "non-string redacted_data") {
		t.Fatalf("expected non-string redacted_data failure, got %v", err)
	}
}

func TestCheckOutputOversizedMessageFailsClosed(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()

	big := strings.Repeat("a", maxCheckOutputBytes+1)
	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: big}, "")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected size-bound failure, got %v", err)
	}
	if called {
		t.Fatal("oversized message must not be sent to the engine")
	}
}

func TestCheckOutputMalformed200FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	_, err := newCheckOutputClient(t, srv.URL).CheckOutput(context.Background(),
		CheckOutputRequest{Message: "x"}, "")
	if err == nil {
		t.Fatal("expected decode failure on malformed 200")
	}
}
