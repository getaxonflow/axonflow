// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package hitl

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateNotifyURL(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", true},
		{"   ", true},
		{"not-a-url", true},
		{"ftp://example.com/cb", true},
		{"file:///etc/passwd", true},
		{"https://", true},
		// R3 R2 MEDIUM-5: reject credentials-in-URL + fragments
		{"https://user:pass@example.com/cb", true},
		{"https://attacker.com#@victim.com/", true},
		{"https://example.com/cb", false},
		{"http://localhost:8081/hook", false},
		{"https://example.com:8443/path?a=b", false},
		{"  https://example.com/cb  ", false}, // trimmed
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := ValidateNotifyURL(tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
		})
	}
}

// receivedPOST captures one inbound POST in a thread-safe way.
type receivedPOST struct {
	mu         sync.Mutex
	count      atomic.Int32
	body       []byte
	signature  string
	userAgent  string
	requestID  string
	deliveryID string
	event      string
}

func (r *receivedPOST) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	body, _ := io.ReadAll(req.Body)
	r.body = body
	r.signature = req.Header.Get("X-AxonFlow-Signature")
	r.userAgent = req.Header.Get("User-Agent")
	r.requestID = req.Header.Get("X-AxonFlow-Request-Id")
	r.deliveryID = req.Header.Get("X-AxonFlow-Delivery-Id")
	r.event = req.Header.Get("X-AxonFlow-Event")
	r.count.Add(1)
}

// TestDispatcher_DeliversWithValidSignature exercises the happy path:
// a single POST with the correct HMAC + headers.
func TestDispatcher_DeliversWithValidSignature(t *testing.T) {
	rec := &receivedPOST{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	key := []byte("test-key-32-bytes-long-padding00")
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest(key)
	d.setHTTPClientForTest(srv.Client())

	approvalID := uuid.New()
	envelope := WebhookEnvelope{
		ApprovalID: approvalID.String(),
		Status:     "approved",
		DecidedBy:  "reviewer@example.com",
		DecidedAt:  time.Now().UTC(),
	}
	d.Enqueue(srv.URL, envelope)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.count.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec.count.Load() != 1 {
		t.Fatalf("expected 1 POST, got %d", rec.count.Load())
	}
	if !strings.HasPrefix(rec.userAgent, "axonflow-hitl/") {
		t.Errorf("User-Agent=%q", rec.userAgent)
	}
	if rec.requestID != approvalID.String() {
		t.Errorf("X-AxonFlow-Request-Id=%q want %q", rec.requestID, approvalID.String())
	}
	if rec.event != "hitl.approved" {
		t.Errorf("X-AxonFlow-Event=%q", rec.event)
	}
	if rec.deliveryID == "" {
		t.Error("missing X-AxonFlow-Delivery-Id")
	}

	// Verify signature.
	if !strings.HasPrefix(rec.signature, "sha256=") {
		t.Fatalf("signature missing sha256= prefix: %q", rec.signature)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(rec.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(rec.signature), []byte(want)) {
		t.Errorf("signature mismatch:\n got  %s\n want %s", rec.signature, want)
	}

	var got WebhookEnvelope
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if got.ApprovalID != approvalID.String() || got.Status != "approved" {
		t.Errorf("envelope mismatch: %+v", got)
	}
}

// TestDispatcher_RetryAfterNon2xx covers the retry loop. We respond with
// 503 for two attempts then 200. The dispatcher's retry schedule is
// 5s/30s/5m — too long for a unit test, so we patch retryDelays.
func TestDispatcher_RetryAfterNon2xx(t *testing.T) {
	origDelays := retryDelays
	retryDelays = []time.Duration{1 * time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond}
	t.Cleanup(func() { retryDelays = origDelays })

	var hitCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hitCount.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte("k"))
	d.setHTTPClientForTest(srv.Client())
	d.Enqueue(srv.URL, WebhookEnvelope{ApprovalID: "abc", Status: "approved"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hitCount.Load() >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if hitCount.Load() != 3 {
		t.Fatalf("expected 3 attempts before success, got %d", hitCount.Load())
	}
}

// TestDispatcher_NilNotifyURLNoop covers the no-op path.
func TestDispatcher_NilNotifyURLNoop(t *testing.T) {
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte("k"))
	// Should not panic, should not block.
	d.Enqueue("", WebhookEnvelope{ApprovalID: "abc"})
}

// TestDispatcher_MissingSigningKeyDrops covers the safety-net log+drop
// when the signing key isn't configured.
func TestDispatcher_MissingSigningKeyDrops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not POST when signing key is unset")
	}))
	defer srv.Close()
	d := NewWebhookDispatcher()
	// signingKey unset (env var not present) → drop.
	d.signingKey = nil
	d.setHTTPClientForTest(srv.Client())
	d.Enqueue(srv.URL, WebhookEnvelope{ApprovalID: "abc", Status: "approved"})
	time.Sleep(50 * time.Millisecond) // give it a chance to (incorrectly) fire
}

// TestDispatcher_RejectsBadSchemeAtDispatchTime — defense in depth against
// a row whose notify_url was inserted via a non-API path.
func TestDispatcher_RejectsBadSchemeAtDispatchTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not POST to file:// URL")
	}))
	defer srv.Close()
	d := NewWebhookDispatcher()
	d.setSigningKeyForTest([]byte("k"))
	d.setHTTPClientForTest(srv.Client())
	d.Enqueue("file:///etc/passwd", WebhookEnvelope{ApprovalID: "abc", Status: "approved"})
	time.Sleep(50 * time.Millisecond)
}

// TestIsPrivateIP covers the SSRF blocklist directly — independent of any
// http.Client substitution. R3 R2 HIGH-3 surfaced that all other dispatcher
// tests swap the client and thus never exercise the guard.
func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"127.0.0.1", "127.0.0.2", "0.0.0.0", "0.0.0.1",
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"169.254.169.254", // AWS IMDS
		"100.64.0.1",      // CGNAT
		"198.18.0.1",      // benchmark
		"224.0.0.1",       // multicast
		"255.255.255.255", // broadcast
		"::1",             // IPv6 loopback
		"fc00::1",         // ULA
		"fe80::1",         // link-local
		"::",              // unspecified
	}
	public := []string{
		"1.1.1.1", "8.8.8.8", "151.101.0.81", "172.32.0.1", // outside 172.16/12
		"100.128.0.1",                                    // outside CGNAT 100.64/10
		"2606:4700:4700::1111", "2001:4860:4860::8888",
	}
	for _, ipStr := range private {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Errorf("parse %q failed", ipStr)
			continue
		}
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = false, want true", ipStr)
		}
	}
	for _, ipStr := range public {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Errorf("parse %q failed", ipStr)
			continue
		}
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = true, want false (public)", ipStr)
		}
	}
}

// TestNewSSRFSafeDialer_BlocksReservedHosts exercises the dialer
// end-to-end against literal IP shapes the parser permits but production
// must reject. We hit a real listener (httptest.NewServer is on 127.0.0.1)
// to confirm the dialer refuses BEFORE the connection lands.
func TestNewSSRFSafeDialer_BlocksReservedHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not connect to private/reserved host")
	}))
	defer srv.Close()
	// Extract the port the listener bound — addr is 127.0.0.1:port; we
	// substitute "0" + "169.254.169.254" + "127.0.0.1" for the host so the
	// dialer's IP check fires before the TCP attempt.
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	dial := newSSRFSafeDialer(false)
	cases := []struct {
		name string
		addr string
	}{
		{"0", "0:" + port},
		{"0.0.0.0", "0.0.0.0:" + port},
		{"127.0.0.1", "127.0.0.1:" + port},
		{"169.254.169.254 (AWS IMDS)", "169.254.169.254:80"},
		{"10.0.0.1", "10.0.0.1:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := dial(context.Background(), "tcp", tc.addr)
			if err == nil {
				_ = conn.Close()
				t.Fatal("expected SSRF guard to reject; got connection")
			}
			if !strings.Contains(err.Error(), "SSRF guard") && !strings.Contains(err.Error(), "DNS lookup failed") {
				t.Fatalf("expected SSRF-guard error, got: %v", err)
			}
		})
	}
}

// TestNewSSRFSafeDialer_AllowPrivateBypassesGuard confirms the env-gated
// escape hatch works for self-hosted local-dev.
func TestNewSSRFSafeDialer_AllowPrivateBypassesGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	dial := newSSRFSafeDialer(true)
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("allow-private dialer rejected loopback: %v", err)
	}
	_ = conn.Close()
}
