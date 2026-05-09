package agent

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncBuf is a thread-safe wrapper around strings.Builder for use as
// log.SetOutput target. Without the mutex, concurrent log.Printf calls
// from leaked goroutines (surviving across tests in this package) race
// with the test reading buf.String() — strings.Builder is not safe for
// concurrent use. Caught 2026-05-09 by go test -race on PR #2094 (mirror
// pattern fixed in platform/orchestrator/startup_telemetry_test.go).
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestNormalizeStartupLicenseTier covers the emitter-side closed-enum
// mapping. Mirror of the server-side telemetry.NormalizeLicenseTier
// asserted in ee/platform/checkpoint-service/pkg/telemetry/telemetry_test.go.
// Defense-in-depth: both sides converge to the same canonical set.
func TestNormalizeStartupLicenseTier(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Canonical capitalized passthrough.
		{"Community", "Community"},
		{"Evaluation", "Evaluation"},
		{"Professional", "Professional"},
		{"Enterprise", "Enterprise"},
		{"EnterprisePlus", "EnterprisePlus"},
		// Lowercase variants (community-mode default from currentLicenseTier()).
		{"community", "Community"},
		{"enterprise", "Enterprise"},
		{"enterpriseplus", "EnterprisePlus"},
		// Plus alias (csaas health endpoint serialization).
		{"Plus", "EnterprisePlus"},
		{"plus", "EnterprisePlus"},
		// Empty / starting / unknown all bucket as "unknown" — never-skip rule.
		{"", "unknown"},
		{"starting", "unknown"},
		{"FooBar", "unknown"},
		{"EnterpriseUltra", "unknown"}, // future tier not yet in emit map
		// Mixed case.
		{"ENTERPRISE", "Enterprise"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeStartupLicenseTier(tc.in); got != tc.want {
				t.Errorf("normalizeStartupLicenseTier(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDetectEnvironmentClass covers the 8-step precedence locked in the
// #2004 secondary amendment. Each case sets only the env var the
// detection should match on, with the others cleared, so we test ONE
// arm at a time. Lambda > ECS Fargate > Kubernetes > ECS EC2 > /.dockerenv
// > /proc/1/cgroup substring > Linux fallback > unknown.
func TestDetectEnvironmentClass(t *testing.T) {
	// Snapshot + clear all env vars the function reads so tests are
	// independent of the host's actual environment.
	envVars := []string{
		"AWS_LAMBDA_FUNCTION_NAME",
		"AWS_EXECUTION_ENV",
		"KUBERNETES_SERVICE_HOST",
		"ECS_CONTAINER_METADATA_URI",
		"ECS_CONTAINER_METADATA_URI_V4",
	}
	saved := make(map[string]string)
	for _, k := range envVars {
		saved[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	t.Cleanup(func() {
		for _, k := range envVars {
			if v, ok := saved[k]; ok && v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	})

	t.Run("AWS_LAMBDA_FUNCTION_NAME wins", func(t *testing.T) {
		os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "my-fn")
		defer os.Unsetenv("AWS_LAMBDA_FUNCTION_NAME")
		// Even with KUBERNETES_SERVICE_HOST also set, lambda takes precedence.
		os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		defer os.Unsetenv("KUBERNETES_SERVICE_HOST")
		if got := detectEnvironmentClass(); got != "lambda" {
			t.Errorf("got %q, want lambda", got)
		}
	})

	t.Run("AWS_ECS_FARGATE before kubernetes", func(t *testing.T) {
		os.Setenv("AWS_EXECUTION_ENV", "AWS_ECS_FARGATE")
		defer os.Unsetenv("AWS_EXECUTION_ENV")
		os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		defer os.Unsetenv("KUBERNETES_SERVICE_HOST")
		if got := detectEnvironmentClass(); got != "ecs_fargate" {
			t.Errorf("got %q, want ecs_fargate", got)
		}
	})

	t.Run("kubernetes before ecs_ec2", func(t *testing.T) {
		os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		defer os.Unsetenv("KUBERNETES_SERVICE_HOST")
		// ECS_CONTAINER_METADATA_URI also set — kubernetes still wins per
		// the precedence (an EKS pod is K8s, not ECS).
		os.Setenv("ECS_CONTAINER_METADATA_URI", "http://169.254.170.2/v3")
		defer os.Unsetenv("ECS_CONTAINER_METADATA_URI")
		if got := detectEnvironmentClass(); got != "kubernetes" {
			t.Errorf("got %q, want kubernetes", got)
		}
	})

	t.Run("ecs_ec2 from ECS_CONTAINER_METADATA_URI", func(t *testing.T) {
		os.Setenv("ECS_CONTAINER_METADATA_URI", "http://169.254.170.2/v3")
		defer os.Unsetenv("ECS_CONTAINER_METADATA_URI")
		if got := detectEnvironmentClass(); got != "ecs_ec2" {
			t.Errorf("got %q, want ecs_ec2", got)
		}
	})

	t.Run("ecs_ec2 from V4 endpoint", func(t *testing.T) {
		os.Setenv("ECS_CONTAINER_METADATA_URI_V4", "http://169.254.170.2/v4")
		defer os.Unsetenv("ECS_CONTAINER_METADATA_URI_V4")
		if got := detectEnvironmentClass(); got != "ecs_ec2" {
			t.Errorf("got %q, want ecs_ec2", got)
		}
	})
}

// TestStartupTelemetryEnabled covers AXONFLOW_TELEMETRY=off as the SOLE
// opt-out. Anything else (empty, "true", "0", arbitrary garbage) leaves
// telemetry on. Casing is normalized.
func TestStartupTelemetryEnabled(t *testing.T) {
	saved := os.Getenv("AXONFLOW_TELEMETRY")
	t.Cleanup(func() { os.Setenv("AXONFLOW_TELEMETRY", saved) })

	cases := []struct {
		val     string
		enabled bool
	}{
		{"", true},
		{"off", false},
		{"OFF", false},
		{"Off", false},
		{" off ", false}, // whitespace-tolerant
		{"true", true},
		{"0", true},
		{"no", true},
		{"yes", true},
		{"random", true},
	}
	for _, tc := range cases {
		t.Run(tc.val, func(t *testing.T) {
			os.Setenv("AXONFLOW_TELEMETRY", tc.val)
			if got := startupTelemetryEnabled(); got != tc.enabled {
				t.Errorf("AXONFLOW_TELEMETRY=%q → enabled=%v, want %v", tc.val, got, tc.enabled)
			}
		})
	}
}

// TestStartupStampReadWriteRoundtrip covers the on-disk persistence of
// instance_id + last_sent. Verifies stamp survives across read/write —
// the property the 7-day rate limit depends on.
func TestStartupStampReadWriteRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stamp")

	// Empty file path → empty stamp, no error.
	stamp, err := readStartupStamp("")
	if err != nil || stamp.InstanceID != "" || !stamp.LastSent.IsZero() {
		t.Errorf("empty path: stamp=%+v err=%v, want zero", stamp, err)
	}

	// Missing file → empty stamp, no error.
	stamp, err = readStartupStamp(path)
	if err != nil {
		t.Fatalf("readStartupStamp on missing file: unexpected error %v", err)
	}
	if stamp.InstanceID != "" || !stamp.LastSent.IsZero() {
		t.Errorf("missing-file stamp = %+v, want zero", stamp)
	}

	// Write + re-read.
	now := time.Now().UTC().Truncate(time.Second)
	in := startupTelemetryStamp{InstanceID: "test-uuid-1234", LastSent: now}
	if err := writeStartupStamp(path, in); err != nil {
		t.Fatalf("writeStartupStamp: %v", err)
	}
	out, err := readStartupStamp(path)
	if err != nil {
		t.Fatalf("readStartupStamp after write: %v", err)
	}
	if out.InstanceID != in.InstanceID {
		t.Errorf("InstanceID round-trip: got %q, want %q", out.InstanceID, in.InstanceID)
	}
	if !out.LastSent.Equal(in.LastSent) {
		t.Errorf("LastSent round-trip: got %v, want %v", out.LastSent, in.LastSent)
	}
}

// TestMaybeSendStartupTelemetry_OptOut asserts AXONFLOW_TELEMETRY=off
// short-circuits before any network or disk activity. We use a test
// HTTP server that fails the test if it receives any request — a clean
// way to assert "no network call made".
func TestMaybeSendStartupTelemetry_OptOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("opt-out should not produce HTTP traffic; got request to %s", r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_TELEMETRY", "off")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Errorf("opt-out path: unexpected error %v", err)
	}
	if sent {
		t.Errorf("opt-out path: sent=true, want false")
	}
}

// TestMaybeSendStartupTelemetry_RateLimit asserts the 7-day stamp gate
// fires correctly. We seed a stamp dated "now" and expect no send;
// then seed one dated 8 days ago and expect a send.
func TestMaybeSendStartupTelemetry_RateLimit(t *testing.T) {
	// Capture POSTs so we can assert send-vs-skip cleanly.
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"latest_version":"","alerts":[]}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", dir)
	t.Setenv("AXONFLOW_TELEMETRY", "")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	// Seed stamp 1 hour ago — should NOT send.
	stampPath := resolveStartupStampPath()
	if err := os.MkdirAll(filepath.Dir(stampPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := writeStartupStamp(stampPath, startupTelemetryStamp{
		InstanceID: "existing-id",
		LastSent:   time.Now().Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("writeStartupStamp: %v", err)
	}

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Errorf("rate-limit-hit path: unexpected error %v", err)
	}
	if sent {
		t.Errorf("rate-limit-hit: sent=true, want false")
	}
	if got := posts.Load(); got != 0 {
		t.Errorf("rate-limit-hit: %d POSTs, want 0", got)
	}

	// Update stamp to 8 days ago — should send.
	if err := writeStartupStamp(stampPath, startupTelemetryStamp{
		InstanceID: "existing-id",
		LastSent:   time.Now().Add(-8 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("writeStartupStamp: %v", err)
	}

	sent, err = MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Errorf("expired-stamp path: unexpected error %v", err)
	}
	if !sent {
		t.Errorf("expired-stamp: sent=false, want true")
	}
	if got := posts.Load(); got != 1 {
		t.Errorf("expired-stamp: %d POSTs, want 1", got)
	}

	// Re-read the stamp — InstanceID should be preserved (NOT regenerated).
	postSendStamp, err := readStartupStamp(stampPath)
	if err != nil {
		t.Fatalf("readStartupStamp after send: %v", err)
	}
	if postSendStamp.InstanceID != "existing-id" {
		t.Errorf("post-send InstanceID = %q, want %q (must NOT regenerate)",
			postSendStamp.InstanceID, "existing-id")
	}
	if time.Since(postSendStamp.LastSent) > 5*time.Second {
		t.Errorf("post-send LastSent should be ~now, got %v", postSendStamp.LastSent)
	}
}

// TestMaybeSendStartupTelemetry_PayloadShape asserts the wire payload
// matches the #2004-locked schema: telemetry_type=platform, sdk empty,
// component=agent, license_tier and environment_class normalized,
// stream=heartbeat. Captures the raw POST body and decodes it.
func TestMaybeSendStartupTelemetry_PayloadShape(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"latest_version":"","alerts":[]}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", dir)
	t.Setenv("AXONFLOW_TELEMETRY", "")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	// Force a synthetic env detection so the test is deterministic across
	// host environments. Setting KUBERNETES_SERVICE_HOST puts detection in
	// the "kubernetes" arm regardless of the runner's actual environment.
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	t.Setenv("AWS_EXECUTION_ENV", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("ECS_CONTAINER_METADATA_URI", "")
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "")

	// Force currentLicenseTier() into a known state. This atomic is package-
	// level; we set it directly so we don't have to spin up the full license
	// loader. After test, restore by clearing the value.
	licenseTier.Store("Enterprise")
	t.Cleanup(func() { licenseTier.Store("") })

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !sent {
		t.Fatalf("expected sent=true")
	}

	var p map[string]interface{}
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("unmarshal payload: %v\nbody=%s", err, captured)
	}

	// Required fields.
	for k, want := range map[string]string{
		"telemetry_type":    "platform",
		"sdk":               "",
		"component":         "agent",
		"deployment_mode":   "self_hosted",
		"license_tier":      "Enterprise",
		"environment_class": "kubernetes",
		"stream":            "heartbeat",
	} {
		got, _ := p[k].(string)
		if got != want {
			t.Errorf("payload[%q] = %q, want %q\nbody=%s", k, got, want, captured)
		}
	}
	// instance_id present + non-empty.
	if iid, _ := p["instance_id"].(string); iid == "" {
		t.Errorf("payload missing instance_id\nbody=%s", captured)
	}
	// os / arch / runtime_version present (values vary by host so just
	// assert non-empty).
	for _, k := range []string{"os", "arch", "runtime_version"} {
		if v, _ := p[k].(string); v == "" {
			t.Errorf("payload[%q] empty", k)
		}
	}
	// sdk_version is empty for platform-class pings (verified via the
	// json:"sdk_version" tag's NON-omitempty serialization — the field
	// is required by the wire schema even when empty).
	if _, present := p["sdk_version"]; !present {
		t.Errorf("payload should include sdk_version key (even empty) for platform pings\nbody=%s", captured)
	}
	if v, _ := p["sdk_version"].(string); v != "" {
		t.Errorf("payload[sdk_version] = %q, want empty for platform ping", v)
	}
}

// TestMaybeSendStartupTelemetry_DisclosureFires asserts the privacy-
// transparency disclosure log line goes to stderr on every delivery.
// We redirect log.Output to a buffer and grep for the marker phrase.
func TestMaybeSendStartupTelemetry_DisclosureFires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"latest_version":"","alerts":[]}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", dir)
	t.Setenv("AXONFLOW_TELEMETRY", "")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	// Capture log output (syncBuf for thread-safety — see type comment).
	var buf syncBuf
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	licenseTier.Store("Community")
	t.Cleanup(func() { licenseTier.Store("") })

	if _, err := MaybeSendStartupTelemetry(context.Background()); err != nil {
		t.Fatalf("send: %v", err)
	}

	if !strings.Contains(buf.String(), "Anonymous telemetry enabled") {
		t.Errorf("disclosure missing — log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "AXONFLOW_TELEMETRY=off") {
		t.Errorf("opt-out hint missing — log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "https://docs.getaxonflow.com/docs/telemetry") {
		t.Errorf("docs URL missing — log:\n%s", buf.String())
	}
}
