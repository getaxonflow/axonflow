package orchestrator

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
// from leaked goroutines (e.g. DatabaseDynamicPolicyEngine.backgroundRefresh
// surviving across tests in this package) race with the test reading
// buf.String() — strings.Builder is not safe for concurrent use.
// Caught 2026-05-09 by go test -race on PR #2094.
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

// TestDetectEnvironmentClass mirrors the agent-side test of the same name;
// covers the 8-step precedence locked in the #2004 secondary amendment.
// Asserts ordering by setting multiple env vars and verifying the
// most-specific arm wins.
func TestDetectEnvironmentClass(t *testing.T) {
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

	t.Run("lambda wins over kubernetes", func(t *testing.T) {
		os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "fn")
		defer os.Unsetenv("AWS_LAMBDA_FUNCTION_NAME")
		os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		defer os.Unsetenv("KUBERNETES_SERVICE_HOST")
		if got := detectEnvironmentClass(); got != "lambda" {
			t.Errorf("got %q, want lambda", got)
		}
	})

	t.Run("ecs_fargate before kubernetes", func(t *testing.T) {
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
		os.Setenv("ECS_CONTAINER_METADATA_URI", "http://169.254.170.2/v3")
		defer os.Unsetenv("ECS_CONTAINER_METADATA_URI")
		if got := detectEnvironmentClass(); got != "kubernetes" {
			t.Errorf("got %q, want kubernetes", got)
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

// TestStartupTelemetryEnabled mirrors the agent-side opt-out + CI auto-
// suppress coverage. See platform/agent/startup_telemetry_test.go for the
// full rationale; this is a parallel set of cases on the orchestrator.
func TestStartupTelemetryEnabled(t *testing.T) {
	for _, k := range []string{"AXONFLOW_TELEMETRY", "GITHUB_ACTIONS", "CI"} {
		saved := os.Getenv(k)
		t.Cleanup(func(k, v string) func() {
			return func() {
				if v == "" {
					os.Unsetenv(k)
				} else {
					os.Setenv(k, v)
				}
			}
		}(k, saved))
	}

	cases := []struct {
		name        string
		telemetry   string
		gha         string
		ci          string
		wantEnabled bool
	}{
		{"telemetry=off blocks", "off", "", "", false},
		{"telemetry=on overrides CI", "on", "true", "true", true},
		{"GITHUB_ACTIONS=true suppresses", "", "true", "", false},
		{"CI=true suppresses", "", "", "true", false},
		{"GITHUB_ACTIONS=false treated as not-CI", "", "false", "", true},
		{"all unset → enabled", "", "", "", true},
		{"garbage telemetry + CI=true → suppressed", "garbage", "", "true", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setOrUnset := func(k, v string) {
				if v == "" {
					os.Unsetenv(k)
				} else {
					os.Setenv(k, v)
				}
			}
			setOrUnset("AXONFLOW_TELEMETRY", tc.telemetry)
			setOrUnset("GITHUB_ACTIONS", tc.gha)
			setOrUnset("CI", tc.ci)
			if got := startupTelemetryEnabled(); got != tc.wantEnabled {
				t.Errorf("telemetry=%q gha=%q ci=%q → enabled=%v, want %v",
					tc.telemetry, tc.gha, tc.ci, got, tc.wantEnabled)
			}
		})
	}
}

// TestClassifyDeploymentMode covers the csaas short-circuit. Locks DOWN
// the env var contract: DEPLOYMENT_MODE is the SOLE signal. Pre-fix this
// function checked AXONFLOW_BUILD + COMMUNITY_SAAS_MODE — neither of
// which the actual docker-compose.community-saas.yml or the ECS task-def
// set on csaas deployments. Result: orchestrator emitted from
// try.getaxonflow.com (csaas prod) despite the design suppressing
// self-pings. Test now asserts that DEPLOYMENT_MODE=community-saas
// triggers the short-circuit AND that the legacy/wrong env vars do NOT.
func TestClassifyDeploymentMode(t *testing.T) {
	t.Run("DEPLOYMENT_MODE=community-saas → community_saas", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community-saas")
		t.Setenv("AXONFLOW_BUILD", "")
		t.Setenv("COMMUNITY_SAAS_MODE", "")
		if got := classifyDeploymentMode(); got != "community_saas" {
			t.Errorf("DEPLOYMENT_MODE=community-saas: got %q, want community_saas", got)
		}
	})
	t.Run("default self_hosted when DEPLOYMENT_MODE unset", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "")
		t.Setenv("AXONFLOW_BUILD", "")
		t.Setenv("COMMUNITY_SAAS_MODE", "")
		if got := classifyDeploymentMode(); got != "self_hosted" {
			t.Errorf("unset: got %q, want self_hosted", got)
		}
	})
	t.Run("legacy AXONFLOW_BUILD does NOT trigger (regression gate for #2087)", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "")
		t.Setenv("AXONFLOW_BUILD", "community-saas")
		t.Setenv("COMMUNITY_SAAS_MODE", "")
		if got := classifyDeploymentMode(); got != "self_hosted" {
			t.Errorf("legacy AXONFLOW_BUILD only: got %q, want self_hosted (DEPLOYMENT_MODE is the only signal)", got)
		}
	})
	t.Run("legacy COMMUNITY_SAAS_MODE does NOT trigger (regression gate for #2087)", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "")
		t.Setenv("AXONFLOW_BUILD", "")
		t.Setenv("COMMUNITY_SAAS_MODE", "true")
		if got := classifyDeploymentMode(); got != "self_hosted" {
			t.Errorf("legacy COMMUNITY_SAAS_MODE only: got %q, want self_hosted", got)
		}
	})
	t.Run("DEPLOYMENT_MODE non-csaas value → self_hosted", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "production")
		if got := classifyDeploymentMode(); got != "self_hosted" {
			t.Errorf("DEPLOYMENT_MODE=production: got %q, want self_hosted", got)
		}
	})
}

func TestStartupStampReadWriteRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stamp")

	stamp, err := readStartupStamp("")
	if err != nil || stamp.InstanceID != "" || !stamp.LastSent.IsZero() {
		t.Errorf("empty path: stamp=%+v err=%v, want zero", stamp, err)
	}

	stamp, err = readStartupStamp(path)
	if err != nil || stamp.InstanceID != "" || !stamp.LastSent.IsZero() {
		t.Errorf("missing-file: stamp=%+v err=%v, want zero", stamp, err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	in := startupTelemetryStamp{InstanceID: "orch-uuid-1234", LastSent: now}
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

// TestMaybeSendStartupTelemetry_OptOut: AXONFLOW_TELEMETRY=off → no network.
func TestMaybeSendStartupTelemetry_OptOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("opt-out should not produce HTTP traffic; got request")
	}))
	defer srv.Close()
	t.Setenv("AXONFLOW_TELEMETRY", "off")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Errorf("opt-out path err = %v, want nil", err)
	}
	if sent {
		t.Errorf("opt-out path sent = true, want false")
	}
}

// TestMaybeSendStartupTelemetry_CommunitySaaSSkip: csaas mode skips emission.
func TestMaybeSendStartupTelemetry_CommunitySaaSSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("csaas mode should not produce HTTP traffic")
	}))
	defer srv.Close()
	t.Setenv("AXONFLOW_TELEMETRY", "")
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Errorf("csaas path err = %v, want nil", err)
	}
	if sent {
		t.Errorf("csaas path sent = true, want false")
	}
}

// TestMaybeSendStartupTelemetry_RateLimit: stamp dated < 7 days ago
// blocks; > 7 days ago sends; instance_id PERSISTS across calls.
func TestMaybeSendStartupTelemetry_RateLimit(t *testing.T) {
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
	stampPath := filepath.Join(dir, stampFilename)
	t.Setenv("AXONFLOW_TELEMETRY", "")
	t.Setenv("DEPLOYMENT_MODE", "")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")
	// Clear CI signals — 2026-05-13 CI auto-suppress added; without
	// this, running the test under GitHub Actions (where GITHUB_ACTIONS=true)
	// short-circuits before stamp-eval and fails. CI auto-suppress
	// itself is covered separately in TestStartupTelemetryEnabled.
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("CI", "")

	if err := writeStartupStamp(stampPath, startupTelemetryStamp{
		InstanceID: "orch-existing",
		LastSent:   time.Now().Add(-1 * time.Hour),
	}); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil || sent {
		t.Errorf("fresh stamp: sent=%v err=%v, want sent=false err=nil", sent, err)
	}
	if got := posts.Load(); got != 0 {
		t.Errorf("fresh stamp: %d POSTs, want 0", got)
	}

	if err := writeStartupStamp(stampPath, startupTelemetryStamp{
		InstanceID: "orch-existing",
		LastSent:   time.Now().Add(-8 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("update stamp: %v", err)
	}

	sent, err = MaybeSendStartupTelemetry(context.Background())
	if err != nil || !sent {
		t.Errorf("expired stamp: sent=%v err=%v, want sent=true err=nil", sent, err)
	}
	if got := posts.Load(); got != 1 {
		t.Errorf("expired stamp: %d POSTs, want 1", got)
	}

	postSendStamp, err := readStartupStamp(stampPath)
	if err != nil {
		t.Fatalf("read post-send: %v", err)
	}
	if postSendStamp.InstanceID != "orch-existing" {
		t.Errorf("InstanceID = %q, want %q (must NOT regenerate)", postSendStamp.InstanceID, "orch-existing")
	}
}

// TestMaybeSendStartupTelemetry_PayloadShape captures the live POST body.
// Asserts: telemetry_type=platform, sdk empty, component=orchestrator,
// stream=heartbeat, environment_class deterministic via env override.
// license_tier: empty by default; populated when
// AXONFLOW_TELEMETRY_LICENSE_TIER_OVERRIDE is set (runtime-e2e hook).
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
	t.Setenv("DEPLOYMENT_MODE", "")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("CI", "")

	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
	t.Setenv("AWS_EXECUTION_ENV", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("ECS_CONTAINER_METADATA_URI", "")

	t.Setenv("AXONFLOW_TELEMETRY_LICENSE_TIER_OVERRIDE", "Enterprise")

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil || !sent {
		t.Fatalf("send: sent=%v err=%v", sent, err)
	}

	var p map[string]interface{}
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, captured)
	}
	for k, want := range map[string]string{
		"telemetry_type":    "platform",
		"sdk":               "",
		"component":         "orchestrator",
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
	if iid, _ := p["instance_id"].(string); iid == "" {
		t.Errorf("payload missing instance_id\nbody=%s", captured)
	}
	if v, _ := p["sdk_version"].(string); v != "" {
		t.Errorf("sdk_version = %q, want empty for orchestrator platform ping", v)
	}
}

// TestMaybeSendStartupTelemetry_DisclosureFires: privacy-transparency
// disclosure log line on every delivery.
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
	t.Setenv("DEPLOYMENT_MODE", "")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("CI", "")

	var buf syncBuf
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

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
