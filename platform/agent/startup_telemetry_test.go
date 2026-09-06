package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/heartbeat"
)

// syncBuf is a thread-safe wrapper around strings.Builder for use as a
// log.SetOutput target. Without the mutex, concurrent log.Printf calls from
// leaked goroutines (surviving across tests in this package) race with the test
// reading buf.String() — strings.Builder is not safe for concurrent use. Caught
// 2026-05-09 by `go test -race` on PR #2094.
//
// It lives in this file because it is the package's shared log sink; other
// tests in package agent (authzen_mandatory_obligation_test.go) use it too.
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

// THE SHARED EMITTER'S BEHAVIOUR IS TESTED WHERE IT LIVES.
//
// The stamp format, the 7-day rate limit, the AXONFLOW_TELEMETRY opt-out, the
// CI auto-suppress, the environment-class precedence, the licence-tier
// normalisation, the hostile-value handling and the community-SaaS
// no-longer-skips property are all asserted in
// platform/shared/heartbeat/heartbeat_test.go. Duplicating them here would give
// two copies of an assertion that can only ever agree, which is what the
// extraction was for.
//
// What is left is the BINDING, and it is the part that has historically
// drifted: which component name, which stamp file, which version, which
// edition, and whether the licence tier actually reaches the wire from this
// binary's own atomic.

// clearEmitterEnv clears every variable the emitter reads so an assertion is
// about what the test set. CI is the one that bites: this suite runs on a
// GitHub Actions runner where GITHUB_ACTIONS=true, which the auto-suppress
// honours, so a test that forgot it would report a green "no ping" for the
// wrong reason (#2196).
func clearEmitterEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AXONFLOW_TELEMETRY", "GITHUB_ACTIONS", "CI",
		"AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "KUBERNETES_SERVICE_HOST",
		"ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4",
		"DEPLOYMENT_MODE", "ORG_ID",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

// TestMaybeSendStartupTelemetry_OptOut asserts AXONFLOW_TELEMETRY=off
// short-circuits before any network activity, THROUGH this binding — the gate
// is only useful if the agent's entry point actually runs it.
func TestMaybeSendStartupTelemetry_OptOut(t *testing.T) {
	clearEmitterEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("opt-out should produce no HTTP traffic; got a request to %s", r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_TELEMETRY", "off")
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", t.TempDir())

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Errorf("opt-out path: unexpected error %v", err)
	}
	if sent {
		t.Error("opt-out path: sent=true, want false")
	}
}

// TestMaybeSendStartupTelemetry_PayloadShape asserts the agent's binding puts
// the right identity on the wire: component=agent, the platform version, the
// edition of THIS build, the licence tier from this package's own atomic, and
// the deployment's org_id and DEPLOYMENT_MODE.
func TestMaybeSendStartupTelemetry_PayloadShape(t *testing.T) {
	clearEmitterEnv(t)
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"latest_version":"","alerts":[]}`))
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", t.TempDir())
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")
	// A deterministic environment class regardless of the host running the suite.
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	t.Setenv("ORG_ID", "acme-corp")

	licenseTier.Store("Enterprise")
	t.Cleanup(func() { licenseTier.Store("") })

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !sent {
		t.Fatal("expected sent=true")
	}

	var p map[string]any
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("unmarshal payload: %v\nbody=%s", err, captured)
	}

	for k, want := range map[string]string{
		"telemetry_type":           "platform",
		"sdk":                      "",
		"component":                "agent",
		"deployment_mode":          "self_hosted",
		"platform_deployment_mode": "in-vpc-enterprise",
		"org_id":                   "acme-corp",
		"edition":                  edition.Current,
		"license_tier":             "Enterprise",
		"environment_class":        "kubernetes",
		"stream":                   "heartbeat",
	} {
		if got, _ := p[k].(string); got != want {
			t.Errorf("payload[%q] = %q, want %q\nbody=%s", k, got, want, captured)
		}
	}

	// platform_version must be non-empty: the receiver REJECTS a platform-class
	// ping without it, so a binding that failed to supply one would be dropped
	// at the wire with no local signal at all.
	if v, _ := p["platform_version"].(string); v == "" {
		t.Errorf("platform_version is empty; the receiver rejects platform pings without it\nbody=%s", captured)
	}
	if iid, _ := p["instance_id"].(string); iid == "" {
		t.Errorf("payload missing instance_id\nbody=%s", captured)
	}
	for _, k := range []string{"os", "arch", "runtime_version"} {
		if v, _ := p[k].(string); v == "" {
			t.Errorf("payload[%q] is empty", k)
		}
	}
	// sdk_version is required-but-empty on platform pings.
	if _, present := p["sdk_version"]; !present {
		t.Errorf("platform pings must carry the sdk_version key even when empty\nbody=%s", captured)
	}
	if v, _ := p["sdk_version"].(string); v != "" {
		t.Errorf("payload[sdk_version] = %q, want empty for a platform ping", v)
	}
}

// TestAgentBindingUsesItsOwnStampFile pins the per-binary rate limit. A host
// running the agent AND the orchestrator must emit one ping per binary per 7
// days; a shared stamp file would silence whichever booted second.
func TestAgentBindingUsesItsOwnStampFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", dir)
	got := heartbeat.ResolveStampPath(stampFilename)
	if !strings.HasSuffix(got, "/agent-startup-telemetry-stamp") {
		t.Errorf("agent stamp path = %q, want a path ending in the agent-specific filename", got)
	}
}

// TestAgentComponentMatchesTheSharedVocabulary is the drift pin between this
// binding and the component identifier the receiver validates against. A
// component the ingest allowlist does not know is rejected with HTTP 400, so
// the failure mode of a typo here is total and silent from the agent's side.
func TestAgentComponentMatchesTheSharedVocabulary(t *testing.T) {
	if startupTelemetryComponent != heartbeat.ComponentAgent {
		t.Errorf("startupTelemetryComponent = %q, want %q", startupTelemetryComponent, heartbeat.ComponentAgent)
	}
	if startupTelemetryComponent != "agent" {
		t.Errorf("the agent component identifier is %q; the receiver's ValidComponents "+
			"gates on the literal \"agent\"", startupTelemetryComponent)
	}
}

// TestSetLicenseTierForRuntimeTestRejectsEmpty keeps the runtime-e2e hook
// honest: seeding an empty tier would make the bundle's payload assertion pass
// for the wrong reason.
func TestSetLicenseTierForRuntimeTest(t *testing.T) {
	t.Cleanup(func() { licenseTier.Store("") })
	if err := SetLicenseTierForRuntimeTest(""); err == nil {
		t.Error("SetLicenseTierForRuntimeTest(\"\") returned nil; an empty tier must be refused")
	}
	if err := SetLicenseTierForRuntimeTest("Enterprise"); err != nil {
		t.Fatalf("SetLicenseTierForRuntimeTest: %v", err)
	}
	if got := currentLicenseTier(); got != "Enterprise" {
		t.Errorf("currentLicenseTier() = %q after seeding, want Enterprise", got)
	}
}
