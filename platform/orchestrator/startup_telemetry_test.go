package orchestrator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/heartbeat"
)

// THE SHARED EMITTER'S BEHAVIOUR IS TESTED WHERE IT LIVES —
// platform/shared/heartbeat/heartbeat_test.go covers the stamp, the rate limit,
// the opt-out, the CI auto-suppress, the environment-class precedence, the
// hostile-value handling, and the fact that a community-SaaS stack now emits.
// This file covers the ORCHESTRATOR BINDING, which is where the drift that
// motivated #3660 actually lived.

func clearEmitterEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AXONFLOW_TELEMETRY", "GITHUB_ACTIONS", "CI",
		"AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "KUBERNETES_SERVICE_HOST",
		"ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4",
		"DEPLOYMENT_MODE", "ORG_ID", "AXONFLOW_TELEMETRY_LICENSE_TIER_OVERRIDE",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

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
		t.Errorf("opt-out path err = %v, want nil", err)
	}
	if sent {
		t.Error("opt-out path sent = true, want false")
	}
}

// TestOrchestratorPingCarriesOrgID is the regression test for #3660 census
// finding 2, and it is the reason this lane exists on the orchestrator side.
//
// The orchestrator's ping omitted org_id entirely. telemetry-filter rules 6 and
// 7 — the PRIMARY internal-vs-external classification signal since PR #2236 —
// key on OrgID, so they could never fire on an orchestrator row. Every
// AxonFlow-operated orchestrator was held internal only by the LEGACY rule 8,
// which digest.go documents as retiring; on the day it retires, our own fleet
// would have reclassified as external customer adoption and inflated every
// headline number in the digest.
//
// Deleting the OrgID line from heartbeat.BuildPayload, or reverting this
// binding to a payload struct without the field, turns this red.
func TestOrchestratorPingCarriesOrgID(t *testing.T) {
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
	t.Setenv("ORG_ID", "axonflow-production-us")

	sent, err := MaybeSendStartupTelemetry(context.Background())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !sent {
		t.Fatal("expected sent=true")
	}

	var p map[string]any
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, captured)
	}
	got, _ := p["org_id"].(string)
	if got != "axonflow-production-us" {
		t.Errorf("org_id = %q, want %q — without it the receiver's rule 6 cannot classify "+
			"an AxonFlow-operated orchestrator as internal, and rule 8's retirement "+
			"reclassifies our own fleet as customer adoption\nbody=%s",
			got, "axonflow-production-us", captured)
	}
}

// TestOrchestratorPayloadShape asserts the orchestrator binding's identity.
func TestOrchestratorPayloadShape(t *testing.T) {
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
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("DEPLOYMENT_MODE", "saas")
	t.Setenv("AXONFLOW_TELEMETRY_LICENSE_TIER_OVERRIDE", "EnterprisePlus")

	if _, err := MaybeSendStartupTelemetry(context.Background()); err != nil {
		t.Fatalf("send: %v", err)
	}

	var p map[string]any
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, captured)
	}
	for k, want := range map[string]string{
		"telemetry_type":           "platform",
		"sdk":                      "",
		"component":                "orchestrator",
		"deployment_mode":          "self_hosted",
		"platform_deployment_mode": "saas",
		"edition":                  edition.Current,
		"license_tier":             "EnterprisePlus",
		"environment_class":        "kubernetes",
		"stream":                   "heartbeat",
	} {
		if got, _ := p[k].(string); got != want {
			t.Errorf("payload[%q] = %q, want %q\nbody=%s", k, got, want, captured)
		}
	}
	if v, _ := p["platform_version"].(string); v == "" {
		t.Errorf("platform_version is empty; the receiver rejects platform pings without it\nbody=%s", captured)
	}
}

// TestOrchestratorLicenseTierStaysAbsent pins the documented behaviour AND the
// wire compatibility of the extraction.
//
// This binding cannot determine a tier at all, so the field is OMITTED — "not
// reported", which is a different claim from "unknown" ("this emitter reports
// the dimension and had not resolved it"). It is also byte-identical to the
// pre-extraction shape: the old orchestrator payload struct left LicenseTier
// empty and omitempty dropped the key. An earlier revision of the shared
// emitter folded empty into "unknown", which would have changed an existing
// field's value on a shipped emitter while the PR disclosed that nothing did.
func TestOrchestratorLicenseTierStaysAbsent(t *testing.T) {
	clearEmitterEnv(t)
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", t.TempDir())
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	if _, err := MaybeSendStartupTelemetry(context.Background()); err != nil {
		t.Fatalf("send: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, present := p["license_tier"]; present {
		t.Errorf("license_tier is PRESENT as %#v; a binding that cannot determine a tier must "+
			"OMIT the field, and omitting it is also the pre-extraction wire shape\nbody=%s", v, captured)
	}
}

// TestOrchestratorBindingUsesItsOwnStampFile pins the per-binary rate limit: a
// host running both binaries emits one ping per binary per 7 days, and a shared
// stamp would silence whichever booted second.
func TestOrchestratorBindingUsesItsOwnStampFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", dir)
	got := heartbeat.ResolveStampPath(stampFilename)
	if !strings.HasSuffix(got, "/orchestrator-startup-telemetry-stamp") {
		t.Errorf("orchestrator stamp path = %q, want the orchestrator-specific filename", got)
	}
	if got == heartbeat.ResolveStampPath("agent-startup-telemetry-stamp") {
		t.Error("the orchestrator and agent stamp paths are identical; the rate limit is no longer per-binary")
	}
}

func TestOrchestratorComponentMatchesTheSharedVocabulary(t *testing.T) {
	if startupTelemetryComponent != heartbeat.ComponentOrchestrator {
		t.Errorf("startupTelemetryComponent = %q, want %q", startupTelemetryComponent, heartbeat.ComponentOrchestrator)
	}
	if startupTelemetryComponent != "orchestrator" {
		t.Errorf("the orchestrator component identifier is %q; the receiver's ValidComponents "+
			"gates on the literal \"orchestrator\"", startupTelemetryComponent)
	}
}
