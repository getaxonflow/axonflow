// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package heartbeat

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

// syncBuf is a thread-safe log sink. Without the mutex, a log.Printf from a
// goroutine leaked by another test races the test's own buf.String() read —
// strings.Builder is not safe for concurrent use. (Caught by `go test -race`
// on PR #2094; the same pattern is used in the agent and orchestrator tests.)
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

// clearEmitterEnv clears every environment variable the emitter reads, so a
// test asserts on what IT set rather than on whatever the host happened to
// carry. CI is the one that bites: this suite runs on a GitHub Actions runner
// where GITHUB_ACTIONS=true, which the auto-suppress honours, so a test that
// forgot to clear it would report a green "no ping was sent" for the wrong
// reason (#2196 forensics).
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

// newCapturingCheckpoint returns a checkpoint stand-in that records every POST
// body, plus an accessor. Used only by UNIT tests; the real-client proof is
// runtime-e2e/3660_platform_ping_edition_mode, which drives the shipped agent
// binary against a listener over real HTTP.
func newCapturingCheckpoint(t *testing.T) (*httptest.Server, func() [][]byte, *atomic.Int32) {
	t.Helper()
	var mu sync.Mutex
	var bodies [][]byte
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"latest_version":"","alerts":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(bodies))
		copy(out, bodies)
		return out
	}, &posts
}

// sendOnce wires a fresh stamp dir + endpoint and calls Send.
func sendOnce(t *testing.T, srvURL string, cfg Config) (bool, error) {
	t.Helper()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", t.TempDir())
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srvURL+"/v1/ping")
	return Send(context.Background(), cfg)
}

func baseConfig() Config {
	return Config{
		Component:        ComponentAgent,
		StampFilename:    "unit-test-stamp",
		PlatformVersion:  "10.4.0",
		Edition:          "enterprise",
		LicenseTier:      "Enterprise",
		InstanceIDPrefix: "unit",
	}
}

// -----------------------------------------------------------------------------
// Gate behaviour
// -----------------------------------------------------------------------------

func TestEnabled(t *testing.T) {
	clearEmitterEnv(t)

	cases := []struct {
		name      string
		telemetry string // "" means unset
		gha       string
		ci        string
		want      bool
	}{
		// The sole user-facing opt-out, casing- and whitespace-tolerant.
		{"telemetry=off blocks", "off", "", "", false},
		{"telemetry=OFF blocks", "OFF", "", "", false},
		{"telemetry=' off ' blocks", " off ", "", "", false},

		// Explicit opt-in beats the CI auto-suppress.
		{"telemetry=on overrides CI", "on", "true", "true", true},
		{"telemetry=ON overrides", "ON", "true", "", true},

		// CI auto-suppress when AXONFLOW_TELEMETRY is unset.
		{"GITHUB_ACTIONS=true suppresses", "", "true", "", false},
		{"CI=true suppresses", "", "", "true", false},
		{"GITHUB_ACTIONS=1 suppresses (presence-only)", "", "1", "", false},
		{"CI=yes suppresses (presence-only)", "", "", "yes", false},

		// An explicit false is not-in-CI.
		{"GITHUB_ACTIONS=false is not CI", "", "false", "", true},
		{"CI=false is not CI", "", "", "false", true},
		{"GITHUB_ACTIONS=False is not CI", "", "False", "", true},

		// Production default.
		{"all unset enables", "", "", "", true},

		// A value that is neither on nor off falls through to the CI check —
		// the dominant production case: a deployment that never set the
		// variable but happens to run in CI is suppressed.
		{"garbage + no CI enables", "random", "", "", true},
		{"garbage + GITHUB_ACTIONS=true suppresses", "garbage", "true", "", false},
		{"garbage + CI=true suppresses", "garbage", "", "true", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range map[string]string{
				"AXONFLOW_TELEMETRY": tc.telemetry, "GITHUB_ACTIONS": tc.gha, "CI": tc.ci,
			} {
				if v == "" {
					t.Setenv(k, "")
					os.Unsetenv(k)
				} else {
					t.Setenv(k, v)
				}
			}
			if got := Enabled(); got != tc.want {
				t.Errorf("telemetry=%q gha=%q ci=%q → %v, want %v", tc.telemetry, tc.gha, tc.ci, got, tc.want)
			}
		})
	}
}

// TestCIAutoSuppressSurvivedTheExtraction is the guard for the specific
// regression the #3660 R3 brief names: "the CI auto-suppress lost in the
// extraction". It asserts through Send, not through Enabled, so moving the
// check out of the send path (rather than deleting it) still fails.
func TestCIAutoSuppressSurvivedTheExtraction(t *testing.T) {
	clearEmitterEnv(t)
	srv, _, posts := newCapturingCheckpoint(t)
	t.Setenv("GITHUB_ACTIONS", "true")

	sent, err := sendOnce(t, srv.URL, baseConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sent {
		t.Error("sent=true under GITHUB_ACTIONS=true; the CI auto-suppress is not in the send path")
	}
	if n := posts.Load(); n != 0 {
		t.Errorf("%d POSTs under CI auto-suppress, want 0", n)
	}
}

func TestSendOptOutMakesNoRequest(t *testing.T) {
	clearEmitterEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("opt-out must produce no HTTP traffic; got %s", r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("AXONFLOW_TELEMETRY", "off")
	sent, err := sendOnce(t, srv.URL, baseConfig())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if sent {
		t.Error("sent=true on the opt-out path")
	}
}

// -----------------------------------------------------------------------------
// #3660: the community-SaaS emission skip is gone
// -----------------------------------------------------------------------------

// TestCommunitySaaSStackEmits is the mutation gate for the census's finding 1.
// Restoring the `if deploymentMode == "community_saas" { return false, nil }`
// early return turns this red.
//
// It also asserts the row carries what makes the removal SAFE: an
// `axonflow-`-prefixed org_id, which is what telemetry-filter rule 6 keys on to
// classify these AxonFlow-operated stacks as internal at the receiver. Dropping
// the emitter-side skip without the org_id would reclassify our own fleet as
// customer adoption, so the two assertions belong in one test.
func TestCommunitySaaSStackEmits(t *testing.T) {
	clearEmitterEnv(t)
	srv, bodies, posts := newCapturingCheckpoint(t)
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	t.Setenv("ORG_ID", "axonflow-community-saas")

	sent, err := sendOnce(t, srv.URL, baseConfig())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !sent {
		t.Fatal("a community-saas stack did not emit; the early return is back")
	}
	if n := posts.Load(); n != 1 {
		t.Fatalf("%d POSTs, want 1", n)
	}

	var p map[string]any
	if err := json.Unmarshal(bodies()[0], &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := p["deployment_mode"]; got != TopologyCommunitySaaS {
		t.Errorf("deployment_mode = %v, want %q", got, TopologyCommunitySaaS)
	}
	if got := p["platform_deployment_mode"]; got != "community-saas" {
		t.Errorf("platform_deployment_mode = %v, want \"community-saas\"", got)
	}
	if got, _ := p["org_id"].(string); !strings.HasPrefix(got, "axonflow-") {
		t.Errorf("org_id = %q; without the axonflow- prefix the receiver classifies "+
			"this AxonFlow-operated stack as an external customer", got)
	}
}

// -----------------------------------------------------------------------------
// Deployment-mode resolution
// -----------------------------------------------------------------------------

func TestPlatformDeploymentMode(t *testing.T) {
	clearEmitterEnv(t)

	cases := []struct {
		raw  string
		want string
		why  string
	}{
		{"", "", "UNSET MUST OMIT. Reporting `community` here would publish the SCHEMA " +
			"default as if it were the operator's configuration, while the runtime " +
			"posture for an unset value is the enterprise one (#3128)."},
		{"community", "community", "canonical passthrough"},
		{"community-saas", "community-saas", "canonical passthrough"},
		{"in-vpc-enterprise", "in-vpc-enterprise", "canonical passthrough"},
		{"in-vpc-healthcare", "in-vpc-healthcare", "canonical passthrough"},
		{"saas", "saas", "canonical passthrough"},
		{"evaluation", "evaluation", "canonical passthrough"},
		{"enterprise", "in-vpc-enterprise", "alias folds; every self-hosted enterprise " +
			"compose file defaults to this spelling and it must not split the population"},
		{"invpc", "in-vpc-enterprise", "legacy alias folds"},
		{"not-a-mode", "unknown", "unrecognised must not reach the wire verbatim"},
		{" community", "unknown", "deploymode matches EXACTLY; a whitespace slip is not community"},
	}
	for _, tc := range cases {
		name := tc.raw
		if name == "" {
			name = "(unset)"
		}
		t.Run(name, func(t *testing.T) {
			if tc.raw == "" {
				os.Unsetenv("DEPLOYMENT_MODE")
			} else {
				t.Setenv("DEPLOYMENT_MODE", tc.raw)
			}
			if got := PlatformDeploymentMode(); got != tc.want {
				t.Errorf("PlatformDeploymentMode() with DEPLOYMENT_MODE=%q = %q, want %q — %s",
					tc.raw, got, tc.want, tc.why)
			}
		})
	}
}

// TestPlatformDeploymentModeIsBounded proves the emitter-side cap. The
// orchestrator does NOT validate DEPLOYMENT_MODE (only the agent refuses to
// boot on an unrecognised value), so an operator's oversized typo reaches this
// function. Removing capCoarseEnum or the unrecognised→"unknown" branch turns
// this red.
func TestPlatformDeploymentModeIsBounded(t *testing.T) {
	clearEmitterEnv(t)
	t.Setenv("DEPLOYMENT_MODE", strings.Repeat("a", 10_000))
	got := PlatformDeploymentMode()
	if len(got) > maxCoarseEnumValueBytes {
		t.Errorf("a %d-byte DEPLOYMENT_MODE produced a %d-byte wire value; the cap is not applied",
			10_000, len(got))
	}
	if got != "unknown" {
		t.Errorf("got %q, want \"unknown\" — an unrecognised mode must never reach the wire verbatim", got)
	}
}

func TestTopologyDeploymentMode(t *testing.T) {
	clearEmitterEnv(t)
	cases := map[string]string{
		"":                  TopologySelfHosted,
		"community":         TopologySelfHosted,
		"community-saas":    TopologyCommunitySaaS,
		"in-vpc-enterprise": TopologySelfHosted,
		"enterprise":        TopologySelfHosted,
		"not-a-mode":        TopologySelfHosted,
	}
	for raw, want := range cases {
		name := raw
		if name == "" {
			name = "(unset)"
		}
		t.Run(name, func(t *testing.T) {
			if raw == "" {
				os.Unsetenv("DEPLOYMENT_MODE")
			} else {
				t.Setenv("DEPLOYMENT_MODE", raw)
			}
			if got := TopologyDeploymentMode(); got != want {
				t.Errorf("TopologyDeploymentMode() with DEPLOYMENT_MODE=%q = %q, want %q", raw, got, want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Payload
// -----------------------------------------------------------------------------

// TestBuildPayloadOmitsUnknownsRatherThanDefaulting is the "absent is not
// empty" pin. Every optional dimension the emitter could not determine must be
// MISSING from the serialised object, not present with a zero value — a reader
// distinguishes "not reported" from a real value only by the key's absence.
func TestBuildPayloadOmitsUnknownsRatherThanDefaulting(t *testing.T) {
	clearEmitterEnv(t)
	// No DEPLOYMENT_MODE, no ORG_ID, no edition.
	cfg := baseConfig()
	cfg.Edition = ""

	body, err := json.Marshal(BuildPayload(cfg, "iid-1"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, k := range []string{"edition", "platform_deployment_mode", "org_id"} {
		if v, present := p[k]; present {
			t.Errorf("key %q is present with value %#v; an undetermined dimension must be OMITTED "+
				"so a reader cannot mistake a default for an observation\nbody=%s", k, v, body)
		}
	}
}

// TestBuildPayloadCarriesTheNewDimensions is the positive half of the pin
// above: when the emitter DOES know, the values are on the wire.
func TestBuildPayloadCarriesTheNewDimensions(t *testing.T) {
	clearEmitterEnv(t)
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-banking")
	t.Setenv("ORG_ID", "acme-corp")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

	cfg := baseConfig()
	cfg.Component = ComponentOrchestrator
	body, _ := json.Marshal(BuildPayload(cfg, "iid-2"))
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for k, want := range map[string]string{
		"telemetry_type":           "platform",
		"sdk":                      "",
		"component":                ComponentOrchestrator,
		"platform_version":         "10.4.0",
		"edition":                  "enterprise",
		"platform_deployment_mode": "in-vpc-banking",
		"deployment_mode":          TopologySelfHosted,
		"org_id":                   "acme-corp",
		"license_tier":             "Enterprise",
		"environment_class":        "kubernetes",
		"stream":                   "heartbeat",
		"instance_id":              "iid-2",
	} {
		if got, _ := p[k].(string); got != want {
			t.Errorf("payload[%q] = %q, want %q\nbody=%s", k, got, want, body)
		}
	}
	// sdk_version is required-but-empty on platform pings: the key must be
	// present (non-omitempty) and its value empty.
	if _, present := p["sdk_version"]; !present {
		t.Errorf("platform ping must carry the sdk_version key even when empty\nbody=%s", body)
	}
	for _, k := range []string{"os", "arch", "runtime_version"} {
		if v, _ := p[k].(string); v == "" {
			t.Errorf("payload[%q] is empty", k)
		}
	}
}

// TestPayloadSurvivesHostileValues is the DoD's hostile-but-valid case. Every
// field the emitter fills from operator-controlled input is handed to
// encoding/json, never spliced into a hand-built string — the failure mode that
// silently killed the whole plugin heartbeat when a /health value contained a
// quote (#3619). A quote, a backslash, a newline and 10 KB must all produce a
// payload the receiver can still parse, with every OTHER field intact.
func TestPayloadSurvivesHostileValues(t *testing.T) {
	hostile := map[string]string{
		"double quote":  `a"b`,
		"backslash":     `a\b`,
		"newline":       "a\nb",
		"cr":            "a\rb",
		"tab":           "a\tb",
		"json fragment": `","org_id":"pwned`,
		"10KB":          strings.Repeat("x", 10*1024),
		"nul":           "a\x00b",
	}
	for name, v := range hostile {
		t.Run(name, func(t *testing.T) {
			clearEmitterEnv(t)
			// A NUL byte cannot travel through the process environment at all —
			// the OS rejects the setenv — so the env-sourced fields skip it while
			// the Config-sourced fields below still carry it. Silently dropping
			// the whole case would have made this the only hostile input the
			// suite claims to cover and does not.
			if !strings.ContainsRune(v, 0) {
				t.Setenv("DEPLOYMENT_MODE", v)
				t.Setenv("ORG_ID", v)
			} else {
				t.Setenv("DEPLOYMENT_MODE", "definitely-not-a-mode")
			}

			cfg := baseConfig()
			cfg.Edition = v
			cfg.PlatformVersion = v
			cfg.LicenseTier = v

			body, err := json.Marshal(BuildPayload(cfg, "iid-3"))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var p map[string]any
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatalf("the payload no longer parses — a hostile value escaped the serializer: %v\nbody=%s", err, body)
			}
			// The structural fields a smuggled fragment would target must be
			// exactly what the emitter set, not what the value tried to inject.
			if got, _ := p["telemetry_type"].(string); got != "platform" {
				t.Errorf("telemetry_type = %q; a value broke out of its field", got)
			}
			if got, _ := p["component"].(string); got != ComponentAgent {
				t.Errorf("component = %q; a value broke out of its field", got)
			}
			// Closed enums collapse; they never carry the hostile value.
			if got, _ := p["platform_deployment_mode"].(string); got != "unknown" {
				t.Errorf("platform_deployment_mode = %q, want \"unknown\"", got)
			}
			if got, _ := p["license_tier"].(string); got != "unknown" {
				t.Errorf("license_tier = %q, want \"unknown\"", got)
			}
			// The emitter-side byte cap holds on the enum it owns.
			if got, _ := p["edition"].(string); len(got) > maxCoarseEnumValueBytes {
				t.Errorf("edition is %d bytes on the wire; the emitter cap is not applied", len(got))
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stamp + rate limit
// -----------------------------------------------------------------------------

func TestStampRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stamp")

	if s, err := ReadStamp(""); err != nil || s.InstanceID != "" || !s.LastSent.IsZero() {
		t.Errorf("empty path: stamp=%+v err=%v, want zero/nil", s, err)
	}
	s, err := ReadStamp(path)
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if s.InstanceID != "" || !s.LastSent.IsZero() {
		t.Errorf("missing-file stamp = %+v, want zero", s)
	}

	now := time.Now().UTC().Truncate(time.Second)
	in := Stamp{InstanceID: "test-uuid-1234", LastSent: now}
	if err := WriteStamp(path, in); err != nil {
		t.Fatalf("WriteStamp: %v", err)
	}
	out, err := ReadStamp(path)
	if err != nil {
		t.Fatalf("ReadStamp: %v", err)
	}
	if out.InstanceID != in.InstanceID || !out.LastSent.Equal(in.LastSent) {
		t.Errorf("round-trip: got %+v, want %+v", out, in)
	}
}

func TestRateLimitAndInstanceIDPersistence(t *testing.T) {
	clearEmitterEnv(t)
	srv, _, posts := newCapturingCheckpoint(t)

	dir := t.TempDir()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", dir)
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	cfg := baseConfig()
	stampPath := ResolveStampPath(cfg.StampFilename)

	// Inside the window → no send.
	if err := WriteStamp(stampPath, Stamp{InstanceID: "existing-id", LastSent: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatalf("WriteStamp: %v", err)
	}
	sent, err := Send(context.Background(), cfg)
	if err != nil || sent {
		t.Errorf("inside the rate-limit window: sent=%v err=%v, want false/nil", sent, err)
	}
	if n := posts.Load(); n != 0 {
		t.Errorf("%d POSTs inside the window, want 0", n)
	}

	// Outside the window → send, and the instance id must be REUSED.
	if err := WriteStamp(stampPath, Stamp{InstanceID: "existing-id", LastSent: time.Now().Add(-8 * 24 * time.Hour)}); err != nil {
		t.Fatalf("WriteStamp: %v", err)
	}
	sent, err = Send(context.Background(), cfg)
	if err != nil || !sent {
		t.Fatalf("outside the window: sent=%v err=%v, want true/nil", sent, err)
	}
	if n := posts.Load(); n != 1 {
		t.Errorf("%d POSTs after the window expired, want 1", n)
	}

	after, err := ReadStamp(stampPath)
	if err != nil {
		t.Fatalf("ReadStamp: %v", err)
	}
	if after.InstanceID != "existing-id" {
		t.Errorf("instance_id = %q after send, want the persisted %q — regenerating it breaks "+
			"both the rate limit and the longitudinal analytics property", after.InstanceID, "existing-id")
	}
	if time.Since(after.LastSent) > 5*time.Second {
		t.Errorf("last_sent = %v, want ~now", after.LastSent)
	}
}

// TestStampNotAdvancedOnFailure pins stamp-on-delivery: a non-2xx must leave
// the stamp untouched so the next restart retries. Advancing it would silence
// a deployment for 7 days on one transient failure.
func TestStampNotAdvancedOnFailure(t *testing.T) {
	clearEmitterEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", dir)
	t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL+"/v1/ping")

	cfg := baseConfig()
	sent, err := Send(context.Background(), cfg)
	if sent {
		t.Error("sent=true on a 503")
	}
	if err == nil {
		t.Error("a 503 must surface an error to the caller")
	}
	s, _ := ReadStamp(ResolveStampPath(cfg.StampFilename))
	if !s.LastSent.IsZero() {
		t.Errorf("last_sent advanced to %v on a failed delivery; the next restart will not retry", s.LastSent)
	}
}

// TestUnreachableCheckpointDoesNotPanic covers the common real-world state:
// the endpoint is simply not there. The emitter must return an error and
// nothing else.
func TestUnreachableCheckpointDoesNotPanic(t *testing.T) {
	clearEmitterEnv(t)
	// A port nothing listens on: bind, capture the URL, close.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", t.TempDir())
	t.Setenv("AXONFLOW_CHECKPOINT_URL", url+"/v1/ping")

	sent, err := Send(context.Background(), baseConfig())
	if sent {
		t.Error("sent=true against a closed endpoint")
	}
	if err == nil {
		t.Error("an unreachable endpoint must surface an error")
	}
}

func TestDisclosureFiresOnEveryDelivery(t *testing.T) {
	clearEmitterEnv(t)
	srv, _, _ := newCapturingCheckpoint(t)

	var buf syncBuf
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	if _, err := sendOnce(t, srv.URL, baseConfig()); err != nil {
		t.Fatalf("send: %v", err)
	}
	for _, want := range []string{
		"Anonymous telemetry enabled",
		"AXONFLOW_TELEMETRY=off",
		"https://docs.getaxonflow.com/docs/telemetry",
		"[startup-telemetry] payload:",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("disclosure missing %q — log:\n%s", want, buf.String())
		}
	}
}

// -----------------------------------------------------------------------------
// Detection helpers
// -----------------------------------------------------------------------------

func TestNormalizeLicenseTier(t *testing.T) {
	cases := map[string]string{
		"Community": "Community", "community": "Community", "COMMUNITY": "Community",
		"Evaluation": "Evaluation", "evaluation": "Evaluation",
		"Professional": "Professional", "professional": "Professional",
		"Enterprise": "Enterprise", "enterprise": "Enterprise", "ENTERPRISE": "Enterprise",
		"EnterprisePlus": "EnterprisePlus", "enterpriseplus": "EnterprisePlus",
		"Plus": "EnterprisePlus", "plus": "EnterprisePlus",
		// EMPTY STAYS EMPTY and "starting" buckets as unknown. They are
		// different facts: empty means the caller cannot determine a tier at
		// all (the field is OMITTED and the row reads "not reported"), where
		// "starting" means an emitter that DOES report the dimension had not
		// resolved it yet. It is also the pre-extraction wire shape for both
		// callers — the agent never passes "" and the orchestrator always does.
		"":                "",
		"starting":        "unknown",
		"FooBar":          "unknown",
		"EnterpriseUltra": "unknown",
	}
	for in, want := range cases {
		name := in
		if name == "" {
			name = "(empty)"
		}
		t.Run(name, func(t *testing.T) {
			if got := NormalizeLicenseTier(in); got != want {
				t.Errorf("NormalizeLicenseTier(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

func TestDetectEnvironmentClass(t *testing.T) {
	clearEmitterEnv(t)

	t.Run("lambda wins over kubernetes", func(t *testing.T) {
		t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "my-fn")
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		if got := DetectEnvironmentClass(); got != "lambda" {
			t.Errorf("got %q, want lambda", got)
		}
	})
	t.Run("ecs_fargate before kubernetes", func(t *testing.T) {
		t.Setenv("AWS_EXECUTION_ENV", "AWS_ECS_FARGATE")
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		if got := DetectEnvironmentClass(); got != "ecs_fargate" {
			t.Errorf("got %q, want ecs_fargate", got)
		}
	})
	t.Run("kubernetes before ecs_ec2", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		t.Setenv("ECS_CONTAINER_METADATA_URI", "http://169.254.170.2/v3")
		if got := DetectEnvironmentClass(); got != "kubernetes" {
			t.Errorf("got %q, want kubernetes", got)
		}
	})
	t.Run("ecs_ec2 from the v3 endpoint", func(t *testing.T) {
		t.Setenv("ECS_CONTAINER_METADATA_URI", "http://169.254.170.2/v3")
		if got := DetectEnvironmentClass(); got != "ecs_ec2" {
			t.Errorf("got %q, want ecs_ec2", got)
		}
	})
	t.Run("ecs_ec2 from the v4 endpoint", func(t *testing.T) {
		t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "http://169.254.170.2/v4")
		if got := DetectEnvironmentClass(); got != "ecs_ec2" {
			t.Errorf("got %q, want ecs_ec2", got)
		}
	})
}

func TestGenerateInstanceIDIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 128)
	for i := 0; i < 128; i++ {
		id := GenerateInstanceID("unit")
		if id == "" {
			t.Fatal("empty instance id")
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate instance id %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestEndpointHonorsOverride(t *testing.T) {
	t.Setenv("AXONFLOW_CHECKPOINT_URL", "")
	os.Unsetenv("AXONFLOW_CHECKPOINT_URL")
	if got := Endpoint(); got != DefaultEndpoint {
		t.Errorf("Endpoint() = %q, want the default %q", got, DefaultEndpoint)
	}
	t.Setenv("AXONFLOW_CHECKPOINT_URL", "http://127.0.0.1:9/v1/ping")
	if got := Endpoint(); got != "http://127.0.0.1:9/v1/ping" {
		t.Errorf("Endpoint() = %q, want the override", got)
	}
}

// TestOrgIDPrefersTheExplicitConfigOverTheEnvVar pins the three-way resolution
// that #3668's R3 found missing.
//
// WHY THIS FIELD IS NOT LIKE THE OTHERS. Every other identity dimension is
// wrong-or-absent in a way an operator eventually notices. org_id is different:
// it decides INTERNAL vs EXTERNAL classification at the receiver, so a binary
// that reports none is silently counted as customer adoption. There is no
// error, no rejected ping and nothing in a log — the number is just wrong, in
// the flattering direction, for as long as it takes someone to ask.
//
// The env fallback alone was not enough, and that is the whole finding: it
// reads ORG_ID, while the gateway-adapters binary's configuration surface is
// AXONFLOW_-prefixed throughout and reads AXONFLOW_ORG_ID. A fallback cannot
// guess the variable a caller happens to use, so a caller whose org lives under
// a different name MUST pass it.
func TestOrgIDPrefersTheExplicitConfigOverTheEnvVar(t *testing.T) {
	orgOf := func(t *testing.T, cfg Config) (string, bool) {
		t.Helper()
		body, _ := json.Marshal(BuildPayload(cfg, "iid-org"))
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		v, present := p["org_id"]
		if !present {
			return "", false
		}
		return v.(string), true
	}

	t.Run("the explicit config wins", func(t *testing.T) {
		clearEmitterEnv(t)
		t.Setenv("ORG_ID", "env-org")
		cfg := baseConfig()
		cfg.OrgID = "axonflow-demo"
		got, present := orgOf(t, cfg)
		if !present || got != "axonflow-demo" {
			t.Errorf("org_id = %q (present=%v), want %q — a caller that reads its org from "+
				"somewhere other than ORG_ID must be able to say so", got, present, "axonflow-demo")
		}
	})

	t.Run("the env var is the fallback for callers that do use it", func(t *testing.T) {
		clearEmitterEnv(t)
		t.Setenv("ORG_ID", "env-org")
		got, present := orgOf(t, baseConfig())
		if !present || got != "env-org" {
			t.Errorf("org_id = %q (present=%v), want %q — removing the fallback would break the "+
				"agent and orchestrator, which do set ORG_ID", got, present, "env-org")
		}
	})

	t.Run("neither: ABSENT, never a default", func(t *testing.T) {
		clearEmitterEnv(t)
		if got, present := orgOf(t, baseConfig()); present {
			t.Errorf("org_id present as %q with nothing configured; an unset org is a legitimate "+
				"state (a community binary with no licence) and must be reported as absent — a "+
				"defaulted value here would classify a real customer as an internal deployment",
				got)
		}
	})
}
