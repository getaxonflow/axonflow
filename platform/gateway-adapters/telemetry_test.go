// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/heartbeat"
)

// collectOutcomes returns every emitted (surface, outcome) pair with its value.
func collectOutcomes(t *testing.T) map[[2]string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	surfaceOutcomes.Collect(ch)
	close(ch)

	out := map[[2]string]float64{}
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		var surface, outcome string
		for _, l := range d.GetLabel() {
			switch l.GetName() {
			case "surface":
				surface = l.GetValue()
			case "outcome":
				outcome = l.GetValue()
			}
		}
		out[[2]string{surface, outcome}] = d.GetCounter().GetValue()
	}
	return out
}

// TestMetricOutcomeMapsEveryRequestOutcomeKind is the drift pin between the
// metric's three labels and the package's own five-valued RequestOutcome enum.
//
// The enum is the AUTHORITY — it is what the seams actually branch on. A kind
// added there without a case here would silently count as `error`, which is the
// alerting series; this walks the enum's whole range so the gap is a failing
// test rather than a page at 3am.
func TestMetricOutcomeMapsEveryRequestOutcomeKind(t *testing.T) {
	cases := map[int]struct {
		want string
		why  string
	}{
		OutcomeAllow: {MetricOutcomeAllow, "a verdict permitted it"},
		OutcomeAllowRedacted: {MetricOutcomeAllow, "A REDACTION IS NOT A REFUSAL. The " +
			"caller's request went through, carrying engine-masked content"},
		OutcomeFailOpen: {MetricOutcomeAllow, "the request went through, which is what the " +
			"caller experienced; the outage is visible on `error` from the legs that failed closed"},
		OutcomeDeny: {MetricOutcomeDeny, "a verdict refused it"},
		OutcomeFailClosed: {MetricOutcomeError, "NO VERDICT WAS OBTAINED. Pooling this with " +
			"`deny` makes a PDP outage read as a policy tightening on the graph an operator pages from"},
	}
	for kind, tc := range cases {
		if got := metricOutcome(kind); got != tc.want {
			t.Errorf("metricOutcome(kind=%d) = %q, want %q — %s", kind, got, tc.want, tc.why)
		}
	}

	// Every kind in the enum's range must be mapped. OutcomeFailOpen is the
	// highest declared kind, so anything up to it is real; the loop catches a
	// new kind inserted in the middle, which is where an iota enum grows.
	for kind := OutcomeAllow; kind <= OutcomeFailOpen; kind++ {
		if _, covered := cases[kind]; !covered {
			t.Errorf("RequestOutcome kind %d is not covered by this test — a new kind was added "+
				"to the enum and metricOutcome silently counts it as %q", kind, metricOutcome(kind))
		}
	}
}

// TestOutcomeLabelsAreAClosedProduct is the cardinality proof.
//
// The metric's bound is not a cap or a seen-set: it is that BOTH labels are
// compile-time constants, so 3 surfaces x 3 outcomes is the whole space for the
// life of the process. This asserts that emitting every combination produces
// exactly nine series and no more — and, critically, that no label value
// outside the two closed sets can appear.
func TestOutcomeLabelsAreAClosedProduct(t *testing.T) {
	surfaceOutcomes.Reset()
	t.Cleanup(surfaceOutcomes.Reset)

	surfaces := []string{SurfaceExtAuthz, SurfaceExtProc, SurfaceExtMcp}
	outcomes := []string{MetricOutcomeAllow, MetricOutcomeDeny, MetricOutcomeError}
	for _, s := range surfaces {
		for _, o := range outcomes {
			recordOutcome(s, o)
		}
	}

	got := collectOutcomes(t)
	if len(got) != 9 {
		t.Errorf("emitted %d series, want exactly 9 (3 surfaces x 3 outcomes)", len(got))
	}
	okSurface := map[string]bool{SurfaceExtAuthz: true, SurfaceExtProc: true, SurfaceExtMcp: true}
	okOutcome := map[string]bool{MetricOutcomeAllow: true, MetricOutcomeDeny: true, MetricOutcomeError: true}
	for key := range got {
		if !okSurface[key[0]] {
			t.Errorf("series carries surface=%q, outside the closed set", key[0])
		}
		if !okOutcome[key[1]] {
			t.Errorf("series carries outcome=%q, outside the closed set", key[1])
		}
	}
}

// TestNoLabelCarriesRequestContent is the privacy assertion, made against the
// metric's DECLARED label names rather than against a sample of values.
//
// A value scan would only ever prove that the values this test happened to
// generate were clean. The real guarantee is structural: the metric declares
// exactly two labels, both drawn from constants in this file, so there is no
// code path by which a path, a method, a host, a model, a tenant or a decision
// id could become a label value. Asserting the LABEL NAMES is what pins that —
// adding a `path` label to carry request content would fail here immediately.
func TestNoLabelCarriesRequestContent(t *testing.T) {
	surfaceOutcomes.Reset()
	t.Cleanup(surfaceOutcomes.Reset)
	recordOutcome(SurfaceExtAuthz, MetricOutcomeAllow)

	ch := make(chan prometheus.Metric, 8)
	surfaceOutcomes.Collect(ch)
	close(ch)

	found := 0
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		var names []string
		for _, l := range d.GetLabel() {
			names = append(names, l.GetName())
		}
		sort.Strings(names)
		if strings.Join(names, ",") != "outcome,surface" {
			t.Errorf("the metric declares labels %v; it must declare exactly [outcome surface]. "+
				"Any additional label is a channel through which request content could reach "+
				"Prometheus, which this metric's contract forbids", names)
		}
		found++
	}
	if found == 0 {
		t.Fatal("no series were collected; the assertion above ran against nothing")
	}
}

// TestEditionIsTheArtifactNotTheBuildTag is the pin for the one place in the
// tree where edition.Current is WRONG.
//
// This image is built WITHOUT `-tags enterprise` (its Dockerfile has no EDITION
// arg — there is no community variant of it), so edition.Current reads
// `community` inside this binary: true of the compilation, false of the
// artifact. Reporting that would put the Enterprise-only integration surface
// into the community bucket of every adoption breakdown.
//
// Mutation: replace `Edition` with `edition.Current` in the heartbeat Config —
// in the untagged build (which is how this binary ships) this test fails.
func TestEditionTracksTheBuildRatherThanBeingPinned(t *testing.T) {
	// THE INVERSE OF WHAT THIS TEST USED TO ASSERT, and the change is the point.
	//
	// It pinned `Edition == edition.Enterprise` on the argument that the
	// component shipped in one edition only, so the value was a property of the
	// artifact rather than of the build tag. Moving this package to a
	// community-syncable location under BSL 1.1 ended that: the mirror carries
	// this source and a community build compiles it, so a pinned constant would
	// report `enterprise` from a community deployment — silently, and in the
	// flattering direction for the adoption split.
	//
	// Asserting equality with edition.Current rather than with a literal is
	// what makes this test hold in BOTH builds from one line. A test that
	// hard-coded "enterprise" here would have to be build-tagged itself, and a
	// build-tagged assertion about a build-tagged constant proves very little.
	if Edition != edition.Current {
		t.Errorf("Edition = %q but this build is %q — the reported edition must track the "+
			"build. A pinned value makes every deployment of the other edition misreport, "+
			"which is invisible: the ping is accepted and nothing logs.", Edition, edition.Current)
	}

	// And it must be one of the two real values, not an empty string that
	// omitempty would drop from the wire — absence and `community` are
	// different claims, and only one of them is true of a community build.
	if Edition != edition.Community && Edition != edition.Enterprise {
		t.Errorf("Edition = %q, which is neither %q nor %q", Edition, edition.Community, edition.Enterprise)
	}
}

// TestClientIDMatchesTheComponentVocabulary keeps one integration to one name.
//
// The same string identifies the adapters in the ping's `component` dimension
// and in the client-version counter. If they drifted, an operator correlating
// "which component pinged" against "which client called the engine" would be
// joining on two different keys and see neither.
func TestClientIDMatchesTheComponentVocabulary(t *testing.T) {
	if ClientID != heartbeat.ComponentGatewayAdapters {
		t.Errorf("ClientID = %q but the ping's component is %q — one integration must have one name",
			ClientID, heartbeat.ComponentGatewayAdapters)
	}
}

// TestClientIDSatisfiesTheAgentsShapeValidator proves the header will actually
// be COUNTED rather than silently dropped.
//
// The agent admits a lowercase slug of [a-z0-9][a-z0-9._-]{0,63}; anything else
// lands in axonflow_client_version_dropped_total{reason="invalid"} and never
// becomes a label. The failure mode of getting this wrong is invisible from
// this side — the request still succeeds — so it is asserted here rather than
// left to be noticed in a dashboard that stays empty.
func TestClientIDSatisfiesTheAgentsShapeValidator(t *testing.T) {
	if ClientID == "" {
		t.Fatal("ClientID is empty")
	}
	if len(ClientID) > 64 {
		t.Errorf("ClientID is %d bytes; the agent's validator admits at most 64", len(ClientID))
	}
	first := ClientID[0]
	if !(first >= 'a' && first <= 'z') && !(first >= '0' && first <= '9') {
		t.Errorf("ClientID %q must start with [a-z0-9]", ClientID)
	}
	for i := 0; i < len(ClientID); i++ {
		c := ClientID[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
		if !ok {
			t.Errorf("ClientID %q contains %q, which the agent's validator rejects — the header "+
				"would be dropped into dropped_total{reason=\"invalid\"} and never counted",
				ClientID, string(c))
		}
	}
	// It must NOT look internal: telemetry-filter classifies an
	// `axonflow-(ci|smoke|synthetic|test|dev)-` prefixed client as AxonFlow's
	// own infrastructure, which would file real customer adoption as internal.
	if strings.HasPrefix(ClientID, "axonflow-") {
		t.Errorf("ClientID %q starts with axonflow-, which the receiver's classifier may treat "+
			"as internal infrastructure — customer adoption would be filed as our own", ClientID)
	}
}

// TestStampFilenameIsPerBinary keeps the 7-day rate limit independent of the
// agent's and the orchestrator's. A shared stamp would silence whichever binary
// booted second on a host running more than one.
func TestStampFilenameIsPerBinary(t *testing.T) {
	for _, other := range []string{"agent-startup-telemetry-stamp", "orchestrator-startup-telemetry-stamp"} {
		if stampFilename == other {
			t.Errorf("the adapter shares the stamp filename %q with another binary; the rate "+
				"limit is no longer per-binary", other)
		}
	}
	if !strings.Contains(stampFilename, heartbeat.ComponentGatewayAdapters) {
		t.Errorf("stampFilename %q does not name this component; an operator reading the cache "+
			"directory cannot tell which binary owns it", stampFilename)
	}
}

// TestStartupPingCarriesTheConfiguredOrgID drives the REAL emitter at a real
// HTTP listener and reads the org_id off the bytes that arrived.
//
// It is deliberately not a test that MaybeSendStartupTelemetry sets
// heartbeat.Config.OrgID — that would assert the line of code I just wrote,
// against itself. The classification defect this fixes is a property of the
// PAYLOAD, so the assertion is on the payload: an AxonFlow-operated deployment
// of this component must arrive at the receiver carrying an org the classifier
// can recognise as internal.
//
// The negative half is the one that would have caught the original bug. Before
// the OrgID parameter existed, this binary read AXONFLOW_ORG_ID while the
// shared emitter's fallback read ORG_ID, so the ping went out with no org at
// all and every house deployment classified as EXTERNAL adoption.
func TestStartupPingCarriesTheConfiguredOrgID(t *testing.T) {
	capture := func(t *testing.T, cfg Config, env map[string]string) map[string]any {
		t.Helper()
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		// A private stamp dir per case, so the 7-day rate limit in the shared
		// emitter cannot make a later case silently send nothing — which would
		// leave its assertions reading a nil map and passing for the wrong
		// reason.
		t.Setenv("AXONFLOW_TELEMETRY_STAMP_DIR", t.TempDir())
		t.Setenv("AXONFLOW_CHECKPOINT_URL", srv.URL)

		// EVERY variable the emitter reads, not the two I happened to think of.
		//
		// The first version of this cleared CI and stopped there, and it failed
		// on a GitHub Actions runner and nowhere else: heartbeat.Enabled()
		// suppresses on GITHUB_ACTIONS *as well as* CI, so `sent` came back
		// false and the fatal below fired. Clearing one auto-suppress variable
		// and leaving its sibling is the same mistake as fixing one instance of
		// a defect class, and the environment is where it is least visible —
		// the test passes on every developer's machine.
		//
		// The list is heartbeat.Enabled() plus the environment-class and
		// identity probes BuildPayload consults, mirroring clearEmitterEnv in
		// platform/shared/heartbeat/heartbeat_test.go. It is spelled out here
		// rather than imported because that helper is an unexported test symbol
		// in another module; if Enabled() learns a new variable, both copies
		// have to learn it, and heartbeat's own vocabulary pin is what catches
		// the emitter side.
		for _, k := range []string{
			"AXONFLOW_TELEMETRY", "GITHUB_ACTIONS", "CI",
			"AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "KUBERNETES_SERVICE_HOST",
			"ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4",
			"DEPLOYMENT_MODE", "ORG_ID", "AXONFLOW_ORG_ID",
		} {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
		for k, v := range env {
			t.Setenv(k, v)
		}

		sent, err := MaybeSendStartupTelemetry(context.Background(), cfg)
		if err != nil {
			t.Fatalf("MaybeSendStartupTelemetry: %v", err)
		}
		if !sent {
			t.Fatal("the emitter reported nothing sent; every assertion below would read a nil " +
				"payload and pass vacuously")
		}
		if got == nil {
			t.Fatal("the listener captured no body")
		}
		return got
	}

	t.Run("an AxonFlow-operated deployment arrives with its org", func(t *testing.T) {
		p := capture(t, Config{OrgID: "axonflow-demo-portal"}, nil)
		if p["org_id"] != "axonflow-demo-portal" {
			t.Errorf("org_id = %#v, want %q — without it the classifier reads this house "+
				"deployment as EXTERNAL adoption, the defect #3662 fixed on the orchestrator",
				p["org_id"], "axonflow-demo-portal")
		}
	})

	t.Run("THE REGRESSION: the emitter's own ORG_ID fallback cannot see AXONFLOW_ORG_ID", func(t *testing.T) {
		// The environment as a real adapters deployment sets it, with the
		// config NOT carrying the org. This is the exact pre-fix shape, and it
		// is why an env fallback alone is not a fix: the variable names differ.
		p := capture(t, Config{}, map[string]string{"AXONFLOW_ORG_ID": "axonflow-demo-portal"})
		if _, present := p["org_id"]; present {
			t.Fatalf("org_id = %#v: the shared emitter picked up AXONFLOW_ORG_ID after all, so "+
				"this test no longer describes the fallback and the reason the explicit "+
				"parameter exists has changed", p["org_id"])
		}
		// Documenting, not asserting a wish: the absence above is precisely why
		// main.go must pass cfg.OrgID, and TestMainPassesTheOrgThrough covers
		// that it does.
	})

	t.Run("a customer deployment with no org reports ABSENT", func(t *testing.T) {
		p := capture(t, Config{}, nil)
		if v, present := p["org_id"]; present {
			t.Errorf("org_id present as %#v; a deployment with no org must report absence, not "+
				"a default — defaulting it would classify a real customer as internal and "+
				"delete them from the adoption number", v)
		}
	})
}

// TestMainPassesTheOrgThrough guards the one link the tests above cannot reach.
//
// MaybeSendStartupTelemetry now takes a Config, so the compiler guarantees that
// SOMETHING is passed — and `Config{}` compiles just as happily as `cfg`. That
// is not a hypothetical: an empty Config reproduces the original defect exactly,
// with a signature that looks fixed.
//
// WHAT THIS GUARD CANNOT SEE, stated so nobody reads more into it than it
// proves: it matches source text, so it is only as wide as the syntax it
// matches. Assigning `c := cfg` and passing `c`, or building a second Config
// from the environment, would defeat it. It catches the realistic regression —
// someone adding a parameter and wiring a zero value — and nothing subtler.
func TestMainPassesTheOrgThrough(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("cmd", "axonflow-gateway-adapters", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	const want = "gatewayadapters.StartTelemetry(context.Background(), cfg)"
	if !strings.Contains(string(src), want) {
		t.Errorf("main.go does not contain %q.\n\nThe telemetry call must be handed the "+
			"CONFIG THE SERVER WAS BUILT FROM. A zero Config compiles and sends a ping with no "+
			"org_id, which classifies every AxonFlow-operated deployment of this component as "+
			"external customer adoption — silently, with no error and nothing in a log.", want)
	}
}

// TestTopologyIsConstantForThisBinary pins the reading of `deployment_mode` that
// MaybeSendStartupTelemetry's doc comment asserts.
//
// The field is `self_hosted` on every row this binary emits, and the doc says
// so — but it is right by CONSTRUCTION rather than by measurement:
// TopologyDeploymentMode() answers community_saas only when DEPLOYMENT_MODE is
// exactly that, and Community-SaaS does not deploy gateway adapters. A comment
// making that claim is worth exactly nothing on its own, so this asserts it,
// including under the environment that would falsify it.
//
// If adapters ever do ship in the SaaS, the second case goes red and whoever
// makes that change has to decide what the field should say — which is the
// point of pinning a claim you cannot otherwise enforce.
func TestTopologyIsConstantForThisBinary(t *testing.T) {
	for _, mode := range []string{"", "enterprise", "in-vpc-enterprise", "community"} {
		t.Setenv("DEPLOYMENT_MODE", mode)
		if got := heartbeat.TopologyDeploymentMode(); got != "self_hosted" {
			t.Errorf("DEPLOYMENT_MODE=%q gives topology %q, want self_hosted", mode, got)
		}
	}

	// The falsifier. Nothing in this binary sets it, but if a deployment did,
	// the row would stop saying self_hosted — so the claim is about the
	// deployment shape, not about the code, and must be read that way.
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	if got := heartbeat.TopologyDeploymentMode(); got == "self_hosted" {
		t.Error("topology is self_hosted even under DEPLOYMENT_MODE=community-saas — the field " +
			"is then a constant rather than a derivation, and the doc comment on " +
			"MaybeSendStartupTelemetry (which tells a reader the value tracks the deployment) " +
			"is wrong")
	}
}
