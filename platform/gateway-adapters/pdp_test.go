// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/pep"
)

func TestBreakerTripsAndCoolsDown(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newBreaker(3, 30*time.Second)
	b.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("breaker should allow before threshold (i=%d)", i)
		}
		b.record(true)
	}
	if b.allow() {
		t.Fatal("breaker should be open after threshold consecutive failures")
	}

	now = now.Add(31 * time.Second)
	if !b.allow() {
		t.Fatal("breaker should half-open after cooldown")
	}
	b.record(true) // probe fails → re-open
	now = now.Add(time.Second)
	if b.allow() {
		t.Fatal("breaker should re-open after a failed probe")
	}

	now = now.Add(31 * time.Second)
	if !b.allow() {
		t.Fatal("breaker should half-open again")
	}
	b.record(false) // probe succeeds → reset
	if !b.allow() {
		t.Fatal("breaker should close after a successful probe")
	}
}

func TestBreakerHalfOpenAdmitsSingleProbe(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newBreaker(2, 30*time.Second)
	b.now = func() time.Time { return now }
	b.record(true)
	b.record(true) // open
	now = now.Add(31 * time.Second)
	if !b.allow() {
		t.Fatal("first caller after cooldown should be admitted as the probe")
	}
	if b.allow() {
		t.Fatal("second concurrent caller must fail fast while the probe is in flight")
	}
	b.record(false) // probe succeeds
	if !b.allow() {
		t.Fatal("breaker should close after the probe succeeds")
	}
}

func TestBreakerIgnoresEngineAnswers(t *testing.T) {
	b := newBreaker(2, time.Minute)
	for i := 0; i < 10; i++ {
		b.record(false) // denies / 4xx are answers, not transport failures
	}
	if !b.allow() {
		t.Fatal("engine answers must not trip the breaker")
	}
}

func TestPDPBreakerFailsFastWhenOpen(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.BreakerThreshold = 2
	cfg.BreakerCooldown = time.Hour
	facade := newTestPDPFacade(t, cfg)
	pdp.srv.Close()

	for i := 0; i < 2; i++ {
		_, err := facade.Decide(context.Background(), pep.DecideRequest{Stage: StageLLM, Query: "x"}, "")
		if err == nil {
			t.Fatal("expected transport failure")
		}
	}
	// Circuit now open: the next call must fail fast with an open-circuit
	// unavailability, not attempt the network.
	start := time.Now()
	_, err := facade.Decide(context.Background(), pep.DecideRequest{Stage: StageLLM, Query: "x"}, "")
	if err == nil || !strings.Contains(err.Error(), "circuit open") {
		t.Fatalf("expected open-circuit failure, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("open circuit should fail fast")
	}
}

func TestGateRequestObligationFailureNeverFailsOpen(t *testing.T) {
	// Even under fail-open, an unfulfillable redaction obligation blocks.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("ignored")
	pdp.set(func(f *fakePDP) { f.checkInputStatus = 500 })
	cfg := testConfig(pdp)
	cfg.FailMode = FailModeOpen
	facade := newTestPDPFacade(t, cfg)

	out := facade.GateRequest(context.Background(),
		pep.DecideRequest{Stage: StageLLM, Query: "q"}, "statement", "", seamBodyCapable)
	if out.Kind != OutcomeFailClosed {
		t.Fatalf("expected OutcomeFailClosed, got %d (%s)", out.Kind, out.Reason)
	}
}

func TestConfigValidate(t *testing.T) {
	base := func() Config {
		return Config{
			ListenAddr:       ":0",
			AxonFlowEndpoint: "http://pdp:8080",
			DefaultStage:     StageLLM,
			FailMode:         FailModeClosed,
			RequestTimeout:   time.Second,
			MaxBodyBytes:     1024,
			BreakerThreshold: 3,
			BreakerCooldown:  time.Second,
		}
	}
	if err := func() error { c := base(); return c.Validate() }(); err != nil {
		t.Fatalf("base config should validate: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing endpoint", func(c *Config) { c.AxonFlowEndpoint = " " }},
		{"bad fail mode", func(c *Config) { c.FailMode = "sometimes" }},
		{"bad stage", func(c *Config) { c.DefaultStage = "bogus" }},
		{"bad timeout", func(c *Config) { c.RequestTimeout = 0 }},
		{"bad body bound", func(c *Config) { c.MaxBodyBytes = 0 }},
		{"bad breaker", func(c *Config) { c.BreakerThreshold = 0 }},
	}
	for _, tc := range cases {
		c := base()
		tc.mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("AXONFLOW_ENDPOINT", "http://pdp:8080")
	cfg := ConfigFromEnv()
	if cfg.FailMode != FailModeClosed {
		t.Fatalf("default fail mode must be closed, got %q", cfg.FailMode)
	}
	if cfg.DefaultStage != StageLLM || cfg.GatewayID != "agentgateway" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("env defaults should validate: %v", err)
	}
}

func TestBearerTokenParsing(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":      "abc",
		"bearer xyz":      "xyz",
		"Basic dXNlcg==":  "", // gateway credentials are not an end-user token
		"":                "",
		"Bearer  spaced ": "spaced",
	}
	for in, want := range cases {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrustIdentityFromEnvParse(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"":      false,
		"false": false,
		"TRUE":  false, // fail-safe: only the exact lowercase opt-in counts
		"1":     false,
		" true": true, // trimmed
	}
	for in, want := range cases {
		t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", in)
		if got := trustIdentityFromEnv(); got != want {
			t.Errorf("trustIdentityFromEnv(%q) = %v, want %v", in, got, want)
		}
	}
}

// #2958: the seam→capability mapping is the contract's load-bearing half — it
// is what tells the PDP which obligations it may emit. GateRequest backs the
// body-capable seams (ExtMcp, ext_proc), Decide backs headers-only (ext_authz).

func TestGateRequestAdvertisesTheCallerSuppliedCapability(t *testing.T) {
	// GateRequest is shared by paths with DIFFERENT capabilities (ext_proc is
	// body-capable with a body, headers-only on a bodyless request), so the set
	// is a parameter. A constant inside GateRequest silently over-declared the
	// bodyless path and reinstated the allow→403 on it.
	for _, tc := range []struct {
		name string
		seam Seam
		want string
	}{
		{"body-capable path", seamBodyCapable, "request_body_redaction"},
		{"headers-only path (ext_proc bodyless)", seamHeadersOnly, "request_header_mutation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pdp := newFakePDP(t)
			cfg := testConfig(pdp)
			facade := newTestPDPFacade(t, cfg)

			out := facade.GateRequest(context.Background(), pep.DecideRequest{
				Stage: StageLLM, Query: "hello",
			}, "hello", "", tc.seam)
			if out.Kind != OutcomeAllow {
				t.Fatalf("expected allow, got kind=%d reason=%s", out.Kind, out.Reason)
			}
			got := pdp.lastDecideCapabilities()
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("capabilities = %v, want exactly [%s]", got, tc.want)
			}
		})
	}
}

func TestGateRequestHeadersOnlyPathGetsFallbackNotObligation(t *testing.T) {
	// A headers-only caller through GateRequest must never be handed a
	// request-body redaction: a conforming PDP suppresses it and the org posture
	// decides, so the outcome is a plain allow (log) — never OutcomeAllowRedacted,
	// which the caller could not apply.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("ignored")
	cfg := testConfig(pdp)
	facade := newTestPDPFacade(t, cfg)

	out := facade.GateRequest(context.Background(), pep.DecideRequest{
		Stage: StageLLM, Query: "customer NRIC S1234567A",
	}, "customer NRIC S1234567A", "", seamHeadersOnly)
	if out.Kind != OutcomeAllow {
		t.Fatalf("expected a plain OutcomeAllow under the log fallback, got kind=%d reason=%s", out.Kind, out.Reason)
	}
}

func TestGateRequestStillRedactsWhenCapable(t *testing.T) {
	// The capability advertisement must not disturb the path it enables: a
	// body-capable seam still receives the obligation and still fulfills it
	// through the engine.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("customer NRIC [REDACTED]")
	cfg := testConfig(pdp)
	facade := newTestPDPFacade(t, cfg)

	out := facade.GateRequest(context.Background(), pep.DecideRequest{
		Stage: StageLLM, Query: "customer NRIC S1234567A",
	}, "customer NRIC S1234567A", "", seamBodyCapable)
	if out.Kind != OutcomeAllowRedacted {
		t.Fatalf("expected OutcomeAllowRedacted, got kind=%d reason=%s", out.Kind, out.Reason)
	}
	if out.RedactedStatement != "customer NRIC [REDACTED]" {
		t.Fatalf("expected the engine-redacted statement, got %q", out.RedactedStatement)
	}
}

func TestDecideAdvertisesHeadersOnlyCapabilityNotBody(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	facade := newTestPDPFacade(t, cfg)

	if _, err := facade.Decide(context.Background(), pep.DecideRequest{
		Stage: StageLLM, Query: "hello",
	}, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	got := pdp.lastDecideCapabilities()
	if len(got) != 1 || got[0] != "request_header_mutation" {
		t.Fatalf("capabilities = %v, want exactly [request_header_mutation]", got)
	}
}

func TestDecideOverridesCallerSuppliedCapabilities(t *testing.T) {
	// The seam owns its declaration. A caller that (wrongly) claims body
	// capability on the headers-only path must not be able to talk the PDP into
	// emitting an obligation this seam cannot discharge.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	facade := newTestPDPFacade(t, cfg)

	if _, err := facade.Decide(context.Background(), pep.DecideRequest{
		Stage: StageLLM, Query: "hello",
		FulfillmentCapabilities: pep.AdvertiseCapabilities([]string{"request_body_redaction"}),
	}, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	got := pdp.lastDecideCapabilities()
	if len(got) != 1 || got[0] != "request_header_mutation" {
		t.Fatalf("caller-supplied capabilities leaked to the PDP: %v", got)
	}
}

func TestObligationBackstop(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	facade := newTestPDPFacade(t, cfg)

	if facade.ObligationBackstop(nil) {
		t.Error("nil decision must not trip the backstop")
	}
	if facade.ObligationBackstop(&pep.DecideResponse{Verdict: "allow"}) {
		t.Error("an allow with no obligations must not trip the backstop")
	}
	tripped := facade.ObligationBackstop(&pep.DecideResponse{
		Verdict: "allow",
		Obligations: []pep.Obligation{{
			Type:        pep.ObligationRedactPII,
			Fulfillment: &pep.ObligationFulfillment{Phase: pep.PhaseRequest, Endpoint: "/api/v1/mcp/check-input"},
		}},
	})
	if !tripped {
		t.Error("a request-phase redact_pii obligation MUST trip the backstop on a headers-only seam")
	}
	// A response-phase obligation is not this seam's problem: the PEP client
	// fans out to check-output after the backend call, so it must not block here.
	if facade.ObligationBackstop(&pep.DecideResponse{
		Verdict: "allow",
		Obligations: []pep.Obligation{{
			Type:        pep.ObligationRedactPII,
			Fulfillment: &pep.ObligationFulfillment{Phase: pep.PhaseResponse},
		}},
	}) {
		t.Error("a response-phase obligation must not trip the request-plane backstop")
	}
}

// TestRenderSeamsCopiesRatherThanAliasingThePackageVars.
//
// The PDP's own field comment says the seams are held per-instance "so that a
// process which did not opt into the handshake and one that did are two VALUES
// rather than one value plus a global that a test can leave mutated". A struct
// assignment does not achieve that: the slices still share backing arrays, so
// one accessor's caller could corrupt the global for every PDP in the process.
func TestRenderSeamsCopiesRatherThanAliasingThePackageVars(t *testing.T) {
	originalFulfillment := append([]string(nil), seamHeadersOnly.Fulfillment...)
	originalCapabilities := len(seamBodyCapable.Capabilities)

	headersOnly, bodyCapable, err := renderSeams("axonflow-decision-proof")
	if err != nil {
		t.Fatal(err)
	}
	if len(headersOnly.Fulfillment) == 0 {
		t.Fatal("fixture invalid: the headers-only seam declares nothing to mutate, so this test proves nothing")
	}

	headersOnly.Fulfillment[0] = "mutated-through-the-copy"
	bodyCapable.Capabilities = append(bodyCapable.Capabilities, contract.Capability{Type: contract.ObImmutableAudit, Version: 9})

	for i, want := range originalFulfillment {
		if seamHeadersOnly.Fulfillment[i] != want {
			t.Errorf("the package var was mutated through a rendered seam: %v", seamHeadersOnly.Fulfillment)
		}
	}
	if len(seamBodyCapable.Capabilities) != originalCapabilities {
		t.Errorf("the package var's capability slice grew through a rendered seam: %v", seamBodyCapable.Capabilities)
	}

	// The copy is never NIL for an empty input. `append([]T(nil), ...)` returns
	// nil there, which is the idiom contract.SortCapabilities' own comment
	// forbids as the #2958 collapse — and the first version of Seam.copy used
	// it for Fulfillment, latent only because both declared seams are non-empty.
	emptySeam := Seam{Name: "n", Fulfillment: []string{}, Capabilities: []contract.Capability{}}.copy()
	if emptySeam.Fulfillment == nil {
		t.Error("Seam.copy returned a NIL Fulfillment for an empty input; a seam declaring no mechanic would reach the wire as an ABSENT member")
	}
	if emptySeam.Capabilities == nil {
		t.Error("Seam.copy returned a NIL Capabilities for an empty input")
	}

	// The ACCESSORS hand out copies too, or the hazard is narrowed (to this
	// PDP, for every subsequent request) rather than removed — and two call
	// sites already pass SeamHeadersOnly().Fulfillment onward.
	facade := &PDP{seamHeadersOnly: headersOnly, seamBodyCapable: bodyCapable}
	handed := facade.SeamHeadersOnly()
	if len(handed.Fulfillment) == 0 {
		t.Fatal("fixture invalid: nothing to mutate through the accessor")
	}
	handed.Fulfillment[0] = "mutated-through-the-accessor"
	if facade.SeamHeadersOnly().Fulfillment[0] == "mutated-through-the-accessor" {
		t.Error("the accessor handed out the PDP's own slice; a caller could rewrite this process's declaration for every subsequent request")
	}

	// And the handshakes really were rendered, so the copy is not being proved
	// on a path that returned early.
	if headersOnly.handshake == "" || bodyCapable.handshake == "" {
		t.Error("renderSeams returned empty handshakes for a configured audience")
	}
	if headersOnly.handshake == bodyCapable.handshake {
		t.Error("the two seams rendered the SAME handshake; they declare different capability sets and must not collapse")
	}
}

// TestRenderSeamsIsDarkWithoutAnAudience.
//
// The opt-in property, asserted rather than assumed. It gates an ALLOW -> DENY
// transition for the headers-only seam, so "no header is sent by default" is a
// behaviour claim and not a configuration detail.
func TestRenderSeamsIsDarkWithoutAnAudience(t *testing.T) {
	headersOnly, bodyCapable, err := renderSeams("")
	if err != nil {
		t.Fatal(err)
	}
	if headersOnly.handshake != "" || bodyCapable.handshake != "" {
		t.Fatalf("an unconfigured audience rendered a handshake: %q / %q", headersOnly.handshake, bodyCapable.handshake)
	}
	// The #2958 declarations are UNAFFECTED by the opt-in: they are a different
	// axis and they ship on by default, as they did before #3704.
	if len(headersOnly.Fulfillment) != 1 || headersOnly.Fulfillment[0] != pep.CapabilityRequestHeaderMutation {
		t.Errorf("the seam-mechanics declaration changed with the handshake opt-in: %v", headersOnly.Fulfillment)
	}
}
