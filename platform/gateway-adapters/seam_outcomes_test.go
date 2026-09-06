// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"net/http"
	"strings"
	"testing"

	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	agwapi "axonflow/platform/gateway-adapters/agentgateway/api"
	"axonflow/platform/shared/version"
)

// Per-surface outcome counting (#3660), driven through the REAL seam handlers
// against the in-process fake engine — not by calling recordOutcome directly.
// A test that called the recorder would prove the counter increments and
// nothing about whether the seams reach it.

// outcomeCount reads one (surface, outcome) series.
func outcomeCount(t *testing.T, surface, outcome string) float64 {
	t.Helper()
	return collectOutcomes(t)[[2]string{surface, outcome}]
}

// resetOutcomes clears the vec so a test's assertions are about its own
// records. Every test here takes an absolute count after the reset, so clearing
// cannot make another test read a wrong number.
func resetOutcomes(t *testing.T) {
	t.Helper()
	surfaceOutcomes.Reset()
	t.Cleanup(surfaceOutcomes.Reset)
}

// TestExtAuthzCountsAllowDenyAndError drives the ext_authz seam through all
// three outcome classes and asserts each lands on its own series.
//
// THE `deny` / `error` SPLIT IS THE POINT. A PDP outage makes this seam block
// with 503 — a block, but not a policy result. Counting it as `deny` would make
// an outage indistinguishable from a policy tightening on exactly the graph an
// operator pages from, so the outage case is asserted separately here rather
// than folded into "it blocked".
func TestExtAuthzCountsAllowDenyAndError(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		resetOutcomes(t)
		pdp := newFakePDP(t)
		cfg := testConfig(pdp)
		s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

		if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got := outcomeCount(t, SurfaceExtAuthz, MetricOutcomeAllow); got != 1 {
			t.Errorf("ext_authz allow = %v, want 1", got)
		}
	})

	t.Run("deny is a policy result", func(t *testing.T) {
		resetOutcomes(t)
		pdp := newFakePDP(t)
		pdp.setDecideVerdict("deny", "blocked by policy")
		cfg := testConfig(pdp)
		s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

		if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got := outcomeCount(t, SurfaceExtAuthz, MetricOutcomeDeny); got != 1 {
			t.Errorf("ext_authz deny = %v, want 1", got)
		}
		if got := outcomeCount(t, SurfaceExtAuthz, MetricOutcomeError); got != 0 {
			t.Errorf("a policy deny also counted as error (%v); the two must not be pooled", got)
		}
	})

	t.Run("a PDP outage is error, NOT deny", func(t *testing.T) {
		resetOutcomes(t)
		pdp := newFakePDP(t)
		// A 5xx is the fail-closed path: no verdict was obtained.
		pdp.set(func(f *fakePDP) { f.decideStatus = http.StatusInternalServerError })
		cfg := testConfig(pdp)
		cfg.FailMode = FailModeClosed
		s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

		if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got := outcomeCount(t, SurfaceExtAuthz, MetricOutcomeError); got != 1 {
			t.Errorf("ext_authz error = %v, want 1 — a fail-closed block during a PDP outage is "+
				"NOT a policy result and must not be counted as one", got)
		}
		if got := outcomeCount(t, SurfaceExtAuthz, MetricOutcomeDeny); got != 0 {
			t.Errorf("a PDP outage counted as deny (%v); an operator reading the deny series "+
				"would see a policy tightening that did not happen", got)
		}
	})

	t.Run("a fail-OPEN allow counts as allow", func(t *testing.T) {
		resetOutcomes(t)
		pdp := newFakePDP(t)
		pdp.set(func(f *fakePDP) { f.decideStatus = http.StatusInternalServerError })
		cfg := testConfig(pdp)
		cfg.FailMode = FailModeOpen
		s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

		if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got := outcomeCount(t, SurfaceExtAuthz, MetricOutcomeAllow); got != 1 {
			t.Errorf("ext_authz allow = %v, want 1 — the request went through, which is what "+
				"the caller experienced", got)
		}
	})

	t.Run("a misconfigured stage is error", func(t *testing.T) {
		resetOutcomes(t)
		pdp := newFakePDP(t)
		cfg := testConfig(pdp)
		s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

		_, err := s.Check(context.Background(), authzCheckRequest(openAIBody, map[string]string{
			"axonflow-stage": "not-a-stage",
		}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got := outcomeCount(t, SurfaceExtAuthz, MetricOutcomeError); got != 1 {
			t.Errorf("a misconfigured leg = %v on error, want 1 — it is a configuration fault, "+
				"not a verdict", got)
		}
	})
}

// TestEveryExtAuthzCallIsCountedExactlyOnce is the wrapper's own guard.
//
// The counting wraps the whole handler precisely so a return path added later
// is covered without anyone remembering. This asserts the invariant that makes
// that true: N calls produce N records, across mixed outcomes. A double-count
// (a counter left behind at a branch as well as in the wrapper) or a missed
// path both break it.
func TestEveryExtAuthzCallIsCountedExactlyOnce(t *testing.T) {
	resetOutcomes(t)
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	const allows = 3
	for i := 0; i < allows; i++ {
		if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
			t.Fatalf("Check: %v", err)
		}
	}
	pdp.setDecideVerdict("deny", "blocked by policy")
	const denies = 2
	for i := 0; i < denies; i++ {
		if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
			t.Fatalf("Check: %v", err)
		}
	}

	total := 0.0
	for key, v := range collectOutcomes(t) {
		if key[0] == SurfaceExtAuthz {
			total += v
		}
	}
	if total != allows+denies {
		t.Errorf("%d ext_authz calls produced %v records, want %d — a path is counted twice or "+
			"not at all", allows+denies, total, allows+denies)
	}
}

// TestExtMcpCountsBothPlanes covers the MCP seam's request and response planes.
// The response plane is UNCONDITIONALLY fail-closed, so its `error` bucket is
// especially load-bearing: a withheld response during an engine outage must not
// look like a policy that blocked the content.
func TestExtMcpCountsBothPlanes(t *testing.T) {
	t.Run("request allow", func(t *testing.T) {
		resetOutcomes(t)
		pdp := newFakePDP(t)
		cfg := testConfig(pdp)
		s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

		if _, err := s.CheckRequest(context.Background(), toolsCallRequest("jwt-mcp")); err != nil {
			t.Fatalf("CheckRequest: %v", err)
		}
		if got := outcomeCount(t, SurfaceExtMcp, MetricOutcomeAllow); got != 1 {
			t.Errorf("ext_mcp allow = %v, want 1", got)
		}
	})

	t.Run("response-plane engine outage is error", func(t *testing.T) {
		resetOutcomes(t)
		pdp := newFakePDP(t)
		pdp.set(func(f *fakePDP) { f.checkOutputStatus = http.StatusInternalServerError })
		cfg := testConfig(pdp)
		s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

		if _, err := s.CheckResponse(context.Background(), &agwapi.McpResponse{McpResponse: []byte(`{"result":"ok"}`)}); err != nil {
			t.Fatalf("CheckResponse: %v", err)
		}
		if got := outcomeCount(t, SurfaceExtMcp, MetricOutcomeError); got != 1 {
			t.Errorf("ext_mcp response error = %v, want 1 — a response withheld because the "+
				"engine was unreachable is not a policy block", got)
		}
	})
}

// TestPDPRoundTripCarriesTheClientHeader is the header proof, asserted from the
// ENGINE's side of the wire.
//
// Checking the client's own configuration field would prove the value was
// stored. What matters is that it ARRIVES: the agent counts what it receives,
// and a header set on a struct nobody sends is exactly the invisibility this
// change exists to end.
func TestPDPRoundTripCarriesTheClientHeader(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
		t.Fatalf("Check: %v", err)
	}

	var hdrs http.Header
	pdp.set(func(f *fakePDP) { hdrs = f.lastDecideHdrs })
	got := hdrs.Get("X-Axonflow-Client")
	if got == "" {
		t.Fatal("the engine received no X-Axonflow-Client header; the adapters remain invisible " +
			"in axonflow_client_version_requests_total")
	}

	// A test binary is UNBAKED, so version.Resolve() is empty and the wire form
	// is the bare id — which the agent counts in its explicit `unversioned`
	// bucket rather than dropping. Assert exactly what each case must send, so
	// this test says something in both.
	want := ClientID
	if v := version.Resolve(); v != "" {
		want = ClientID + "/" + v
	}
	if got != want {
		t.Errorf("X-Axonflow-Client = %q, want %q", got, want)
	}
}

// TestEverySeamCountsAnUnscannableBodyTheSameWay is M3 from #3668's R3: ONE
// condition, ONE classification, asserted across all three seams at once.
//
// THE BUG THIS PINS. A body larger than MaxBodyBytes is the same event on every
// seam: this adapter cannot scan the content, so it fail-closes. ext_proc
// counted it `error` and said why; ext_mcp agreed through its own vocabulary
// (RESOURCE_EXHAUSTED); ext_authz's otherwise identical switch simply omitted
// the case and fell through to `deny`. One seam therefore reported a body-size
// misconfiguration as a policy refusal.
//
// That split matters because of what an operator does with each graph. A rising
// `deny` line means policy is refusing traffic and sends someone to the policy
// set. A rising `error` line means the governance path itself is failing — and
// here the fix is raising MaxBodyBytes, which no amount of policy review would
// ever reach.
//
// It is written as ONE test over the three seams rather than three tests
// because the property is agreement. Three separate tests would each keep
// passing while the seams drifted apart, which is exactly what happened.
func TestEverySeamCountsAnUnscannableBodyTheSameWay(t *testing.T) {
	// Big enough to exceed every bound below, and made of one repeated byte so
	// nothing in it can be mistaken for a policy-relevant payload — the block
	// under test is about SIZE, not content.
	oversized := strings.Repeat("a", 4096)

	seams := map[string]func(t *testing.T){
		SurfaceExtAuthz: func(t *testing.T) {
			cfg := testConfig(newFakePDP(t))
			cfg.MaxBodyBytes = 8
			s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)
			res, err := s.Check(context.Background(), authzCheckRequest(oversized, nil))
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			// The positive control: assert the seam really took the size path,
			// so a future change that makes it allow (or deny for some other
			// reason) cannot leave this test asserting about the wrong block.
			if code := res.GetDeniedResponse().GetStatus().GetCode(); code != typev3.StatusCode_PayloadTooLarge {
				t.Fatalf("ext_authz answered %v, not 413 — this run is not exercising the size bound", code)
			}
		},
		SurfaceExtProc: func(t *testing.T) {
			cfg := testConfig(newFakePDP(t))
			cfg.MaxBodyBytes = 16
			stream := openExtProcStream(t, startServer(t, cfg))
			roundTrip(t, stream, requestHeadersMsg(false))
			resp := roundTrip(t, stream, requestBodyMsg(oversized, true))
			if code := resp.GetImmediateResponse().GetStatus().GetCode(); code != typev3.StatusCode_PayloadTooLarge {
				t.Fatalf("ext_proc answered %v, not 413 — this run is not exercising the size bound", code)
			}
		},
		SurfaceExtMcp: func(t *testing.T) {
			cfg := testConfig(newFakePDP(t))
			cfg.MaxBodyBytes = 8
			s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)
			req := toolsCallRequest("")
			req.McpRequest = []byte(oversized)
			res, err := s.CheckRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("CheckRequest: %v", err)
			}
			if code := res.GetError().GetCode(); code != agwapi.AuthorizationError_RESOURCE_EXHAUSTED {
				t.Fatalf("ext_mcp answered %v, not RESOURCE_EXHAUSTED — this run is not exercising "+
					"the size bound", code)
			}
		},
	}

	for surface, drive := range seams {
		t.Run(surface, func(t *testing.T) {
			resetOutcomes(t)
			drive(t)

			if got := outcomeCount(t, surface, MetricOutcomeError); got != 1 {
				t.Errorf("%s counted error=%v for an unscannable body, want 1", surface, got)
			}
			if got := outcomeCount(t, surface, MetricOutcomeDeny); got != 0 {
				t.Errorf("%s counted deny=%v for an unscannable body. This block carries NO verdict "+
					"from the engine — the adapter refused to look. Counting it as a policy refusal "+
					"makes a MaxBodyBytes misconfiguration read as a policy tightening on the graph "+
					"an operator pages from, and sends them to the policy set instead of to the "+
					"setting that actually caused it.", surface, got)
			}
			if got := outcomeCount(t, surface, MetricOutcomeAllow); got != 0 {
				t.Errorf("%s counted allow=%v for a request it blocked", surface, got)
			}
		})
	}
}

// TestExtProcCountsBlocksBuiltInTheProcessLoop is M2 from #3668's R3.
//
// THE BUG. Counting lived in the three on* phase wrappers. Four groups of arms
// in the Process loop build a response INLINE and reach none of them: the
// ResponseHeaders, RequestTrailers and ResponseTrailers cases, and the
// fail-closed default for an unknown message type. Every block those arms
// produce — an unsupported body mode, an undelivered request body, a protocol
// revision this adapter cannot govern — incremented nothing.
//
// That is worse than an uninstrumented seam. An operator watching
// axonflow_gateway_adapter_surface_outcomes_total sees a flat, healthy graph
// while the adapter refuses every request on a misconfigured leg. The leg most
// likely to hit it is exactly the one the counter is least able to describe:
// requestHeaderMode: skip + requestBodyMode: none, where ResponseHeaders is the
// FIRST and ONLY phase that ever runs.
//
// The subtests below are the two directions. A block from an inline arm must be
// counted; a pass-through continue from the same arm must NOT be, or protocol
// bookkeeping inflates `allow` and the seam looks busier than it is.
func TestExtProcCountsBlocksBuiltInTheProcessLoop(t *testing.T) {
	invalidModeStream := func(t *testing.T) extprocv3.ExternalProcessor_ProcessClient {
		t.Helper()
		return openExtProcStream(t, startServer(t, streamingConfig(newFakePDP(t))))
	}
	responseHeadersFirst := func() *extprocv3.ProcessingRequest {
		msg := responseHeadersMsg()
		msg.ProtocolConfig = &extprocv3.ProtocolConfiguration{
			RequestBodyMode:  extprocfilterv3.ProcessingMode_NONE, // invalid: request must be BUFFERED
			ResponseBodyMode: extprocfilterv3.ProcessingMode_NONE,
		}
		return msg
	}

	t.Run("the ResponseHeaders arm: a block is counted", func(t *testing.T) {
		resetOutcomes(t)
		resp := roundTrip(t, invalidModeStream(t), responseHeadersFirst())

		// Positive control first: without it, a change that made this leg
		// CONTINUE would leave the count at zero and the assertion below would
		// have to be read as "nothing was counted", which is also what a
		// deleted counter looks like.
		if resp.GetImmediateResponse() == nil {
			t.Fatalf("this leg must be rejected at ResponseHeaders; got %+v — the run is not "+
				"exercising the inline arm", resp)
		}
		if got := outcomeCount(t, SurfaceExtProc, MetricOutcomeError); got != 1 {
			t.Errorf("ext_proc error = %v, want 1. This block is built inline in the Process "+
				"loop and never passes an on* wrapper, so before the per-message latch it "+
				"incremented nothing: the adapter refused the request and the graph stayed flat.", got)
		}
	})

	t.Run("the trailers arm: a block is counted", func(t *testing.T) {
		resetOutcomes(t)
		stream := invalidModeStream(t)
		roundTrip(t, stream, responseHeadersFirst())
		resp := roundTrip(t, stream, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseTrailers{
				ResponseTrailers: &extprocv3.HttpTrailers{},
			},
		})
		if resp.GetImmediateResponse() == nil {
			t.Fatalf("trailers on an invalid-mode leg must be rejected; got %+v", resp)
		}
		// Two messages, two blocks, two records. NOTE what this does NOT show:
		// both messages are blocks, so isImmediate counts them whatever the
		// latch holds. Per-message CLEARING is pinned by the control below,
		// where a governed phase is followed by a pass-through.
		if got := outcomeCount(t, SurfaceExtProc, MetricOutcomeError); got != 2 {
			t.Errorf("ext_proc error = %v after two blocked messages, want 2", got)
		}
	})

	// THE CONTROL, and the only subtest that pins per-message CLEARING.
	//
	// It runs a governed phase (which sets the latch) and then a pass-through
	// (which must not be counted). A latch cleared per STREAM rather than per
	// message stays set from the first and counts the second, so this is where
	// removing `st.phaseGoverned = false` from the loop goes red. The two
	// blocked messages above cannot see it: isImmediate counts a block whatever
	// the latch holds.
	t.Run("THE CONTROL: a governed phase does not leave the latch set", func(t *testing.T) {
		resetOutcomes(t)
		cfg := testConfig(newFakePDP(t))
		stream := openExtProcStream(t, startServer(t, cfg))

		// 1. Headers promising a body: a pass-through, the verdict happens at
		//    the body. Counts nothing.
		resp := roundTrip(t, stream, requestHeadersMsg(false))
		if resp.GetImmediateResponse() != nil {
			t.Fatalf("expected a continue at headers; got a block %+v", resp)
		}
		if got := outcomeCount(t, SurfaceExtProc, MetricOutcomeAllow); got != 0 {
			t.Fatalf("the headers pass-through counted allow=%v; counting protocol bookkeeping "+
				"inflates the seam's volume with messages that carry no decision", got)
		}

		// 2. The body: a real decision. Counts exactly one allow, and sets the
		//    latch.
		resp = roundTrip(t, stream, requestBodyMsg(openAIBody, true))
		if resp.GetImmediateResponse() != nil {
			t.Fatalf("expected the body to be allowed; got a block %+v", resp)
		}
		if got := outcomeCount(t, SurfaceExtProc, MetricOutcomeAllow); got != 1 {
			t.Fatalf("the governed body phase counted allow=%v, want 1 — without this the "+
				"assertion below would hold for the wrong reason", got)
		}

		// 3. Trailers: protocol bookkeeping on a healthy leg, arriving right
		//    after the phase that set the latch. Must add nothing.
		roundTrip(t, stream, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_RequestTrailers{
				RequestTrailers: &extprocv3.HttpTrailers{},
			},
		})
		if got := outcomeCount(t, SurfaceExtProc, MetricOutcomeAllow); got != 1 {
			t.Errorf("ext_proc allow = %v after a governed phase followed by a pass-through, "+
				"want 1. The latch is cleared per MESSAGE; leaving it set for the stream makes "+
				"every trailer and bookkeeping message after the first decision count as another "+
				"governed allow, silently multiplying the seam's apparent volume.", got)
		}
		for _, outcome := range []string{MetricOutcomeDeny, MetricOutcomeError} {
			if got := outcomeCount(t, SurfaceExtProc, outcome); got != 0 {
				t.Errorf("ext_proc %s = %v on a healthy leg, want 0", outcome, got)
			}
		}
	})
}
