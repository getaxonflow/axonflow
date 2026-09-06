// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"strings"
	"testing"

	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// Streaming-safe request redaction (#2959): buffered request + ungoverned
// (responseBodyMode: none) response, so a prompt can be engine-redacted while
// the completion streams back as SSE.

// --- helpers ---------------------------------------------------------------

// withModes attaches a ProtocolConfiguration to a message. The gateway sends
// one exactly once, on the FIRST message of the stream.
func withModes(msg *extprocv3.ProcessingRequest, req, resp extprocfilterv3.ProcessingMode_BodySendMode) *extprocv3.ProcessingRequest {
	msg.ProtocolConfig = &extprocv3.ProtocolConfiguration{
		RequestBodyMode:  req,
		ResponseBodyMode: resp,
	}
	return msg
}

// streamingConfig is the partner-shaped adapter posture: ungoverned-response
// legs permitted.
func streamingConfig(pdp *fakePDP) Config {
	cfg := testConfig(pdp)
	cfg.ExtProcResponseGovernance = ExtProcResponseGovernanceOff
	return cfg
}

// openStreamingLeg drives the request phases of a buffered-request /
// none-response leg and returns the body-phase response.
func openStreamingLeg(t *testing.T, cfg Config, body string) (extprocv3.ExternalProcessor_ProcessClient, *extprocv3.ProcessingResponse) {
	t.Helper()
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)
	roundTrip(t, stream, withModes(requestHeadersMsg(false),
		extprocfilterv3.ProcessingMode_BUFFERED, extprocfilterv3.ProcessingMode_NONE))
	return stream, roundTrip(t, stream, requestBodyMsg(body, true))
}

// --- the accept matrix -----------------------------------------------------

// allBodyModes is every BodySendMode the ext_proc proto defines. Enumerating
// the whole enum (rather than the subset agentgateway can emit) is deliberate:
// the adapter also faces raw Envoy, and a mode we never thought about must
// land in the reject default, not slip through.
var allBodyModes = []extprocfilterv3.ProcessingMode_BodySendMode{
	extprocfilterv3.ProcessingMode_NONE,
	extprocfilterv3.ProcessingMode_STREAMED,
	extprocfilterv3.ProcessingMode_BUFFERED,
	extprocfilterv3.ProcessingMode_BUFFERED_PARTIAL,
	extprocfilterv3.ProcessingMode_FULL_DUPLEX_STREAMED,
	// Added upstream in go-control-plane (BodySendMode = 5). Like every other
	// non-BUFFERED request mode it lands in the reject path — the adapter
	// decides on the FULL request payload — and as a response mode it falls to
	// the switch default alongside STREAMED/BUFFERED_PARTIAL/FULL_DUPLEX.
	extprocfilterv3.ProcessingMode_GRPC,
}

// TestBodyModeEnumExhaustive pins allBodyModes against the proto enum itself,
// so a go-control-plane upgrade that adds a sixth BodySendMode cannot silently
// shrink the accept-matrix's "exhaustive" claim — the new mode must be added
// to the table (where the reject default already covers it) before this
// compiles into a passing suite again.
func TestBodyModeEnumExhaustive(t *testing.T) {
	if len(allBodyModes) != len(extprocfilterv3.ProcessingMode_BodySendMode_name) {
		t.Fatalf("allBodyModes has %d entries but the proto enum defines %d — a new BodySendMode was added upstream; extend allBodyModes (and the accept-matrix rows/cells) to cover it",
			len(allBodyModes), len(extprocfilterv3.ProcessingMode_BodySendMode_name))
	}
}

// TestExtProcBodyModeAcceptMatrix pins the full request x response accept
// matrix under both governance postures — the same table the docs publish.
//
// The expectations are WRITTEN OUT, not computed from the production
// predicate: a table derived from the expression under test passes whatever
// that expression says, including "accept everything".
func TestExtProcBodyModeAcceptMatrix(t *testing.T) {
	// Rows = request mode, columns = response mode, in allBodyModes order:
	//                     NONE STRM BUFF BPART FDUP GRPC
	governedMatrix := []string{
		/* req NONE  */ "n n n n n n",
		/* req STRM  */ "n n n n n n",
		/* req BUFF  */ "n n y n n n",
		/* req BPART */ "n n n n n n",
		/* req FDUP  */ "n n n n n n",
		/* req GRPC  */ "n n n n n n",
	}
	// The ONLY cell the opt-in changes: buffered request + none response.
	ungovernedMatrix := []string{
		/* req NONE  */ "n n n n n n",
		/* req STRM  */ "n n n n n n",
		/* req BUFF  */ "y n y n n n",
		/* req BPART */ "n n n n n n",
		/* req FDUP  */ "n n n n n n",
		/* req GRPC  */ "n n n n n n",
	}

	for _, tc := range []struct {
		name       string
		governance string
		matrix     []string
	}{
		{"default (buffered)", ExtProcResponseGovernanceBuffered, governedMatrix},
		{"opt-in (off)", ExtProcResponseGovernanceOff, ungovernedMatrix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for ri, req := range allBodyModes {
				cells := strings.Fields(tc.matrix[ri])
				if len(cells) != len(allBodyModes) {
					t.Fatalf("matrix row %d malformed: %q", ri, tc.matrix[ri])
				}
				for ci, resp := range allBodyModes {
					wantAccept := cells[ci] == "y"
					t.Run(req.String()+"/"+resp.String(), func(t *testing.T) {
						pdp := newFakePDP(t)
						cfg := testConfig(pdp)
						cfg.ExtProcResponseGovernance = tc.governance
						conn := startServer(t, cfg)
						stream := openExtProcStream(t, conn)

						// end_of_stream=false: the headers phase returns without
						// a decide call, isolating the mode gate from policy.
						got := roundTrip(t, stream, withModes(requestHeadersMsg(false), req, resp))
						im := got.GetImmediateResponse()

						if wantAccept && im != nil {
							t.Fatalf("request=%s response=%s must be ACCEPTED, got rejection: %s",
								req, resp, im.GetBody())
						}
						if !wantAccept && im == nil {
							t.Fatalf("request=%s response=%s must be REJECTED fail-closed, got %+v",
								req, resp, got)
						}
						if !wantAccept && im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
							t.Fatalf("request=%s response=%s: rejection should be 503, got %v",
								req, resp, im.GetStatus().GetCode())
						}
					})
				}
			}
		})
	}
}

// TestExtProcNoneResponseRejectionNamesTheOptIn pins the diagnosability of the
// one rejection an operator is actually expected to hit: they configured a
// streaming leg and have not opted in yet. An error that does not name the
// variable turns a 30-second fix into a support ticket.
func TestExtProcNoneResponseRejectionNamesTheOptIn(t *testing.T) {
	pdp := newFakePDP(t)
	conn := startServer(t, testConfig(pdp))
	stream := openExtProcStream(t, conn)

	got := roundTrip(t, stream, withModes(requestHeadersMsg(false),
		extprocfilterv3.ProcessingMode_BUFFERED, extprocfilterv3.ProcessingMode_NONE))
	im := got.GetImmediateResponse()
	if im == nil {
		t.Fatalf("responseBodyMode: none must be rejected without the opt-in, got %+v", got)
	}
	body := string(im.GetBody())
	if !strings.Contains(body, "AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE") || !strings.Contains(body, "off") {
		t.Fatalf("rejection must name the env var and its opt-in value, got: %s", body)
	}
}

// TestExtProcNoneResponseWasSilentlyAcceptedBefore2959 is a REGRESSION pin on a
// deliberate behavior change, not a new feature.
//
// Before #2959 the mode gate only rejected STREAMED/FULL_DUPLEX_STREAMED, so
// responseBodyMode: none sailed through and the gateway simply never sent a
// response body — response governance was off, silently, from gateway config
// alone. That is the hole the opt-in closes, and closing it BREAKS any
// deployment already running none: it now needs the env var. This test exists
// so that tightening can never be quietly reverted to "accept and hope".
func TestExtProcNoneResponseWasSilentlyAcceptedBefore2959(t *testing.T) {
	pdp := newFakePDP(t)
	conn := startServer(t, testConfig(pdp)) // default posture, no opt-in
	stream := openExtProcStream(t, conn)

	got := roundTrip(t, stream, withModes(requestHeadersMsg(false),
		extprocfilterv3.ProcessingMode_BUFFERED, extprocfilterv3.ProcessingMode_NONE))
	if got.GetImmediateResponse() == nil {
		t.Fatal("responseBodyMode: none must NOT be accepted by default — before #2959 it was, which let a gateway-config edit alone drop response governance with no adapter-side consent")
	}
}

// TestExtProcAbsentProtocolConfigStaysGoverned covers the compatibility trap in
// the wire format: an all-zero ProtocolConfiguration reads as NONE/NONE, and a
// gateway that sends no ProtocolConfiguration at all is INDISTINGUISHABLE from
// one advertising NONE. Treating absence as an ungoverned advertisement would
// silently disable the response plane for every gateway too old to send the
// field — so absence must keep the pre-#2959 governed contract.
func TestExtProcAbsentProtocolConfigStaysGoverned(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := streamingConfig(pdp) // even WITH the opt-in set
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false)) // no ProtocolConfig at all
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	roundTrip(t, stream, responseHeadersMsg())
	resp := roundTrip(t, stream, responseBodyMsg(`{"choices":[]}`, true))

	if resp.GetResponseBody() == nil {
		t.Fatalf("a gateway that sends no ProtocolConfiguration must keep the governed path, got %+v", resp)
	}
	if pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckOutput }) == nil {
		t.Fatal("response governance was skipped for a gateway that never advertised a mode — absence must not be read as responseBodyMode: none")
	}
}

// TestExtProcInvalidModeEnforcedOnEveryPhase pins the R3 round-1 finding: a
// leg configured requestHeaderMode: skip + requestBodyMode: none delivers
// ResponseHeaders as the FIRST message of the stream (carrying the
// ProtocolConfiguration), and the request phases never run. If any phase
// returned an unconditional CONTINUE, that invalid-mode leg would complete
// with no governance and no rejection anywhere — so every phase must consult
// invalidMode, not just the request ones.
func TestExtProcInvalidModeEnforcedOnEveryPhase(t *testing.T) {
	sendResponseHeadersFirst := func(t *testing.T, stream extprocv3.ExternalProcessor_ProcessClient) *extprocv3.ProcessingResponse {
		t.Helper()
		msg := responseHeadersMsg()
		msg.ProtocolConfig = &extprocv3.ProtocolConfiguration{
			RequestBodyMode:  extprocfilterv3.ProcessingMode_NONE, // invalid: request must be BUFFERED
			ResponseBodyMode: extprocfilterv3.ProcessingMode_NONE,
		}
		return roundTrip(t, stream, msg)
	}

	t.Run("response headers as the first (and only) enforceable phase", func(t *testing.T) {
		pdp := newFakePDP(t)
		conn := startServer(t, streamingConfig(pdp)) // even WITH the opt-in
		stream := openExtProcStream(t, conn)

		resp := sendResponseHeadersFirst(t, stream)
		im := resp.GetImmediateResponse()
		if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
			t.Fatalf("an invalid-mode leg whose only phase is ResponseHeaders must be rejected there, got %+v", resp)
		}
	})

	t.Run("trailers phases also enforce", func(t *testing.T) {
		pdp := newFakePDP(t)
		conn := startServer(t, streamingConfig(pdp))
		stream := openExtProcStream(t, conn)

		sendResponseHeadersFirst(t, stream)
		resp := roundTrip(t, stream, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseTrailers{
				ResponseTrailers: &extprocv3.HttpTrailers{},
			},
		})
		if resp.GetImmediateResponse() == nil {
			t.Fatalf("trailers on an invalid-mode leg must be rejected, got %+v", resp)
		}
	})
}

// TestExtProcPromisedRequestBodyNeverDelivered pins the R3 round-2 MED-1
// symmetric contradiction guard: request headers advertise a body
// (end_of_stream=false), the decision defers to it — and the gateway then
// jumps straight to the response phases without ever sending it. The request
// reached the upstream UNDECIDED; on an opted-in NONE leg the stream would
// otherwise complete with ZERO governed phases. Mirror image of
// TestExtProcResponseBodyOnUngovernedLegFailsClosed.
func TestExtProcPromisedRequestBodyNeverDelivered(t *testing.T) {
	openWithPromise := func(t *testing.T, cfg Config, respMode extprocfilterv3.ProcessingMode_BodySendMode) extprocv3.ExternalProcessor_ProcessClient {
		t.Helper()
		conn := startServer(t, cfg)
		stream := openExtProcStream(t, conn)
		roundTrip(t, stream, withModes(requestHeadersMsg(false), // promises a body
			extprocfilterv3.ProcessingMode_BUFFERED, respMode))
		return stream
	}

	t.Run("streaming (NONE) leg: response headers rejected", func(t *testing.T) {
		pdp := newFakePDP(t)
		stream := openWithPromise(t, streamingConfig(pdp), extprocfilterv3.ProcessingMode_NONE)

		resp := roundTrip(t, stream, responseHeadersMsg()) // body never sent
		im := resp.GetImmediateResponse()
		if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
			t.Fatalf("a promised-but-undelivered request body must fail the response phases closed, got %+v", resp)
		}
		if pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide }) != nil {
			t.Fatal("no decide should have run — the point is the request went upstream undecided")
		}
	})

	t.Run("governed (BUFFERED) leg: response body rejected too", func(t *testing.T) {
		pdp := newFakePDP(t)
		stream := openWithPromise(t, testConfig(pdp), extprocfilterv3.ProcessingMode_BUFFERED)

		roundTrip(t, stream, responseHeadersMsg())
		resp := roundTrip(t, stream, responseBodyMsg(`{"choices":[]}`, true))
		im := resp.GetImmediateResponse()
		if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
			t.Fatalf("the guard must hold on a governed leg as well — the request still went upstream undecided, got %+v", resp)
		}
		if pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckOutput }) != nil {
			t.Fatal("the contradicting response must be rejected without an engine call")
		}
	})

	t.Run("discharged promise is not a false positive", func(t *testing.T) {
		// The normal conversation: promise, deliver, respond — must continue.
		pdp := newFakePDP(t)
		conn := startServer(t, streamingConfig(pdp))
		stream := openExtProcStream(t, conn)

		roundTrip(t, stream, withModes(requestHeadersMsg(false),
			extprocfilterv3.ProcessingMode_BUFFERED, extprocfilterv3.ProcessingMode_NONE))
		roundTrip(t, stream, requestBodyMsg(openAIBody, true))
		resp := roundTrip(t, stream, responseHeadersMsg())
		if resp.GetResponseHeaders() == nil {
			t.Fatalf("a discharged promise must not trip the guard, got %+v", resp)
		}
	})

	t.Run("bodyless request never promises", func(t *testing.T) {
		// end_of_stream=true headers are decided immediately — no promise, so
		// the response phases proceed.
		pdp := newFakePDP(t)
		conn := startServer(t, streamingConfig(pdp))
		stream := openExtProcStream(t, conn)
		roundTrip(t, stream, withModes(requestHeadersMsg(true),
			extprocfilterv3.ProcessingMode_BUFFERED, extprocfilterv3.ProcessingMode_NONE))
		resp := roundTrip(t, stream, responseHeadersMsg())
		if resp.GetResponseHeaders() == nil {
			t.Fatalf("a bodyless (end_of_stream) request makes no promise; response phases must continue, got %+v", resp)
		}
	})
}

// --- the streaming leg ------------------------------------------------------

// TestExtProcStreamingLegRedactsRequestAndSkipsResponseGovernance is the
// capability this issue exists for: the prompt is engine-redacted before it is
// forwarded, and the response plane makes no engine call at all.
func TestExtProcStreamingLegRedactsRequestAndSkipsResponseGovernance(t *testing.T) {
	pdp := newFakePDP(t)
	redacted := `{"model":"gpt-x","messages":[{"role":"user","content":"NIK [REDACTED]"}]}`
	pdp.setDecideRedactionObligation(redacted)

	stream, resp := openStreamingLeg(t, streamingConfig(pdp), openAIBody)

	// Request plane: engine bytes replace the forwarded body.
	common := resp.GetRequestBody().GetResponse()
	if common.GetStatus() != extprocv3.CommonResponse_CONTINUE_AND_REPLACE {
		t.Fatalf("streaming leg must still replace the request body with engine-redacted bytes, got status %v", common.GetStatus())
	}
	if got := string(common.GetBodyMutation().GetBody()); got != redacted {
		t.Fatalf("forwarded body = %q, want the engine's redacted bytes %q", got, redacted)
	}

	// Response plane: the gateway sends nothing, and we must call nothing.
	roundTrip(t, stream, responseHeadersMsg())
	if out := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckOutput }); out != nil {
		t.Fatalf("an ungoverned-response leg must make ZERO engine calls on the response plane; check-output was invoked with %v", out)
	}
}

// TestExtProcStreamingLegResponseHeadersContinueImmediately guards the SSE
// latency property: the response-headers phase must return a plain continue,
// with no engine round-trip standing between the provider's first byte and the
// client.
func TestExtProcStreamingLegResponseHeadersContinueImmediately(t *testing.T) {
	pdp := newFakePDP(t)
	stream, _ := openStreamingLeg(t, streamingConfig(pdp), openAIBody)

	resp := roundTrip(t, stream, responseHeadersMsg())
	if resp.GetResponseHeaders() == nil {
		t.Fatalf("response headers must continue immediately on a streaming leg, got %+v", resp)
	}
	if resp.GetImmediateResponse() != nil {
		t.Fatalf("response headers must not be blocked on a streaming leg: %s", resp.GetImmediateResponse().GetBody())
	}
}

// TestExtProcStreamingLegRequestPlaneUnchanged proves the request plane behaves
// IDENTICALLY on an ungoverned-response leg. The opt-in buys off the response
// plane and nothing else; if it also softened deny or fail-closed, the leg
// would be a governance bypass wearing a streaming costume.
func TestExtProcStreamingLegRequestPlaneUnchanged(t *testing.T) {
	t.Run("deny still blocks pre-stream", func(t *testing.T) {
		pdp := newFakePDP(t)
		pdp.setDecideVerdict("deny", "sql injection")
		_, resp := openStreamingLeg(t, streamingConfig(pdp), openAIBody)

		im := resp.GetImmediateResponse()
		if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
			t.Fatalf("deny must still block on a streaming leg, got %+v", resp)
		}
	})

	t.Run("PDP down still fails closed", func(t *testing.T) {
		pdp := newFakePDP(t)
		pdp.srv.Close() // PDP unreachable
		_, resp := openStreamingLeg(t, streamingConfig(pdp), openAIBody)

		im := resp.GetImmediateResponse()
		if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
			t.Fatalf("PDP-down must still fail closed on a streaming leg, got %+v", resp)
		}
	})

	t.Run("fail-open still forwards", func(t *testing.T) {
		pdp := newFakePDP(t)
		pdp.srv.Close()
		cfg := streamingConfig(pdp)
		cfg.FailMode = FailModeOpen
		_, resp := openStreamingLeg(t, cfg, openAIBody)

		if resp.GetRequestBody() == nil {
			t.Fatalf("fail-open must forward on a streaming leg, got %+v", resp)
		}
	})

	t.Run("oversize body still fails closed", func(t *testing.T) {
		pdp := newFakePDP(t)
		cfg := streamingConfig(pdp)
		cfg.MaxBodyBytes = 16
		_, resp := openStreamingLeg(t, cfg, strings.Repeat("x", 64))

		im := resp.GetImmediateResponse()
		if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_PayloadTooLarge {
			t.Fatalf("oversize body must still fail closed on a streaming leg, got %+v", resp)
		}
	})
}

// TestExtProcStreamingLegPartialRequestChunkRejected is the partial-chunk
// interplay the mode gate must NOT paper over. requestBodyMode: buffered was
// advertised and accepted, so the gate is satisfied — but if the gateway then
// delivers the body in pieces anyway, deciding on the first piece would forward
// unscanned bytes. The end_of_stream guard is what catches an advertisement
// that turns out to be a lie.
func TestExtProcStreamingLegPartialRequestChunkRejected(t *testing.T) {
	pdp := newFakePDP(t)
	conn := startServer(t, streamingConfig(pdp))
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, withModes(requestHeadersMsg(false),
		extprocfilterv3.ProcessingMode_BUFFERED, extprocfilterv3.ProcessingMode_NONE))
	resp := roundTrip(t, stream, requestBodyMsg(`{"partial":`, false)) // end_of_stream=false

	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("a partial request chunk must fail closed even on an accepted streaming leg, got %+v", resp)
	}
	if pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide }) != nil {
		t.Fatal("a partial request chunk must be rejected BEFORE any decide call — deciding on a fragment forwards unscanned bytes")
	}
}

// TestExtProcResponseBodyOnUngovernedLegFailsClosed covers the gateway that
// contradicts itself: it advertised responseBodyMode: none and then sent a
// response body. Unreachable with a conforming agentgateway (its body pump is
// gated on the same mode), but the advertisement is the ONLY evidence the
// opt-in was evaluated against — once it is proven unreliable, we cannot claim
// this response was scanned.
func TestExtProcResponseBodyOnUngovernedLegFailsClosed(t *testing.T) {
	pdp := newFakePDP(t)
	stream, _ := openStreamingLeg(t, streamingConfig(pdp), openAIBody)
	roundTrip(t, stream, responseHeadersMsg())

	resp := roundTrip(t, stream, responseBodyMsg(`{"choices":[]}`, true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("a response body on a leg that advertised none must fail closed, got %+v", resp)
	}
	if pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckOutput }) != nil {
		t.Fatal("the contradicting body must be rejected without an engine call")
	}
}

// --- capability declaration, per call path ---------------------------------

// TestExtProcStreamingLegAdvertisesBodyCapability asserts the declaration
// DIRECTLY (#2958 contract), not via a redaction outcome: an outcome-based
// check passes even when the capability is wrong, as long as the fake PDP
// happens to redact anyway.
func TestExtProcStreamingLegAdvertisesBodyCapability(t *testing.T) {
	pdp := newFakePDP(t)
	openStreamingLeg(t, streamingConfig(pdp), openAIBody)

	got := pdp.lastDecideCapabilities()
	if len(got) != 1 || got[0] != "request_body_redaction" {
		t.Fatalf("capabilities = %v, want exactly [request_body_redaction] — the streaming leg's request-BODY path can still mask, and under-declaring would make the PDP withhold a redaction this seam can perform, silently degrading the leg to the org fallback posture", got)
	}
}

// TestExtProcStreamingLegBodylessAdvertisesHeadersOnly pins the OTHER call path
// on the same leg. Capability is per call path, not per seam or per leg: a
// bodyless request here is still headers-only, and it must advertise a
// non-empty set, because fulfillment_capabilities is omitempty and an empty
// slice serializes away into "legacy caller".
func TestExtProcStreamingLegBodylessAdvertisesHeadersOnly(t *testing.T) {
	pdp := newFakePDP(t)
	conn := startServer(t, streamingConfig(pdp))
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, withModes(requestHeadersMsg(true), // end_of_stream => bodyless
		extprocfilterv3.ProcessingMode_BUFFERED, extprocfilterv3.ProcessingMode_NONE))

	got := pdp.lastDecideCapabilities()
	if len(got) != 1 || got[0] != "request_header_mutation" {
		t.Fatalf("capabilities = %v, want exactly [request_header_mutation]: the bodyless path cannot rewrite :path/:method even on a streaming leg, and it must still advertise SOMETHING — an empty set is omitempty'd away and read as a legacy caller", got)
	}
}

// --- config surface ---------------------------------------------------------

func TestExtProcResponseGovernanceConfig(t *testing.T) {
	t.Run("env default keeps response governance", func(t *testing.T) {
		t.Setenv("AXONFLOW_ENDPOINT", "http://pdp:8080")
		cfg := ConfigFromEnv()
		if cfg.ExtProcResponseGovernance != ExtProcResponseGovernanceBuffered {
			t.Fatalf("default = %q, want %q", cfg.ExtProcResponseGovernance, ExtProcResponseGovernanceBuffered)
		}
		if cfg.responseGovernanceOff() {
			t.Fatal("the default posture must govern responses")
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("env defaults must validate: %v", err)
		}
	})

	t.Run("opt-in is read from the environment", func(t *testing.T) {
		t.Setenv("AXONFLOW_ENDPOINT", "http://pdp:8080")
		t.Setenv("AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE", "off")
		cfg := ConfigFromEnv()
		if !cfg.responseGovernanceOff() {
			t.Fatalf("AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE=off must opt in, got %q", cfg.ExtProcResponseGovernance)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("opt-in must validate: %v", err)
		}
	})

	t.Run("zero value resolves to the governed posture", func(t *testing.T) {
		// Only reachable from a Config literal; it must land on the SAFE side
		// so a caller that never heard of this field keeps response governance.
		var cfg Config
		if cfg.responseGovernanceOff() {
			t.Fatal("the zero value must NOT disable response governance")
		}
	})

	t.Run("surrounding whitespace is trimmed, case is not folded", func(t *testing.T) {
		// envOr trims every variable this adapter reads (FailMode,
		// DefaultStage, ...), so " off " must behave like "off" — a trailing
		// space is a YAML/shell artifact, and the operator's intent is not in
		// doubt. Case is a different matter: "OFF" is not obviously the same
		// keystroke, so it refuses to boot below rather than being guessed at.
		t.Setenv("AXONFLOW_ENDPOINT", "http://pdp:8080")
		t.Setenv("AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE", " off ")
		cfg := ConfigFromEnv()
		if !cfg.responseGovernanceOff() || cfg.Validate() != nil {
			t.Fatalf("\" off \" must trim to the opt-in like every other env var here, got %q (validate: %v)",
				cfg.ExtProcResponseGovernance, cfg.Validate())
		}
	})

	t.Run("unrecognised values refuse to boot", func(t *testing.T) {
		// Exact-string, no case folding, no truthiness guessing: refusing to
		// boot is safe precisely BECAUSE the default is the governed posture,
		// so a typo stops the process instead of silently picking a side.
		for _, v := range []string{"OFF", "Off", "none", "true", "false", "0", "disabled"} {
			t.Run(v, func(t *testing.T) {
				t.Setenv("AXONFLOW_ENDPOINT", "http://pdp:8080")
				t.Setenv("AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE", v)
				cfg := ConfigFromEnv()
				if cfg.responseGovernanceOff() {
					t.Fatalf("%q must never be read as the opt-in", v)
				}
				if err := cfg.Validate(); err == nil {
					t.Fatalf("%q must fail Validate rather than silently resolving to a posture", v)
				}
			})
		}
	})
}
