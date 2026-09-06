// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"axonflow/platform/shared/pep"
)

// ExtProcServer implements envoy.service.ext_proc.v3.ExternalProcessor:
// request+response BODY governance for the HTTP/LLM leg — the seam that can
// actually fulfill body-redaction obligations.
//
// Supported processing modes (header modes SEND; body modes are validated PER
// DIRECTION — see noteProtocolConfig for the accept matrix):
//
//   - requestBodyMode MUST be BUFFERED. Anything else gives us a fragment of
//     the payload, or none of it, and a verdict on unseen bytes is not a
//     verdict.
//   - responseBodyMode BUFFERED governs the response (the default posture).
//   - responseBodyMode NONE runs the leg with the response UNGOVERNED, and is
//     accepted only under AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE=off. This is
//     the streaming-safe seam (#2959): the prompt is decided and engine-
//     redacted before it reaches the provider, while the completion streams
//     back untouched — the only shape that works for SSE, since buffering a
//     response to scan it is what destroys the stream.
//   - BUFFERED_PARTIAL / STREAMED / FULL_DUPLEX_STREAMED are rejected
//     FAIL-CLOSED in both directions.
//
// Request plane: decide (+ engine redaction fulfillment) on the buffered
// request body; posture applies only to PDP-unreachable. It is IDENTICAL on a
// governed and an ungoverned-response leg — deny still blocks before the
// provider is called, fail-mode and the size bound behave the same. Response
// plane: engine response-governance on the buffered response body,
// unconditionally fail-closed — but a leg that advertised NONE has no response
// plane at all, which is why enabling that is an adapter-side decision and not
// a gateway-side one.
type ExtProcServer struct {
	extprocv3.UnimplementedExternalProcessorServer
	pdp *PDP
	cfg Config
}

// NewExtProcServer builds the ext_proc adapter.
func NewExtProcServer(pdp *PDP, cfg Config) *ExtProcServer {
	return &ExtProcServer{pdp: pdp, cfg: cfg}
}

// extProcStream is the per-stream (per-HTTP-request) state.
type extProcStream struct {
	ident       Identity
	method      string
	path        string
	stage       string
	invalidMode string // non-empty => reject every governed phase with this reason
	reqBody     bytes.Buffer
	respBody    bytes.Buffer

	// reqBodyPromised records that request headers arrived with
	// end_of_stream=false — the gateway told us a request body follows, and
	// the decision was deferred to it. reqGated records that the request
	// plane actually ran (the bodyless-headers gate, or the request body
	// arriving complete). promised && !gated at a response phase means the
	// gateway skipped the body it advertised: the request reached the
	// upstream undecided, and the response phases are the mirror image of
	// the response-body-on-a-NONE-leg contradiction below — fail closed.
	reqBodyPromised bool
	reqGated        bool

	// phaseGoverned is the PER-MESSAGE latch the outcome counter reads, set by
	// whichever handler decided this message, and cleared at the top of every
	// loop iteration.
	//
	// It exists because counting used to happen in the three on* wrappers,
	// which are the CALLERS — the exact shape recordExtProcPhase's own comment
	// warns against. Four groups of arms in Process build a response inline and
	// never touch a wrapper: the ResponseHeaders, RequestTrailers and
	// ResponseTrailers cases, and the fail-closed `default` for an unknown
	// message type. Every block those arms produce — an unsupported body mode,
	// an undelivered request body, an ungovernable protocol revision — was
	// invisible in axonflow_gateway_adapter_surface_outcomes_total. A seam
	// refusing traffic while its metric says nothing happened is worse than an
	// uninstrumented seam, because the graph looks healthy.
	//
	// A pass-through continue on trailers stays uncounted, which is why this is
	// a latch rather than an unconditional count: it is not a decision, and
	// counting it would inflate `allow` with protocol bookkeeping.
	phaseGoverned bool

	// responseGoverned records whether this leg's response body is scanned.
	// It defaults to TRUE (set in Process, not by the zero value) so that a
	// gateway which sends no ProtocolConfiguration — or a code path that
	// forgets to consult one — keeps the response plane rather than losing it
	// by omission. Only an explicit, opted-in NONE advertisement clears it.
	responseGoverned bool

	// postureLogged keeps the once-per-stream ungoverned-leg log line to one
	// line, whichever governed phase reaches it first.
	postureLogged bool
}

// Process handles one bidirectional ext_proc conversation (one HTTP request).
func (s *ExtProcServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	st := &extProcStream{stage: s.cfg.DefaultStage, responseGoverned: true}

	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}

		if pc := msg.GetProtocolConfig(); pc != nil {
			s.noteProtocolConfig(st, pc)
		}
		// Per-route stage override comes ONLY from gateway config (the
		// extProc metadataContext CEL map), never from a client-settable
		// request header — the governed party must not pick its own policy
		// layer.
		if s := stageFromMetadata(msg.GetMetadataContext()); s != "" {
			st.stage = s
		}

		// Cleared per MESSAGE, not per stream: a stream carries many phases and
		// a latch left set by the request-body phase would count the trailers
		// that follow it.
		st.phaseGoverned = false

		var resp *extprocv3.ProcessingResponse
		switch msg.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp = s.onRequestHeaders(ctx, st, msg.GetRequestHeaders())
		case *extprocv3.ProcessingRequest_RequestBody:
			resp = s.onRequestBody(ctx, st, msg.GetRequestBody())
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			// invalidMode is enforced on EVERY phase, this one included. A leg
			// configured requestHeaderMode: skip + requestBodyMode: none makes
			// ResponseHeaders the FIRST — possibly only — enforceable phase of
			// the whole stream; if it returned an unconditional CONTINUE, an
			// invalid-mode leg would sail through with no request governance
			// and no rejection anywhere (R3 round-1 finding).
			if st.invalidMode != "" {
				resp = immediateResponse(typev3.StatusCode_ServiceUnavailable, st.invalidMode, "", "unsupported_body_mode")
				break
			}
			if g := st.undeliveredRequestBody(); g != nil {
				resp = g
				break
			}
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}},
			}}
		case *extprocv3.ProcessingRequest_ResponseBody:
			resp = s.onResponseBody(ctx, st, msg.GetResponseBody())
		case *extprocv3.ProcessingRequest_RequestTrailers:
			if st.invalidMode != "" {
				resp = immediateResponse(typev3.StatusCode_ServiceUnavailable, st.invalidMode, "", "unsupported_body_mode")
				break
			}
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
				RequestTrailers: &extprocv3.TrailersResponse{},
			}}
		case *extprocv3.ProcessingRequest_ResponseTrailers:
			if st.invalidMode != "" {
				resp = immediateResponse(typev3.StatusCode_ServiceUnavailable, st.invalidMode, "", "unsupported_body_mode")
				break
			}
			if g := st.undeliveredRequestBody(); g != nil {
				resp = g
				break
			}
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
				ResponseTrailers: &extprocv3.TrailersResponse{},
			}}
		default:
			// Unknown message type from a newer protocol revision: we cannot
			// govern what we do not understand — fail closed.
			resp = immediateResponse(typev3.StatusCode_ServiceUnavailable,
				"unsupported ext_proc message (fail-closed)", "", "unsupported_message")
		}

		// THE ONE COUNTING SITE for this seam. Every arm above — the three
		// phase handlers and the four inline groups — passes through here
		// exactly once per message, so an arm added later is counted without
		// anyone remembering to instrument it.
		//
		// isImmediate is OR-ed in rather than left to the handlers: a block is a
		// governed operation whoever produced it, and the inline arms that
		// fail closed do not set the latch at all.
		recordExtProcPhase(resp, st.phaseGoverned || isImmediate(resp))

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// noteProtocolConfig applies the PER-DIRECTION body-mode contract (#2959).
// The two directions are judged separately because they fail differently: a
// request we have not seen whole cannot be decided at all, whereas a response
// we are never shown is a survivable — but explicitly opted-into — loss of the
// response plane. OR-ing them (as this did before #2959) made
// buffered-request + ungoverned-response unexpressible, which is exactly the
// combination a streaming (SSE) completion needs.
//
// Accept matrix — the docs table publishes these same rules:
//
//	request \ response | NONE    BUFFERED | BUFFERED_PARTIAL, STREAMED, FULL_DUPLEX
//	BUFFERED           | opt-in  govern   | reject
//	every other mode   | reject  reject   | reject
//
// where opt-in = accepted only under ExtProcResponseGovernanceOff.
//
// pc is sent by the gateway EXACTLY ONCE, on the first message of the stream
// (Envoy contract; agentgateway honors it). A gateway that sends none at all
// keeps the pre-#2959 behavior: both planes govern, and the partial-chunk
// guards below fail closed if that assumption turns out wrong. Absence is
// indistinguishable from an all-zero (NONE) config on the wire, so it CANNOT
// be treated as an ungoverned-response advertisement — that would silently
// disable the response plane for every legacy gateway.
func (s *ExtProcServer) noteProtocolConfig(st *extProcStream, pc *extprocv3.ProtocolConfiguration) {
	req := pc.GetRequestBodyMode()
	resp := pc.GetResponseBodyMode()

	// REQUEST: buffered only. Every other mode either hands us the body in
	// pieces (STREAMED / FULL_DUPLEX_STREAMED / BUFFERED_PARTIAL) or withholds
	// it entirely (NONE) while the request may still carry one — both mean
	// deciding on content we have not seen in full, i.e. forwarding unscanned
	// bytes. Unchanged in spirit from the pre-#2959 gate, now stated per
	// direction.
	if req != extprocfilterv3.ProcessingMode_BUFFERED {
		st.invalidMode = fmt.Sprintf(
			"unsupported ext_proc request body mode %s: AxonFlow decides on the FULL request payload, so this seam requires processingOptions.requestBodyMode: buffered (fail-closed)",
			req)
		return
	}

	switch resp {
	case extprocfilterv3.ProcessingMode_BUFFERED:
		st.responseGoverned = true

	case extprocfilterv3.ProcessingMode_NONE:
		// The gateway is telling us it will never show us the response body.
		// That is the ONLY way to redact a prompt while the completion streams
		// (buffering an SSE response destroys the stream), but it drops the
		// response plane — so it takes an ADAPTER-side opt-in. Without this
		// gate, editing one line of gateway YAML would silently disable
		// response governance, which is the posture doc.go promises is not
		// configurable from outside.
		if !s.cfg.responseGovernanceOff() {
			st.invalidMode = fmt.Sprintf(
				"ext_proc responseBodyMode: none leaves the response body ungoverned, which this adapter does not permit by default; set %s=%s to accept ungoverned-response legs (streaming/SSE completions), or set processingOptions.responseBodyMode: buffered to keep response governance (fail-closed)",
				envExtProcResponseGovernance, ExtProcResponseGovernanceOff)
			return
		}
		st.responseGoverned = false

	default:
		// BUFFERED_PARTIAL / STREAMED / FULL_DUPLEX_STREAMED: the gateway would
		// hand us a fragment of the response and expect a verdict on it.
		// Scanning part of a body and calling it governed is a false claim of
		// coverage, so these stay rejected — a leg that cannot buffer its
		// response should say so honestly with none.
		st.invalidMode = fmt.Sprintf(
			"unsupported ext_proc response body mode %s: this adapter governs a response only when it receives it whole, so responseBodyMode must be buffered — or none, with %s=%s, to run this leg with the response ungoverned (fail-closed)",
			resp, envExtProcResponseGovernance, ExtProcResponseGovernanceOff)
	}
}

// undeliveredRequestBody is the symmetric contradiction guard to the
// response-body-on-a-NONE-leg check in onResponseBody (R3 round-2 MED-1): the
// gateway's request headers advertised "a body follows" (end_of_stream=false),
// the decision was deferred to that body, and the stream has now moved on to
// the response phases without the body ever arriving — so the request reached
// the upstream UNDECIDED. Unreachable with a conforming gateway (a buffered
// request leg always delivers its body message, empty bodies included), and on
// an opted-in NONE leg it is the sequence that would otherwise complete with
// ZERO governed phases. Returns the fail-closed rejection, or nil when the
// promise was discharged (or never made).
func (st *extProcStream) undeliveredRequestBody() *extprocv3.ProcessingResponse {
	if !st.reqBodyPromised || st.reqGated {
		return nil
	}
	return immediateResponse(typev3.StatusCode_ServiceUnavailable,
		"request headers promised a body (end_of_stream=false) that never arrived before the response phases — the request was forwarded undecided, which this adapter cannot vouch for (fail-closed)",
		"", "request_body_undelivered")
}

// logLegPosture records, ONCE per stream, that this leg forwards the upstream
// response without scanning it. An ungoverned response plane is a security
// posture, and a posture nobody can see in the logs is one nobody can audit —
// the startup banner proves the operator opted in, this proves which traffic
// actually took the ungoverned path.
func (st *extProcStream) logLegPosture() {
	if st.responseGoverned || st.postureLogged {
		return
	}
	st.postureLogged = true
	// On a requestHeaderMode: skip leg this fires from the body phase, where
	// :method/:path were never seen — name that state rather than logging a
	// bare "( )" (R3 round-2 LOW-4).
	leg := strings.TrimSpace(st.method + " " + st.path)
	if leg == "" {
		leg = "request line unavailable (headers phase skipped)"
	}
	log.Printf("[gateway-adapters] ext_proc ungoverned-response leg (%s): gateway advertised responseBodyMode=NONE and %s=%s — the request is decided and redacted, the RESPONSE BODY IS NOT SCANNED on this leg",
		leg, envExtProcResponseGovernance, ExtProcResponseGovernanceOff)
}

// onRequestHeaders captures identity/routing context. Bodyless requests
// (end_of_stream) are decided immediately; requests with bodies defer the
// decision to the buffered body.
func (s *ExtProcServer) onRequestHeaders(ctx context.Context, st *extProcStream, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	resp := s.requestHeaders(ctx, st, h)
	// A body-carrying leg's headers phase is a PASS-THROUGH, not a decision:
	// the verdict happens in onRequestBody, where the content is. Counting it
	// would double every allow on the dominant path. It IS counted when it
	// blocked (an immediate response) or when it gated the bodyless request
	// itself (st.reqGated).
	st.phaseGoverned = st.reqGated
	return resp
}

func (s *ExtProcServer) requestHeaders(ctx context.Context, st *extProcStream, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	st.ident = identityFromEnvoyHeaderMap(h.GetHeaders())
	for _, hv := range h.GetHeaders().GetHeaders() {
		switch hv.GetKey() {
		case ":method":
			st.method = headerValueString(hv)
		case ":path":
			st.path = headerValueString(hv)
		}
	}
	if st.invalidMode != "" {
		return immediateResponse(typev3.StatusCode_ServiceUnavailable, st.invalidMode, "", "unsupported_body_mode")
	}
	if !isValidStage(st.stage) {
		return immediateResponse(typev3.StatusCode_InternalServerError,
			"invalid axonflow stage: "+st.stage, "", "invalid_stage")
	}
	st.logLegPosture()

	if !h.GetEndOfStream() {
		// A body follows — the decision happens there, where the content is.
		st.reqBodyPromised = true
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}},
		}}
	}
	st.reqGated = true

	// Bodyless request: gate on the request line.
	//
	// HEADERS-ONLY on this path (#2958): the only content here is :path/:method,
	// which Envoy ext_proc cannot rewrite — so this leg genuinely cannot
	// discharge a request-body redaction, even though the same adapter can on
	// the request-BODY path below. Declaring it accurately is what lets the PDP
	// suppress the obligation and apply the org's fallback posture, instead of
	// handing us a redaction we can only answer with a local 403.
	query := st.method + " " + st.path
	outcome := s.pdp.GateRequest(ctx, s.decideRequest(st, "", query), query, st.ident.Traceparent, s.pdp.SeamHeadersOnly())
	switch outcome.Kind {
	case OutcomeAllow, OutcomeFailOpen:
		if outcome.Kind == OutcomeFailOpen {
			log.Printf("[gateway-adapters] ext_proc fail-open allow (bodyless %s %s): %s", st.method, st.path, outcome.Reason)
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{
				HeaderMutation: extProcDecisionHeaders(outcome.Decision),
			}},
		}}
	case OutcomeAllowRedacted:
		// UNREACHABLE against a >=9.11.0 PDP (#2958): this path advertised
		// headers-only, so a conforming PDP suppresses the request-line
		// redaction and applies the org's obligation-fallback posture — which
		// arrives here as OutcomeAllow (log) or OutcomeDeny (block), never as a
		// redaction we cannot apply. Reaching here means the PDP ignored the
		// advertisement, i.e. a platform older than the adapter.
		//
		// Block: we hold content a policy wanted masked and cannot mask it
		// (ext_proc cannot rewrite :path/:method), and forwarding the original
		// would leak exactly what the obligation exists to prevent. Posture does
		// not apply, for the same reason it does not on the ext_authz backstop.
		log.Printf("[gateway-adapters] ERROR: PDP returned a request-line redaction obligation to the BODYLESS ext_proc path despite advertising %v — this path cannot rewrite :path/:method, blocking (decision_id=%s, %s %s). Cause: the AxonFlow platform predates 9.11.0 and ignores fulfillment_capabilities; upgrade the platform and the adapter together.",
			s.pdp.SeamHeadersOnly().Fulfillment, decisionID(outcome.Decision), st.method, st.path)
		return immediateResponseFull(typev3.StatusCode_Forbidden,
			"policy requires redacting this request, which this gateway seam cannot perform (AxonFlow platform/adapter version mismatch)",
			decisionID(outcome.Decision), traceID(outcome.Decision), "", "redaction_unfulfillable_bodyless")
	case OutcomeDeny:
		return denyImmediate(outcome)
	default:
		return immediateResponse(typev3.StatusCode_ServiceUnavailable,
			"policy decision unavailable (fail-closed): "+outcome.Reason, "", "pdp_unavailable")
	}
}

// onRequestBody buffers the request body and, at end-of-stream, runs the full
// decide -> fulfill -> forward path against it.
func (s *ExtProcServer) onRequestBody(ctx context.Context, st *extProcStream, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	resp := s.requestBody(ctx, st, b)
	// Every path out of this phase either blocks or carries a verdict, so it is
	// always a governed operation.
	st.phaseGoverned = true
	return resp
}

func (s *ExtProcServer) requestBody(ctx context.Context, st *extProcStream, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	if st.invalidMode != "" {
		return immediateResponse(typev3.StatusCode_ServiceUnavailable, st.invalidMode, "", "unsupported_body_mode")
	}
	// Also logged here: a leg configured requestHeaderMode: skip never reaches
	// onRequestHeaders, and the posture of an ungoverned leg must be recorded
	// whichever phase is the first one to run.
	st.logLegPosture()
	st.reqBody.Write(b.GetBody())
	if st.reqBody.Len() > s.cfg.MaxBodyBytes {
		return immediateResponse(typev3.StatusCode_PayloadTooLarge,
			"request body exceeds the governable size bound (fail-closed)", "", "body_too_large")
	}
	if !b.GetEndOfStream() {
		// Buffered modes deliver the body as a single end-of-stream message; a
		// partial chunk means the gateway is streaming, which this adapter
		// cannot govern — fail closed with a configuration pointer.
		return immediateResponse(typev3.StatusCode_ServiceUnavailable,
			"received a partial (streamed) request body; configure processingOptions.requestBodyMode: buffered (fail-closed)", "", "streamed_body")
	}

	// The complete body arrived: the promise is discharged and the request
	// plane runs, whatever the outcome (allow/deny/fail-per-posture all mean
	// governance happened).
	st.reqGated = true

	body := st.reqBody.Bytes()
	model, query := extractLLMQuery(body)
	// Body-capable: this path rewrites the request body it forwards, so it can
	// carry the engine-redacted payload (#2958).
	outcome := s.pdp.GateRequest(ctx, s.decideRequest(st, model, query), string(body), st.ident.Traceparent, s.pdp.SeamBodyCapable())

	switch outcome.Kind {
	case OutcomeAllow:
		return bodyContinue(nil, outcome.Decision)
	case OutcomeAllowRedacted:
		// The engine redacted the full body. If the original was JSON the
		// redacted form must still parse — otherwise the upstream would see a
		// corrupted payload we cannot vouch for; fail closed.
		if json.Valid(body) && !json.Valid([]byte(outcome.RedactedStatement)) {
			return immediateResponse(typev3.StatusCode_Forbidden,
				"engine-redacted request body is not forwardable JSON (fail-closed)",
				decisionID(outcome.Decision), "redaction_unforwardable")
		}
		return bodyContinue([]byte(outcome.RedactedStatement), outcome.Decision)
	case OutcomeDeny:
		return denyImmediate(outcome)
	case OutcomeFailOpen:
		log.Printf("[gateway-adapters] ext_proc fail-open forward (%s %s): %s", st.method, st.path, outcome.Reason)
		return bodyContinue(nil, nil)
	default:
		return immediateResponse(typev3.StatusCode_ServiceUnavailable,
			"policy decision unavailable (fail-closed): "+outcome.Reason, "", "pdp_unavailable")
	}
}

// onResponseBody buffers the response body and, at end-of-stream, runs the
// engine response-governance round-trip. UNCONDITIONALLY fail-closed.
func (s *ExtProcServer) onResponseBody(ctx context.Context, st *extProcStream, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	resp := s.responseBody(ctx, st, b)
	st.phaseGoverned = true
	return resp
}

func (s *ExtProcServer) responseBody(ctx context.Context, st *extProcStream, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	if st.invalidMode != "" {
		return immediateResponse(typev3.StatusCode_ServiceUnavailable, st.invalidMode, "", "unsupported_body_mode")
	}
	// UNREACHABLE against a conforming gateway: responseBodyMode: none means
	// no response body message is ever sent (agentgateway v1.3.1 gates its
	// body pump on `send_body = body_path != None && had_body`). Reaching here
	// means the gateway is not honoring the ProtocolConfiguration it just
	// advertised, so its advertisement — the very thing the opt-in was
	// evaluated against — is unreliable. We cannot claim this response was
	// scanned, and the response plane does not fail open. Blocking a leg the
	// operator opted OUT of governing looks harsh, but the alternative is
	// trusting a gateway that has already contradicted itself.
	if !st.responseGoverned {
		return immediateResponse(typev3.StatusCode_ServiceUnavailable,
			"received a response body on a leg that advertised responseBodyMode: none — the gateway is contradicting its own ProtocolConfiguration, so this response cannot be proven scanned (fail-closed)",
			"", "response_body_on_ungoverned_leg")
	}
	// Same nonconforming-gateway class, opposite direction (R3 round-2 MED-1):
	// a promised request body that never arrived means the request went
	// upstream undecided — govern nothing on its response, reject.
	if g := st.undeliveredRequestBody(); g != nil {
		return g
	}
	st.respBody.Write(b.GetBody())
	if st.respBody.Len() > s.cfg.MaxBodyBytes {
		return immediateResponse(typev3.StatusCode_ServiceUnavailable,
			"response body exceeds the scannable size bound; withholding (fail-closed)", "", "body_too_large")
	}
	if !b.GetEndOfStream() {
		return immediateResponse(typev3.StatusCode_ServiceUnavailable,
			"received a partial (streamed) response body; configure processingOptions.responseBodyMode: buffered (fail-closed)", "", "streamed_body")
	}

	body := st.respBody.Bytes()
	if len(body) == 0 {
		return responseBodyContinue(nil)
	}

	// X-User-Email / X-Session-Id are forwarded ONLY under the explicit
	// TrustIdentityHeaders opt-in: they are client-assertable, and
	// agentgateway runs route header modifiers AFTER the ext_proc callout,
	// so no gateway config can strip a forged value before it reaches us.
	// The bearer token always flows — the PDP validates it independently.
	var userEmail, sessionID string
	if s.cfg.TrustIdentityHeaders {
		userEmail = st.ident.UserEmail
		sessionID = st.ident.SessionID
	}
	out, err := s.pdp.CheckOutput(ctx, pep.CheckOutputRequest{
		Message:   string(body),
		UserToken: st.ident.Bearer,
		UserEmail: userEmail,
		SessionID: sessionID,
	}, st.ident.Traceparent)
	if err != nil {
		if blocked, ok := asOutputBlocked(err); ok {
			return immediateResponse(typev3.StatusCode_Forbidden,
				blockReasonOrDefault(blocked.Reason), blocked.DecisionID, "response_blocked")
		}
		return immediateResponse(typev3.StatusCode_ServiceUnavailable,
			"response governance unavailable; withholding response (fail-closed): "+err.Error(), "", "response_governance_unavailable")
	}
	if !out.Redacted {
		return responseBodyContinue(nil)
	}
	if json.Valid(body) && !json.Valid([]byte(out.RedactedMessage)) {
		return immediateResponse(typev3.StatusCode_Forbidden,
			"engine-redacted response body is not forwardable JSON (fail-closed)", out.DecisionID, "redaction_unforwardable")
	}
	return responseBodyContinue([]byte(out.RedactedMessage))
}

// decideRequest assembles the decide call for this stream.
func (s *ExtProcServer) decideRequest(st *extProcStream, model, query string) pep.DecideRequest {
	return pep.DecideRequest{
		Stage:          st.stage,
		CallerIdentity: pep.CallerIdentity{GatewayID: s.cfg.GatewayID},
		// Same string as before #3717, now taken from the declared vocabulary
		// so the census guard can see it. See pep.TargetTypeHTTP for why this
		// seam is not being moved onto TargetTypeLLM in this change.
		Target:    pep.Target{Type: pep.TargetTypeHTTP, Model: model},
		Query:     query,
		UserToken: st.ident.Bearer,
		Context: map[string]interface{}{
			"http_method": st.method,
			"http_path":   st.path,
		},
	}
}

// --- response constructors ---

// bodyContinue lets the request proceed, optionally replacing the buffered
// body with engine-redacted bytes and stamping the decision headers (header
// mutations in a body response take effect under BUFFERED mode).
func bodyContinue(replacement []byte, d *pep.DecideResponse) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{HeaderMutation: extProcDecisionHeaders(d)}
	if replacement != nil {
		common.Status = extprocv3.CommonResponse_CONTINUE_AND_REPLACE
		common.BodyMutation = &extprocv3.BodyMutation{
			Mutation: &extprocv3.BodyMutation_Body{Body: replacement},
		}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
		RequestBody: &extprocv3.BodyResponse{Response: common},
	}}
}

// responseBodyContinue forwards the response, optionally replacing it with
// engine-redacted bytes.
func responseBodyContinue(replacement []byte) *extprocv3.ProcessingResponse {
	common := &extprocv3.CommonResponse{}
	if replacement != nil {
		common.Status = extprocv3.CommonResponse_CONTINUE_AND_REPLACE
		common.BodyMutation = &extprocv3.BodyMutation{
			Mutation: &extprocv3.BodyMutation_Body{Body: replacement},
		}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
		ResponseBody: &extprocv3.BodyResponse{Response: common},
	}}
}

// denyImmediate turns a PDP deny/needs_approval into a direct 403 carrying
// the decision context.
func denyImmediate(outcome RequestOutcome) *extprocv3.ProcessingResponse {
	verdict := ""
	if outcome.Decision != nil {
		verdict = outcome.Decision.Verdict
	}
	return immediateResponseFull(typev3.StatusCode_Forbidden,
		blockReasonOrDefault(outcome.Reason), decisionID(outcome.Decision),
		traceID(outcome.Decision), verdict, "policy_deny")
}

// immediateResponse builds a locally-generated response that stops the
// filter chain (the ext_proc deny/fail-closed primitive).
// isImmediate reports whether a phase answered with a block rather than letting
// the request continue.
func isImmediate(resp *extprocv3.ProcessingResponse) bool {
	return resp != nil && resp.GetImmediateResponse() != nil
}

// recordExtProcPhase counts one ext_proc phase, when that phase was a GOVERNED
// operation. It is called from ONE place: the bottom of the Process loop, once
// per message.
//
// THE COUNTING CLASSIFIES THE ANSWER, rather than incrementing at each
// `return`. This file has more than a dozen return paths across the three
// phases and the number grows; a counter per branch is a guard at the callers,
// which is the shape that silently stops covering whichever branch somebody
// adds next.
//
// It said that before #3668's R3 and was itself an instance of it: the call
// lived in the three on* phase wrappers, which are callers, and the four groups
// of arms that build a response inline in Process reached none of them. The
// per-message latch (extProcStream.phaseGoverned) is what moved it to one
// site.
//
// The `deny` / `error` split reads the status the phase already chose, which is
// where the adapter encodes the difference:
//
//   - ServiceUnavailable — the PDP was unreachable, the leg advertised a body
//     mode this adapter will not govern, or the gateway contradicted its own
//     ProtocolConfiguration. A block with NO verdict behind it.
//   - InternalServerError — a misconfigured stage. Likewise not a verdict.
//   - PayloadTooLarge — a payload too large to scan. Fail-closed, again with no
//     verdict; counting it as a policy deny would make a body-size
//     misconfiguration look like a policy tightening.
//   - anything else — a real refusal from the engine.
func recordExtProcPhase(resp *extprocv3.ProcessingResponse, governed bool) {
	if !governed {
		return
	}
	recordOutcome(SurfaceExtProc, classifyExtProcOutcome(resp))
}

func classifyExtProcOutcome(resp *extprocv3.ProcessingResponse) string {
	if resp == nil {
		return MetricOutcomeError
	}
	imm := resp.GetImmediateResponse()
	if imm == nil {
		return MetricOutcomeAllow
	}
	return blockOutcomeForStatus(imm.GetStatus().GetCode())
}

func immediateResponse(status typev3.StatusCode, reason, decisionID, details string) *extprocv3.ProcessingResponse {
	return immediateResponseFull(status, reason, decisionID, "", "", details)
}

func immediateResponseFull(status typev3.StatusCode, reason, decisionID, traceID, verdict, details string) *extprocv3.ProcessingResponse {
	payload := map[string]interface{}{
		"error":  reason,
		"source": "axonflow",
	}
	if verdict != "" {
		payload["verdict"] = verdict
	}
	if decisionID != "" {
		payload["decision_id"] = decisionID
	}
	if traceID != "" {
		payload["trace_id"] = traceID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"blocked by policy","source":"axonflow"}`)
	}

	headers := &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
		overwriteHeader("content-type", "application/json"),
	}}
	if decisionID != "" {
		headers.SetHeaders = append(headers.SetHeaders, overwriteHeader("x-axonflow-decision-id", decisionID))
	}

	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status:  &typev3.HttpStatus{Code: status},
			Headers: headers,
			Body:    body,
			Details: details,
		},
	}}
}

// extProcDecisionHeaders stamps decision identifiers onto the upstream
// request.
func extProcDecisionHeaders(d *pep.DecideResponse) *extprocv3.HeaderMutation {
	if d == nil {
		return nil
	}
	return &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
		overwriteHeader("x-axonflow-decision-id", d.DecisionID),
		overwriteHeader("x-axonflow-trace-id", d.TraceID),
	}}
}

// stageFromMetadata reads the trusted per-route stage override from the
// ext_proc metadata_context — populated by the GATEWAY's extProc
// metadataContext CEL config, e.g.
//
//	extProc:
//	  metadataContext:
//	    axonflow: { stage: '"tool"' }
//
// Returns "" when unset.
func stageFromMetadata(md *corev3.Metadata) string {
	axon, ok := md.GetFilterMetadata()["axonflow"]
	if !ok {
		return ""
	}
	return axon.GetFields()["stage"].GetStringValue()
}

func decisionID(d *pep.DecideResponse) string {
	if d == nil {
		return ""
	}
	return d.DecisionID
}

func traceID(d *pep.DecideResponse) string {
	if d == nil {
		return ""
	}
	return d.TraceID
}

func blockReasonOrDefault(reason string) string {
	if reason == "" {
		return "blocked by policy"
	}
	return reason
}
