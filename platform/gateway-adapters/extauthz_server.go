// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"encoding/json"
	"log"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	"axonflow/platform/shared/pep"
)

// stageContextExtension is the ext_authz/ext_proc context key a gateway
// config can set (extAuthz.protocol.grpc.context: {axonflow-stage: tool}) to
// override the adapter's default decide stage per route.
const stageContextExtension = "axonflow-stage"

// ExtAuthzServer implements envoy.service.auth.v3.Authorization over
// POST /api/v1/decide: allow/deny plus header mutation.
//
// ext_authz is a HEADERS-ONLY seam — it cannot rewrite bodies, so it can never
// discharge a request-phase redact_pii obligation. It declares that up front
// (#2958): every Decide call advertises the headers-only capability set, and a
// >=9.11.0 PDP therefore does not emit an obligation this seam cannot fulfill.
// What happens instead to content that WOULD have been redacted is a policy
// question the PDP owns — it applies the org's obligation-fallback posture
// (log: allow + audit the suppressed redaction; block: deny) — so this adapter
// simply enforces the verdict it is handed.
//
// It used to answer that question locally, converting the PDP's `allow` into a
// 403 whenever the verdict carried an obligation it could not fulfill. That was
// a policy decision made in the PEP — the one thing doc.go says this package
// never does — and it took a design partner's LLM chat offline for every prompt
// containing PII. The only local block left is ObligationBackstop, which cannot
// fire against a >=9.11.0 PDP; see its doc.
type ExtAuthzServer struct {
	authv3.UnimplementedAuthorizationServer
	pdp *PDP
	cfg Config
}

// NewExtAuthzServer builds the ext_authz adapter.
func NewExtAuthzServer(pdp *PDP, cfg Config) *ExtAuthzServer {
	return &ExtAuthzServer{pdp: pdp, cfg: cfg}
}

// Check performs the authorization check for one HTTP request, and counts the
// outcome.
//
// THE COUNTING WRAPS THE WHOLE FUNCTION AND CLASSIFIES THE RESPONSE, rather
// than incrementing a counter at each `return`. There are six return paths
// today and the number grows; a counter per branch is a guard at the callers,
// which is the shape that silently stops covering the branch somebody adds
// next. Classifying what the seam ACTUALLY ANSWERED covers every path,
// including future ones, by construction.
func (s *ExtAuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	resp, err := s.check(ctx, req)
	recordOutcome(SurfaceExtAuthz, classifyExtAuthzOutcome(resp, err))
	return resp, err
}

// classifyExtAuthzOutcome maps what the seam answered onto the closed outcome
// set.
//
// The `deny` / `error` split is the operationally load-bearing one, and it is
// derivable from the response because this adapter already encodes it in the
// status it returns:
//
//   - a gRPC-level error       -> error (the seam itself failed)
//   - Status OK                -> allow
//   - 503 ServiceUnavailable   -> error. This is the fail-CLOSED block when the
//     PDP could not be reached. It blocks the caller, but it is NOT a policy
//     result, and pooling it with `deny` would make a PDP outage read as a
//     policy tightening on exactly the graph an operator pages from.
//   - 500 InternalServerError  -> error. A misconfigured leg (an invalid
//     axonflow-stage), which is likewise not a verdict.
//   - 413 PayloadTooLarge      -> error. A body too large for this adapter to
//     scan. Raising MaxBodyBytes is what fixes it, not editing a policy. This
//     seam counted it as `deny` until #3668's R3, disagreeing with the other
//     two seams about the same condition.
//   - anything else            -> deny, a real refusal from the engine.
//
// The switch itself lives in blockOutcomeForStatus, shared with ext_proc, so
// the two cannot drift apart again.
func classifyExtAuthzOutcome(resp *authv3.CheckResponse, err error) string {
	if err != nil || resp == nil {
		return MetricOutcomeError
	}
	if resp.GetStatus().GetCode() == int32(codes.OK) {
		return MetricOutcomeAllow
	}
	return blockOutcomeForStatus(resp.GetDeniedResponse().GetStatus().GetCode())
}

func (s *ExtAuthzServer) check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpReq.GetHeaders()
	ident := identityFromMap(headers)

	stage := s.cfg.DefaultStage
	if v, ok := req.GetAttributes().GetContextExtensions()[stageContextExtension]; ok {
		stage = v
	}
	if !isValidStage(stage) {
		// A misconfigured stage must not silently degrade to a default —
		// deny loudly so the gateway config gets fixed.
		return denyResponse(typev3.StatusCode_InternalServerError,
			"invalid axonflow-stage context extension: "+stage, nil), nil
	}

	body := requestBodyBytes(httpReq)
	if len(body) > s.cfg.MaxBodyBytes {
		return denyResponse(typev3.StatusCode_PayloadTooLarge,
			"request body exceeds the governable size bound (fail-closed)", nil), nil
	}
	model, query := extractLLMQuery(body)
	if query == "" {
		// Bodyless (or unconfigured-body) requests are gated on the request
		// line — decide still sees a meaningful, bounded query.
		query = httpReq.GetMethod() + " " + httpReq.GetPath()
	}

	decision, err := s.pdp.Decide(ctx, pep.DecideRequest{
		Stage:          stage,
		CallerIdentity: pep.CallerIdentity{GatewayID: s.cfg.GatewayID},
		// Same string as before #3717, now from the declared vocabulary — see
		// pep.TargetTypeHTTP.
		Target:    pep.Target{Type: pep.TargetTypeHTTP, Model: model},
		Query:     query,
		UserToken: ident.Bearer,
		Context: map[string]interface{}{
			"http_method": httpReq.GetMethod(),
			"http_path":   httpReq.GetPath(),
			"http_host":   httpReq.GetHost(),
		},
	}, ident.Traceparent)
	if err != nil {
		outcome := s.pdp.ClassifyDecideErr(err)
		if outcome.Kind == OutcomeFailOpen {
			log.Printf("[gateway-adapters] ext_authz fail-open allow (path=%s): %s", httpReq.GetPath(), outcome.Reason)
			return okResponse(nil), nil
		}
		return denyResponse(typev3.StatusCode_ServiceUnavailable,
			"policy decision unavailable (fail-closed): "+outcome.Reason, nil), nil
	}

	switch decision.Verdict {
	case pep.VerdictAllow:
		if s.pdp.ObligationBackstop(decision) {
			// UNREACHABLE against a >=9.11.0 PDP: this seam advertised that it
			// cannot fulfill a request-body redaction, so a conforming PDP would
			// have suppressed the obligation and applied the org's fallback
			// posture. Reaching here means the PDP ignored the advertisement —
			// in practice a platform older than the adapter. Block: we hold
			// content a policy wanted masked and cannot mask it (see
			// ObligationBackstop for why posture does not apply).
			log.Printf("[gateway-adapters] ERROR: PDP returned a request-redaction obligation to the headers-only ext_authz seam despite advertising %v — this seam cannot fulfill it, blocking (decision_id=%s, path=%s). Cause: the AxonFlow platform predates 9.11.0 and ignores fulfillment_capabilities; upgrade the platform and the adapter together.",
				s.pdp.SeamHeadersOnly().Fulfillment, decision.DecisionID, httpReq.GetPath())
			return denyResponse(typev3.StatusCode_Forbidden,
				"policy requires redacting this request body, which this gateway seam cannot perform (AxonFlow platform/adapter version mismatch)", decision), nil
		}
		return okResponse(decision), nil
	default: // deny, needs_approval, anything unrecognized
		return denyResponse(typev3.StatusCode_Forbidden, firstReason(decision), decision), nil
	}
}

// requestBodyBytes returns the buffered request body when the gateway was
// configured with includeRequestBody (raw_body wins under pack_as_bytes).
func requestBodyBytes(httpReq *authv3.AttributeContext_HttpRequest) []byte {
	if raw := httpReq.GetRawBody(); len(raw) > 0 {
		return raw
	}
	return []byte(httpReq.GetBody())
}

// okResponse allows the request, stamping the decision identifiers onto the
// upstream request headers and exposing them as dynamic metadata (CEL
// `extauthz.*`).
func okResponse(d *pep.DecideResponse) *authv3.CheckResponse {
	ok := &authv3.OkHttpResponse{}
	if d != nil {
		ok.Headers = []*corev3.HeaderValueOption{
			overwriteHeader("x-axonflow-decision-id", d.DecisionID),
			overwriteHeader("x-axonflow-trace-id", d.TraceID),
		}
	}
	return &authv3.CheckResponse{
		Status:          &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse:    &authv3.CheckResponse_OkResponse{OkResponse: ok},
		DynamicMetadata: decisionStruct(d),
	}
}

// denyResponse blocks the request with an explicit direct response carrying
// the decision context — the deny body always names the decision_id so a
// blocked caller can quote it.
func denyResponse(status typev3.StatusCode, reason string, d *pep.DecideResponse) *authv3.CheckResponse {
	payload := map[string]interface{}{
		"error":  reason,
		"source": "axonflow",
	}
	if d != nil {
		payload["verdict"] = d.Verdict
		payload["decision_id"] = d.DecisionID
		payload["trace_id"] = d.TraceID
		if len(d.Reasons) > 0 {
			payload["reasons"] = d.Reasons
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"error":"blocked by policy","source":"axonflow"}`)
	}

	denied := &authv3.DeniedHttpResponse{
		Status: &typev3.HttpStatus{Code: status},
		Headers: []*corev3.HeaderValueOption{
			overwriteHeader("content-type", "application/json"),
		},
		Body: string(body),
	}
	if d != nil {
		denied.Headers = append(denied.Headers,
			overwriteHeader("x-axonflow-decision-id", d.DecisionID))
	}
	return &authv3.CheckResponse{
		Status:          &rpcstatus.Status{Code: int32(codes.PermissionDenied), Message: reason},
		HttpResponse:    &authv3.CheckResponse_DeniedResponse{DeniedResponse: denied},
		DynamicMetadata: decisionStruct(d),
	}
}

// overwriteHeader builds a set-or-overwrite header option.
func overwriteHeader(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: key, Value: value},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

// decisionStruct exposes the decision as dynamic metadata.
func decisionStruct(d *pep.DecideResponse) *structpb.Struct {
	if d == nil {
		return nil
	}
	md, err := structpb.NewStruct(map[string]interface{}{
		"axonflow_decision_id": d.DecisionID,
		"axonflow_trace_id":    d.TraceID,
		"axonflow_verdict":     d.Verdict,
	})
	if err != nil {
		return nil
	}
	return md
}

// extractLLMQuery pulls the policy-relevant query out of an OpenAI-shaped
// chat-completions body: the LAST user message with plain-string content,
// plus the model. Non-conforming bodies fall back to the whole body as the
// query (bounded upstream by MaxBodyBytes). Extraction feeds the DECIDE call
// only — redaction fulfillment always runs against the full payload.
func extractLLMQuery(body []byte) (model, query string) {
	if len(body) == 0 {
		return "", ""
	}
	var payload struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Messages) == 0 {
		return "", string(body)
	}
	for i := len(payload.Messages) - 1; i >= 0; i-- {
		m := payload.Messages[i]
		if m.Role != "user" {
			continue
		}
		var content string
		if err := json.Unmarshal(m.Content, &content); err == nil && content != "" {
			return payload.Model, content
		}
		// Structured (multi-part) content: gate on its serialized form.
		return payload.Model, string(m.Content)
	}
	return payload.Model, string(body)
}
