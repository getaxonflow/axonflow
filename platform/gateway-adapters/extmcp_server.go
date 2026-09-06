// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"google.golang.org/protobuf/types/known/structpb"

	"axonflow/platform/shared/pep"

	agwapi "axonflow/platform/gateway-adapters/agentgateway/api"
)

// ExtMcpServer implements agentgateway.dev.ext_mcp.ExtMcp: MCP-layer gating
// and mutation as a thin translator over the AxonFlow engine.
//
//   - CheckRequest — decide (stage=tool) on the JSON-RPC params; a redact_pii
//     obligation is fulfilled through the engine's request-redaction endpoint
//     and returned as Mutated params (engine bytes, never a local mask).
//   - CheckResponse — the JSON-RPC result goes through the engine's
//     response-governance endpoint; engine-redacted results come back as
//     Mutated. The response plane is unconditionally fail-closed.
//
// The handlers always return a well-formed result message (never a bare gRPC
// error) so the block reason and decision_id reach the MCP client instead of
// being flattened into the gateway's generic failure_mode handling.
type ExtMcpServer struct {
	agwapi.UnimplementedExtMcpServer
	pdp *PDP
	cfg Config
}

// NewExtMcpServer builds the ExtMcp adapter.
func NewExtMcpServer(pdp *PDP, cfg Config) *ExtMcpServer {
	return &ExtMcpServer{pdp: pdp, cfg: cfg}
}

// mcpToolCallParams is the JSON-RPC params shape of tools/call.
type mcpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// CheckRequest gates (and, under a redaction obligation, mutates) an MCP
// request before agentgateway forwards it upstream.
func (s *ExtMcpServer) CheckRequest(ctx context.Context, req *agwapi.McpRequest) (*agwapi.McpRequestResult, error) {
	resp, err := s.checkRequest(ctx, req)
	recordOutcome(SurfaceExtMcp, classifyMcpRequestOutcome(resp, err))
	return resp, err
}

// classifyMcpRequestOutcome maps what this seam answered onto the metric label,
// WRAPPING the whole handler rather than counting at each `return`.
//
// There are seven return paths and the number grows; a counter per branch is a
// guard at the callers, the shape that silently stops covering whichever branch
// somebody adds next. Classifying the ANSWER covers every path by construction.
//
// The `deny` / `error` split follows the seam's own AuthorizationError code,
// which is where it already encodes the difference: PERMISSION_DENIED is a
// verdict, while RESOURCE_EXHAUSTED (a payload too large to scan) and UNKNOWN
// (the engine unreachable) are refusals with NO verdict behind them.
func classifyMcpRequestOutcome(resp *agwapi.McpRequestResult, err error) string {
	if err != nil || resp == nil {
		return MetricOutcomeError
	}
	e := resp.GetError()
	if e == nil {
		return MetricOutcomeAllow
	}
	if e.GetCode() == agwapi.AuthorizationError_PERMISSION_DENIED {
		return MetricOutcomeDeny
	}
	return MetricOutcomeError
}

func (s *ExtMcpServer) checkRequest(ctx context.Context, req *agwapi.McpRequest) (*agwapi.McpRequestResult, error) {
	params := req.GetMcpRequest()
	if len(params) > s.cfg.MaxBodyBytes {
		return mcpRequestError(agwapi.AuthorizationError_RESOURCE_EXHAUSTED,
			fmt.Sprintf("MCP params exceed %d bytes and cannot be scanned (fail-closed)", s.cfg.MaxBodyBytes), nil), nil
	}

	ident := identityFromMcpHeaders(req.GetHeaders())
	tool, query := extractMcpCall(req.GetMethod(), params)

	decideReq := pep.DecideRequest{
		Stage:          StageTool,
		CallerIdentity: pep.CallerIdentity{GatewayID: s.cfg.GatewayID},
		// pep.TargetTypeTool, not the "mcp_tool" this seam sent until #3717.
		// The PDP records tool attribution only for the canonical spelling, so
		// the old value silently emptied tool_server and tool_name on every
		// audit row this seam produced and degraded the HITL queue descriptor
		// to the literal type string. See pep.TargetTypes for why this is one
		// canonical value and not a gate that accepts both.
		//
		// It does NOT re-enable capability-scoped evaluation for this seam, and
		// that took a deliberate split on the platform side: the tool name here
		// comes from the MCP client's own request body, and this adapter is
		// in-path, so the trust premise that makes scoping safe on an advisory
		// plane does not hold. See the separation of the audit identity from
		// the scoping key in platform/agent/decision_handler.go.
		Target: pep.Target{
			Type:   pep.TargetTypeTool,
			Server: mcpTargetServer(req.GetServiceNames()),
			Tool:   tool,
		},
		Query:     query,
		UserToken: ident.Bearer,
		Context:   mcpDecideContext(req),
	}

	// Fulfillment statement is the FULL params payload that will actually be
	// forwarded — redacting only the extracted query would leak PII riding in
	// sibling fields.
	// Body-capable: this seam forwards Mutated params, so it can carry the
	// engine-redacted payload (#2958).
	outcome := s.pdp.GateRequest(ctx, decideReq, string(params), ident.Traceparent, s.pdp.SeamBodyCapable())

	switch outcome.Kind {
	case OutcomeAllow:
		return &agwapi.McpRequestResult{
			Result:         &agwapi.McpRequestResult_Pass{Pass: &agwapi.Pass{}},
			HeaderMutation: decisionHeaderMutation(outcome.Decision),
			Metadata:       decisionMetadata(outcome.Decision),
		}, nil

	case OutcomeAllowRedacted:
		// The gateway JSON-decodes Mutated params; hand it engine bytes only
		// if they are still valid JSON, else fail closed rather than trigger
		// a gateway-side protocol violation with content we cannot vouch for.
		if len(params) == 0 || !json.Valid([]byte(outcome.RedactedStatement)) {
			return mcpRequestError(agwapi.AuthorizationError_PERMISSION_DENIED,
				"engine-redacted params are not forwardable JSON (fail-closed)", outcome.Decision), nil
		}
		return &agwapi.McpRequestResult{
			Result:         &agwapi.McpRequestResult_Mutated{Mutated: []byte(outcome.RedactedStatement)},
			HeaderMutation: decisionHeaderMutation(outcome.Decision),
			Metadata:       decisionMetadata(outcome.Decision),
		}, nil

	case OutcomeDeny:
		return mcpRequestError(agwapi.AuthorizationError_PERMISSION_DENIED, outcome.Reason, outcome.Decision), nil

	case OutcomeFailOpen:
		log.Printf("[gateway-adapters] ExtMcp CheckRequest fail-open pass (method=%s): %s", req.GetMethod(), outcome.Reason)
		return &agwapi.McpRequestResult{Result: &agwapi.McpRequestResult_Pass{Pass: &agwapi.Pass{}}}, nil

	default: // OutcomeFailClosed
		return mcpRequestError(agwapi.AuthorizationError_UNKNOWN,
			"policy decision unavailable (fail-closed): "+outcome.Reason, outcome.Decision), nil
	}
}

// CheckResponse governs an MCP result before agentgateway returns it to the
// client. Unconditionally fail-closed: any path that cannot prove the result
// was scanned withholds it.
//
// Attribution note: the upstream McpResponse message carries NO headers, so
// this plane cannot forward end-user identity or traceparent — the response
// audit row attributes to the gateway credentials. The request-plane row for
// the same tools/call still names the end user (CheckRequest forwards the
// bearer token).
func (s *ExtMcpServer) CheckResponse(ctx context.Context, req *agwapi.McpResponse) (*agwapi.McpResponseResult, error) {
	resp, err := s.checkResponse(ctx, req)
	recordOutcome(SurfaceExtMcp, classifyMcpResponseOutcome(resp, err))
	return resp, err
}

// classifyMcpResponseOutcome is the response-plane twin of
// classifyMcpRequestOutcome. Same wrapping rationale, same code-based split.
//
// The response plane is UNCONDITIONALLY fail-closed, so `error` here is
// especially load-bearing: a withheld response during an engine outage must not
// be indistinguishable from a policy that blocked the content.
func classifyMcpResponseOutcome(resp *agwapi.McpResponseResult, err error) string {
	if err != nil || resp == nil {
		return MetricOutcomeError
	}
	e := resp.GetError()
	if e == nil {
		return MetricOutcomeAllow
	}
	if e.GetCode() == agwapi.AuthorizationError_PERMISSION_DENIED {
		return MetricOutcomeDeny
	}
	return MetricOutcomeError
}

func (s *ExtMcpServer) checkResponse(ctx context.Context, req *agwapi.McpResponse) (*agwapi.McpResponseResult, error) {
	result := req.GetMcpResponse()
	if len(result) == 0 {
		// Nothing to scan and nothing to leak — skip the engine round-trip.
		return &agwapi.McpResponseResult{Result: &agwapi.McpResponseResult_Pass{Pass: &agwapi.Pass{}}}, nil
	}
	if len(result) > s.cfg.MaxBodyBytes {
		return mcpResponseError(agwapi.AuthorizationError_RESOURCE_EXHAUSTED,
			fmt.Sprintf("MCP result exceeds %d bytes and cannot be scanned (fail-closed)", s.cfg.MaxBodyBytes), ""), nil
	}

	out, err := s.pdp.CheckOutput(ctx, pep.CheckOutputRequest{Message: string(result)}, "")
	if err != nil {
		if blocked, ok := asOutputBlocked(err); ok {
			return mcpResponseError(agwapi.AuthorizationError_PERMISSION_DENIED, blocked.Reason, blocked.DecisionID), nil
		}
		// Engine unreachable, auth failure, redactor-did-not-run, unexpected
		// wire shape — all withhold the result. No fail-open on responses.
		return mcpResponseError(agwapi.AuthorizationError_UNKNOWN,
			"response governance unavailable (fail-closed): "+err.Error(), ""), nil
	}

	if !out.Redacted {
		return &agwapi.McpResponseResult{Result: &agwapi.McpResponseResult_Pass{Pass: &agwapi.Pass{}}}, nil
	}
	if !json.Valid([]byte(out.RedactedMessage)) {
		return mcpResponseError(agwapi.AuthorizationError_PERMISSION_DENIED,
			"engine-redacted result is not forwardable JSON (fail-closed)", out.DecisionID), nil
	}
	return &agwapi.McpResponseResult{
		Result: &agwapi.McpResponseResult_Mutated{Mutated: []byte(out.RedactedMessage)},
	}, nil
}

// mcpTargetServer names the backend this call targets, for Target.Server.
//
// service_names is "exactly one entry for single-target methods (tools/call,
// ...); one entry per backend for fanout methods" (ext_mcp.proto). Only the
// single-target case yields a server: naming one of several fanned-out backends
// on an audit row would be a WRONG attribution, which is worse than the empty
// one this seam wrote before #3717 — an auditor can see an absence, but has no
// way to see that a present name is the wrong one of three.
func mcpTargetServer(serviceNames []string) string {
	if len(serviceNames) == 1 {
		return serviceNames[0]
	}
	return ""
}

// extractMcpCall derives the decide target + query from a JSON-RPC method and
// its params. tools/call gets first-class treatment (target.tool = the tool
// name, query = the arguments); other governed methods (prompts/get,
// resources/read, fanout lists) are gated generically on their full params.
//
// The generic branch puts the JSON-RPC METHOD in the tool slot, which is this
// seam's declared unit of governance for a non-tools/call request and is pinned
// by TestExtMcpCheckRequestGenericMethod. That was inert before #3717 (the PDP
// discarded the whole target) and is now recorded as audit_logs' tool_name, so
// a `resources/read` row reads tool_name="resources/read". Deliberately left
// as-is: narrowing it would DROP attribution this fix exists to restore, and
// whether a method name belongs in that column is a question for the audit
// vocabulary as a whole (#3709), not a change to smuggle in here.
func extractMcpCall(method string, params []byte) (tool, query string) {
	if method == "tools/call" && len(params) > 0 {
		var p mcpToolCallParams
		if err := json.Unmarshal(params, &p); err == nil && p.Name != "" {
			args := "{}"
			if len(p.Arguments) > 0 {
				args = string(p.Arguments)
			}
			return p.Name, args
		}
	}
	if len(params) > 0 {
		return method, string(params)
	}
	return method, method
}

// mcpDecideContext builds the bounded decide context: the JSON-RPC method,
// the native backend names, and any gateway-configured CEL metadata keys.
func mcpDecideContext(req *agwapi.McpRequest) map[string]interface{} {
	ctxMap := map[string]interface{}{
		// pep.ContextKeyMCPMethod, not a literal: the PDP reads this member's
		// PRESENCE to know the request came through an in-path MCP gateway and
		// to withhold capability scoping accordingly (#3717). A rename on one
		// side only would silently restore the relaxation.
		pep.ContextKeyMCPMethod: req.GetMethod(),
	}
	if names := req.GetServiceNames(); len(names) > 0 {
		vals := make([]interface{}, 0, len(names))
		for _, n := range names {
			vals = append(vals, n)
		}
		ctxMap["mcp_service_names"] = vals
	}
	if md := req.GetMetadataContext(); md != nil {
		for k, v := range md.AsMap() {
			ctxMap["gateway_"+k] = v
		}
	}
	return ctxMap
}

// decisionHeaderMutation stamps the decision identifiers onto the upstream
// HTTP request carrying the MCP call (honored on Pass and Mutated).
func decisionHeaderMutation(d *pep.DecideResponse) *agwapi.HeaderMutation {
	if d == nil {
		return nil
	}
	return &agwapi.HeaderMutation{
		Set: []*agwapi.McpHeader{
			{Key: "x-axonflow-decision-id", Value: []byte(d.DecisionID)},
			{Key: "x-axonflow-trace-id", Value: []byte(d.TraceID)},
		},
	}
}

// decisionMetadata exposes the decision to subsequent gateway filters as CEL
// `extMcp.*` values.
func decisionMetadata(d *pep.DecideResponse) *structpb.Struct {
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

// mcpRequestError builds an AuthorizationError request result carrying the
// decision context in mcp_error (which agentgateway surfaces as the JSON-RPC
// error `data` payload).
func mcpRequestError(code agwapi.AuthorizationError_Code, reason string, d *pep.DecideResponse) *agwapi.McpRequestResult {
	return &agwapi.McpRequestResult{
		Result: &agwapi.McpRequestResult_Error{Error: authorizationError(code, reason, d, "")},
	}
}

// mcpResponseError is the response-plane analogue of mcpRequestError.
func mcpResponseError(code agwapi.AuthorizationError_Code, reason, decisionID string) *agwapi.McpResponseResult {
	return &agwapi.McpResponseResult{
		Result: &agwapi.McpResponseResult_Error{Error: authorizationError(code, reason, nil, decisionID)},
	}
}

// authorizationError assembles the shared AuthorizationError shape. The
// decision identifiers ride the JSON `data` payload so the MCP client can
// quote a decision_id when contesting a block.
func authorizationError(code agwapi.AuthorizationError_Code, reason string, d *pep.DecideResponse, decisionID string) *agwapi.AuthorizationError {
	data := map[string]interface{}{"source": "axonflow"}
	if d != nil {
		data["decision_id"] = d.DecisionID
		data["trace_id"] = d.TraceID
		data["verdict"] = d.Verdict
		if len(d.Reasons) > 0 {
			data["reasons"] = d.Reasons
		}
	} else if decisionID != "" {
		data["decision_id"] = decisionID
	}
	e := &agwapi.AuthorizationError{Code: code, Reason: reason}
	if payload, err := json.Marshal(data); err == nil {
		e.McpError = payload
	}
	return e
}

// asOutputBlocked unwraps a pep response-plane policy block.
func asOutputBlocked(err error) (*pep.OutputBlockedError, bool) {
	var be *pep.OutputBlockedError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}
