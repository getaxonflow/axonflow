// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// decisionRejectedError is returned when the Decision API responds with a 4xx
// status. These errors must NOT be treated as fail-open eligible because they
// indicate a real problem (bad credentials, rate limit, identity mismatch).
type decisionRejectedError struct {
	StatusCode int
	Body       string
}

func (e *decisionRejectedError) Error() string {
	return fmt.Sprintf("decision API rejected request (%d): %s", e.StatusCode, e.Body)
}

const (
	maxRequestBodySize      = 10 * 1024 * 1024 // 10 MB
	maxDecisionResponseSize = 1 * 1024 * 1024  // 1 MB
)

// Config controls how the adapter talks to the AxonFlow Decision API.
type Config struct {
	// AxonFlowEndpoint is the base URL of the AxonFlow agent (e.g. "http://localhost:8080").
	AxonFlowEndpoint string

	// GatewayID identifies this PEP in audit logs (e.g. "llm-gateway-prod").
	GatewayID string

	// OrgID is the organisation scope for policy evaluation.
	OrgID string

	// TenantID is the tenant scope for policy evaluation.
	TenantID string

	// ClientID is the AxonFlow client credential ID. Empty in community mode.
	ClientID string

	// ClientSecret is the AxonFlow client credential secret. Empty in community mode.
	ClientSecret string

	// Stage is the Decision API stage (llm, tool, agent). Default: "llm".
	Stage string

	// FailOpen controls behavior when the Decision API is unreachable or returns
	// a transport/5xx error. true = forward the request (fail-open); false = block
	// the request (fail-closed). Default: false (fail-closed).
	FailOpen bool

	// Timeout for the Decision API HTTP call. Default: 5s.
	Timeout time.Duration

	// HTTPClient overrides the default http.Client used for Decision API calls.
	// Useful for injecting mTLS transport or test doubles.
	HTTPClient *http.Client
}

func (c *Config) stage() string {
	if c.Stage != "" {
		return c.Stage
	}
	return "llm"
}

func (c *Config) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 5 * time.Second
}

func (c *Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: c.timeout()}
}

// DecideRequest mirrors the platform's POST /api/v1/decide request shape.
type DecideRequest struct {
	Stage          string         `json:"stage"`
	CallerIdentity CallerIdentity `json:"caller_identity"`
	Target         Target         `json:"target"`
	Query          string         `json:"query"`
	UserToken      string         `json:"user_token,omitempty"`
	Context        map[string]any `json:"context,omitempty"`
}

type CallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

type Target struct {
	Type     string `json:"type,omitempty"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// DecideResponse mirrors the platform's POST /api/v1/decide 200 response shape.
//
// IT HAS NO `Error` MEMBER, AND THAT IS DELIBERATE (#3724). One was carried
// here, and in platform/shared/pep, and in all five SDKs, and no server has
// ever populated it: the platform's 200 body has no such field. The error
// envelope is a DIFFERENT shape - `{error, verdict, ...}`, published as
// DecideErrorResponse - and it arrives as a NON-200, which this adapter (like
// the blessed client) surfaces as an error return rather than decoding into
// this type. An integrator writing `if resp.Error != ""` got a branch that
// could never be true while every real failure came back through the error
// return they were not checking.
//
// THIS IS ONE OF FOUR IN-TREE MIRRORS of the Decision API DTOs, and it is in
// its own Go module, so the spec-versus-code guard in platform/orchestrator
// cannot reach it. The others are platform/agent, platform/shared/pep, and
// examples/integrations/decision-mode-mcp-adapter - which already diverges,
// carrying ExpiresAt as a string where the other three carry a time.Time. A
// first version of this comment said THIRD; review round 2 found the fourth,
// which is the point: nobody can count mirrors reliably, and that is why the
// guard exists for the two it can reach. Recorded on #3709. Until it is
// addressed, a change to the Decision API contract has to be made here by
// hand.
type DecideResponse struct {
	Verdict           string       `json:"verdict"`
	DecisionID        string       `json:"decision_id"`
	TraceID           string       `json:"trace_id"`
	Reasons           []string     `json:"reasons,omitempty"`
	Obligations       []Obligation `json:"obligations"`
	EvaluatedPolicies []string     `json:"evaluated_policies"`
	Stage             string       `json:"stage,omitempty"`
	ExpiresAt         time.Time    `json:"expires_at"`
}

type Obligation struct {
	Type        string                 `json:"type"`
	Detail      string                 `json:"detail,omitempty"`
	Fulfillment *ObligationFulfillment `json:"fulfillment,omitempty"`
}

// ObligationFulfillment names the AxonFlow engine call that discharges an
// obligation (ADR-056 / #2563). A conforming PEP POSTs the source content to
// Endpoint and forwards the engine-redacted content the endpoint returns — it
// NEVER redacts with its own patterns. This adapter honours that: the only way
// it produces redacted content is by calling the named endpoint.
//
// ContentTypes advertises the mime-types the endpoint's detectors can redact
// today (e.g. "text/plain"). The contract is content-type-agnostic: a PEP
// holding content of an unadvertised type (e.g. an image awaiting OCR-PII
// redaction) must fail closed rather than forward it unredacted. Media support
// arrives by registering a detector server-side, not by redesigning this shape.
type ObligationFulfillment struct {
	Endpoint     string   `json:"endpoint"`
	Method       string   `json:"method"`
	Phase        string   `json:"phase"`
	ContentTypes []string `json:"content_types,omitempty"`
}

const (
	obligationRedactPII    = "redact_pii"
	obligationPhaseRequest = "request"
	contentTypeText        = "text/plain"
	// requestRedactionPath is the only engine endpoint this adapter will POST
	// content to for fulfillment. Refusing any other endpoint stops a malformed
	// verdict from steering the PEP into calling an arbitrary URL.
	requestRedactionPath = "/api/v1/mcp/check-input"
)

// checkInputRequest / checkInputResponse mirror the platform's
// MCPCheckInputRequest / MCPCheckInputResponse (the request-redaction endpoint).
// ContentType selects the server-side redaction detector; this adapter handles
// text only and submits "text/plain".
type checkInputRequest struct {
	ConnectorType string `json:"connector_type"`
	Statement     string `json:"statement"`
	ContentType   string `json:"content_type,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	Operation     string `json:"operation,omitempty"`
}

type checkInputResponse struct {
	Allowed            bool   `json:"allowed"`
	Redacted           bool   `json:"redacted,omitempty"`
	RedactedStatement  string `json:"redacted_statement,omitempty"`
	RedactionEvaluated bool   `json:"redaction_evaluated,omitempty"`
}

// openAIChatRequest is the subset of the OpenAI chat-completion body the
// adapter inspects to build the Decision API request. Only model and the
// first user message are read; the full body is forwarded verbatim on allow.
type openAIChatRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Middleware returns an http.Handler that intercepts OpenAI-shaped POST
// requests, calls the AxonFlow Decision API, and enforces the verdict
// before forwarding to downstream.
func Middleware(cfg Config, downstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			downstream.ServeHTTP(w, r)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
		r.Body.Close()
		if err != nil {
			writeErrorJSON(w, http.StatusBadRequest, "failed to read request body", "", "")
			return
		}
		if len(body) > maxRequestBodySize {
			writeErrorJSON(w, http.StatusRequestEntityTooLarge, "request body too large", "", "")
			return
		}

		var chatReq openAIChatRequest
		if err := json.Unmarshal(body, &chatReq); err != nil {
			writeErrorJSON(w, http.StatusBadRequest, "invalid JSON body", "", "")
			return
		}

		query := extractQuery(chatReq)
		model := chatReq.Model
		provider := inferProvider(model)

		stage := cfg.stage()
		decideReq := DecideRequest{
			Stage: stage,
			CallerIdentity: CallerIdentity{
				GatewayID: cfg.GatewayID,
				OrgID:     cfg.OrgID,
				TenantID:  cfg.TenantID,
			},
			Target: Target{
				Type:     stage,
				Model:    model,
				Provider: provider,
			},
			Query: query,
		}

		resp, err := callDecisionAPI(r.Context(), cfg, decideReq, r.Header.Get("traceparent"))
		if err != nil {
			// 4xx errors (bad credentials, rate limit, identity mismatch) must
			// always block — they indicate a real problem, not transient degradation.
			var rejected *decisionRejectedError
			if errors.As(err, &rejected) {
				writeErrorJSON(w, http.StatusBadGateway,
					fmt.Sprintf("AxonFlow Decision API rejected request: %s", rejected.Body),
					"", "")
				return
			}
			// Transport and 5xx errors: apply fail-open/fail-closed posture.
			if cfg.FailOpen {
				r.Body = io.NopCloser(bytes.NewReader(body))
				downstream.ServeHTTP(w, r)
				return
			}
			writeErrorJSON(w, http.StatusServiceUnavailable,
				"AxonFlow Decision API unreachable and fail-closed is configured", "", "")
			return
		}

		switch resp.Verdict {
		case "allow":
			// Discharge any request-phase redact_pii obligation THROUGH THE
			// ENGINE before forwarding (ADR-056 / #2563). We never redact
			// locally: the obligation names an engine endpoint, we POST the
			// query there, and we forward exactly what it returns. On any
			// fulfillment failure we fail closed (block) rather than forward
			// unredacted content.
			outBody := body
			if hasRequestRedaction(resp.Obligations) {
				redactedQuery, ferr := fulfillRequestRedaction(r.Context(), cfg, resp.Obligations, query, r.Header.Get("traceparent"))
				if ferr != nil {
					writeErrorJSON(w, http.StatusBadGateway,
						fmt.Sprintf("AxonFlow obligation could not be fulfilled via the engine: %v", ferr),
						resp.DecisionID, resp.TraceID)
					return
				}
				if redactedQuery != query {
					rewritten, rerr := rewriteUserQuery(body, redactedQuery)
					if rerr != nil {
						writeErrorJSON(w, http.StatusBadGateway,
							"failed to apply engine redaction to request body", resp.DecisionID, resp.TraceID)
						return
					}
					outBody = rewritten
				}
			}
			if resp.TraceID != "" {
				r.Header.Set("traceparent", formatTraceparent(resp.TraceID))
				w.Header().Set("X-Axonflow-Trace-Id", resp.TraceID)
				w.Header().Set("X-Axonflow-Decision-Id", resp.DecisionID)
			}
			r.ContentLength = int64(len(outBody))
			r.Body = io.NopCloser(bytes.NewReader(outBody))
			downstream.ServeHTTP(w, r)

		case "deny":
			writeBlockedJSON(w, http.StatusForbidden, resp)

		case "needs_approval":
			writeBlockedJSON(w, http.StatusForbidden, resp)

		default:
			if cfg.FailOpen {
				r.Body = io.NopCloser(bytes.NewReader(body))
				downstream.ServeHTTP(w, r)
				return
			}
			writeErrorJSON(w, http.StatusForbidden,
				fmt.Sprintf("unexpected verdict: %s", resp.Verdict), resp.DecisionID, resp.TraceID)
		}
	})
}

// callDecisionAPI sends the decision request to the AxonFlow agent.
func callDecisionAPI(ctx context.Context, cfg Config, req DecideRequest, incomingTraceparent string) (*DecideResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal decision request: %w", err)
	}

	url := strings.TrimRight(cfg.AxonFlowEndpoint, "/") + "/api/v1/decide"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if incomingTraceparent != "" {
		httpReq.Header.Set("traceparent", incomingTraceparent)
	}

	if cfg.ClientID != "" {
		httpReq.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}

	httpResp, err := cfg.httpClient().Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("decision API call failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxDecisionResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read decision response: %w", err)
	}

	// Transport and 5xx errors are fail-open eligible.
	if httpResp.StatusCode >= 500 {
		return nil, fmt.Errorf("decision API returned %d: %s", httpResp.StatusCode, string(respBody))
	}

	// 4xx errors (401, 403, 429, etc.) are NOT fail-open eligible — they
	// indicate a real problem the caller must fix, not transient degradation.
	if httpResp.StatusCode >= 400 {
		return nil, &decisionRejectedError{StatusCode: httpResp.StatusCode, Body: string(respBody)}
	}

	var resp DecideResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("decode decision response: %w", err)
	}

	return &resp, nil
}

// hasRequestRedaction reports whether any obligation requires request-phase
// PII redaction.
func hasRequestRedaction(obs []Obligation) bool {
	for _, o := range obs {
		if o.Type == obligationRedactPII && o.Fulfillment != nil && o.Fulfillment.Phase == obligationPhaseRequest {
			return true
		}
	}
	return false
}

// fulfillRequestRedaction discharges every request-phase redact_pii obligation
// by calling the engine endpoint the obligation names. It performs NO local
// redaction; the returned string is exactly what the engine produced. Any
// obligation that names no request-phase endpoint, an endpoint this adapter
// refuses to call, or a content-type the endpoint cannot redact, is a hard
// error so the caller fails closed.
func fulfillRequestRedaction(ctx context.Context, cfg Config, obs []Obligation, query, traceparent string) (string, error) {
	redacted := query
	for _, o := range obs {
		if o.Type != obligationRedactPII {
			continue
		}
		f := o.Fulfillment
		if f == nil || f.Phase != obligationPhaseRequest {
			return query, fmt.Errorf("redact_pii obligation has no request-phase fulfillment endpoint")
		}
		if !endpointMatches(f.Endpoint, requestRedactionPath) {
			return query, fmt.Errorf("refusing to call non-redaction endpoint %q", f.Endpoint)
		}
		// Content-type-agnostic check: this adapter only holds text. If the
		// endpoint cannot redact text, fail closed rather than forward.
		if len(f.ContentTypes) > 0 && !contains(f.ContentTypes, contentTypeText) {
			return query, fmt.Errorf("endpoint does not advertise a %s detector", contentTypeText)
		}
		out, err := callRedactionEndpoint(ctx, cfg, redacted, traceparent)
		if err != nil {
			return query, err
		}
		redacted = out
	}
	return redacted, nil
}

// callRedactionEndpoint POSTs the statement to the request-redaction engine
// endpoint and returns the engine-masked statement.
func callRedactionEndpoint(ctx context.Context, cfg Config, statement, traceparent string) (string, error) {
	reqBody, err := json.Marshal(checkInputRequest{
		ConnectorType: "gateway",
		Statement:     statement,
		ContentType:   contentTypeText,
		TenantID:      cfg.TenantID,
		Operation:     "execute",
	})
	if err != nil {
		return "", fmt.Errorf("marshal redaction request: %w", err)
	}
	url := strings.TrimRight(cfg.AxonFlowEndpoint, "/") + requestRedactionPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("create redaction request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if traceparent != "" {
		httpReq.Header.Set("traceparent", traceparent)
	}
	if cfg.ClientID != "" {
		httpReq.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	httpResp, err := cfg.httpClient().Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("redaction endpoint call failed: %w", err)
	}
	defer httpResp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxDecisionResponseSize))
	if httpResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("redaction endpoint returned %d: %s", httpResp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var cir checkInputResponse
	if err := json.Unmarshal(respBody, &cir); err != nil {
		return "", fmt.Errorf("decode redaction response: %w", err)
	}
	// Fail closed if the redactor did not actually run (#2563 B1): "redacted:false"
	// with the redactor disabled is indistinguishable from "looked, found nothing".
	if !cir.RedactionEvaluated {
		return "", fmt.Errorf("engine redactor did not run (redaction disabled) — failing closed")
	}
	if cir.Redacted && cir.RedactedStatement != "" {
		return cir.RedactedStatement, nil
	}
	return statement, nil
}

// rewriteUserQuery replaces the last user message's content in the original
// request body with the redacted query, preserving every other field.
func rewriteUserQuery(body []byte, redacted string) ([]byte, error) {
	var generic map[string]interface{}
	if err := json.Unmarshal(body, &generic); err != nil {
		return nil, err
	}
	msgs, ok := generic["messages"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("request has no messages array to rewrite")
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		m, ok := msgs[i].(map[string]interface{})
		if !ok {
			continue
		}
		if role, _ := m["role"].(string); role == "user" {
			m["content"] = redacted
			return json.Marshal(generic)
		}
	}
	return nil, fmt.Errorf("request has no user message to rewrite")
}

// endpointMatches reports whether endpoint resolves to the expected engine path
// (accepting an absolute URL whose path matches).
func endpointMatches(endpoint, expected string) bool {
	e := strings.TrimSpace(endpoint)
	if e == expected {
		return true
	}
	if i := strings.Index(e, "://"); i >= 0 {
		rest := e[i+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			path := rest[slash:]
			if q := strings.IndexByte(path, '?'); q >= 0 {
				path = path[:q]
			}
			return path == expected
		}
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// extractQuery pulls the last user message from the OpenAI chat request.
func extractQuery(req openAIChatRequest) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			return req.Messages[i].Content
		}
	}
	if len(req.Messages) > 0 {
		return req.Messages[len(req.Messages)-1].Content
	}
	return ""
}

// inferProvider guesses the LLM provider from the model name.
func inferProvider(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "gpt") || strings.HasPrefix(m, "o1") || strings.HasPrefix(m, "o3") || strings.HasPrefix(m, "o4"):
		return "openai"
	case strings.HasPrefix(m, "claude"):
		return "anthropic"
	case strings.HasPrefix(m, "gemini"):
		return "google"
	case strings.HasPrefix(m, "mistral") || strings.HasPrefix(m, "mixtral"):
		return "mistral"
	case strings.HasPrefix(m, "llama") || strings.HasPrefix(m, "meta"):
		return "meta"
	default:
		return "unknown"
	}
}

// formatTraceparent builds a W3C traceparent header from a 32-hex trace_id.
// Uses version 00, a random 8-byte parent-id (span-id), and sampled flag.
func formatTraceparent(traceID string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("00-%s-%s-01", traceID, hex.EncodeToString(b[:]))
}

// writeBlockedJSON writes a structured JSON error for deny / needs_approval.
func writeBlockedJSON(w http.ResponseWriter, statusCode int, resp *DecideResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Axonflow-Trace-Id", resp.TraceID)
	w.Header().Set("X-Axonflow-Decision-Id", resp.DecisionID)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message":            fmt.Sprintf("Request blocked by AxonFlow policy (verdict: %s)", resp.Verdict),
			"type":               "policy_violation",
			"code":               "policy_" + resp.Verdict,
			"decision_id":        resp.DecisionID,
			"trace_id":           resp.TraceID,
			"reasons":            resp.Reasons,
			"evaluated_policies": resp.EvaluatedPolicies,
		},
	})
}

// writeErrorJSON writes a structured JSON error for adapter-level failures.
func writeErrorJSON(w http.ResponseWriter, statusCode int, message, decisionID, traceID string) {
	w.Header().Set("Content-Type", "application/json")
	if traceID != "" {
		w.Header().Set("X-Axonflow-Trace-Id", traceID)
	}
	if decisionID != "" {
		w.Header().Set("X-Axonflow-Decision-Id", decisionID)
	}
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "adapter_error",
		},
	})
}
