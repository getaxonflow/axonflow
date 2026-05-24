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
	maxRequestBodySize         = 10 * 1024 * 1024 // 10 MB
	maxDecisionResponseSize    = 1 * 1024 * 1024  // 1 MB
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

// DecideResponse mirrors the platform's POST /api/v1/decide response shape.
type DecideResponse struct {
	Verdict           string       `json:"verdict"`
	DecisionID        string       `json:"decision_id"`
	TraceID           string       `json:"trace_id"`
	Reasons           []string     `json:"reasons,omitempty"`
	Obligations       []Obligation `json:"obligations"`
	EvaluatedPolicies []string     `json:"evaluated_policies"`
	Stage             string       `json:"stage,omitempty"`
	ExpiresAt         time.Time    `json:"expires_at"`
	Error             string       `json:"error,omitempty"`
}

type Obligation struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
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
			if resp.TraceID != "" {
				r.Header.Set("traceparent", formatTraceparent(resp.TraceID))
				w.Header().Set("X-Axonflow-Trace-Id", resp.TraceID)
				w.Header().Set("X-Axonflow-Decision-Id", resp.DecisionID)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
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
