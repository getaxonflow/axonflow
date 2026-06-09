// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pep is the blessed Policy Enforcement Point client for AxonFlow
// Decision Mode (ADR-056, epic #2563).
//
// A PEP follows one path: decide -> fulfill -> forward.
//
//   - decide:  ask the PDP (POST /api/v1/decide) for a verdict on a request.
//   - fulfill: for every obligation the verdict carries, call the ENGINE
//     endpoint named in the obligation's Fulfillment block to obtain
//     engine-redacted content.
//   - forward: forward the (possibly redacted) content, or block, per verdict.
//
// The structural guarantee #2563 demands: this client contains NO redaction
// logic of its own. There is no regex, no pattern table, no masking branch.
// The ONLY way it can discharge a redact_pii obligation is by POSTing the
// source content to the engine endpoint the obligation names and forwarding
// what the engine returns. A PEP built on this helper therefore cannot
// reimplement redaction the way the desktop proxy's redact.go did (a
// hand-rolled regex subset that punted US SSN); the capability simply is not
// here to misuse. If an obligation arrives without a fulfillable engine
// endpoint, FulfillRequest fails closed rather than forwarding unredacted.
//
// The helper re-declares the small Decision API wire DTOs rather than importing
// platform/agent, so it stays light enough to vendor into a customer gateway.
// pep_contract_test.go pins the wire shape against the real bytes the platform
// emits, so the duplicated DTOs cannot silently drift from decision_handler.go.
package pep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Obligation types and fulfillment phases. These mirror the platform constants
// in platform/agent/decision_handler.go; the contract test pins them.
const (
	ObligationRedactPII = "redact_pii"

	PhaseRequest  = "request"
	PhaseResponse = "response"

	// ContentTypeText is the only redaction modality this client submits. The
	// contract is content-type-agnostic (an obligation advertises which mimes
	// its endpoint can redact); a PEP holding content of an unadvertised type
	// must fail closed. Media support is a server-side detector, not a client
	// change here.
	ContentTypeText = "text/plain"

	// decidePath is the PDP verdict endpoint.
	decidePath = "/api/v1/decide"

	// requestRedactionPath / responseRedactionPath are the only engine
	// endpoints this client will POST content to for fulfillment. An obligation
	// whose Fulfillment.Endpoint is not one of these is rejected — a PEP must
	// not be steered into calling an arbitrary URL by a malformed verdict.
	requestRedactionPath  = "/api/v1/mcp/check-input"
	responseRedactionPath = "/api/v1/mcp/check-output"
)

// Sentinel errors callers can match with errors.Is.
var (
	// ErrDecisionRejected is a 4xx from the PDP (bad credentials, rate limit,
	// identity mismatch). It is NOT transient — callers must block, never
	// fail-open, because it signals a real problem with the request.
	ErrDecisionRejected = errors.New("pep: decision API rejected request")

	// ErrPDPUnavailable is a transport error or 5xx from the PDP. Callers apply
	// their configured fail-open / fail-closed posture.
	ErrPDPUnavailable = errors.New("pep: decision API unavailable")

	// ErrObligationNotFulfillable means an obligation could not be discharged
	// through the engine — it named no endpoint, named an endpoint this client
	// will not call, or the engine endpoint itself failed. The helper returns
	// this rather than forwarding unredacted content, so an unfulfillable
	// redact obligation fails closed.
	ErrObligationNotFulfillable = errors.New("pep: obligation not engine-fulfillable")

	// ErrConfig is a construction-time configuration error.
	ErrConfig = errors.New("pep: invalid config")
)

// Verdict values returned by the PDP.
const (
	VerdictAllow         = "allow"
	VerdictDeny          = "deny"
	VerdictNeedsApproval = "needs_approval"
)

// Config configures a PEP Client.
type Config struct {
	// Endpoint is the AxonFlow agent base URL, e.g. "https://pdp.internal:8443".
	Endpoint string

	// OrgID + LicenseKey are the HTTP Basic credentials the PDP authenticates.
	// Decision Mode auth is HTTP Basic (org:license-key) — X-Client-* headers
	// are ignored by the enterprise PDP and produce a 401. Leave both empty
	// only for a community-mode PDP that requires no credentials.
	OrgID      string
	LicenseKey string

	// TenantID scopes the decision + fulfillment calls. Required when the PDP
	// runs in a mode that authenticates a tenant; passed through on every call.
	TenantID string

	// ConnectorTag is the connector_type the fulfillment endpoints record. In
	// gateway/PDP mode there is no managed connector, so this is a synthetic
	// origin tag (default "gateway") — it lets the audit trail attribute the
	// redaction to the PEP layer. See #2563 (connector-agnostic gateway mode).
	ConnectorTag string

	// HTTPClient is optional; a sane default with a timeout is used when nil.
	HTTPClient *http.Client
}

// Client is a Decision Mode PEP client. Safe for concurrent use.
type Client struct {
	endpoint     string
	org          string
	license      string
	tenantID     string
	connectorTag string
	http         *http.Client
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		return nil, fmt.Errorf("%w: Endpoint is required", ErrConfig)
	}
	// Basic auth is all-or-nothing: supplying only one half is a config bug
	// that would silently send a malformed credential.
	if (cfg.OrgID == "") != (cfg.LicenseKey == "") {
		return nil, fmt.Errorf("%w: OrgID and LicenseKey must be set together", ErrConfig)
	}
	connectorTag := strings.TrimSpace(cfg.ConnectorTag)
	if connectorTag == "" {
		connectorTag = "gateway"
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		endpoint:     endpoint,
		org:          cfg.OrgID,
		license:      cfg.LicenseKey,
		tenantID:     cfg.TenantID,
		connectorTag: connectorTag,
		http:         httpClient,
	}, nil
}

// --- Decision API wire DTOs (mirror platform/agent/decision_handler.go) ---

// DecideRequest is the POST /api/v1/decide body.
type DecideRequest struct {
	Stage          string                 `json:"stage"`
	CallerIdentity CallerIdentity         `json:"caller_identity"`
	Target         Target                 `json:"target"`
	Query          string                 `json:"query"`
	UserToken      string                 `json:"user_token,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
}

// CallerIdentity is the gateway-asserted identity.
type CallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// Target describes what the gateway is about to call.
type Target struct {
	Type     string `json:"type,omitempty"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
	Tool     string `json:"tool,omitempty"`
}

// DecideResponse is the PDP verdict.
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

// Obligation is a self-describing, engine-fulfillable PEP requirement.
type Obligation struct {
	Type        string                 `json:"type"`
	Detail      string                 `json:"detail,omitempty"`
	Fulfillment *ObligationFulfillment `json:"fulfillment,omitempty"`
}

// ObligationFulfillment names the engine call that discharges the obligation.
// ContentTypes advertises the mime-types the endpoint can redact today; a PEP
// holding unadvertised content must fail closed (ADR-056 / #2563 addendum).
type ObligationFulfillment struct {
	Endpoint     string   `json:"endpoint"`
	Method       string   `json:"method"`
	Phase        string   `json:"phase"`
	ContentTypes []string `json:"content_types,omitempty"`
}

// checkInputRequest / checkInputResponse mirror the platform's
// MCPCheckInputRequest / MCPCheckInputResponse (the request-redaction endpoint).
type checkInputRequest struct {
	ConnectorType string `json:"connector_type"`
	Statement     string `json:"statement"`
	ContentType   string `json:"content_type,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	Operation     string `json:"operation,omitempty"`
}

type checkInputResponse struct {
	Allowed            bool   `json:"allowed"`
	BlockReason        string `json:"block_reason,omitempty"`
	Redacted           bool   `json:"redacted,omitempty"`
	RedactedStatement  string `json:"redacted_statement,omitempty"`
	RedactionEvaluated bool   `json:"redaction_evaluated,omitempty"`
}

// Decide asks the PDP for a verdict. incomingTraceparent (may be empty) is
// forwarded so multi-layer decisions stitch into one trace.
func (c *Client) Decide(ctx context.Context, req DecideRequest, incomingTraceparent string) (*DecideResponse, error) {
	// Stamp the configured tenant when the caller didn't set one explicitly.
	if req.CallerIdentity.TenantID == "" {
		req.CallerIdentity.TenantID = c.tenantID
	}
	if req.CallerIdentity.OrgID == "" {
		req.CallerIdentity.OrgID = c.org
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("pep: marshal decide request: %w", err)
	}
	httpReq, err := c.newPost(ctx, decidePath, body, incomingTraceparent)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPDPUnavailable, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusOK:
		var dr DecideResponse
		if err := json.Unmarshal(respBody, &dr); err != nil {
			return nil, fmt.Errorf("pep: decode decide response: %w", err)
		}
		return &dr, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return nil, fmt.Errorf("%w (status %d): %s", ErrDecisionRejected, resp.StatusCode, strings.TrimSpace(string(respBody)))
	default:
		// 5xx incl. circuit-breaker 503 — transient; caller applies posture.
		return nil, fmt.Errorf("%w (status %d): %s", ErrPDPUnavailable, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
}

// FulfillRequest discharges every request-phase redact_pii obligation on the
// verdict by calling the engine endpoint the obligation names, and returns the
// engine-redacted statement to forward.
//
// Contract:
//   - No obligations (or none that mutate the request): returns (statement,
//     false, nil) — forward the original.
//   - A redact_pii obligation with a valid request-phase Fulfillment: POSTs
//     statement to that endpoint and returns (engineRedacted, true, nil).
//   - A redact_pii obligation that names no endpoint, or an endpoint this
//     client will not call, or whose engine call fails: returns
//     ErrObligationNotFulfillable. The caller MUST treat this as fail-closed
//     (block) — never forward unredacted content.
//
// There is no code path in which this method redacts locally. Fulfillment is
// always the engine round-trip.
func (c *Client) FulfillRequest(ctx context.Context, decision *DecideResponse, statement string) (string, bool, error) {
	if decision == nil {
		return statement, false, nil
	}
	redacted := statement
	didRedact := false
	for _, ob := range decision.Obligations {
		if ob.Type != ObligationRedactPII {
			// Unknown obligation types are not silently ignored when they would
			// change content; redact_pii is the only content-mutating type
			// today, so non-redact obligations are pass-through by contract.
			continue
		}
		if ob.Fulfillment == nil || ob.Fulfillment.Phase != PhaseRequest {
			// A redact_pii obligation with no request-phase fulfillment cannot
			// be discharged here — fail closed rather than forward unredacted.
			return statement, false, fmt.Errorf("%w: redact_pii missing request-phase fulfillment", ErrObligationNotFulfillable)
		}
		// Content-type-agnostic check: this client submits text. If the endpoint
		// advertises content types and text is not one of them, fail closed
		// rather than forward — never assume the endpoint can handle our content.
		if len(ob.Fulfillment.ContentTypes) > 0 && !containsString(ob.Fulfillment.ContentTypes, ContentTypeText) {
			return statement, false, fmt.Errorf("%w: endpoint does not advertise a %s detector", ErrObligationNotFulfillable, ContentTypeText)
		}
		out, err := c.callRequestRedaction(ctx, ob.Fulfillment.Endpoint, redacted)
		if err != nil {
			return statement, false, err
		}
		// didRedact reflects whether the ENGINE actually changed the content,
		// not merely that an obligation was present — the engine may report
		// nothing to mask (callRequestRedaction returns the statement unchanged).
		if out != redacted {
			didRedact = true
		}
		redacted = out
	}
	return redacted, didRedact, nil
}

// DecideAndFulfill is the blessed one-call path: decide, then fulfill any
// request-phase obligation. It returns the verdict, the content to forward
// (engine-redacted when an obligation applied), and the raw decision.
//
// Callers branch on verdict: forward `content` on allow; block on deny /
// needs_approval. On any returned error the caller applies its posture (an
// ErrObligationNotFulfillable error is a fail-closed signal — do not forward).
func (c *Client) DecideAndFulfill(ctx context.Context, req DecideRequest, incomingTraceparent string) (verdict, content string, decision *DecideResponse, err error) {
	decision, err = c.Decide(ctx, req, incomingTraceparent)
	if err != nil {
		return "", req.Query, nil, err
	}
	if decision.Verdict != VerdictAllow {
		return decision.Verdict, req.Query, decision, nil
	}
	redacted, _, ferr := c.FulfillRequest(ctx, decision, req.Query)
	if ferr != nil {
		// Return empty content on the not-fulfillable path so a caller that
		// ignores the error cannot accidentally forward the unredacted query —
		// fail-closed is impossible-by-construction here (#2563 L2).
		return decision.Verdict, "", decision, ferr
	}
	return decision.Verdict, redacted, decision, nil
}

// callRequestRedaction POSTs statement to the request-redaction engine endpoint
// and returns the engine-masked statement. It refuses any endpoint other than
// the known request-redaction path so a malformed verdict cannot steer the PEP
// into calling an arbitrary URL.
func (c *Client) callRequestRedaction(ctx context.Context, endpoint, statement string) (string, error) {
	if !isAllowedFulfillmentEndpoint(endpoint, requestRedactionPath) {
		return "", fmt.Errorf("%w: endpoint %q is not the request-redaction endpoint", ErrObligationNotFulfillable, endpoint)
	}
	reqBody, err := json.Marshal(checkInputRequest{
		ConnectorType: c.connectorTag,
		Statement:     statement,
		ContentType:   ContentTypeText,
		TenantID:      c.tenantID,
		Operation:     "execute",
	})
	if err != nil {
		return "", fmt.Errorf("%w: marshal: %v", ErrObligationNotFulfillable, err)
	}
	httpReq, err := c.newPost(ctx, requestRedactionPath, reqBody, "")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrObligationNotFulfillable, err)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("%w: engine call failed: %v", ErrObligationNotFulfillable, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: engine returned status %d: %s", ErrObligationNotFulfillable, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var cir checkInputResponse
	if err := json.Unmarshal(respBody, &cir); err != nil {
		return "", fmt.Errorf("%w: decode engine response: %v", ErrObligationNotFulfillable, err)
	}
	// FAIL CLOSED if the redactor did not actually run (#2563 B1). Without this
	// the PEP cannot distinguish "engine looked, found nothing" (safe to forward
	// the original) from "engine wasn't looking" (would leak PII) — both arrive
	// as redacted:false. The endpoint sets redaction_evaluated=true on every
	// evaluated allow path; its absence means the redactor was disabled and we
	// must NOT forward.
	if !cir.RedactionEvaluated {
		return "", fmt.Errorf("%w: engine reported the redactor did not run (redaction disabled)", ErrObligationNotFulfillable)
	}
	if cir.Redacted && cir.RedactedStatement != "" {
		return cir.RedactedStatement, nil
	}
	// Redactor ran and found nothing to mask — forward the statement unchanged.
	return statement, nil
}

// newPost builds an authenticated JSON POST. Basic auth (org:license) is set
// when credentials are configured; community-mode PDPs need none.
func (c *Client) newPost(ctx context.Context, path string, body []byte, incomingTraceparent string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pep: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.org != "" && c.license != "" {
		req.SetBasicAuth(c.org, c.license)
	}
	if incomingTraceparent != "" {
		req.Header.Set("traceparent", incomingTraceparent)
	}
	return req, nil
}

// HasRequestRedaction reports whether any obligation requires request-phase
// PII redaction. Exposed so a PEP can branch ("does this verdict carry work
// for me?") before calling FulfillRequest.
func HasRequestRedaction(obs []Obligation) bool {
	for _, o := range obs {
		if o.Type == ObligationRedactPII && o.Fulfillment != nil && o.Fulfillment.Phase == PhaseRequest {
			return true
		}
	}
	return false
}

// containsString reports whether v is in s.
func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// isAllowedFulfillmentEndpoint reports whether endpoint is the expected engine
// path. It tolerates an absolute URL whose path component matches (some PDPs
// return a fully-qualified obligation endpoint) and a missing/blank endpoint is
// treated as the expected default for backward tolerance only when it equals
// expected exactly.
func isAllowedFulfillmentEndpoint(endpoint, expected string) bool {
	e := strings.TrimSpace(endpoint)
	if e == expected {
		return true
	}
	// Accept an absolute URL whose path is the expected engine path.
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
