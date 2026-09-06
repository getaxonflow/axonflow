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

package pep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxCheckOutputBytes bounds both the submitted message and the response body.
// A response larger than this cannot be scanned, so the caller fails CLOSED
// rather than forwarding it unscanned (mirrors the desktop proxy bound).
const maxCheckOutputBytes = 8 << 20 // 8 MB

// ErrOutputBlocked is the errors.Is target for a response-plane policy block
// from check-output. Match the concrete *OutputBlockedError with errors.As to
// read the engine's reason and decision_id.
var ErrOutputBlocked = errors.New("pep: response blocked by output policy")

// OutputBlockedError is a policy BLOCK from the response-governance endpoint:
// the engine refused to allow the response (critical-PII hard-deny,
// response-side SQLi, or exfiltration). The caller MUST NOT forward.
type OutputBlockedError struct {
	Reason     string
	DecisionID string
}

func (e *OutputBlockedError) Error() string {
	if e.Reason != "" {
		return "pep: response blocked by output policy: " + e.Reason
	}
	return "pep: response blocked by output policy"
}

// Is makes errors.Is(err, ErrOutputBlocked) match.
func (e *OutputBlockedError) Is(target error) bool { return target == ErrOutputBlocked }

// CheckOutputRequest is the caller-facing input to CheckOutput. Message is the
// full response content to govern (the response plane is content-shape
// agnostic: a PEP submits the serialized response as one text blob and
// forwards only what the engine returns). The identity fields are optional
// per-request end-user attribution for the audit row.
type CheckOutputRequest struct {
	Message   string
	UserToken string
	UserEmail string
	SessionID string
}

// CheckOutputResult is the outcome of an allowed check-output call.
type CheckOutputResult struct {
	// Redacted is true when the engine masked PII; RedactedMessage then holds
	// the engine-redacted content to forward INSTEAD of the original.
	Redacted        bool
	RedactedMessage string

	DecisionID        string
	PoliciesEvaluated int
}

// checkOutputWireRequest / checkOutputWireResponse mirror the platform's
// MCPCheckOutputRequest / MCPCheckOutputResponse (platform/agent/mcp_handler.go).
// The message path is the only modality this client submits (never
// response_data rows), so redacted_data comes back as the redacted message
// STRING. check_output_contract_test.go pins these bytes.
type checkOutputWireRequest struct {
	ClientID      string `json:"client_id,omitempty"`
	UserToken     string `json:"user_token,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	ConnectorType string `json:"connector_type"`
	Message       string `json:"message"`
}

type checkOutputWireResponse struct {
	Allowed            bool        `json:"allowed"`
	BlockReason        string      `json:"block_reason,omitempty"`
	RedactedData       interface{} `json:"redacted_data,omitempty"`
	PoliciesEvaluated  int         `json:"policies_evaluated"`
	DecisionID         string      `json:"decision_id,omitempty"`
	RedactionEvaluated bool        `json:"redaction_evaluated,omitempty"`
}

// CheckOutput submits a response payload to the engine's response-governance
// endpoint (POST /api/v1/mcp/check-output) and returns the redaction outcome.
// Like every method on this client it contains NO redaction logic — the engine
// round-trip is the only way content changes.
//
// Fail-CLOSED contract — the response plane is UNCONDITIONALLY fail-closed
// (there is no fail-open posture for responses; a PEP that cannot prove a
// response was scanned must withhold it). The caller forwards ONLY on a
// (result, nil) return:
//   - policy block (403, or 200 allowed:false)     → *OutputBlockedError
//   - transport error / 5xx                        → ErrPDPUnavailable (still block)
//   - other 4xx (auth / bad request)               → ErrDecisionRejected
//   - 200 allowed:true, redaction_evaluated:false  → ErrObligationNotFulfillable
//     (the redactor did not run — #2866 response-plane mirror of the #2563 B1
//     contract; requires platform >= 9.7.0, which always sets the field on
//     evaluated allow paths)
//   - non-string redacted_data                     → error (a wire shape this
//     client never asks for)
//   - oversized message                            → error (cannot be scanned)
func (c *Client) CheckOutput(ctx context.Context, req CheckOutputRequest, incomingTraceparent string) (*CheckOutputResult, error) {
	body, err := json.Marshal(checkOutputWireRequest{
		ClientID:      c.org,
		UserToken:     req.UserToken,
		TenantID:      c.tenantID,
		ConnectorType: c.connectorTag,
		Message:       req.Message,
	})
	if err != nil {
		return nil, fmt.Errorf("pep: marshal check-output request: %w", err)
	}
	if len(body) > maxCheckOutputBytes {
		return nil, fmt.Errorf("pep: check-output request too large (%d bytes > %d): cannot be scanned, do not forward", len(body), maxCheckOutputBytes)
	}

	httpReq, err := c.newPost(ctx, responseRedactionPath, body, incomingTraceparent, "")
	if err != nil {
		return nil, err
	}
	// Per-request identity headers, RESERVED: the check-output handler
	// currently derives audit identity from the PDP-validated user_token
	// only and ignores X-User-Email / X-Session-Id (unlike check-input,
	// which does read X-User-Email — mcp_handler.go). They are still sent
	// (matching the desktop-proxy wire behavior) so a future engine-side
	// wiring needs no client change; callers must not claim header-based
	// attribution until the engine honors them.
	if req.UserEmail != "" {
		httpReq.Header.Set("X-User-Email", req.UserEmail)
	}
	if req.SessionID != "" {
		httpReq.Header.Set("X-Session-Id", req.SessionID)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPDPUnavailable, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxCheckOutputBytes))

	var parsed checkOutputWireResponse
	parseErr := json.Unmarshal(respBody, &parsed)

	switch {
	case resp.StatusCode == http.StatusOK:
		if parseErr != nil {
			return nil, fmt.Errorf("pep: decode check-output response: %w", parseErr)
		}
		if !parsed.Allowed {
			// Block paths normally return 403; treat a 200 allowed:false
			// defensively as a block — never forward.
			return nil, &OutputBlockedError{Reason: parsed.BlockReason, DecisionID: parsed.DecisionID}
		}
		return buildCheckOutputResult(parsed)
	case resp.StatusCode == http.StatusForbidden:
		// 403 is the engine's block status (critical-PII / response SQLi /
		// exfiltration). Surface the engine's reason when the body parses.
		return nil, &OutputBlockedError{Reason: parsed.BlockReason, DecisionID: parsed.DecisionID}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return nil, fmt.Errorf("%w (status %d): %s", ErrDecisionRejected, resp.StatusCode, strings.TrimSpace(string(respBody)))
	default:
		return nil, fmt.Errorf("%w (status %d): %s", ErrPDPUnavailable, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
}

// buildCheckOutputResult interprets a 200 allowed:true wire response.
func buildCheckOutputResult(parsed checkOutputWireResponse) (*CheckOutputResult, error) {
	// FAIL CLOSED if the response-plane redactor did not run (#2866, the
	// response mirror of check-input's redaction_evaluated). Without this the
	// PEP cannot distinguish "engine scanned, nothing to mask" from "engine
	// wasn't looking" — both arrive with no redacted_data.
	if !parsed.RedactionEvaluated {
		return nil, fmt.Errorf("%w: engine reported the response redactor did not run (redaction disabled or platform < 9.7.0)", ErrObligationNotFulfillable)
	}
	out := &CheckOutputResult{DecisionID: parsed.DecisionID, PoliciesEvaluated: parsed.PoliciesEvaluated}
	switch v := parsed.RedactedData.(type) {
	case nil:
		return out, nil // nothing redacted — forward the original unchanged
	case string:
		if v == "" {
			return out, nil
		}
		out.RedactedMessage = v
		out.Redacted = true
		return out, nil
	default:
		// This client only ever submits `message`, so the engine returns a
		// string (or nothing). Any other shape is unexpected — fail closed
		// rather than guess and risk forwarding unredacted content.
		return nil, fmt.Errorf("pep: check-output returned non-string redacted_data (%T); failing closed", v)
	}
}
