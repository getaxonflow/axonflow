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

	"axonflow/platform/decision/contract"
)

// Obligation types and fulfillment phases. These mirror the platform constants
// in platform/agent/decision_handler.go; the contract test pins them.
const (
	ObligationRedactPII = "redact_pii"

	PhaseRequest  = "request"
	PhaseResponse = "response"

	// --- Fulfillment capabilities (#2958) ---
	//
	// A PEP advertises what its SEAM can actually do on
	// DecideRequest.FulfillmentCapabilities, so the PDP emits only obligations
	// that caller can discharge. Before this existed, /decide emitted a
	// request-phase redact_pii obligation blind to the seam: a headers-only
	// seam (Envoy ext_authz cannot rewrite bodies) could not fulfill it and had
	// to turn the PDP's `allow` into a local 403 — a policy decision made in the
	// PEP, which is exactly what ADR-056 forbids.
	//
	// WIRE CONTRACT — read this before adding a capability:
	//
	//   - Member ABSENT          => legacy caller. The PDP emits obligations
	//     exactly as it did pre-9.11.0. Every SDK and every pre-9.11.0 PEP is in
	//     this bucket and is bit-identically unaffected.
	//   - Member `[]`            => still a LEGACY caller, deliberately. The
	//     state is sendable from Go since #3704 and distinguishable in the type,
	//     but its READING is unchanged; see
	//     DecideRequest.FulfillmentCapabilities.
	//   - Member NON-EMPTY       => capability-aware caller. The PDP emits only
	//     the obligations these capabilities can discharge and applies the org's
	//     obligation-fallback posture to any it suppresses.
	//   - UNKNOWN values are IGNORED (never an error, never a block): an older
	//     PDP meeting a newer PEP's vocabulary must degrade, not fail.
	//
	// #3704 NOTE. This block used to end: "An empty slice is indistinguishable
	// from absent on the wire (the field is `omitempty`), so it reads as legacy
	// — which is the FAIL-SAFE direction". Half of that expired and half of it
	// is load bearing, and telling them apart is the point of this note: `[]`
	// IS now sendable from Go and IS distinguishable in the type, but it still
	// READS as legacy, deliberately, because the server's decoder always
	// accepted those bytes from a non-Go caller and changing their meaning
	// would widen a security control for a caller that changed nothing.
	//
	// A headers-only seam should still advertise CapabilityRequestHeaderMutation
	// rather than `[]`: it is the TRUTHFUL declaration, and truthful beats
	// minimal.
	//
	// UNDER-advertising is always safe (you lose an obligation you could have
	// fulfilled, and the org fallback posture decides the outcome).
	// OVER-advertising is the dangerous direction — never advertise a capability
	// the seam cannot actually perform.

	// CapabilityRequestBodyRedaction means the seam can replace the request
	// payload it is about to forward with engine-redacted content — i.e. it can
	// discharge a request-phase redact_pii obligation via FulfillRequest. True
	// for body-capable seams (Envoy ext_proc, the agentgateway ExtMcp hook, an
	// in-process SDK interceptor). NOT true for Envoy ext_authz.
	CapabilityRequestBodyRedaction = "request_body_redaction"

	// CapabilityRequestHeaderMutation means the seam can add or overwrite
	// request headers before forwarding. True for ext_authz (its OkHttpResponse
	// carries header mutations) and ext_proc.
	//
	// No obligation type requires this capability today; it is part of the
	// vocabulary so a headers-only seam has a TRUTHFUL, non-empty capability set
	// to advertise (see the wire contract above), and so a future
	// header-injection obligation can be gated through the same mechanism
	// instead of growing a second one.
	CapabilityRequestHeaderMutation = "request_header_mutation"

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

	// ClientID identifies the CALLING SOFTWARE on `X-Axonflow-Client`, sent as
	// `<ClientID>/<ClientVersion>` on every engine round-trip this client
	// makes. An empty ClientID means NO HEADER, which is exactly the pre-#3660
	// behaviour for any PEP that does not opt in. An ID with an empty version
	// sends the bare id, which the agent counts in its explicit `unversioned`
	// bucket — see New for why that beats silence.
	//
	// WHAT IT IS FOR, AND WHAT IT IS NOT. The agent records the pair into
	// axonflow_client_version_requests_total (#2860), so a self-hosted fleet
	// can answer "which version of which integration is calling us". It is
	// TELEMETRY-ONLY on both sides: the agent's recorder is documented as never
	// consulted for auth or a verdict, and this client must never treat it as
	// a credential. Authentication is the HTTP Basic pair above.
	//
	// The agent validates the SHAPE, not a list of known ids — a lowercase slug
	// of [a-z0-9._-] up to 64 bytes, with a semver-ish version — so a new
	// caller is admitted without a server change, bounded by that counter's
	// per-process series cap. A value outside the shape is silently dropped
	// into axonflow_client_version_dropped_total{reason="invalid"} and never
	// becomes a label, so a malformed value here costs a datum, never a
	// request.
	ClientID      string
	ClientVersion string

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
	// clientHeader is the pre-rendered `<id>/<version>` value, or "" when the
	// caller did not supply both. Rendered ONCE at construction rather than per
	// request: it cannot change over the client's life, and building it in
	// newPost would put a string concat on every engine round-trip for a value
	// that is constant.
	clientHeader string
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
	// An ID with NO version sends the bare id, and that is deliberate rather
	// than a fallback nobody thought about.
	//
	// The agent's recorder maps a value with no "/" to the explicit
	// `client_version="unversioned"` bucket — a DISTINCT series, not a merge
	// into some other version's row. So an unbaked build (a `go build` without
	// the version ldflag: local dev, and every runtime-e2e harness) is counted
	// as "gateway-adapters, version unknown" instead of vanishing entirely.
	//
	// Sending nothing was the first shape here and it was wrong twice over: it
	// made the header untestable anywhere the binary is not baked, and it meant
	// the one deployment shape most likely to be misconfigured — a hand-built
	// binary — was also the one that reported nothing at all.
	clientHeader := ""
	switch {
	case cfg.ClientID != "" && cfg.ClientVersion != "":
		clientHeader = cfg.ClientID + "/" + cfg.ClientVersion
	case cfg.ClientID != "":
		clientHeader = cfg.ClientID
	}

	return &Client{
		endpoint:     endpoint,
		org:          cfg.OrgID,
		license:      cfg.LicenseKey,
		tenantID:     cfg.TenantID,
		connectorTag: connectorTag,
		clientHeader: clientHeader,
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
	// FulfillmentCapabilities advertises what this PEP's SEAM can discharge, so
	// the PDP never emits an obligation the caller cannot fulfill (#2958). Use
	// the Capability* constants, wrapped by AdvertiseCapabilities.
	//
	// A POINTER since #3704, so a Go client can SEND an empty list at all -
	// `[]string` with omitempty omits a nil slice and an empty one alike.
	//
	//	nil            -> member omitted   -> legacy caller
	//	&[]string{}    -> []               -> newly SENDABLE from Go
	//	&[]string{"a"} -> ["a"]            -> unchanged
	//
	// WHAT THE SERVER MAKES OF `[]` IS UNCHANGED, and #3704 got that wrong once
	// before correcting it. The first version read a present-and-empty list as
	// "a capability-aware caller whose seam discharges nothing", justified as
	// additive because the state had been unsendable. That was a claim about
	// this ENCODER, not about the wire: the server's decoder has always accepted
	// those bytes and any non-Go PEP could send them, so the new reading would
	// have moved an unchanged caller from "obligation emitted, the PEP fails
	// closed" to "obligation suppressed, org fallback posture" - default `log`,
	// i.e. allowed without the redaction. See
	// canonicalizeFulfillmentCapabilities in platform/agent for the full
	// statement.
	FulfillmentCapabilities *[]string `json:"fulfillment_capabilities,omitempty"`

	// Handshake is the ADR-065 capability declaration this call presents,
	// already rendered by contract.PEPHandshake.Encode.
	//
	// `json:"-"`: it is NOT a body member. It rides
	// contract.PEPHandshakeHeader, because one governed route
	// (/api/v1/access/evaluation) carries the standardised AuthZEN envelope
	// that this platform does not own, and a body member would need a second
	// carrier there. Carrying it on this struct rather than on the Client is
	// what lets ONE client declare different capability sets on different call
	// paths - which the gateway adapters need, since GateRequest is
	// body-capable and Decide is headers-only and both authenticate with the
	// same credential.
	//
	// Empty means no handshake is presented, which is byte-for-byte today's
	// request.
	Handshake string `json:"-"`
}

// AdvertiseCapabilities wraps a seam capability list for the wire.
//
// It COPIES, so a caller passing a package-level constant slice cannot have it
// mutated through the request, and it returns a non-nil pointer to a non-nil
// slice even for an empty input - which is the whole point: an empty
// advertisement must be sendable and must be distinguishable from silence. Pass
// nil to send nothing, which is the legacy shape.
func AdvertiseCapabilities(values []string) *[]string {
	out := make([]string, len(values))
	copy(out, values)
	return &out
}

// CallerIdentity is the gateway-asserted identity.
type CallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// Target.Type vocabulary (#3717).
//
// DECLARED HERE, in the package every PEP imports, because the alternative is
// what #3717 was: a free string at the construction site and a different free
// string at the comparison in platform/agent, with nothing linking them. The
// ext_mcp seam sent "mcp_tool", the PDP's tool-attribution gate compared
// against "tool", and every MCP-seam audit row was written with tool_server and
// tool_name empty. Nothing failed, because a row missing two optional fields is
// a valid row.
//
// A NEW SPELLING IS NOT AN OPTION HERE. Widening the PDP gate to accept a
// second spelling would have fixed the symptom and forked the vocabulary
// permanently; instead there is exactly one accepted value per target shape and
// the producers construct from these constants. TestDecideTargetTypeVocabulary
// (platform/agent) fails on any Target.Type string literal in the tree that is
// not one of them.
const (
	// TargetTypeLLM names a model call: Model + Provider carry the target.
	TargetTypeLLM = "llm"

	// TargetTypeTool names a tool call: Server + Tool carry the target, and
	// this is the ONLY value for which the PDP records tool attribution onto
	// the audit row (audit_logs.policy_details.tool_server / .tool_name) and
	// onto the descriptor a human approver sees.
	//
	// It does NOT follow that the tool name relaxes evaluation. Capability
	// scoping (#2801) is a separate question with its own precondition: a
	// target that ALSO names a Server describes a call the caller routes to a
	// backend it does not execute, and gets full evaluation (#3717). Setting
	// Server is therefore never a way to weaken enforcement — only to make the
	// audit row name the backend.
	TargetTypeTool = "tool"

	// TargetTypeAgent names an agent-to-agent call.
	TargetTypeAgent = "agent"

	// TargetTypeHTTP is what the ext_proc and ext_authz seams send. It is an
	// LLM-SHAPED target under a transport-flavoured name (it carries Model,
	// never Server/Tool), and it predates this vocabulary; it is declared so
	// the set describes the tree as it is rather than as the DecisionTarget
	// doc comment once claimed. Whether those two seams should send
	// TargetTypeLLM instead is a separate call with its own visible
	// consequence (the HITL queue descriptor for an LLM step-up reads "http"
	// today) and is tracked on the audit umbrella #3709 — it is deliberately
	// NOT folded into #3717, whose whole subject is not changing a value some
	// other consumer may already read.
	TargetTypeHTTP = "http"
)

// TargetTypes is the declared vocabulary, in one place so a guard can enumerate
// it instead of an author enumerating the spellings they happen to know.
var TargetTypes = []string{TargetTypeLLM, TargetTypeTool, TargetTypeAgent, TargetTypeHTTP}

// ContextKeyMCPMethod is the DecideRequest.Context member the MCP gateway seam
// stamps with the JSON-RPC method it is gating.
//
// It began as bounded decide context and is now also load-bearing (#3717): its
// PRESENCE is what tells the PDP that this request came through an in-path MCP
// gateway, and therefore that Target.Tool was chosen by the MCP client rather
// than by the party enforcing — which is the condition under which capability
// scoping's trust premise fails and the relaxation is withheld.
//
// Reading it that way is safe WITHOUT trusting the caller, and that is the
// whole reason it can be a context member instead of an authenticated one: a
// caller who sets it spuriously gets MORE evaluation, never less. It is
// declared here rather than spelled at both ends precisely because a producer
// string facing a consumer string with nothing linking them is what #3717 was.
const ContextKeyMCPMethod = "mcp_method"

// Target describes what the gateway is about to call.
//
// MIRRORED by agent.DecisionTarget, which is the decoder on the other side of
// the wire. The mirror is deliberate — it is what makes the wire contract
// testable rather than tautological — and it is DRIFT-GUARDED by
// TestDecisionTargetMirrorsPEPTarget, which compares the two field sets by
// reflection. Server was missing from this side until #3717, so no PEP built on
// the blessed client could populate audit_logs' tool_server at all, whatever
// Type it sent.
type Target struct {
	Type     string `json:"type,omitempty"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Server is the tool's hosting server (an MCP backend name), when
	// Type == TargetTypeTool.
	Server string `json:"server,omitempty"`
	Tool   string `json:"tool,omitempty"`
}

// DecideResponse is the PDP verdict.
//
// IT HAS NO `Error` MEMBER, AND THAT IS A REMOVAL (#3724, v10.4.0). One was
// carried here from #2563 and was unreachable by construction: Decide only
// decodes a 200 body into this type, and the platform's 200 body is
// DecideResponse in decision_handler.go, which has no such field. The error
// envelope is a DIFFERENT shape - sendDecideError's `{error, verdict, ...}`,
// published as DecideErrorResponse - and it arrives as a non-200, which Decide
// surfaces as ErrDecisionRejected or ErrPDPUnavailable with the body attached.
//
// Leaving it was worse than cosmetic: a PEP author writing
// `if resp.Error != ""` gets a branch that can never be true, and would
// believe they had handled PDP failure while every real failure came back
// through the `error` return they were not checking. Nothing in this tree read
// it, no server has ever populated it, and removing it changes no bytes in
// either direction - JSON decoding ignores members with no field.
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
	httpReq, err := c.newPost(ctx, decidePath, body, incomingTraceparent, req.Handshake)
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
	httpReq, err := c.newPost(ctx, requestRedactionPath, reqBody, "", "")
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
// handshake is the rendered ADR-065 declaration, or "" for none. It is a
// parameter rather than a Client field so that ONE function still sets every
// header this client sends while the VALUE can vary per call - the gateway
// adapters' two seams declare different capability sets through one client.
func (c *Client) newPost(ctx context.Context, path string, body []byte, incomingTraceparent, handshake string) (*http.Request, error) {
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
	// Set HERE, in the one function that builds every request this client
	// makes, so the decide call and both fulfillment calls carry it without
	// three call sites having to remember. Absent when unconfigured, which is
	// the unchanged behaviour for every caller that does not opt in.
	if c.clientHeader != "" {
		req.Header.Set("X-Axonflow-Client", c.clientHeader)
	}
	// The ADR-065 capability declaration. Set, never added, so a caller cannot
	// produce two header lines an intermediary would join - a joined pair
	// decodes to malformed rather than to either half, but the refusal an
	// operator then sees would name this client rather than the framework that
	// merged them.
	//
	// X-Axonflow-Client and this header answer DIFFERENT questions and neither
	// is derived from the other: the first says which client LIBRARY made the
	// call, the second says which ENFORCEMENT POINT this is and what it can
	// discharge. Inferring one from the other would be a server-side table of
	// "library X version Y implies capability set Z", maintained for clients
	// that ship independently and wrong for every build that disagrees with its
	// version string.
	if handshake != "" {
		req.Header.Set(contract.PEPHandshakeHeader, handshake)
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
