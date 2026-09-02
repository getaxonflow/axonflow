// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

// Decision Mode handler (ADR-056, epic #2426).
//
// POST /api/v1/decide is the Decision API endpoint -- the same policy engine
// Gateway Mode's POST /api/policy/pre-check uses, surfaced for a different
// caller. Gateway Mode is called by application code; Decision Mode is called
// by the customer's infrastructure gateway (PEP), which enforces the verdict.
// Both share the same shared-policy engine; only the request/response shape
// and the caller differ.
//
// M1 scope: static policies only (PII detection, SQL injection, dangerous
// patterns, RBI India PII) to keep the inline RPC budget in single-digit
// milliseconds. Dynamic/custom policy support (orchestrator round-trip) is
// M2 scope per the epic.
//
// OTel: each decision emits an OpenTelemetry span via the
// platform/agent/telemetry package (#2437) and returns a W3C-compatible
// 32-hex trace_id in the response. If the caller passes a W3C traceparent
// header, its trace_id is reused so the gateway can stitch multi-layer
// decisions into one end-to-end trace (WS4). Otherwise a fresh trace_id
// is minted. When AXONFLOW_OTEL_ENDPOINT is unset the noop tracer runs
// and trace_id is locally generated via crypto/rand.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"axonflow/platform/agent/circuitbreaker"
	"axonflow/platform/agent/fincrime"
	"axonflow/platform/agent/hitl"
	"axonflow/platform/agent/telemetry"
	sharedaudit "axonflow/platform/shared/audit"
	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/pep"

	"axonflow/platform/decision/legacycompile"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

// Verdict values returned by the Decision API ON THE WIRE.
//
// These are the PEP-enforcement contract (OpenAPI agent-api.yaml
// `enum: [allow, deny, needs_approval]` — "the PEP MUST enforce this verdict")
// and are compared by the blessed PEP client (platform/shared/pep.VerdictAllow).
// They MUST NOT change value — doing so silently breaks every PEP/SDK in the
// field. They are DELIBERATELY DISTINCT from the canonical audit_logs vocabulary
// below (#2643 / #2638): the wire verdict is the caller contract, the audit
// verdict is the persisted decision label. writeDecisionAuditLog translates one
// to the other via canonicalAuditVerdict (on the decision plane) so
// audit_logs.policy_decision is canonical without disturbing the wire.
const (
	VerdictAllow         = "allow"
	VerdictDeny          = "deny"
	VerdictNeedsApproval = "needs_approval"
	decisionHandlerPath  = "/api/v1/decide"
	// decisionResponseDefaultTTL is the default expires_at delta returned
	// to the PEP. Override with AXONFLOW_DECISION_EXPIRES_AFTER (a Go
	// time.Duration string, e.g. "30s", "2m"). Regulated tenants typically
	// want a shorter cache window than the default 5min.
	decisionResponseDefaultTTL = 5 * time.Minute
	envDecisionExpiresAfter    = "AXONFLOW_DECISION_EXPIRES_AFTER"

	// envDecisionContextAllowlist names the comma-separated allowlist of
	// request-context keys the Decision API persists + traces. Customer-
	// supplied DecideRequest.context may carry arbitrary keys (secrets,
	// PII, oversized values); only keys matching this allowlist survive
	// into the OTel span + audit JSONB. Entries are matched case- and
	// separator-insensitively (X-AI-Agent == x-ai-agent == x_ai_agent);
	// a trailing "*" makes the entry a prefix match (x-tenant-*).
	// Empty / unset falls back to defaultDecisionContextAllowlist.
	envDecisionContextAllowlist = "AXONFLOW_DECISION_CONTEXT_ALLOWLIST"

	// Per-key / per-value / key-count caps applied during canonicalization.
	// The value cap (256 bytes, rune-safe) keeps each emitted span attribute
	// well under the 32 KiB collector ceiling; the key cap (32 chars) keeps
	// attribute names bounded; the count cap (10) bounds the per-span
	// attribute count and trips the truncated flag when exceeded.
	maxContextKeyLen   = 32
	maxContextValueLen = 256
	maxContextKeys     = 10
)

// Canonical audit_logs.policy_decision vocabulary (#2643 / #2638 / ADR-058).
//
// These are now ALIASES onto the single shared vocabulary in
// platform/shared/audit (#2638 S-WRITERS const-swap) — the one source of truth
// every plane's audit writer converges on, so a query over
// audit_logs.policy_decision is consistent across the decision / mcp / llm /
// agent planes and enforced by the migration-123 CHECK. The names are retained
// (decision-plane provenance, used by this file + tests); the VALUES come from
// the shared package so they can never drift. DISTINCT from the wire Verdict*
// values above: the legacy wire tokens `allow`/`deny` are value-WRONG for
// audit_logs, so the /decide writer translates them via canonicalAuditVerdict.
const (
	AuditVerdictAllowed  = sharedaudit.DecisionAllowed
	AuditVerdictBlocked  = sharedaudit.DecisionBlocked
	AuditVerdictRedacted = sharedaudit.DecisionRedacted
	AuditVerdictError    = sharedaudit.DecisionError
)

// auditPolicyDecisionFor returns the value written to audit_logs.policy_decision
// for one plane's verdict.
//
// It is a named function rather than an inline condition so a TEST can call the
// real predicate. The inline version was guarded by a test that iterated planes
// and then called canonicalAuditVerdict directly, never touching the plane
// condition at all -- the plane appeared only in the failure message. That test
// passed with the allow-list mutated, which is exactly the defect it was written
// to prevent.
//
// THE ALLOW-LIST. These planes emit the WIRE vocabulary (`allow`/`deny`) and
// need canonicalizing. The MCP planes already emit the canonical vocabulary
// directly and are excluded, per #2643: re-canonicalizing them is a no-op at
// best, and `override_lifecycle` -- which the column accepts and which is not a
// verdict -- would be rewritten to `error` by the canonicalizer. So this cannot
// become an unconditional call.
//
// A plane missing from the list writes the raw wire verdict, which violates the
// audit_logs_policy_decision_check constraint. Because the insert is
// deliberately non-fatal, that loses the row while the caller still receives a
// 200 -- silent, and invisible to any sqlmock-backed test.
func auditPolicyDecisionFor(plane, verdict string) string {
	switch plane {
	case PlaneDecision, PlaneOpenAICompat, PlaneAccessEvaluation:
		return canonicalAuditVerdict(verdict)
	default:
		return verdict
	}
}

// canonicalAuditVerdict maps a verdict — either a wire Verdict* value OR an
// already-canonical audit value — onto the canonical audit_logs vocabulary.
//
//   - allow  -> allowed   deny -> blocked   needs_approval -> needs_approval
//   - already-canonical values pass through unchanged (idempotent), so a caller
//     may pass AuditVerdictError/Blocked directly for a path that has no wire
//     verdict (e.g. a malformed-request early return).
//   - an UNRECOGNIZED value fails SAFE to `error` (never `allowed`), so a future
//     verdict can never silently inflate the allowed/compliance counts.
//
// Localized to the audit-write boundary on purpose: the OTel decision span and
// the wire response keep the caller-facing verdict untouched.
func canonicalAuditVerdict(v string) string {
	switch v {
	case VerdictAllow:
		return AuditVerdictAllowed
	case VerdictDeny:
		return AuditVerdictBlocked
	case VerdictNeedsApproval:
		return sharedaudit.DecisionNeedsApproval // wire + audit spelling coincide
	case AuditVerdictAllowed, AuditVerdictBlocked, AuditVerdictRedacted, AuditVerdictError:
		return v
	default:
		log.Printf("⚠️ [Decide] unrecognized verdict %q → recording canonical 'error' (fail-safe)", v)
		return AuditVerdictError
	}
}

// defaultDecisionContextAllowlist is the default for
// AXONFLOW_DECISION_CONTEXT_ALLOWLIST: the common agent / session / leader
// identity headers. Deployments that capture additional headers (e.g. a
// tenant-scoped family) set AXONFLOW_DECISION_CONTEXT_ALLOWLIST explicitly — a
// trailing "*" is a prefix match. Entries are hyphen form; matching normalizes both sides.
var defaultDecisionContextAllowlist = []string{
	"x-ai-agent",
	"x-session-id",
	"x-leader-identity",
}

// Stage values accepted by the Decision API. Mirrors the three gateway layers
// in the ADR-056 reference architecture (agent / MCP / LLM).
const (
	DecisionStageLLM   = "llm"
	DecisionStageTool  = "tool"
	DecisionStageAgent = "agent"
)

// Plane (surface) discriminator values for the audit_logs.plane column
// (#2592 / ADR-058 Decision-1). Identifies which gateway/surface emitted a
// decision so a single query over audit_logs can return every block across
// every plane. Distinct from the per-request `stage` (llm/tool/agent): plane
// is the SURFACE (which PEP wrote the row), stage is the request shape.
const (
	PlaneDecision     = "decision"      // POST /api/v1/decide (the Decision API itself)
	PlaneMCP          = "mcp"           // MCP check-input / check-output handlers
	PlaneLLM          = "llm"           // LLM gateway PEP
	PlaneAgent        = "agent"         // agent gateway PEP
	PlaneGateway      = "gateway"       // generic reference PEP adapter
	PlaneOpenAICompat = "openai_compat" // OpenAI-compatible chat-completions surface
	PlaneMedia        = "media"         // orchestrator media-governance analysis (#2680)
	PlaneCowork       = "cowork"        // Claude Desktop (Cowork) OTEL ingest plane (#2760 / WS-6)
	PlaneClaudeCode   = "claude_code"   // Claude Code native OTEL ingest plane (#2760 / WS-6)
)

// Caller-origin buckets for the decision metrics `origin` label (WS-5, #2761).
//
// This is a CLOSED, low-cardinality enum: every request maps to exactly one of
// these constants via classifyDecisionOrigin. Raw hostnames, emails, and client
// version strings are NEVER used as label values (that would be a cardinality
// bomb + a PII leak); they are bucketed down to the integration family. New
// integrations get a new constant here, not a free-form value.
const (
	OriginClaudeCode    = "claude-code"    // Claude Code plugin (X-Axonflow-Client: claude-code-plugin | claude-code/<v>)
	OriginClaudeDesktop = "claude-desktop" // Claude Desktop governance proxy (gateway_id claude_desktop.<host>)
	OriginSDK           = "sdk"            // Any language SDK (X-Axonflow-Client: sdk-<lang>/<v>)
	OriginPlugin        = "plugin"         // Other coding-agent plugins (openclaw, cursor-plugin, codex-plugin, *-plugin)
	OriginGateway       = "gateway"        // A generic infrastructure PEP that asserted a caller_identity.gateway_id
	OriginUnknown       = "unknown"        // No recognizable client header and no gateway_id
)

// classifyDecisionOrigin buckets a /decide caller into one of the low-cardinality
// OriginXxx values from two signals:
//
//   - clientHeader: the X-Axonflow-Client request header (ADR-050 §4 convention,
//     e.g. "claude-code-plugin", "sdk-go/1.2.3", "openclaw/2.1.0"). Only the
//     segment before the first '/' (the client id, sans version) is inspected.
//   - gatewayID: the sanitized caller_identity.gateway_id (e.g.
//     "claude_desktop.<host>") — the /decide-native origin signal an
//     infrastructure PEP asserts. Only its LEADING family token is used; the
//     host suffix is never surfaced as a label.
//
// The gateway_id claude_desktop marker is authoritative for Desktop (the Desktop
// proxy asserts a gateway_id and may not send an X-Axonflow-Client header), so
// it is checked first. Everything unrecognized but gateway-asserted falls to
// `gateway`; a request with neither signal is `unknown`. The result is always a
// bucket constant — never caller-controlled free text — so it is safe as a
// Prometheus label and an OTel span dimension.
func classifyDecisionOrigin(clientHeader, gatewayID string) string {
	// gateway_id is the /decide-native origin; claude_desktop is authoritative
	// (the Desktop proxy asserts it and may omit X-Axonflow-Client).
	gw := strings.ToLower(strings.TrimSpace(gatewayID))
	if strings.HasPrefix(gw, "claude_desktop") || strings.HasPrefix(gw, "claude-desktop") {
		return OriginClaudeDesktop
	}

	// X-Axonflow-Client header: the plugin/SDK identity. Strip the version
	// suffix so "claude-code/1.6.0" and "claude-code-plugin" both bucket the same.
	ch := strings.ToLower(strings.TrimSpace(clientHeader))
	if slash := strings.IndexByte(ch, '/'); slash >= 0 {
		ch = ch[:slash]
	}
	switch {
	case ch == "claude-code" || ch == "claude-code-plugin":
		return OriginClaudeCode
	case strings.HasPrefix(ch, "claude-desktop") || ch == "mcp-proxy":
		// mcp-proxy is the Desktop governance proxy's on-wire client id
		// (#2860, axonflow-claude-desktop-plugin). The gateway_id check above
		// stays authoritative; this keeps the bucket correct even for a call
		// that carries the header without a claude_desktop gateway_id.
		return OriginClaudeDesktop
	case strings.HasPrefix(ch, "sdk-"):
		return OriginSDK
	case ch == "openclaw" || strings.HasSuffix(ch, "-plugin"):
		return OriginPlugin
	}

	// A generic PEP that asserted some gateway_id but no recognized client
	// header still gets a stable bucket; a request with no signal at all is
	// unknown. Both keep the label a bounded enum.
	if gw != "" {
		return OriginGateway
	}
	return OriginUnknown
}

// Obligation contract constants (ADR-056, #2563).
const (
	// ObligationRedactPII is the obligation a PEP discharges by replacing the
	// request content with engine-redacted content before forwarding.
	ObligationRedactPII = "redact_pii"

	// ObligationPhaseRequest / ObligationPhaseResponse are the two fulfillment
	// phases. /decide runs pre-call, so it only ever emits request-phase
	// obligations; the response-phase value is named in the contract for PEP
	// helpers that fan out to the response-redaction endpoint after the call.
	ObligationPhaseRequest  = "request"
	ObligationPhaseResponse = "response"

	// requestRedactionEndpoint is the engine endpoint a PEP POSTs to in order
	// to discharge a request-phase redact_pii obligation. ADR-056 settles the
	// "request-phase redaction has no home" question in favour of extending
	// check-input (the request gate) to return engine-redacted content, keeping
	// it symmetric with check-output (the response gate) and keeping /decide a
	// pure PDP. The "/mcp/" path segment is historical; in gateway/PDP mode the
	// endpoint is connector-agnostic (the PEP passes a synthetic connector tag).
	requestRedactionEndpoint = "/api/v1/mcp/check-input"

	// (The response-phase fulfillment endpoint — /api/v1/mcp/check-output — is
	// not referenced here: /decide runs pre-call and only emits request-phase
	// obligations. Response-phase fulfillment lives in the PEP client, which
	// fans out to check-output after the backend call. See platform/shared/pep.)

	// contentTypeText is the only redaction content-type wired today. Media
	// (image/*, application/pdf) routes to the existing orchestrator media-
	// governance subsystem via the detector seam — see RequestRedactionDetector
	// in request_redaction_detector.go.
	contentTypeText = "text/plain"
)

// newRedactPIIObligation builds a self-describing request-phase redact_pii
// obligation. Centralized so every emission site carries identical, complete
// Fulfillment metadata — a PEP must never have to infer the endpoint OR which
// content modalities the endpoint can redact.
func newRedactPIIObligation(detail string) DecisionObligation {
	return DecisionObligation{
		Type:   ObligationRedactPII,
		Detail: detail,
		Fulfillment: &ObligationFulfillment{
			Endpoint:     requestRedactionEndpoint,
			Method:       http.MethodPost,
			Phase:        ObligationPhaseRequest,
			ContentTypes: requestRedactionContentTypes(),
		},
	}
}

// DecideRequest is the inbound contract for POST /api/v1/decide.
// Required: stage, query. caller_identity.gateway_id is recommended so the
// audit trail records which gateway layer issued the decision. user_token
// is OPTIONAL -- in enterprise mode a PEP that supplies one gets the
// validated-user record on the audit row; a PEP that doesn't (the common
// case for infrastructure gateways) gets a synthesized service user.
type DecideRequest struct {
	Stage          string                 `json:"stage"`
	CallerIdentity DecisionCallerIdentity `json:"caller_identity"`
	Target         DecisionTarget         `json:"target"`
	Query          string                 `json:"query"`
	UserToken      string                 `json:"user_token,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
	// FulfillmentCapabilities is the caller's advertised seam capability set
	// (#2958) — see pep.CapabilityRequestBodyRedaction for the wire contract.
	// Absent/empty means a legacy (pre-9.11.0) PEP and reproduces the previous
	// behavior exactly: obligations are emitted regardless of the seam.
	//
	// THREAT MODEL — this is client-supplied input that STEERS a policy outcome
	// (advertising a set WITHOUT request_body_redaction downgrades a request-body
	// redaction to the org's obligation-fallback posture), so it deserves the
	// explicit reasoning:
	//
	//   - It crosses NO new trust boundary. The obligation model ALREADY trusts
	//     the authenticated PEP to actually perform the redaction it is told to
	//     perform — the PDP cannot verify fulfillment. A caller dishonest enough
	//     to under-advertise could simply ignore the obligation instead, which
	//     is strictly worse for it (it forwards content the org wanted masked
	//     with no audit record); under-advertising at least produces the audit
	//     row this change adds.
	//   - It can never WIDEN authority: the outcome of a suppressed obligation is
	//     resolved SERVER-SIDE from the org's posture (ResolveObligationFallbackAction),
	//     never from the request. An org that refuses detect-and-log sets the
	//     posture to block and a dishonest advertisement then yields a DENY.
	//   - It cannot reach any other decision input: the field is read at exactly
	//     ONE site (applySeamCapabilityObligations). That is pinned by
	//     TestFulfillmentCapabilityReadCensus (decision_obligation_capability_test.go),
	//     so a second read site fails CI.
	FulfillmentCapabilities []string `json:"fulfillment_capabilities,omitempty"`
}

// DecisionCallerIdentity is the gateway-asserted identity for the request.
// org_id / tenant_id are optional in the body -- the auth-derived identity
// from apiAuthMiddleware is authoritative. Body-supplied values are accepted
// only when they match the auth-derived identity (or in community mode).
type DecisionCallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// DecisionTarget describes what the gateway is about to call.
type DecisionTarget struct {
	Type     string `json:"type,omitempty"`     // "llm" | "tool" | "agent"
	Model    string `json:"model,omitempty"`    // when type=llm
	Provider string `json:"provider,omitempty"` // when type=llm
	Server   string `json:"server,omitempty"`   // when type=tool (#2904)
	Tool     string `json:"tool,omitempty"`     // when type=tool
}

// DecideResponse is the verdict returned to the PEP.
// trace_id is W3C-format (32 lowercase hex chars). decision_id is a fresh
// UUID per request, used for audit-log correlation. obligations is always a
// non-nil slice so PEP code can iterate without a nil-check.
type DecideResponse struct {
	Verdict           string               `json:"verdict"`
	DecisionID        string               `json:"decision_id"`
	TraceID           string               `json:"trace_id"`
	Reasons           []string             `json:"reasons,omitempty"`
	Obligations       []DecisionObligation `json:"obligations"`
	EvaluatedPolicies []string             `json:"evaluated_policies"`
	Stage             string               `json:"stage,omitempty"`
	ExpiresAt         time.Time            `json:"expires_at"`
}

// DecisionObligation is a PEP-side requirement attached to an allow verdict
// (e.g. redact PII before forwarding the call).
//
// Obligations are SELF-DESCRIBING and ENGINE-FULFILLABLE (ADR-056, #2563):
// `/decide` is a pure PDP and never mutates content, so a redact_pii obligation
// is not "go redact this yourself with your own patterns" — it is "call the
// AxonFlow engine endpoint named in Fulfillment to obtain engine-redacted
// content." The Fulfillment block tells the PEP exactly which endpoint, method,
// and phase discharges the obligation, so no PEP ever hand-rolls a regex
// (which is how the desktop proxy's redact.go ended up punting US SSN). The
// blessed client path is platform/shared/pep.
type DecisionObligation struct {
	Type        string                 `json:"type"`                  // e.g. "redact_pii"
	Detail      string                 `json:"detail,omitempty"`      // human-readable detail for audit logs
	Fulfillment *ObligationFulfillment `json:"fulfillment,omitempty"` // how the PEP discharges this via the engine
}

// ObligationFulfillment names the engine call a PEP makes to discharge an
// obligation. It exists so fulfillment is a property of the contract, not of
// PEP-author discipline: a conforming PEP POSTs the obligation's source content
// to Endpoint and forwards the engine-redacted content the endpoint returns.
// There is no other blessed way to satisfy a redact_pii obligation — client-
// side redaction is forbidden by ADR-056.
//
// Phase distinguishes which content the PEP submits:
//   - "request"  -> the PEP redacts the request it is about to forward
//     (the `query` it asked /decide about), via the request-redaction endpoint.
//   - "response" -> the PEP redacts a backend response before returning it,
//     via the response-redaction endpoint (check-output). /decide itself runs
//     pre-call so it only emits request-phase obligations; the response-phase
//     value is part of the contract for PEP helpers that fan out to both.
//
// ContentTypes advertises the mime-types the endpoint's redaction detectors can
// handle today (e.g. "text/plain"). The contract is deliberately content-type-
// agnostic: a PEP holding content of a type NOT in this list (an image awaiting
// OCR-PII redaction, say) must fail closed rather than forward it unredacted.
// Adding media is a server-side detector registration plus a new entry here —
// NOT a redesign of this shape. This is the same lesson as the connector trap
// (#2563): don't bake a single content modality into the contract.
type ObligationFulfillment struct {
	Endpoint     string   `json:"endpoint"`                // engine path, e.g. "/api/v1/mcp/check-input"
	Method       string   `json:"method"`                  // HTTP method, e.g. "POST"
	Phase        string   `json:"phase"`                   // "request" | "response"
	ContentTypes []string `json:"content_types,omitempty"` // mime-types the endpoint can redact today
}

// Decision Mode Prometheus metrics. Mirrors gateway pre-check shape so
// dashboards already wired for Gateway Mode can be reused.
//
// The `origin` label (WS-5, #2761) buckets the caller integration —
// claude-code / claude-desktop / sdk / plugin / gateway / unknown, derived from
// the X-Axonflow-Client header and caller_identity.gateway_id via
// classifyDecisionOrigin. It is a CLOSED, low-cardinality enum by construction
// (never a raw hostname/email/version), so per-integration filtering (e.g.
// "Claude Code traffic only") is possible without a cardinality blow-up.
var (
	decideRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_decision_requests_total",
			Help: "Total POST /api/v1/decide requests by verdict, stage and caller origin",
		},
		[]string{"verdict", "stage", "origin"},
	)
	decideDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_decision_duration_milliseconds",
			Help:    "POST /api/v1/decide handler duration (ms) by caller origin",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		},
		[]string{"origin"},
	)
	// decideObligations counts obligations attached to an allow verdict — today
	// only redact_pii — so a dashboard can surface "allowed-with-redaction"
	// (the closest thing to a `redacted` outcome on the decision plane, where
	// redaction is an OBLIGATION on allow, not a distinct wire verdict). Labels
	// are all bounded low-cardinality: obligation type (a fixed enum),
	// stage (llm|tool|agent) and origin (the WS-5 caller bucket).
	decideObligations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_decision_obligations_total",
			Help: "Obligations attached to a POST /api/v1/decide allow verdict (e.g. redact_pii) by type, stage and caller origin",
		},
		[]string{"obligation", "stage", "origin"},
	)
	// decideObligationFallbacks counts obligations the PDP WITHHELD because the
	// caller advertised a seam that cannot fulfill them (#2958), labelled by the
	// posture applied (log → allowed with an audit record; block → denied). This
	// is the signal that a seam is receiving content it cannot govern — e.g. a
	// headers-only ext_authz leg fronting an LLM that is being sent PII. All
	// labels are bounded: obligation type (fixed enum), action (log|block),
	// stage (llm|tool|agent), origin (the WS-5 caller bucket).
	decideObligationFallbacks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_decision_obligation_fallbacks_total",
			Help: "Obligations suppressed because the caller's seam cannot fulfill them, by obligation type, org fallback posture (log|block), stage and caller origin",
		},
		[]string{"obligation", "action", "stage", "origin"},
	)
	// decideBlocks counts deny verdicts keyed by the single blocking policy so a
	// dashboard can rank "top blocked policies". The `policy` label is BOUNDED to
	// a low-cardinality set by boundedBlockPolicy: a SYSTEM/ENTERPRISE-tier policy
	// keeps its human-readable seeded id (e.g. sys_sqli_union_select,
	// rbi_pii_protection — a fixed, bounded set), but a per-tenant / per-org custom
	// policy (tier=tenant|organization, id "custom_<hex>") is COLLAPSED to the
	// single bucket "tenant_custom". This matters because /decide loads tenant +
	// global policies (loader: WHERE tenant_id=$1 OR tenant_id='global'), so a
	// custom static policy in an evaluated category CAN be the blocking policy —
	// and its id is effectively unbounded across tenants (no tenant label here), so
	// surfacing it raw would be a cardinality bomb. Only the SINGLE blocking policy
	// is recorded per deny (never the full triggered list).
	decideBlocks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_decision_blocks_total",
			Help: "POST /api/v1/decide deny verdicts by blocking policy (system/enterprise id kept, per-tenant custom collapsed to tenant_custom) and caller origin",
		},
		[]string{"policy", "origin"},
	)
	// decideAuditWriteFailures makes the best-effort canonical audit_logs write
	// OBSERVABLE instead of silent (#2643 DECIDE-WRITE-BESTEFFORT-SILENT). Reason
	// labels: `nodb` (no usage DB wired — expected in DB-less community
	// deployments), `empty_decision_id` (guard), `marshal` (policy_details
	// JSONB), `insert` (the INSERT itself). reason=insert|marshal indicates a
	// real persistence failure to alert on; reason=nodb is informational. A
	// write failure on a DENY path never changes the verdict — the request is
	// already denied — so this is alerting signal, not a control.
	//
	// Two further reasons come from the AuthZEN surface's amendment of a row
	// this writer already committed (authzen_handler.go): the withholding rule
	// runs after the delegated evaluation has audited its own permit, so the row
	// has to be corrected to say what the caller was told.
	// `authzen_withheld_amend` is the UPDATE erroring and
	// `authzen_withheld_amend_norow` is it matching nothing — the second being
	// the silent one, since the durable record then still reads `allowed` for a
	// request answered `{"decision":false}`. They are values on THIS series
	// rather than a metric of their own because they mean exactly what it
	// already means: the audit trail does not describe what happened.
	decideAuditWriteFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_decision_audit_write_failures_total",
			Help: "Canonical audit_logs write failures by reason (nodb|empty_decision_id|marshal|insert|authzen_withheld_amend|authzen_withheld_amend_norow)",
		},
		[]string{"reason"},
	)
)

func init() {
	_ = prometheus.Register(decideRequests)
	_ = prometheus.Register(decideDuration)
	_ = prometheus.Register(decideObligations)
	_ = prometheus.Register(decideObligationFallbacks)
	_ = prometheus.Register(decideBlocks)
	_ = prometheus.Register(decideAuditWriteFailures)
}

// handleDecide handles POST /api/v1/decide -- Decision Mode entry point.
//
// Flow mirrors handlePolicyPreCheck (gateway_handlers.go) so a single policy
// engine evaluation answers both Gateway Mode (application caller) and
// Decision Mode (infrastructure-gateway caller). Differences from pre-check:
//
//   - request shape is stage/target oriented (vs. data_sources oriented)
//   - response carries verdict (allow/deny/needs_approval) and a W3C trace_id
//     rather than a context_id, because Decision Mode is one-shot per
//     gateway hop (no follow-up audit call)
//   - circuit-breaker trips return HTTP 503 so the PEP adapter can apply its
//     configured fail-open / fail-closed posture (ADR-056 §Components)
func handleDecide(w http.ResponseWriter, r *http.Request) {
	// #3092 defence in depth. This route is registered `.Methods("POST",
	// "OPTIONS")` so a preflight does not 404, and apiAuthMiddleware now
	// TERMINATES OPTIONS rather than forwarding it. Neither fact is this
	// handler's to rely on: the decision engine is reachable only by an
	// authenticated POST, so it refuses anything else itself. Without this,
	// re-adding a method to the registration — or reintroducing the preflight
	// passthrough — silently hands an anonymous caller a full policy
	// evaluation plus an audit_logs row with empty tenancy.
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()
	ctx := r.Context()

	// #2896: trust-gated attribution identity. The desktop proxy (and any PEP
	// fronting multiple principals behind one org:license credential) asserts
	// the end-user via X-User-Email / X-Session-Id. Honored for audit
	// ATTRIBUTION ONLY, and only when the deployment opted in via
	// AXONFLOW_TRUST_IDENTITY_HEADERS — a forgeable header must never be
	// trusted by default. Both resolve to "" when absent or untrusted; the
	// session id rides the context so writeDecisionAuditLog persists it into
	// audit_logs.session_id (same mechanism as the MCP writers, #2753).
	// #2922: canonicalize (lower+trim) so the /decide plane stamps the SAME
	// identity key into audit_logs.user_email that the MCP-server plane stamps
	// and the role-scoped read path filters on — a mixed-case header here
	// previously wrote rows the same user's scoped read could not match
	// (the #2920 gap-2 silent-failure trap, closed on the MCP plane only).
	attributedEmail := sharedidentity.CanonicalEmail(
		trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen))
	if sid := attributedSessionID(r); sid != "" {
		ctx = withClientSessionID(ctx, sid)
		r = r.WithContext(ctx)
	}

	// #2643: mint the correlation ids + capture the auth-derived identity
	// UP-FRONT, before body decode, so EVERY early-return deny below — a decode
	// failure, an invalid stage, a cross-tenant/org impersonation attempt — writes
	// a canonical, correlatable plane=decision audit_logs row instead of returning
	// invisibly. apiAuthMiddleware has already stamped tenant/org/client into ctx,
	// so the identity is available even when the body never parses. The same
	// decision_id/trace_id ride the error envelope returned to the PEP.
	//
	// W3C trace_id: reuse the incoming traceparent trace-id when present so
	// multi-layer gateways stitch into one end-to-end trace (WS4); otherwise mint
	// a fresh 16-byte (32 hex) id.
	// Read ONCE per request. Reading it at each use fired the test observer
	// twice and made the assertion depend on which read happened last.
	plane := decisionPlaneFromContext(ctx)
	traceID := traceIDFromHeader(r.Header.Get("traceparent"))
	if traceID == "" {
		traceID = newW3CTraceID()
	}
	decisionID := uuid.New().String()
	authClientID := ClientIDFromContext(ctx)
	tenantID := TenantIDFromContext(ctx)
	orgID := OrgIDFromContext(ctx)
	authKind := AuthKindFromContext(ctx)

	// WS-5 (#2761): bucket the caller integration into the low-cardinality
	// `origin` metric/span label. Computed up-front from the X-Axonflow-Client
	// header so even the pre-decode early-return denies below carry an origin;
	// refreshed once caller_identity.gateway_id is parsed (gateway_id is the
	// authoritative Claude Desktop signal). clientHeader is read but never
	// emitted raw — classifyDecisionOrigin maps it to a bucket constant.
	clientHeader := r.Header.Get("X-Axonflow-Client")
	origin := classifyDecisionOrigin(clientHeader, "")

	// #2860: Enterprise per-client version-distribution telemetry — record the
	// validated client/version pair (e.g. mcp-proxy/0.3.0) for the decide
	// plane. This used to carry its own POST-only guard, because
	// apiAuthMiddleware forwarded CORS preflights UNAUTHENTICATED straight to
	// this handler and recording on OPTIONS would let an anonymous caller mint
	// label series and exhaust the per-process series cap, permanently
	// blinding the distribution. #3092 moved that guard to the top of the
	// handler where it protects the whole body rather than this one call, so
	// an authenticated POST is again the only request that reaches here.
	// Telemetry-only +
	// fail-open by contract (community no-op): a missing/garbage header is
	// dropped inside the recorder and can never influence the verdict below —
	// a version-bearing caller whose POST is later DENIED by policy still
	// lands in the distribution (denies are traffic too; this plane counts
	// attempts, unlike the post-decode check-output plane).
	recordClientVersionTelemetry(plane, clientHeader)

	// Canonicalized request context (#2509) is computed after a successful decode
	// (it needs req.Context); declared here so the early-deny audit closure can
	// thread whatever is known so far — nil before decode.
	var reqContext map[string]string
	var contextTruncated bool

	// Audit identity for the row, refined as the request is parsed/authorized and
	// threaded into every recordDecideDecision call (incl. the early-return
	// denies) so the decision is listable via GET /api/v1/decisions + explainable.
	// correlationID is the SHARED cross-stage key (#2598): the inbound traceparent
	// trace-id (or the freshly minted one), stable across the PEP's llm/tool/agent
	// hops. Captured here, before recordDecideDecision may swap the RETURNED
	// trace_id for an OTel-assigned one.
	decisionAudit := &decisionAuditInput{
		clientID:  authClientID,
		requestID: decisionID,
		// The SURFACE the decision arrived through. It is read from the context
		// rather than hardcoded because this handler serves more than one
		// route: the AuthZEN adapter delegates to it, and folding that traffic
		// into `decision` would make the new surface's adoption unmeasurable
		// and leave the v11 cutover unable to tell which callers had migrated.
		// A direct POST to /api/v1/decide carries no override and gets
		// PlaneDecision, so its rows are unchanged.
		plane:         plane,
		correlationID: traceID,
		origin:        origin, // WS-5 caller bucket, mirrored onto the decision span
		// #2896: pre-seed the trusted attribution email (empty when absent or
		// untrusted). It is recorded as a CLAIM, never as this row's
		// attribution: audit attribution must always name the principal the
		// decision was evaluated against, and on the early-return denies below
		// — decode failure, impersonation attempt, rejected token, token
		// required — no per-user principal was ever verified, so no human may
		// be named as though one had been. The asserted value survives at
		// policy_details->>'attempted_user_email'; the user_email column falls
		// back to the writer's placeholder until ResolveUser sets it.
		attemptedUserEmail: attributedEmail,
	}

	// auditEarlyDeny persists the canonical plane=decision audit row for an
	// early-return path BEFORE the handler returns, then records the API metric.
	// auditVerdict is canonical: AuditVerdictError for a malformed request (never
	// evaluated), VerdictDeny for a security denial (canonicalizes to `blocked`).
	// The "error" metric label is preserved from the prior behavior so existing
	// Decision-Mode dashboards keep their cardinality.
	auditEarlyDeny := func(auditVerdict, stg string, policyIDs, reasons []string) {
		recordDecideDecision(ctx, decisionID, orgID, tenantID, stg, auditVerdict,
			policyIDs, time.Since(startTime).Milliseconds(), reasons,
			traceID, reqContext, contextTruncated, decisionAudit)
		// origin is captured by reference: refreshed once gateway_id is parsed,
		// so the later impersonation/token denies carry the resolved bucket while
		// the pre-decode malformed-body deny carries the header-only bucket.
		decideRequests.WithLabelValues("error", stg, origin).Inc()
	}

	var req DecideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Malformed body — never evaluated → canonical 'error' (NOT 'blocked').
		auditEarlyDeny(AuditVerdictError, "unknown", nil, []string{"invalid request body"})
		sendDecideError(w, "Invalid request body", http.StatusBadRequest, decisionID, traceID)
		return
	}

	// gateway_id + query are known now — capture them onto the audit identity so
	// even the validation / impersonation denies record what was attempted.
	decisionAudit.gatewayID = sanitizeGatewayID(req.CallerIdentity.GatewayID)
	decisionAudit.query = req.Query

	// #2801/#2904: when the PEP declares a tool target, its server/tool name
	// feeds capability-scoped evaluation further down AND is captured onto the
	// audit identity here (not just at the terminal evaluateInputPolicies call)
	// so EARLY-DENY paths — impersonation, tenant mismatch, circuit-breaker,
	// kill-switch, PII — also carry tool_server/tool_name in their audit_logs
	// row, not only the terminal allow/block decision.
	toolServer := ""
	toolIdentity := ""
	if strings.EqualFold(req.Target.Type, "tool") {
		toolServer = req.Target.Server
		toolIdentity = req.Target.Tool
	}
	decisionAudit.toolServer = toolServer
	decisionAudit.toolName = toolIdentity

	// Refresh the origin bucket now that gateway_id is known (the authoritative
	// Claude Desktop signal). Updates both the closure-captured `origin` used by
	// the metric labels and the value mirrored onto the decision span.
	origin = classifyDecisionOrigin(clientHeader, decisionAudit.gatewayID)
	decisionAudit.origin = origin

	// Required field validation. Stage is required so the audit trail records
	// which gateway layer issued the call; query is required so the policy
	// engine has something to evaluate.
	stage := strings.ToLower(strings.TrimSpace(req.Stage))
	if !isValidStage(stage) {
		auditEarlyDeny(AuditVerdictError, "unknown", nil, []string{"invalid stage"})
		sendDecideError(w, "stage is required and must be one of: llm, tool, agent", http.StatusBadRequest, decisionID, traceID)
		return
	}
	if req.Query == "" {
		auditEarlyDeny(AuditVerdictError, stage, nil, []string{"query field is required"})
		sendDecideError(w, "query field is required", http.StatusBadRequest, decisionID, traceID)
		return
	}

	// Body parsed + stage valid: canonicalize the customer-supplied request
	// context once. The kept map (canonical keys -> sanitized values) is threaded
	// into every verdict's OTel span attributes + audit row (incl. the
	// impersonation denies below); contextTruncated flags that the key-count cap
	// dropped surplus keys. A design partner's Layer-2 headers (X-AI-Agent /
	// X-Session-ID / X-Leader-Identity) land here so the SIEM can join AxonFlow's
	// decision record to BigQuery Cloud Audit Logs by session_id (#2509 / #2508).
	reqContext, contextTruncated = canonicalizeRequestContext(req.Context, decisionContextAllowlist())

	// In community mode the middleware defaults the client to "community";
	// fall back to body-supplied caller_identity values so local-dev callers
	// without credentials still get a useful tenant scope for audit records.
	// Mirrors the pre-check community-mode shim.
	effectiveClientID := authClientID
	if isCommunityMode() && (authClientID == "" || authClientID == "community") {
		if req.CallerIdentity.TenantID != "" {
			tenantID = req.CallerIdentity.TenantID
			effectiveClientID = req.CallerIdentity.TenantID
		}
		if req.CallerIdentity.OrgID != "" {
			orgID = req.CallerIdentity.OrgID
		}
	} else {
		// In non-community modes the body MUST NOT override the authenticated
		// identity. Reject any body that asserts a different tenant/org than the
		// credentials carry, to prevent a compromised PEP from impersonating a
		// different tenant. SECURITY (#2643): these denies were previously
		// INVISIBLE — we now write an auditable `blocked` row capturing
		// attempted-vs-actual. The row's tenant_id/org_id columns are the
		// AUTHENTICATED (actual) identity; policy_details.attempted_* is what the
		// caller tried to claim.
		if req.CallerIdentity.TenantID != "" && req.CallerIdentity.TenantID != tenantID {
			decisionAudit.securityEvent = "tenant_impersonation"
			decisionAudit.attemptedTenantID = sanitizeAuditIdentity(req.CallerIdentity.TenantID)
			auditEarlyDeny(VerdictDeny, stage, []string{"tenant_impersonation"}, []string{"caller_identity.tenant_id does not match authenticated identity"})
			sendDecideError(w, "caller_identity.tenant_id does not match authenticated identity", http.StatusForbidden, decisionID, traceID)
			return
		}
		if req.CallerIdentity.OrgID != "" && req.CallerIdentity.OrgID != orgID {
			decisionAudit.securityEvent = "org_impersonation"
			decisionAudit.attemptedOrgID = sanitizeAuditIdentity(req.CallerIdentity.OrgID)
			auditEarlyDeny(VerdictDeny, stage, []string{"org_impersonation"}, []string{"caller_identity.org_id does not match authenticated identity"})
			sendDecideError(w, "caller_identity.org_id does not match authenticated identity", http.StatusForbidden, decisionID, traceID)
			return
		}
	}
	// Audit row now records the effective (authenticated, or community-fallback)
	// client identity.
	decisionAudit.clientID = effectiveClientID

	// Resolve user via the unified ResolveUser path so the policy engine
	// receives the same user shape as Gateway Mode. In community mode this
	// returns a synthetic user; in enterprise mode it validates the JWT.
	client := &Client{
		ID:       effectiveClientID,
		ClientID: effectiveClientID,
		Name:     effectiveClientID,
		OrgID:    orgID,
		TenantID: tenantID,
		Enabled:  true,
	}
	authResult := &AuthResult{Kind: authKind, TenantID: tenantID, OrgID: orgID, ClientID: effectiveClientID, Client: client}
	user, userErr := ResolveUser(authResult, req.UserToken)
	if userErr != nil {
		// Enterprise-mode PEP callers are typically services, not humans:
		// an infrastructure gateway acting as a Policy Enforcement Point
		// has no end-user JWT to forward. Mirror the mcp_handler.go pattern
		// (line ~1640) -- synthesize a service user so the decision flow
		// proceeds and the audit row carries a service identity. A caller
		// that DOES supply a valid token still gets the validated record.
		if authKind == AuthKindEnterprise && req.UserToken == "" && !ResolveRequireUserToken(ctx, client.OrgID) {
			user = &User{
				ID:       0,
				Email:    effectiveClientID + "@axonflow.local",
				Name:     effectiveClientID,
				TenantID: client.TenantID,
				OrgID:    client.OrgID, // mirror tenant scope so downstream
				// audit / RLS writes (under axonflow_app_role) succeed
				// instead of failing the WITH CHECK with empty org_id.
				Role: "service",
			}
		} else if authKind == AuthKindEnterprise && req.UserToken == "" {
			// #3476: no token was presented AND the org's posture requires one
			// (the synthetic-identity condition above already ruled out "flag
			// off"). Reject at authentication instead of synthesizing a service
			// identity. Distinct audit marker from user_token_rejected (a
			// PRESENTED-but-invalid token) so the two causes never collapse.
			decisionAudit.securityEvent = "user_token_required"
			auditEarlyDeny(VerdictDeny, stage, []string{"user_token_required"}, []string{userErr.Message})
			sendDecideError(w, userErr.Message, userErr.HTTPStatus, decisionID, traceID)
			return
		} else {
			// SECURITY (#2643): a supplied user_token that fails to resolve is a
			// rejected access attempt — audit it as a blocked decision before
			// returning, rather than 401-ing invisibly.
			decisionAudit.securityEvent = "user_token_rejected"
			auditEarlyDeny(VerdictDeny, stage, []string{"user_token_rejected"}, []string{userErr.Message})
			sendDecideError(w, userErr.Message, userErr.HTTPStatus, decisionID, traceID)
			return
		}
	}
	if user.TenantID != client.TenantID {
		// SECURITY (#2643): the resolved user's tenant disagrees with the client
		// tenant — a token/tenant mismatch. Audit attempted-vs-actual before deny.
		decisionAudit.securityEvent = "tenant_mismatch"
		decisionAudit.attemptedTenantID = sanitizeAuditIdentity(user.TenantID)
		auditEarlyDeny(VerdictDeny, stage, []string{"tenant_mismatch"}, []string{"Tenant mismatch"})
		sendDecideError(w, "Tenant mismatch", http.StatusForbidden, decisionID, traceID)
		return
	}

	// User identity is now resolved — complete the audit row so the terminal
	// allow/deny path (and the policy-driven early returns below) carry the
	// principal this decision is evaluated against.
	//
	// INVARIANT: audit attribution names the principal whose VERIFIED identity
	// the decision was evaluated against. Enforcement and attribution read the
	// SAME resolved identity — segment-scoped policy (ADR-060) makes the
	// principal decide WHICH policies apply, so a row naming a different
	// principal would not merely misname the caller, it would misdescribe what
	// was governed in the artifact the compliance exports and the decisions
	// feed read.
	//
	// A caller-asserted X-User-Email supplies attribution ONLY where no
	// per-user identity was verified (#2896: a PEP fronting many principals
	// behind one shared credential). Where one WAS verified, the asserted value
	// is recorded as a claim at policy_details->>'attempted_user_email' — never
	// as this row's principal, since it is forgeable by any governed caller
	// under a deployment-wide trust gate.
	decisionAudit.userEmail = user.Email
	decisionAudit.attemptedUserEmail = ""
	if attributedEmail != "" {
		if callerHasVerifiedUserIdentity(authKind, userErr, req.UserToken) {
			// A VALIDATED per-user identity: the header may not displace it.
			// Record the disagreement as a claim instead.
			if attributedEmail != user.Email {
				decisionAudit.attemptedUserEmail = attributedEmail
			}
		} else {
			// NO verified per-user identity (community / community-SaaS /
			// internal-service / the token-ABSENT enterprise fallback).
			// Nothing principal-specific was evaluated for this caller, so the
			// header does not misdescribe what was governed — and it is
			// strictly better than naming a synthetic service email. This is
			// #2896's actual case and is deliberately UNCHANGED: the invariant
			// constrains DISPLACEMENT of a verified identity, not attribution
			// in its absence.
			decisionAudit.userEmail = attributedEmail
		}
	}
	decisionAudit.userRole = user.Role
	decisionAudit.userID = user.ID

	// Circuit breaker -- transient deny shape. Returns HTTP 503 so the PEP
	// adapter can apply its configured fail-open / fail-closed posture.
	// ADR-056 §Components calls this out explicitly. A 5xx-class status
	// here is the signal to the adapter that the PDP is degraded -- the
	// body's verdict=deny is the fail-closed default for adapters that
	// don't have a posture configured. cbErr (DB error) is intentionally
	// fail-open: degraded availability of the breaker is logged and the
	// decision falls through to the policy engine. Operators that want
	// fail-closed should configure the PEP adapter accordingly.
	if circuitBreakerInstance != nil {
		cbResult, cbErr := circuitBreakerInstance.Check(ctx, circuitbreaker.CheckInput{
			OrgID:    client.OrgID,
			TenantID: client.TenantID,
			ClientID: client.ID,
		})
		if cbErr != nil {
			log.Printf("⚠️ [Decide] Circuit breaker check error (fail-open): %v", cbErr)
		} else if !cbResult.Allowed {
			if retryAfter := circuitBreakerRetryAfter(cbResult.ExpiresAt); retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			// #3243 v9.16.1: name the control that denied. This was the one
			// /decide call site recording a deny with NO policy identity, so
			// its rows rendered a blank (now placeholder) Policy cell on the
			// compliance exports. "circuit_breaker" is the control's own
			// identifier (mirroring the kill-switch's "rbi_kill_switch"), not
			// a fabricated policy name; the reason carries the trip cause.
			traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"circuit_breaker"}, time.Since(startTime).Milliseconds(), []string{string(cbResult.Reason)}, traceID, reqContext, contextTruncated, decisionAudit)
			sendDecideError(w, fmt.Sprintf("Service temporarily unavailable: circuit breaker active (reason: %s)", cbResult.Reason), http.StatusServiceUnavailable, decisionID, traceID)
			recordDecideMetrics("circuit_breaker", stage, origin, startTime)
			return
		}
	}

	// Kill switch (RBI FREE-AI) -- policy-controlled deny. Returns
	// verdict=deny over 200 because it's a deliberate policy decision the
	// PEP should enforce as a final answer (not retry).
	killSwitchResult := checkRBIKillSwitch(ctx, client.OrgID, "")
	if killSwitchResult.IsBlocked {
		log.Printf("🛑 [Decide] Request blocked by RBI kill switch: %s", killSwitchResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"rbi_kill_switch"}, time.Since(startTime).Milliseconds(), []string{killSwitchResult.Reason}, traceID, reqContext, contextTruncated, decisionAudit)
		writeDecideResponse(w, http.StatusOK, DecideResponse{
			Verdict:           VerdictDeny,
			DecisionID:        decisionID,
			TraceID:           traceID,
			Stage:             stage,
			Reasons:           []string{killSwitchResult.Reason},
			Obligations:       []DecisionObligation{},
			EvaluatedPolicies: []string{"rbi_kill_switch"},
			ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
		})
		recordDecideMetrics(VerdictDeny, stage, origin, startTime)
		recordDecideBlock("rbi_kill_switch", origin)
		return
	}

	// #2581: resolve per-org posture (org with no override → deployment-global).
	gwDetectionCfg := ResolveGatewayDetectionConfig(ctx, orgID)

	// blockingPolicyID captures the SINGLE policy that produces a deny
	// verdict, when one exists. The shared engine appends non-blocking
	// matches before the blocking match (engine.go:128-156 evaluates each
	// policy in order and breaks at the first ActionBlock), so
	// policyResult.TriggeredPolicies[0] is NOT reliably the blocking one.
	// We read it off requestResult.BlockedBy below and use it directly
	// when recording violations against the circuit breaker.
	var blockingPolicyID string
	// blockingPolicyTier is the tier ("system"/"enterprise"/"organization"/
	// "tenant") of that blocking policy, captured alongside the id so the
	// decideBlocks `policy` label can collapse per-tenant custom policies to a
	// bounded bucket (boundedBlockPolicy). Empty when no engine block fired.
	var blockingPolicyTier string

	// Indonesia PII pre-check runs FIRST so Indonesia-specific bank account
	// patterns (BCA/Mandiri/BRI/BNI) are attributed to indonesia_pii_protection
	// instead of being shadowed by the generic RBI bank-account detector.
	rbiPIIRequiresRedaction := false
	indonesiaPIIRequiresRedaction := false
	blockOnCriticalPII := gwDetectionCfg.Enabled && gwDetectionCfg.PIIAction == DetectionActionBlock

	// OJK/UU PDP Indonesia PII pre-check (NIK / NPWP / +62 / bank accounts).
	indonesiaPIIResult := checkIndonesiaPII(req.Query, blockOnCriticalPII)
	if indonesiaPIIResult.BlockRecommended {
		log.Printf("🛑 [Decide] Request blocked by Indonesia PII detection: %s", indonesiaPIIResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"indonesia_pii_protection"}, time.Since(startTime).Milliseconds(), []string{indonesiaPIIResult.Reason}, traceID, reqContext, contextTruncated, decisionAudit)
		// #3242: persist the UU PDP / OJK detection events (MASKED values only)
		// keyed to this decision, so the OJK pii_redactions export evidences the
		// refusal and an auditor can pivot to the audit_logs row by decision_id.
		// Best-effort; the deny above is already held. No-op in a community build.
		recordIndonesiaPIIEvents(ctx, client.OrgID, client.TenantID, decisionID, traceID,
			PlaneDecision, indonesiaPIIActionBlocked, indonesiaPIIResult)
		writeDecideResponse(w, http.StatusOK, DecideResponse{
			Verdict:           VerdictDeny,
			DecisionID:        decisionID,
			TraceID:           traceID,
			Stage:             stage,
			Reasons:           []string{indonesiaPIIResult.Reason},
			Obligations:       []DecisionObligation{},
			EvaluatedPolicies: []string{"indonesia_pii_protection"},
			ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
		})
		recordDecideMetrics(VerdictDeny, stage, origin, startTime)
		recordDecideBlock("indonesia_pii_protection", origin)
		return
	}
	// Under PII_ACTION=redact, critical Indonesia PII (NIK / NPWP) is detected
	// but not blocked. Flag it for redaction the same way RBI India PII is
	// flagged below — previously it was detected but never flagged, so NIK
	// slipped through unredacted on the allow path while SSN/Aadhaar redacted.
	if indonesiaPIIResult.HasPII && gwDetectionCfg.Enabled && indonesiaPIIResult.CriticalPII && gwDetectionCfg.PIIAction == DetectionActionRedact {
		indonesiaPIIRequiresRedaction = true
	}
	// #3242: record every non-blocking detection too. Under a warn/log posture
	// /decide returns a plain allow and emits no redact obligation, so this event
	// is the ONLY record that Indonesia PII was present and was not masked —
	// which is precisely what a UU PDP auditor asks for. decisionID is stamped so
	// the event joins to the decision row this request will write.
	if indonesiaPIIResult.HasPII {
		recordIndonesiaPIIEvents(ctx, client.OrgID, client.TenantID, decisionID, traceID,
			PlaneDecision, indonesiaPIIActionForDecisionPlane(false, indonesiaPIIRequiresRedaction), indonesiaPIIResult)
	}

	// RBI India PII pre-check (Aadhaar / PAN / UPI / bank-account validators).
	piiResult := checkRBIPII(req.Query, blockOnCriticalPII)
	if piiResult.BlockRecommended {
		log.Printf("🛑 [Decide] Request blocked by RBI PII detection: %s", piiResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"rbi_pii_protection"}, time.Since(startTime).Milliseconds(), []string{piiResult.Reason}, traceID, reqContext, contextTruncated, decisionAudit)
		writeDecideResponse(w, http.StatusOK, DecideResponse{
			Verdict:           VerdictDeny,
			DecisionID:        decisionID,
			TraceID:           traceID,
			Stage:             stage,
			Reasons:           []string{piiResult.Reason},
			Obligations:       []DecisionObligation{},
			EvaluatedPolicies: []string{"rbi_pii_protection"},
			ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
		})
		recordDecideMetrics(VerdictDeny, stage, origin, startTime)
		recordDecideBlock("rbi_pii_protection", origin)
		return
	}
	if piiResult.HasPII && gwDetectionCfg.Enabled && piiResult.CriticalPII && gwDetectionCfg.PIIAction == DetectionActionRedact {
		rbiPIIRequiresRedaction = true
	}

	// Static-policy evaluation via evaluateInputPolicies (#2801), the same
	// helper mcpQueryHandler / mcpExecuteHandler / mcpCheckInputHandler use —
	// same engine, same category set, so a single policy author gets
	// consistent enforcement across every caller. runDynamicPolicy is false:
	// dynamic policy (rate limits, budgets, time/role access) is M2 scope per
	// epic #2426 (see file doc comment above) — /decide's inline RPC budget
	// only covers static checks today. connectorName is the synthetic
	// "decision" placeholder for metrics/audit; ResolveGatewayDetectionConfig
	// has no connector-scoping mechanism (unlike the MCP surface), so this is
	// never gated by it — /decide has no managed connector to scope against
	// (ADR-056 addendum, Decision 3: "the connector axis is meaningless" for
	// gateway/PDP mode).
	//
	// #2801: when the PEP declares a tool target, its tool name feeds
	// capability-scoped evaluation (text-document tools skip execution-class
	// detectors; unknown tools get full evaluation). toolServer/toolIdentity
	// were already computed + stamped onto decisionAudit right after decode
	// (#2904) so early-deny paths carry them too; reused here unchanged.
	// ADR-061 / #3329: install the fincrime decision metadata (frozen scorer
	// contract plane vocabulary "decide") and lift the documented
	// fincrime_transaction / fincrime_cohort context objects into the
	// parameters map, so the FinCrime Policy Pack rows and the fincrime seam
	// see the same shapes here as on the MCP planes. For every request
	// without those keys fincrimeParams is nil, which is bit-identical to
	// the historical nil-parameters call.
	ctx = fincrime.WithDecisionMeta(ctx, "decide", decisionID)
	fincrimeParams := finCrimeParametersFromContext(req.Context)
	// #3456 R3: resolved HERE, immediately before its only consumer, and
	// deliberately NOT right after the identity is settled. The circuit
	// breaker and the RBI kill switch above are GLOBAL, org-scoped controls
	// that do not depend on this caller's identity; resolving earlier let a
	// per-caller resolution failure preempt them, so an open breaker or a
	// tripped kill switch would surface as a segment deny and report the
	// wrong cause to the operator. Resolving at the point of use also skips
	// the lookup entirely for requests those controls already refused.
	// #3456 (ADR-060 Slice 3): resolve this caller's governance-segment set
	// ONCE, here, where the identity is settled and BEFORE any policy
	// evaluation can run. /decide used to pass a hardcoded nil into
	// evaluateInputPolicies, so a segment-scoped static_policies row could
	// never enforce on this URL: the same content a segment-scoped policy
	// blocks on a segment-aware plane was ALLOWED here, for the same caller,
	// on the credential they already hold — a one-URL edit, no second
	// credential, no privilege change.
	//
	// The key is user.OrgID + the VALIDATED token's email claim (user.Email),
	// never attributedEmail. attributedEmail wins the audit ATTRIBUTION slot
	// just above (#2896) but is caller-supplied and trusted deployment-wide;
	// keying policy scoping on it would let a human shed their segments by
	// naming a non-member colleague — the reported bypass recreated one level
	// down. user.OrgID is populated on BOTH branches above (the validated
	// token's org_id claim, falling back to its tenant per validateUserToken;
	// client.OrgID on the synthesized service identity), which is also the key
	// every other human-actor plane uses (run.go, gateway_handlers.go, the four
	// MCP REST routes), so one human cannot resolve to different sets on
	// different routes. See human_actor_segment_gate.go for the full contract.
	segmentIDs, segOK := resolveHumanActorSegmentsForPolicy(ctx, user.OrgID, authResult.OrgID, user.Email,
		callerIsVerifiedHuman(authResult, userErr, req.UserToken))
	if !segOK {
		// A resolver error for a caller who HAS a principal denies, on its OWN
		// channel: guard id segment_resolution_failed + 403, in the same
		// early-deny shape as the user_token_rejected / tenant_mismatch /
		// user_token_required denies above. Deliberately NOT folded into
		// InputPolicyOutcome.EvalUnavailable (the 503 "policy evaluation
		// temporarily unavailable" channel guarded below): a deliberate
		// policy-side deny must stay distinguishable from an evaluator outage
		// in both the audit row and the operator dashboard. And it must happen
		// HERE, before evaluateInputPolicies — that call's trailing `segments`
		// parameter is a plain slice whose nil means "resolved to none / no
		// identity", never "resolution failed".
		decisionAudit.securityEvent = segmentResolutionFailedPolicyID
		auditEarlyDeny(VerdictDeny, stage, []string{segmentResolutionFailedPolicyID},
			[]string{segmentResolutionFailedReason})
		sendDecideError(w, segmentResolutionFailedReason, http.StatusForbidden, decisionID, traceID)
		return
	}

	outcome := evaluateInputPolicies(ctx,
		user.TenantID, user.OrgID, fmt.Sprintf("%d", user.ID), user.Role,
		"decision", toolIdentity, "decide", req.Query, fincrimeParams,
		gwDetectionCfg, false, /* runDynamicPolicy: M2, #2426 */
		segmentIDs, /* #3456: resolved once above, fail-closed; nil here means "resolved to none", never "resolution failed" */
		legacycompile.PlaneDecide)
	// Defensive fail-closed: evaluateInputPolicies sets EvalUnavailable only when
	// dynamic policy evaluation (runDynamicPolicy) hits a transient store error.
	// /decide passes runDynamicPolicy=false, so this is never set today — but
	// guard it so a future flip to dynamic eval fails closed with a 503 (like the
	// MCP handlers) instead of silently allowing on an unavailable evaluator.
	if outcome.EvalUnavailable {
		log.Printf("⚠️ [Decide] policy evaluation unavailable — failing closed (503)")
		sendDecideError(w, "policy evaluation temporarily unavailable", http.StatusServiceUnavailable, decisionID, traceID)
		return
	}
	policyResult := convertSharedResultToStatic(outcome.StaticResult)
	// #3365: thread the evaluation-time display names onto the audit input so
	// the terminal write stamps policy_names for the same ids it records.
	// FinCrime-appended ids get their names from the seam's MergeAuditDetails.
	decisionAudit.policyNames = policyResult.PolicyNames
	// Capture the blocking policy ID directly from the result so
	// circuit-breaker violation recording targets the right rule regardless
	// of which order the shared engine appended matches in (a request that
	// triggers a non-blocking redact policy AND a blocking SQLi policy must
	// record the SQLi rule).
	if outcome.StaticResult != nil && outcome.StaticResult.BlockedBy != nil {
		blockingPolicyID = outcome.StaticResult.BlockedBy.PolicyID
		blockingPolicyTier = outcome.StaticResult.BlockedBy.Tier
	}

	// #3509 defect 2: spend an outstanding single-use approval BEFORE the
	// verdict is mapped, never after.
	//
	// Flipping needs_approval to allow downstream would produce an allow that
	// skipped mapPolicyResultToVerdict's obligation attachment entirely, so a
	// policy that requires BOTH approval and redaction would be admitted with
	// no redact_pii obligation and the PEP would forward raw content. Clearing
	// the flag here instead lets the admitted request take the ORDINARY allow
	// path, obligations and advisory reasons included.
	//
	// Scoped to a policy-authored step-up. A FinCrime step-up is a function of
	// the risk score computed for THIS request, so an approval of one scored
	// transaction must never admit the next one; decideApprovalIsPolicyAuthored
	// also guarantees the seam cannot re-escalate this verdict after we have
	// spent a grant on it, which would burn the grant and hold the caller
	// anyway.
	//
	// `!policyResult.Blocked` is load-bearing and not defensive padding. Blocked
	// and RequiresApproval can BOTH be true - one matched policy denies while
	// another requires approval - and mapPolicyResultToVerdict short-circuits on
	// Blocked, so the verdict is deny either way. Spending the caller's one
	// approval on a request that is about to be denied anyway destroys it for
	// nothing: single use means they do not get it back.
	approvalGrantID := ""
	if policyResult.RequiresApproval && !policyResult.Blocked && !isCommunityMode() &&
		decideApprovalIsPolicyAuthored(outcome.FinCrime, outcome.StaticResult) {
		// The FULL principal, not just the user. A token-less enterprise PEP is
		// given a synthetic identity whose ID is 0, so `user_id` alone is the
		// string "0" for every such caller in the org and a grant keyed on it
		// would cross credentials.
		if grantID, admitted := consumeApprovalGrant(ctx, hitlPlaneDecide, hitl.GrantSubject{
			OrgID:    client.OrgID,
			TenantID: client.TenantID,
			ClientID: client.ClientID,
			UserID:   fmt.Sprintf("%d", user.ID),
		}, approvalPolicyKey(policyResult.ApprovalPolicyID), req.Query); admitted {
			approvalGrantID = grantID
			policyResult.RequiresApproval = false
		}
	}

	// Map StaticPolicyResult onto the Decision API verdict/reasons/obligations
	// shape. Pulled out so the mapping is unit-testable without standing up
	// the full shared engine + DB-seeded patterns.
	verdict, reasons, obligations := mapPolicyResultToVerdict(policyResult, isCommunityMode())

	// Merge a redaction obligation when a validator-backed detector flagged
	// critical India *or* Indonesia PII and PII_ACTION=redact. Suppressed on
	// deny (the request won't be forwarded anyway) and on needs_approval (the
	// approver makes the redact call at queue exit). The shared engine's
	// regex-based category may or may not have set the same obligation; we
	// dedup to avoid two redact_pii entries. Indonesia (NIK / NPWP) is included
	// here for the same reason RBI India PII is — previously it was detected but
	// never produced a redact obligation, so NIK slipped through unredacted.
	if (rbiPIIRequiresRedaction || indonesiaPIIRequiresRedaction) && verdict == VerdictAllow {
		alreadyHasRedact := false
		for _, o := range obligations {
			if o.Type == ObligationRedactPII {
				alreadyHasRedact = true
				break
			}
		}
		if !alreadyHasRedact {
			redactReason := piiResult.Reason
			if redactReason == "" && indonesiaPIIRequiresRedaction {
				redactReason = fmt.Sprintf("Indonesia PII detected: %v", indonesiaPIIResult.DetectedTypes)
			}
			obligations = append(obligations, newRedactPIIObligation(redactReason))
		}
	}

	// ADR-061 / #3329: fold the FinCrime seam result. Advisory-only mapping:
	// it can escalate an allow to needs_approval (scorer above threshold or
	// protocol-integrity validation), never deny, and it appends the
	// fincrime policy attribution to the evaluated set. A scored or flagged
	// decision then routes into the HITL approval queue via the bridge so
	// the verdict is a reviewable queue entry, not just a wire response.
	verdict, reasons, obligations, policyResult.TriggeredPolicies = applyFinCrimeToDecideVerdict(
		outcome.FinCrime, verdict, reasons, obligations, policyResult.TriggeredPolicies, isCommunityMode())
	if verdict == VerdictNeedsApproval {
		if approvalID := createFinCrimeApprovalForDecision(ctx, client.OrgID, client.TenantID, client.ID,
			fmt.Sprintf("%d", user.ID), req.Query, outcome.FinCrime, outcome.StaticResult); approvalID != "" {
			reasons = append(reasons, finCrimeApprovalReason(approvalID))
		} else if policyResult.RequiresApproval {
			// #3509: a policy-authored require_approval - the EU AI Act
			// human-oversight case the seam comment above names and explicitly
			// declines to handle. It reached here as a verdict with no queue
			// entry and no way for a reviewer to act, which is a strictly worse
			// outcome than a block: refused, with no override flow and no
			// reviewer surface.
			//
			// The `else` is load-bearing. createFinCrimeApprovalForDecision
			// already wrote an entry when it returned an id, and a fincrime
			// step-up on a request that ALSO trips a plain require_approval
			// policy must not raise two entries for one decision. The seam owns
			// the attribution in that case (its precedence rules pick the ML
			// score or the protocol-integrity check over a pack row);
			// policyResult.RequiresApproval is what distinguishes "the seam
			// declined" from "the seam is not involved at all".
			res := enqueuePolicyStepUp(ctx, policyStepUpInput{
				Plane:    hitlPlaneDecide,
				OrgID:    client.OrgID,
				TenantID: client.TenantID,
				// client.ClientID, not client.ID: ADR-052 makes ClientID the
				// credential identity and it is what audit_logs.client_id
				// records, so the queue row joins to its audit row - and it is
				// what the grant consume above matches on.
				ClientID:   client.ClientID,
				UserID:     fmt.Sprintf("%d", user.ID),
				UserEmail:  user.Email,
				PolicyID:   policyResult.ApprovalPolicyID,
				PolicyName: policyResult.ApprovalPolicyName,
				Reason:     "human approval required by policy",
				Severity:   policyResult.Severity,
				DecisionID: decisionID,
				Stage:      stage,
				Query:      req.Query,
				Target:     decideTargetDescriptor(toolServer, toolIdentity, req.Target.Type),
			})
			if res.RequestID != "" {
				reasons = append(reasons, policyStepUpReason(res.RequestID))
			} else {
				// The hold stands, but it is no longer a SILENT dead end: the
				// PEP is told a review was owed and not raised, and the same
				// text lands on the canonical audit row below.
				reasons = append(reasons, res.Detail)
			}
			decisionAudit.approvalEnqueue = res.Outcome
			decisionAudit.approvalRequestID = res.RequestID
		}
	}
	// #3509 defect 2: a spent grant is recorded as a REASON on the allow, so an
	// admission authorised by a human is never a silent bare allow. The
	// consumption itself happened before the verdict was mapped (see
	// approvalGrantID above) precisely so this request takes the ordinary allow
	// path, obligations included.
	if approvalGrantID != "" {
		reasons = append(reasons, approvalGrantReason(approvalGrantID))
		decisionAudit.approvalGrantID = approvalGrantID
	}

	// On deny verdict, record ONE policy violation against the circuit
	// breaker so repeated denies auto-trip it (#1176). We record the
	// blocking policy specifically -- captured from requestResult.BlockedBy
	// above when the shared engine fired, or falls back to the first
	// triggered policy for the engine-bypass paths (no-engine /
	// disabled-detection / empty triggered list).
	if verdict == VerdictDeny && circuitBreakerInstance != nil {
		policyToRecord := blockingPolicyID
		if policyToRecord == "" && len(policyResult.TriggeredPolicies) > 0 {
			policyToRecord = policyResult.TriggeredPolicies[0]
		}
		if policyToRecord != "" {
			if err := circuitBreakerInstance.RecordPolicyViolation(ctx, client.OrgID, client.TenantID, client.ID, policyToRecord); err != nil {
				log.Printf("⚠️ [Decide] Circuit breaker RecordPolicyViolation error: %v", err)
			}
		}
	}

	// #2958: the seam-capability gate. Placed AFTER both obligation-attachment
	// sites (so it sees the final slice) and AFTER the circuit-breaker recording
	// above, which is deliberate: a fallback DENY is a seam-capability outcome,
	// not a policy violation by the caller — the identical content on a
	// body-capable seam would have been allowed with a redaction. Recording it
	// against the breaker would let one headers-only seam trip a tenant-wide
	// breaker and deny traffic that policy never blocked. It still counts as a
	// deny everywhere a deny is counted (decideRequests / decideBlocks / the
	// canonical audit row).
	verdict, reasons, obligations, seamFallback := applySeamCapabilityObligations(
		ctx, orgID, req.FulfillmentCapabilities, verdict, reasons, obligations)

	// Hoist the blocking policy to evaluated_policies[0] so the OpenAPI
	// contract claim ("On deny, the first entry is the blocking policy")
	// holds. Non-blocking matches (PII redact rules that fired but didn't
	// block) follow.
	if verdict == VerdictDeny && blockingPolicyID != "" {
		policyResult.TriggeredPolicies = hoistBlockingPolicy(policyResult.TriggeredPolicies, blockingPolicyID)
	}

	evaluatedPolicies := policyResult.TriggeredPolicies
	if evaluatedPolicies == nil {
		evaluatedPolicies = []string{}
	}

	// Persist the structured obligations (e.g. redact_pii) onto the audit row
	// instead of flattening them into the reason text. Only the terminal
	// allow/deny path carries obligations; the early-return deny paths above
	// (circuit-breaker / kill-switch / PII) have none, so they leave this nil.
	decisionAudit.obligations = obligations
	// #2958: a suppressed obligation must never be an invisible allow. Under the
	// log fallback the PEP is told to do nothing, so THIS row is the only record
	// that PII was detected and that a redaction was withheld — suppressing the
	// obligation AND the audit trail would be a worse compliance regression than
	// the 403 this change removes. evaluated_policies (recorded below) carries
	// the detected categories; these fields carry what was withheld and why.
	if seamFallback != nil {
		decisionAudit.suppressedObligations = seamFallback.suppressed
		decisionAudit.obligationFallback = string(seamFallback.action)
	}

	traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, verdict, evaluatedPolicies, time.Since(startTime).Milliseconds(), reasons, traceID, reqContext, contextTruncated, decisionAudit)

	writeDecideResponse(w, http.StatusOK, DecideResponse{
		Verdict:           verdict,
		DecisionID:        decisionID,
		TraceID:           traceID,
		Stage:             stage,
		Reasons:           reasons,
		Obligations:       obligations,
		EvaluatedPolicies: evaluatedPolicies,
		ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
	})
	recordDecideMetrics(verdict, stage, origin, startTime)
	recordDecideOutcomeMetrics(verdict, stage, origin, obligations, blockingPolicyID, blockingPolicyTier, evaluatedPolicies, seamFallback)
}

// mapPolicyResultToVerdict translates a shared-policy StaticPolicyResult into
// the (verdict, reasons, obligations) triple the Decision API surfaces. Pulled
// out as a pure function so all four verdict transitions can be unit-tested
// without standing up the full shared engine + DB-seeded patterns.
//
// Rules:
//   - Blocked            -> verdict=deny,            reason=block reason
//   - RequiresApproval   -> verdict=needs_approval   (enterprise only;
//     community mode auto-allows because HITL is enterprise-gated)
//   - RequiresRedaction  -> verdict=allow + obligations=[redact_pii]
//   - else               -> verdict=allow
//
// Always returns non-nil slices so the caller can serialize without a nil-check.
func mapPolicyResultToVerdict(result *StaticPolicyResult, communityMode bool) (string, []string, []DecisionObligation) {
	reasons := []string{}
	obligations := []DecisionObligation{}
	if result == nil {
		return VerdictAllow, reasons, obligations
	}
	if result.Blocked {
		if result.Reason != "" {
			reasons = append(reasons, result.Reason)
		}
		return VerdictDeny, reasons, obligations
	}
	if result.RequiresApproval && !communityMode {
		reasons = append(reasons, "require_approval")
		return VerdictNeedsApproval, reasons, obligations
	}
	if result.RequiresRedaction {
		obligations = append(obligations, newRedactPIIObligation(result.Reason))
	}
	// #2965: a PII policy that MATCHED but resolved to warn/log emits no
	// obligation, yet must still produce a governance signal so a matched
	// policy is never a silent bare allow. These reasons ride the allow verdict
	// (and are persisted on the canonical decision audit row via reasons).
	reasons = append(reasons, result.AdvisoryReasons...)
	return VerdictAllow, reasons, obligations
}

// --- Seam-capability-aware obligations (#2958) ---

// Bounds on the untrusted FulfillmentCapabilities slice. A capability is a
// short enum token, so anything longer/larger than these is not a value we
// could match anyway. Surplus entries are DROPPED rather than rejected, which
// is the fail-safe direction: dropping a capability can only ever make the
// caller look LESS capable, which routes the obligation to the org's fallback
// posture (or leaves it emitted) — never to a silent forward of raw content.
const (
	maxFulfillmentCapabilities   = 16
	maxFulfillmentCapabilityLen  = 64
	obligationFallbackLogReason  = "request-body redaction suppressed: the caller's seam cannot fulfill it; detected content recorded for audit per the organization's obligation-fallback posture (log)"
	obligationFallbackDenyReason = "request requires body redaction that the caller's seam cannot fulfill; denied per the organization's obligation-fallback posture (block)"
)

// obligationFallback records what the seam-capability gate withheld and the
// posture it applied, so the audit row and the fallback metric can report a
// suppressed redaction instead of it vanishing silently.
type obligationFallback struct {
	action     DetectionAction      // DetectionActionBlock or DetectionActionLog
	suppressed []DecisionObligation // the obligations withheld from the PEP
}

// applySeamCapabilityObligations is the SINGLE choke point where an obligation
// may be withheld from a caller (#2958). It runs over the FINAL obligation
// slice, AFTER every attachment site (mapPolicyResultToVerdict and the
// validator-backed India/Indonesia merge), so a future third attachment site is
// gated automatically rather than needing to remember this rule — the #2625
// audit-hole class came from per-site copies of a shared rule. The
// newRedactPIIObligation call-site census in
// decision_obligation_capability_test.go pins that property.
//
// Contract:
//   - Legacy caller (no advertised capabilities) → returns everything
//     UNCHANGED. This is the bit-identical pre-9.11.0 path that every SDK, the
//     desktop proxy and the plugins take.
//   - Capability-aware caller → any obligation the seam cannot discharge is
//     removed, and the org's server-side obligation-fallback posture decides
//     the outcome: block → deny; log (the default) → allow, minus the
//     obligation, plus an audit trail of what was suppressed.
//
// The fallback posture is resolved from the ORG, never from the request — a
// caller can influence WHICH obligations it is offered, never what happens when
// one is suppressed. See the threat model on DecideRequest.FulfillmentCapabilities.
//
// Returns the (possibly rewritten) verdict/reasons/obligations plus a non-nil
// obligationFallback when — and only when — something was suppressed.
func applySeamCapabilityObligations(
	ctx context.Context,
	orgID string,
	rawCapabilities []string,
	verdict string,
	reasons []string,
	obligations []DecisionObligation,
) (string, []string, []DecisionObligation, *obligationFallback) {
	// Obligations only ride an allow verdict; deny/needs_approval already carry
	// none. Guarding here keeps the gate a no-op on those paths by construction.
	if verdict != VerdictAllow || len(obligations) == 0 {
		return verdict, reasons, obligations, nil
	}

	capabilities, advertised := canonicalizeFulfillmentCapabilities(rawCapabilities)
	if !advertised {
		// Legacy caller: emit obligations exactly as before. An empty set is
		// deliberately indistinguishable from absent (the wire field is
		// omitempty) and resolves to the STRICTER outcome — the obligation is
		// emitted, and a PEP that cannot fulfill it fails closed rather than
		// forwarding unredacted content.
		return verdict, reasons, obligations, nil
	}

	kept := make([]DecisionObligation, 0, len(obligations))
	var suppressed []DecisionObligation
	for _, o := range obligations {
		if requiresRequestBodyRedaction(o) && !capabilities[pep.CapabilityRequestBodyRedaction] {
			suppressed = append(suppressed, o)
			continue
		}
		kept = append(kept, o)
	}
	if len(suppressed) == 0 {
		// The seam can discharge everything it was offered — untouched.
		return verdict, reasons, obligations, nil
	}

	fallback := &obligationFallback{
		action:     ResolveObligationFallbackAction(ctx, orgID),
		suppressed: suppressed,
	}
	if fallback.action == DetectionActionBlock {
		// The org refuses detect-and-log for content it wanted masked. Deny —
		// and carry no obligations, like every other deny path.
		return VerdictDeny, append(reasons, obligationFallbackDenyReason), []DecisionObligation{}, fallback
	}
	return VerdictAllow, append(reasons, obligationFallbackLogReason), kept, fallback
}

// requiresRequestBodyRedaction reports whether o needs the seam to rewrite the
// request payload. It is the single-obligation mirror of pep.HasRequestRedaction,
// and the two MUST agree: that function is what a PEP branches on to decide
// "does this verdict carry work for me?", so any obligation it would report
// must be one this gate considered. An obligation with no request-phase
// fulfillment block is not reported by either (a PEP would never try to
// discharge it), so it needs no capability and passes through.
func requiresRequestBodyRedaction(o DecisionObligation) bool {
	return o.Type == ObligationRedactPII &&
		o.Fulfillment != nil &&
		o.Fulfillment.Phase == ObligationPhaseRequest
}

// canonicalizeFulfillmentCapabilities turns the untrusted wire slice into a
// bounded lookup set, and reports whether the caller ADVERTISED at all.
//
// The two results are deliberately independent. `advertised` answers "is this a
// capability-aware PEP?" — true as soon as one non-blank entry is present, even
// if every entry is garbage. It must NOT depend on whether the values are
// usable, otherwise identical-in-spirit inputs get opposite treatment: an
// unknown token would route to the org's fallback posture while an over-LONG
// unknown token (dropped from the set) would look like a legacy caller and get
// the obligation emitted. Same intent, different outcome, decided by a length
// cap — so `advertised` is tracked separately from the set's contents.
//
// Bounding is on the INPUT INDEX, not the map size: a hostile caller sending a
// million DUPLICATE entries collapses to a one-entry map, so a size-based cap
// would never trip and the loop would run the whole slice on the decide hot
// path. Capping the index bounds the work as well as the memory. Entries past
// the cap are dropped, which is fail-safe — dropping a capability can only make
// the caller look LESS capable (→ the org fallback posture), never more.
//
// UNKNOWN values are kept but simply never match a Capability* constant, so a
// garbage or forged token reads as "not capable for that obligation". It can
// never raise an error, block the request, or be mistaken for a capability —
// that is what lets an older PDP meet a newer PEP's vocabulary and degrade
// instead of failing.
func canonicalizeFulfillmentCapabilities(raw []string) (set map[string]bool, advertised bool) {
	if len(raw) == 0 {
		return nil, false
	}
	out := make(map[string]bool, min(len(raw), maxFulfillmentCapabilities))
	for i, c := range raw {
		if i >= maxFulfillmentCapabilities {
			break
		}
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue // blank padding is not an advertisement
		}
		advertised = true
		if len(c) > maxFulfillmentCapabilityLen {
			// Cannot match any known capability; don't store it (an unbounded
			// key would let a caller size the map), but it still counts as an
			// advertisement above.
			continue
		}
		out[c] = true
	}
	return out, advertised
}

// isValidStage gates the stage field to the three layers in ADR-056.
// Unknown stages are rejected at the API boundary so audit dashboards
// stay bounded.
func isValidStage(s string) bool {
	switch s {
	case DecisionStageLLM, DecisionStageTool, DecisionStageAgent:
		return true
	default:
		return false
	}
}

// hoistBlockingPolicy moves blockingID to position 0 of the slice. If it
// isn't present, prepends it. If it IS at position 0, returns the slice
// unchanged. Used to satisfy the OpenAPI contract that
// `evaluated_policies[0]` is the blocking policy on deny.
func hoistBlockingPolicy(policies []string, blockingID string) []string {
	if len(policies) == 0 {
		return []string{blockingID}
	}
	if policies[0] == blockingID {
		return policies
	}
	for i, p := range policies {
		if p == blockingID {
			policies[0], policies[i] = policies[i], policies[0]
			return policies
		}
	}
	return append([]string{blockingID}, policies...)
}

// decisionExpiresAfter returns the configured PEP-cache TTL.
// AXONFLOW_DECISION_EXPIRES_AFTER overrides the 5-minute default; an
// unparseable value falls back to the default so a typo can't blow up
// every decision in the field.
func decisionExpiresAfter() time.Duration {
	raw := strings.TrimSpace(getEnv(envDecisionExpiresAfter, ""))
	if raw == "" {
		return decisionResponseDefaultTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("⚠️ [Decide] invalid %s=%q (using default %s)", envDecisionExpiresAfter, raw, decisionResponseDefaultTTL)
		return decisionResponseDefaultTTL
	}
	return d
}

// newW3CTraceID returns 16 random bytes as a lowercase 32-hex string,
// matching the W3C trace-context trace-id field. Crypto-rand is used so
// trace IDs are sampling-friendly when exporters are wired in #2354.
// Falls back to a uuid-derived hex string if the rand source errors (in
// practice this never returns on Linux/macOS, but guard for completeness).
func newW3CTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		u := uuid.New()
		return hex.EncodeToString(u[:])
	}
	return hex.EncodeToString(b[:])
}

// traceIDFromHeader parses a W3C traceparent header and returns its trace-id
// component. Format: "version-trace_id-parent_id-trace_flags" (W3C TC v1).
// Returns "" if the header is empty, malformed, or carries the invalid
// all-zero trace-id (which W3C says receivers MUST reject).
//
// Robustness:
//   - Leading/trailing whitespace is trimmed (proxies sometimes pad).
//   - HTTP allows comma-joined repeated header values; we use the FIRST
//     value (W3C TC says senders MUST send only one, so subsequent values
//     are noise from a forwarder).
//   - parent_id / trace_flags are not validated; we only need the trace_id.
//     A non-"00" version is silently accepted (W3C says receivers MAY
//     accept future versions in forward-compat mode).
func traceIDFromHeader(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if i := strings.IndexByte(h, ','); i >= 0 {
		h = strings.TrimSpace(h[:i])
	}
	parts := strings.Split(h, "-")
	if len(parts) != 4 {
		return ""
	}
	tid := strings.ToLower(parts[1])
	if len(tid) != 32 {
		return ""
	}
	// W3C: trace-id of all-zero is invalid.
	if tid == "00000000000000000000000000000000" {
		return ""
	}
	if _, err := hex.DecodeString(tid); err != nil {
		return ""
	}
	return tid
}

// sendDecideError emits a JSON error body in the same shape as the success
// response (decision_id + trace_id present even on error) so PEP code can
// always parse a single envelope. For request-format errors we don't yet
// have a decision_id/trace_id, so callers pass empty strings.
func sendDecideError(w http.ResponseWriter, message string, statusCode int, decisionID, traceID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	body := map[string]interface{}{
		"error":   message,
		"verdict": VerdictDeny, // deny on error so PEP fail-closed is the default
	}
	if decisionID != "" {
		body["decision_id"] = decisionID
	}
	if traceID != "" {
		body["trace_id"] = traceID
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writeDecideResponse encodes a DecideResponse with the canonical JSON content
// type. Centralized so the contract stays single-source.
func writeDecideResponse(w http.ResponseWriter, statusCode int, resp DecideResponse) {
	if resp.Obligations == nil {
		resp.Obligations = []DecisionObligation{}
	}
	if resp.EvaluatedPolicies == nil {
		resp.EvaluatedPolicies = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

// recordDecideMetrics observes duration + increments the verdict counter.
// Pulled out so both the success and the early-return paths converge on
// one set of metric writes. origin is the low-cardinality caller bucket
// (WS-5, #2761) shared by both the duration histogram and the request counter.
func recordDecideMetrics(verdict, stage, origin string, startTime time.Time) {
	decideDuration.WithLabelValues(origin).Observe(float64(time.Since(startTime).Milliseconds()))
	decideRequests.WithLabelValues(verdict, stage, origin).Inc()
}

// recordDecideOutcomeMetrics records the two supplementary decision-outcome
// series the WS-5 dashboard reads (#2761), on the terminal allow/deny path only:
//
//   - decideObligations: one increment per obligation attached to an ALLOW
//     verdict (today only redact_pii), so a dashboard can surface
//     "allowed-with-redaction" volume. Skipped on deny/needs_approval, which
//     carry no obligations.
//   - decideBlocks: on DENY, one increment keyed by the SINGLE blocking system
//     policy (bounded low-cardinality — see the metric's Help), so a dashboard
//     can rank the top blocked policies. Falls back to evaluated_policies[0]
//     (already hoisted to the blocking policy) when blockingPolicyID is empty
//     (the engine-bypass deny paths); "unknown" if neither is available so a
//     deny is never silently uncounted.
//
// This is deliberately split out of recordDecideMetrics because the early-return
// deny paths (circuit-breaker / kill-switch / pre-check PII) have no obligations
// and their blocking-policy attribution is already recorded via the
// evaluated_policies they pass — only the shared-engine terminal path threads
// blockingPolicyID.
func recordDecideOutcomeMetrics(verdict, stage, origin string, obligations []DecisionObligation, blockingPolicyID, blockingPolicyTier string, evaluatedPolicies []string, fallback *obligationFallback) {
	// #2958: an obligation withheld because the caller's seam cannot fulfill it
	// is recorded on its own series, BEFORE the verdict switch — a fallback can
	// end in either allow (log posture) or deny (block posture), and both are
	// the same operational event: "this seam is receiving content it cannot
	// govern". Alerting on it is how a deployment notices a headers-only seam
	// silently degrading to detect-and-log.
	if fallback != nil {
		for _, o := range fallback.suppressed {
			if o.Type == "" {
				continue
			}
			decideObligationFallbacks.WithLabelValues(o.Type, string(fallback.action), stage, origin).Inc()
		}
	}
	switch verdict {
	case VerdictAllow:
		for _, o := range obligations {
			if o.Type == "" {
				continue
			}
			decideObligations.WithLabelValues(o.Type, stage, origin).Inc()
		}
	case VerdictDeny:
		policy := blockingPolicyID
		if policy == "" && len(evaluatedPolicies) > 0 {
			policy = evaluatedPolicies[0]
		}
		recordDecideBlock(boundedBlockPolicy(policy, blockingPolicyTier), origin)
	}
}

// boundedBlockPolicy keeps the decideBlocks `policy` label a low-cardinality set.
// A system/enterprise-tier policy id comes from the fixed, seeded system-policy
// set, so it is surfaced verbatim (that is the useful "top blocked policies"
// ranking). A per-tenant / per-org custom policy (any other tier) has an
// effectively unbounded id ("custom_<hex>", regenerated on recreate) and no
// tenant label on the metric to scope it, so it is collapsed to the single
// "tenant_custom" bucket to prevent a cardinality blow-up. An empty id (no
// attribution available) is "unknown" so a deny is never silently uncounted.
//
// An empty tier is treated as system-safe: it only arises on the engine-bypass
// fallback (no-engine / disabled detection), whose ids are always system checks
// — a real shared-engine deny always carries BlockedBy.Tier.
func boundedBlockPolicy(policyID, tier string) string {
	if policyID == "" {
		return "unknown"
	}
	switch tier {
	case "system", "enterprise", "":
		return policyID
	default: // "organization" / "tenant" / custom → unbounded per-tenant id space
		return "tenant_custom"
	}
}

// recordDecideBlock increments the top-blocked-policies series for one deny,
// keyed by the blocking system policy (low-cardinality — see decideBlocks Help)
// and the caller origin. An empty policy falls back to "unknown" so a deny is
// never silently uncounted. Shared by the terminal shared-engine deny path
// (recordDecideOutcomeMetrics) and the validator-based early-return denies
// (Indonesia / RBI PII, RBI kill switch), so "top blocked policies" is complete
// across every policy-block path. The transient circuit-breaker 503 and the
// security-impersonation/error denies are deliberately NOT recorded here — they
// are not policy blocks (they still count in decideRequests{verdict}).
func recordDecideBlock(policy, origin string) {
	if policy == "" {
		policy = "unknown"
	}
	decideBlocks.WithLabelValues(policy, origin).Inc()
}

// decisionContextAllowlist returns the active request-context key allowlist.
// AXONFLOW_DECISION_CONTEXT_ALLOWLIST (comma-separated) overrides the
// default; blank entries are dropped and a fully-empty override falls back
// to the default so a typo can't silently disable context capture entirely
// without an operator noticing the env var had no effect.
func decisionContextAllowlist() []string {
	raw := strings.TrimSpace(getEnv(envDecisionContextAllowlist, ""))
	if raw == "" {
		return defaultDecisionContextAllowlist
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return defaultDecisionContextAllowlist
	}
	return out
}

// canonicalizeRequestContext filters a raw DecideRequest.context map against
// the allowlist, canonicalizes surviving keys to lower_snake_case, sanitizes
// + length-caps values, and caps the total key count. It is a pure function
// (no I/O, no globals) so the full edge-case matrix is unit-testable.
//
// Returns the kept map (canonical key -> sanitized value) and whether the
// key-count cap dropped any keys (the caller surfaces this as the
// request.context.truncated span attribute + a JSONB marker).
//
// Behavior:
//   - non-string values are dropped silently (the audit pipeline persists
//     strings only — a nested object or number is not a header value)
//   - keys not matching the allowlist are dropped
//   - keys are canonicalized: lowercased, every non-alphanumeric run becomes
//     a single underscore, capped to maxContextKeyLen (X-AI-Agent -> x_ai_agent)
//   - values have control / unprintable runes stripped and are capped to
//     maxContextValueLen bytes on a rune boundary
//   - if more than maxContextKeys survive, keys are sorted and the first
//     maxContextKeys kept (deterministic); truncated=true
func canonicalizeRequestContext(raw map[string]interface{}, allowlist []string) (map[string]string, bool) {
	kept := map[string]string{}
	if len(raw) == 0 {
		return kept, false
	}
	// Iterate raw keys in sorted order so the result is deterministic even
	// when two distinct raw keys canonicalize to the same key (e.g. after the
	// 32-char cap clips a shared prefix): first sorted raw key wins rather than
	// a random map-iteration winner.
	rawKeys := make([]string, 0, len(raw))
	for k := range raw {
		rawKeys = append(rawKeys, k)
	}
	sort.Strings(rawKeys)
	for _, k := range rawKeys {
		s, ok := raw[k].(string)
		if !ok {
			continue // strings only
		}
		if !matchContextAllowlist(k, allowlist) {
			continue
		}
		ck := canonicalContextKey(k)
		if ck == "" {
			continue
		}
		if _, exists := kept[ck]; exists {
			continue // canonical-key collision: keep the first sorted raw key
		}
		kept[ck] = sanitizeContextValue(s)
	}
	if len(kept) <= maxContextKeys {
		return kept, false
	}
	// Deterministic count cap: sort canonical keys, keep the first N.
	keys := make([]string, 0, len(kept))
	for k := range kept {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	capped := make(map[string]string, maxContextKeys)
	for _, k := range keys[:maxContextKeys] {
		capped[k] = kept[k]
	}
	return capped, true
}

// matchContextAllowlist reports whether key matches any allowlist entry.
// Matching is case- and separator-insensitive: both sides are lowercased and
// '_' is folded to '-' so X-AI-Agent, x-ai-agent and x_ai_agent all match the
// "x-ai-agent" entry. A trailing "*" on an entry makes it a prefix match.
func matchContextAllowlist(key string, allowlist []string) bool {
	nk := normalizeContextKeyForMatch(key)
	if nk == "" {
		return false
	}
	for _, entry := range allowlist {
		ne := normalizeContextKeyForMatch(entry)
		if ne == "" {
			continue
		}
		if strings.HasSuffix(ne, "*") {
			if strings.HasPrefix(nk, strings.TrimSuffix(ne, "*")) {
				return true
			}
			continue
		}
		if nk == ne {
			return true
		}
	}
	return false
}

// normalizeContextKeyForMatch lowercases, trims, and folds '_' to '-' so
// allowlist comparison is insensitive to case and separator style. The
// trailing '*' (prefix marker) is preserved.
func normalizeContextKeyForMatch(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

// canonicalContextKey converts a header-style key to the canonical
// lower_snake_case form persisted in the JSONB + emitted as a span
// attribute suffix. Non-alphanumeric runs collapse to a single underscore;
// leading/trailing underscores are trimmed; the result is capped to
// maxContextKeyLen. Returns "" if nothing alphanumeric survives.
func canonicalContextKey(k string) string {
	var b strings.Builder
	lastUnderscore := true // suppress a leading underscore
	for _, r := range strings.ToLower(strings.TrimSpace(k)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
		if b.Len() >= maxContextKeyLen {
			break
		}
	}
	out := strings.TrimRight(b.String(), "_")
	if len(out) > maxContextKeyLen {
		out = out[:maxContextKeyLen]
	}
	return strings.TrimRight(out, "_")
}

// sanitizeContextValue strips control / unprintable runes and caps the value
// to maxContextValueLen bytes without cutting a multi-byte rune. Customer
// values can carry arbitrary bytes; the audit + trace pipelines require valid,
// bounded UTF-8.
func sanitizeContextValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue // drops control chars, zero-width, unprintable
		}
		if b.Len()+utf8.RuneLen(r) > maxContextValueLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decisionAuditInput carries the static, per-request identity fields the
// audit_logs row needs that recordDecideDecision doesn't otherwise receive.
// Built once in handleDecide and passed to every recordDecideDecision call so
// each verdict (including the circuit-breaker / kill-switch / PII early
// returns) produces a complete, explainable audit row.
type decisionAuditInput struct {
	clientID  string
	requestID string
	userEmail string
	userRole  string
	userID    int
	query     string
	// gatewayID is the gateway-asserted origin (caller_identity.gateway_id),
	// e.g. "claude_desktop.<host>" for the Claude Desktop governance proxy
	// (#2520). Recorded at policy_details->>'gateway_id' so Desktop traffic is
	// distinguishable from other PEP layers in the audit trail, and mirrored
	// onto the decision span's decision.gateway_id attribute. Empty for callers
	// that don't assert one.
	gatewayID string
	// origin is the low-cardinality caller-integration bucket (WS-5, #2761):
	// one of the OriginXxx constants (claude-code / claude-desktop / sdk /
	// plugin / gateway / unknown), derived by classifyDecisionOrigin from the
	// X-Axonflow-Client header + gatewayID. Mirrored onto the decision span's
	// decision.origin attribute so trace search + the OTel spanmetrics path can
	// filter per integration. NOT persisted to audit_logs (the metric/span carry
	// it; the audit row already records the finer-grained gateway_id). Empty only
	// on the OTel-only (audit==nil) OpenAI-compat path, where the tracer defaults
	// it to "unknown".
	origin string
	// plane is the surface that emitted the decision (#2592 / ADR-058):
	// PlaneDecision for /api/v1/decide, PlaneMCP for the MCP handlers, etc.
	// Persisted to the first-class audit_logs.plane column. Empty defaults to
	// PlaneDecision in writeDecisionAuditLog (the /decide path is the only
	// caller that historically left it unset).
	plane string
	// correlationID is the shared key across the decision rows of one logical
	// request (#2598 / ADR-058 Phase 1.5): the W3C trace_id a PEP propagates
	// across its llm/tool/agent hops, so the SEBI/EU-AI-Act exporters can GROUP
	// the stages into one ordered chain. Persisted to the first-class
	// audit_logs.correlation_id column AND mirrored into policy_details JSONB
	// (dual-write, matching decision_id). Empty/"" → NULL column → the row is a
	// singleton chain (legacy + single-shot callers).
	correlationID string
	// obligations is the structured ADR-056/#2563 obligation contract for this
	// decision (e.g. a redact_pii obligation). Persisted to audit_logs.obligations
	// JSONB so obligations are queryable structure, not flattened into the
	// free-text policy_details->>'reason'. Empty/nil → NULL column.
	obligations []DecisionObligation
	// suppressedObligations / obligationFallback record an obligation the PDP
	// WITHHELD because the caller's seam advertised it cannot fulfill it, plus
	// the org posture applied (#2958). They land at
	// policy_details->>'suppressed_obligations' / ->>'obligation_fallback'.
	//
	// They are deliberately NOT written to the audit_logs.obligations COLUMN:
	// that column is the record of what the PEP was actually TOLD to do, and a
	// withheld obligation was not. Keeping them apart means a compliance reader
	// can tell "we asked for redaction" from "we detected PII, could not ask for
	// redaction here, and allowed it under the log posture" — which is the whole
	// point of recording them. Empty on every other path.
	suppressedObligations []DecisionObligation
	obligationFallback    string
	// securityEvent, when set, classifies this row as a security-relevant denial
	// (#2643): "tenant_impersonation" / "org_impersonation" (a body
	// caller_identity that disagrees with the authenticated credentials),
	// "tenant_mismatch" (the resolved user's tenant ≠ the client tenant),
	// "user_token_rejected" (a supplied user_token that failed to resolve),
	// "user_token_required" (#3476: none supplied where the org's posture
	// demands one), or "segment_resolution_failed" (#3456: the caller HAS a
	// principal and governance-segment resolution errored, so this plane fails
	// closed at the resolution site rather than evaluating against an
	// undetermined set). Lands
	// at policy_details->>'security_event' so the audit feed can filter every
	// impersonation attempt with one JSONB predicate. Empty for normal rows.
	securityEvent string
	// attemptedTenantID / attemptedOrgID capture the identity the caller ASSERTED
	// on a rejected impersonation attempt (#2643) — the attempted-vs-actual pair:
	// the row's tenant_id/org_id COLUMNS hold the authenticated (actual) identity;
	// these (at policy_details->>'attempted_tenant_id' / 'attempted_org_id') hold
	// what the caller tried to claim. Sanitized + length-capped (untrusted input).
	// Empty when not applicable.
	attemptedTenantID string
	attemptedOrgID    string
	// attemptedUserEmail holds a caller-ASSERTED per-user identity
	// (X-User-Email, under the trust gate) that did NOT become this row's
	// attribution — because attribution names the principal the decision was
	// actually evaluated against, never a claim the system did not act on.
	// Lands at policy_details->>'attempted_user_email', the same
	// attempted-vs-actual shape as attemptedTenantID/attemptedOrgID: the row's
	// user_email COLUMN holds the principal enforcement used; this holds what
	// the caller said. Empty when absent or when it agrees with the column.
	attemptedUserEmail string
	// redactedFields → audit_logs.redacted_fields JSONB (#2643). Empty → NULL.
	// /decide is a PDP — it emits redact_pii OBLIGATIONS (what the PEP must do) but
	// does not itself redact content — so this is NULL on the decision plane
	// today; the column is wired (was previously omitted from the agent INSERT, so
	// only the orchestrator BatchWriter populated it) so an agent-side redaction
	// path can populate it and keep agent redactions queryable alongside the
	// orchestrator's.
	redactedFields []string
	// toolServer / toolName carry the caller-sent tool identity (#2904) — the
	// server/connector a tool lives on and the tool being invoked — onto
	// policy_details.tool_server / policy_details.tool_name. Only populated
	// when Target.Type == "tool"; empty otherwise (e.g. llm/agent decisions).
	toolServer string
	toolName   string
	// approvalEnqueue / approvalRequestID / approvalGrantID record what happened
	// to the human-oversight surface for this decision (#3509).
	//
	//   approvalEnqueue   - one of the hitlEnqueue* outcomes when this decision
	//                       held the caller and a reviewable entry was owed.
	//                       `cap_reached` / `tier_disabled` / `error` are the
	//                       values that matter: they mean the request is held
	//                       and NO reviewer will see it, which is the invisible
	//                       dead end #3509 exists to remove, and the audit row
	//                       is the only durable record that it happened.
	//   approvalRequestID - the created entry's UUID, so an auditor can join
	//                       this decision to the queue row and its history.
	//   approvalGrantID   - the approval that ADMITTED this request, when a
	//                       single-use grant was spent. An allow that a human
	//                       authorised must never be indistinguishable from an
	//                       allow no policy ever questioned.
	//
	// All three land under policy_details; empty on every decision that never
	// touched the approval path.
	approvalEnqueue   string
	approvalRequestID string
	approvalGrantID   string
	// policyNames carries the EVALUATION-TIME id -> display-name map for the
	// row's policy_ids (#3365), threaded from the engine's matched policies
	// (StaticPolicyResult.PolicyNames / policyNamesFromMatches) so
	// buildDecisionAuditDetails can stamp policy_names without a write-time
	// catalog lookup (a rename between evaluation and write must never mint a
	// name the evaluated policy did not carry). Ids absent from the map fall
	// back to the code-defined builtin guard names; anything else stays
	// unnamed. NOTE the portal's not-recorded marker is ROW-level: it renders
	// only when NO id on the row resolves a name, so a partially-named row
	// shows its resolved names without a marker and the unnamed ids appear
	// only on the Policy IDs surface (per-id markers are a reader follow-up
	// flagged on #3365). Nil on paths with no engine result in scope (early
	// denies stamp only builtin-resolvable ids).
	policyNames map[string]string
}

// maxGatewayIDLen bounds a recorded gateway_id. Gateway ids are short origin
// tags (claude_desktop.<host>); the cap keeps a hostile/oversized value from
// bloating the audit JSONB or a span attribute.
const maxGatewayIDLen = 128

// sanitizeGatewayID trims, strips control/unprintable runes, and length-caps a
// caller-supplied gateway_id so the recorded value is bounded valid UTF-8.
// Returns "" for an empty/whitespace input (the common case for callers that
// don't assert an origin).
func sanitizeGatewayID(s string) string {
	return boundedAuditString(s, maxGatewayIDLen)
}

// sanitizeAuditIdentity bounds a caller-asserted identity (the attempted
// tenant_id / org_id on a rejected impersonation attempt) before it lands in the
// audit JSONB (#2643). The attempted value is UNTRUSTED — a hostile PEP could
// send an oversized or control-char-laden string — so it gets the same
// strip-unprintable + length-cap treatment as a gateway_id.
func sanitizeAuditIdentity(s string) string {
	return boundedAuditString(s, maxGatewayIDLen)
}

// boundedAuditString trims, strips control/unprintable runes, and caps a
// caller-supplied string to max bytes on a rune boundary so the recorded value
// is bounded, valid UTF-8. Returns "" for empty/whitespace input.
func boundedAuditString(s string, max int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// recordDecideDecision emits the OTel decision span via the
// decisionTracerProvider from #2437 AND, when audit != nil, persists a
// durable audit_logs row so GET /api/v1/decisions and the explain endpoint
// can surface this decision (including the sanitized request context).
//
// Returns the OTel-assigned trace_id if the provider is wired, or falls back
// to the caller-supplied fallbackTraceID (the inbound traceparent's trace-id
// or a freshly minted W3C ID). The fallback keeps trace_id populated even
// when AXONFLOW_OTEL_ENDPOINT is unset (noop tracer returns "").
//
// reqContext is the canonicalized request-context map (canonical keys ->
// sanitized values); contextTruncated flags that the key-count cap dropped
// keys. Both are threaded into the span attributes and the audit JSONB.
//
// audit == nil means "OTel only" — the OpenAI-compat caller records its own
// llm_call_audits row and must not double-write audit_logs.
func recordDecideDecision(ctx context.Context, decisionID, orgID, tenantID, stage, verdict string, policyIDs []string, latencyMs int64, reasons []string, fallbackTraceID string, reqContext map[string]string, contextTruncated bool, audit *decisionAuditInput) string {
	// Durable audit first so the decision is recoverable even if the OTel
	// collector is down. Best-effort: a DB hiccup never changes the verdict
	// the PEP already holds (the write logs and returns on error).
	if audit != nil {
		// #3424: latencyMs is the SAME enforcement duration this function
		// already hands to the signed decision chain (below) and to the OTel
		// span + the axonflow_decision_duration_milliseconds histogram. It was
		// measured, carried this far, and then dropped on the floor for
		// audit_logs, which is why the portal's Avg Latency tile had nothing to
		// average. Threading the existing value rather than taking a second
		// measurement here is what keeps the tile, the metric and the chain
		// from reporting three different numbers for one decision.
		writeDecisionAuditLog(ctx, usageDB, decisionID, orgID, tenantID, stage, verdict, policyIDs, reasons, reqContext, contextTruncated, latencyMs, *audit)
	}

	// Non-repudiation (#2732): sign + prev_hash-chain this decision into
	// decision_chain so GET /api/v1/audit/{chains,records}/.../verify can prove
	// its authorship. Placed BEFORE the OTel early-return so signing happens even
	// when AXONFLOW_OTEL_ENDPOINT is unset (the two trackers are independent).
	// Best-effort + off the hot path (recordSignedDecision enqueues; the worker
	// signs). Covers both /api/v1/decide and the OpenAI-compat path (audit==nil),
	// both of which are genuine cross-border-auditable decisions.
	recordSignedDecision(ctx, decisionID, orgID, tenantID, stage, verdict, policyIDs, reasons, latencyMs)

	if decisionTracerProvider == nil {
		return fallbackTraceID
	}
	// gateway_id + origin ride on the span when available (audit may be nil for
	// the OpenAI-compat OTel-only path, which asserts neither — the tracer then
	// defaults decision.origin to "unknown").
	gatewayID := ""
	origin := ""
	if audit != nil {
		gatewayID = audit.gatewayID
		origin = audit.origin
	}
	otelTraceID := decisionTracerProvider.Tracer.RecordDecision(ctx, telemetry.DecisionEvent{
		DecisionID:       decisionID,
		OrgID:            orgID,
		TenantID:         tenantID,
		GatewayID:        gatewayID,
		Origin:           origin,
		Stage:            stage,
		Verdict:          verdict,
		PolicyIDs:        policyIDs,
		LatencyMs:        latencyMs,
		Reasons:          reasons,
		Context:          reqContext,
		ContextTruncated: contextTruncated,
	})
	if otelTraceID != "" {
		return otelTraceID
	}
	return fallbackTraceID
}

// writeDecisionAuditLog persists a Decision Mode verdict to audit_logs so the
// orchestrator's GET /api/v1/decisions list + per-id explain endpoints can
// resolve it (both read policy_details->>'decision_id' against audit_logs).
// Mirrors the established agent-side writer writeExplainableAuditLog: a direct
// INSERT (audit_logs is not FORCE-RLS — migration 101 deliberately left it so
// for the cross-org cleanup worker), best-effort, with NOT-NULL-column
// fallbacks. The sanitized request context lands at policy_details->'context'
// (canonical snake_case keys, string values); truncation is flagged at
// policy_details->'context_truncated'.
//
// Best-effort means the write never changes the verdict the PEP already holds —
// but it is no longer SILENT (#2643): every no-write branch (no DB, empty
// decision_id, marshal failure, INSERT error) increments
// decideAuditWriteFailures{reason} so operators can alert on a degraded audit
// path. A failure on a DENY path does NOT weaken the deny (the request is
// already denied); we deliberately do not additionally hard-fail the response,
// which would convert a clean security deny into a confusing 5xx for the PEP.
//
// latencyMs is the handler's own enforcement duration (#3424), persisted to
// audit_logs.response_time_ms so the portal's Compliance Summary has something
// to average. Pass sharedaudit.LatencyUnmeasured, never a hand-rolled 0, if a
// caller ever has nothing to measure: on this plane a 0 is a real result (a
// decision that finished inside a millisecond) and is stored as one.
func writeDecisionAuditLog(ctx context.Context, db *sql.DB, decisionID, orgID, tenantID, stage, verdict string, policyIDs, reasons []string, reqContext map[string]string, contextTruncated bool, latencyMs int64, audit decisionAuditInput) {
	if db == nil {
		decideAuditWriteFailures.WithLabelValues("nodb").Inc()
		return
	}
	if decisionID == "" {
		decideAuditWriteFailures.WithLabelValues("empty_decision_id").Inc()
		return
	}
	if policyIDs == nil {
		policyIDs = []string{}
	}
	if reasons == nil {
		reasons = []string{}
	}

	details := buildDecisionAuditDetails(decisionID, stage, policyIDs, reasons, reqContext, contextTruncated, audit)
	// ADR-061 / #3329: merge the fincrime attribution recorded on ctx
	// (risk_score, ml_inference_layer_status, fincrime policy
	// ids/names/versions). No-op for every non-fincrime decision.
	details = fincrime.MergeAuditDetails(ctx, details)
	// #3365: id-keyed policy_versions for the row's ids, best-effort, AFTER the
	// fincrime merge so the seam's model/pack version strings win (missing-only
	// add, mirroring MergeAuditDetails' existing-entry-wins rule). Acted rows
	// only: an allow write must not pay the RLS-scoped batch read per request.
	if actedAuditVerdict(verdict) {
		stampMissingPolicyVersions(ctx, db, details)
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		decideAuditWriteFailures.WithLabelValues("marshal").Inc()
		log.Printf("⚠️ [Decide] audit log marshal failed (non-fatal): %v", err)
		return
	}

	writeDecisionAuditRow(ctx, db, detailsJSON, decisionID, orgID, tenantID, stage, verdict, latencyMs, audit)
}

// buildDecisionAuditDetails assembles the policy_details JSONB payload for one
// decision row. Pulled out as a PURE function so the content contract every
// audit/compliance reader depends on — decision_id, the detected policy_ids, and
// (#2958) the suppressed-obligation record — is unit-testable without standing
// up a database or matching a 20-column INSERT positionally.
func buildDecisionAuditDetails(decisionID, stage string, policyIDs, reasons []string, reqContext map[string]string, contextTruncated bool, audit decisionAuditInput) map[string]interface{} {
	details := map[string]interface{}{
		"decision_id": decisionID,
		"source":      "decision_mode",
		"stage":       stage,
		"policy_ids":  policyIDs,
		"reasons":     reasons,
	}
	// #3365: display names for the ids above (evaluation-time map first, then
	// the builtin guard table; a row with NO resolvable name keeps the
	// reader's honest marker, a partially-named row shows the resolved names).
	stampPolicyIdentityNames(details, policyIDs, audit.policyNames)
	// gateway_id distinguishes the PEP origin (e.g. claude_desktop.<host>) so a
	// query over Desktop traffic is a single JSONB filter. Omitted when unset.
	if audit.gatewayID != "" {
		details["gateway_id"] = audit.gatewayID
	}
	if len(reasons) > 0 {
		// explain_handler.go reads policy_details->>'reason' (scalar).
		details["reason"] = strings.Join(reasons, "; ")
	}
	if len(reqContext) > 0 {
		details["context"] = reqContext
	}
	if contextTruncated {
		details["context_truncated"] = true
	}
	// #2598 / ADR-058 Phase 1.5: mirror the correlation key into the JSONB copy
	// alongside the first-class column below, so the exporters' COALESCE read path
	// still resolves it if the column is ever dropped/rolled back (matches the
	// decision_id dual-write). Omitted when unset → the row stays a singleton.
	if audit.correlationID != "" {
		details["correlation_id"] = audit.correlationID
	}
	// #2643: security-relevant denial classification + attempted-vs-actual
	// identity. The row's tenant_id/org_id COLUMNS carry the ACTUAL (authenticated)
	// identity; these record the security event + what the caller TRIED to claim,
	// so a single JSONB predicate surfaces every impersonation/mismatch attempt.
	if audit.securityEvent != "" {
		details["security_event"] = audit.securityEvent
	}
	if audit.attemptedTenantID != "" {
		details["attempted_tenant_id"] = audit.attemptedTenantID
	}
	if audit.attemptedOrgID != "" {
		details["attempted_org_id"] = audit.attemptedOrgID
	}
	if audit.attemptedUserEmail != "" {
		details["attempted_user_email"] = audit.attemptedUserEmail
	}
	if audit.toolServer != "" {
		details["tool_server"] = audit.toolServer
	}
	if audit.toolName != "" {
		details["tool_name"] = audit.toolName
	}
	// #2958: what the seam-capability gate withheld, and the posture applied.
	// Under the log posture this is the ONLY record that a redaction was due —
	// the verdict is a plain allow and the obligations column is empty — so a
	// compliance query can still find "PII was detected here and not masked".
	// The detected categories ride policy_ids/reasons above.
	if len(audit.suppressedObligations) > 0 {
		suppressed := make([]map[string]string, 0, len(audit.suppressedObligations))
		for _, o := range audit.suppressedObligations {
			suppressed = append(suppressed, map[string]string{"type": o.Type, "detail": o.Detail})
		}
		details["suppressed_obligations"] = suppressed
		details["obligation_fallback"] = audit.obligationFallback
	}
	// #3509: the human-oversight surface for this decision. approval_enqueue is
	// the one an operator alerts on - anything other than "created" means the
	// caller was held and no reviewer will ever see the request, and this row is
	// the only durable record of it. approval_grant_id names the human whose
	// approval admitted an allow, so an authorised admission is never
	// indistinguishable from an unquestioned one.
	if audit.approvalEnqueue != "" {
		details["approval_enqueue"] = audit.approvalEnqueue
	}
	if audit.approvalRequestID != "" {
		details["approval_request_id"] = audit.approvalRequestID
	}
	if audit.approvalGrantID != "" {
		details["approval_grant_id"] = audit.approvalGrantID
	}
	return details
}

// writeDecisionAuditRow performs the canonical audit_logs INSERT for one
// decision, given the already-marshalled policy_details payload.
//
// latencyMs is the caller's measured enforcement duration; it reaches
// response_time_ms through sharedaudit.MeasuredLatencyMs. Both live callers
// (the Decision API and the Gateway pre-check) always measure, so this is
// always a real sample -- INCLUDING a 0, which on these planes means the
// decision completed in under the column's 1ms resolution and is recorded as
// such rather than discarded. Only sharedaudit.LatencyUnmeasured stores NULL
// (#3424).
func writeDecisionAuditRow(ctx context.Context, db *sql.DB, detailsJSON []byte, decisionID, orgID, tenantID, stage, verdict string, latencyMs int64, audit decisionAuditInput) {
	// audit_logs NOT-NULL columns: fall back to placeholders rather than
	// fail the insert (mirrors writeExplainableAuditLog).
	userEmail := audit.userEmail
	if userEmail == "" {
		userEmail = "unknown@axonflow.local"
	}
	userRole := audit.userRole
	if userRole == "" {
		userRole = "service"
	}
	clientID := audit.clientID
	if clientID == "" {
		clientID = "unknown"
	}
	if tenantID == "" {
		tenantID = "unknown"
	}
	query := audit.query
	if query == "" {
		query = "(empty)"
	}
	requestID := audit.requestID
	if requestID == "" {
		requestID = decisionID
	}
	sum := sha256.Sum256([]byte(query))
	queryHash := hex.EncodeToString(sum[:])

	// #2592 / ADR-058 Phase 1: promote decision_id to a first-class column +
	// add the plane discriminator + structured obligations, ALONGSIDE the JSONB
	// copy above (dual-write, no flag-day). plane defaults to PlaneDecision
	// because /api/v1/decide is the only writer that historically left it unset.
	plane := audit.plane
	if plane == "" {
		plane = PlaneDecision
	}
	// obligations → JSONB column (NULL when none). Marshal failure is non-fatal:
	// the row still records the verdict, just without the structured obligations.
	var obligationsJSON interface{}
	if len(audit.obligations) > 0 {
		if b, mErr := json.Marshal(audit.obligations); mErr == nil {
			obligationsJSON = b
		} else {
			log.Printf("⚠️ [Decide] obligations marshal failed (non-fatal): %v", mErr)
		}
	}

	// #2598 / ADR-058 Phase 1.5: correlation_id → first-class column (NULL when
	// unset so the row groups as its own singleton). Dual-written into
	// policy_details above for read-path resilience.
	var correlationIDArg interface{}
	if audit.correlationID != "" {
		correlationIDArg = audit.correlationID
	}

	// #2643 / #2638: persist the CANONICAL audit verdict (allowed|blocked|
	// redacted|needs_approval|error), translated from the wire verdict — never the
	// legacy token allow/deny, which the audit summary handler silently buckets as
	// "not blocked".
	//
	// SCOPED to the planes that feed the WIRE verdict (allow/deny): plane=decision
	// (/api/v1/decide) and, as of #2686, plane=openai_compat — the OpenAI-compat
	// surface passes the same wire verdict so its OTel span vocab stays aligned with
	// /decide, and it is NEW to audit_logs (no prior rows / E2E to disturb), so
	// canonicalizing it here is safe. writeDecisionAuditLog is also SHARED with the
	// MCP planes (mcp_handler.go routes through it), which already emit the CANONICAL
	// vocabulary directly — re-canonicalizing them here would be a no-op at best and
	// risk a freshly-merged plane's runtime E2E at worst, so they stay excluded. The
	// one-time historical rows across ALL planes are normalized by migration 122; the
	// reader-side normalizer is the #2638 follow-up.
	policyDecision := auditPolicyDecisionFor(plane, verdict)

	// #2643: redacted_fields → JSONB array column (NULL when none). Previously
	// omitted from the agent INSERT (only the orchestrator BatchWriter populated
	// it); wired here so agent redactions are queryable. /decide is a PDP — it
	// emits redact_pii OBLIGATIONS, it does not itself redact — so it leaves this
	// empty (→ NULL) today.
	var redactedFieldsArg interface{}
	if len(audit.redactedFields) > 0 {
		if b, mErr := json.Marshal(audit.redactedFields); mErr == nil {
			redactedFieldsArg = b
		} else {
			log.Printf("⚠️ [Decide] redacted_fields marshal failed (non-fatal): %v", mErr)
		}
	}

	// #2896: per-session identity → audit_logs.session_id (NULL when the caller
	// didn't assert one or the trust gate is off). Read from the request context
	// — handleDecide (and the check-input/check-output handlers that route
	// through this writer) stamp it via withClientSessionID ONLY under the
	// trust gate, so an unstamped context is the untrusted default. Same
	// mechanism as the sibling MCP writers (#2753).
	var sessionIDArg interface{}
	if sid := clientSessionIDFromContext(ctx); sid != "" {
		sessionIDArg = sid
	}

	_, err := db.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, decision_id, plane, obligations,
			correlation_id, redacted_fields, session_id, response_time_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
	`,
		"decide_"+decisionID,                     // id (PK; one row per decision)
		requestID,                                // request_id
		time.Now().UTC(),                         // timestamp
		audit.userID,                             // user_id
		userEmail,                                // user_email
		userRole,                                 // user_role
		clientID,                                 // client_id
		tenantID,                                 // tenant_id
		orgID,                                    // org_id (nullable)
		"decision_"+stage,                        // request_type — bounded: decision_llm|tool|agent
		query,                                    // query
		queryHash,                                // query_hash
		policyDecision,                           // policy_decision — CANONICAL: allowed|blocked|redacted|needs_approval|error (#2643)
		detailsJSON,                              // policy_details (JSONB) — decision_id still mirrored here
		decisionID,                               // decision_id (first-class column; #2592)
		plane,                                    // plane (surface discriminator; #2592)
		obligationsJSON,                          // obligations (JSONB or NULL; #2592)
		correlationIDArg,                         // correlation_id (first-class column or NULL; #2598)
		redactedFieldsArg,                        // redacted_fields (JSONB array or NULL; #2643)
		sessionIDArg,                             // session_id (first-class column or NULL; #2896)
		sharedaudit.MeasuredLatencyMs(latencyMs), // response_time_ms (NULL only for LatencyUnmeasured; #3424)
	)
	if err != nil {
		decideAuditWriteFailures.WithLabelValues("insert").Inc()
		log.Printf("⚠️ [Decide] audit log insert failed (non-fatal): %v", err)
	}
}

// RegisterDecisionHandlers registers the Decision Mode endpoint.
// Wired in run.go alongside RegisterGatewayHandlers. OPTIONS is registered
// alongside POST so CORS preflight requests don't 404 -- apiAuthMiddleware
// itself shortcircuits OPTIONS so the preflight does not get auth-checked.
func RegisterDecisionHandlers(r *mux.Router) {
	r.Handle(decisionHandlerPath, apiAuthMiddleware(http.HandlerFunc(handleDecide))).Methods("POST", "OPTIONS")
	log.Printf("✅ Decision Mode endpoint registered: POST %s", decisionHandlerPath)
}
