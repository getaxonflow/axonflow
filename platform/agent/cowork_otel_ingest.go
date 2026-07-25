//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// WS-6 (#2760) — Cowork / Claude Code OTEL ingest plane.
//
// Anthropic keeps Claude Cowork activity out of its own audit logs, Compliance
// API, and data exports, so a customer's ONLY central-capture path for Cowork is
// the native OpenTelemetry export. This file receives that OTLP log stream
// (Cowork AND Claude Code), and — per the single-audit-source rule (#2585 /
// #2625; the anti-pattern of a plane writing a satellite table and skipping
// canonical audit_logs is exactly what #2679/#2680 closed) — lands each event as
// a CANONICAL audit_logs row (plane='cowork' / 'claude_code'), redacted at the
// collector, and wired into the existing Ed25519 signed decision chain. It is NOT
// a parallel store: the reporting/query surface stays the unified one (session
// summary #2759 reads audit_logs).
//
// Invariants (see the WS-6 brief + addendum):
//   - Authenticated + tenant-tagged ingest. org_id/tenant_id come from the
//     authenticated license (apiAuthMiddleware), NEVER from the (spoofable) OTEL
//     attributes. user.email from the telemetry is attribution only.
//   - Identity/session attribution reads the LOG RECORD attributes first, then
//     falls back to resource attributes (#2838): real Claude Code / Cowork
//     exporters carry user.email / session.id / user.account_uuid on EVERY log
//     record (verified against a real captured export), while their resource
//     block holds only service.*/os.*/host.arch. The resource-level fallback
//     stays for collectors that promote record attributes to the resource.
//   - Redact BEFORE persist, fail-closed: content is routed through the engine
//     (evaluateOutputPolicies — the SAME response-plane redactor check-output
//     uses; no new regex). If no redactor is active, raw content is WITHHELD.
//   - Reply text (assistant_response, emitted by Cowork ≥1.17377 and Claude
//     Code) IS ingested (#2838) and force-redacted like all content fields.
//   - Reuse the existing signed chain (recordSignedDecision → decision_chain,
//     #2722/#2732); no signing is reimplemented.
package agent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"

	sharedaudit "axonflow/platform/shared/audit"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	// coworkOTELLogsPath is the standard OTLP/HTTP logs path. Cowork / Claude Code
	// exporters POST to <OTEL_EXPORTER_OTLP_ENDPOINT>/v1/logs.
	coworkOTELLogsPath = "/v1/logs"

	// maxCoworkOTLPBody caps a single OTLP export request body (defense against an
	// unbounded ingest). 8 MiB comfortably holds a batched export.
	maxCoworkOTLPBody = 8 << 20

	// maxCoworkRecordsPerRequest bounds how many log records one export request may
	// turn into synchronous audit_logs INSERTs (defense against ingest
	// amplification). Excess records are skipped and reported via partial_success.
	maxCoworkRecordsPerRequest = 5000

	contentTypeProtobuf = "application/x-protobuf"
	contentTypeJSON     = "application/json"

	// Canonical (prefix-stripped) OTEL event names we map. Cowork and Claude Code
	// emit these with a "cowork." / "claude_code." prefix which we normalize away.
	evUserPrompt        = "user_prompt"
	evToolResult        = "tool_result"
	evToolDecision      = "tool_decision"
	evAPIRequest        = "api_request"
	evAPIError          = "api_error"
	evAssistantResponse = "assistant_response"

	// audit_logs column widths (migrations 059/119/121/129). EVERY client-supplied
	// telemetry value bound for a bounded column is truncated/clamped: an
	// oversized value would fail the row INSERT, and a client-triggerable
	// insert failure on this plane is an audit-evasion channel (the event would
	// be ACKed but never audited — R3 H1).
	maxCoworkUserEmailLen     = 255
	maxCoworkSessionIDLen     = 255
	maxCoworkModelLen         = 100 // audit_logs.model VARCHAR(100)
	maxCoworkCorrelationIDLen = 255 // audit_logs.correlation_id VARCHAR(255)
	maxCoworkAccountUUIDLen   = 64  // UUID-shaped join key; free text is hostile
	maxCoworkAccountIDLen     = 128 // user_…-tagged join key
	maxCoworkToolNameLen      = 256 // descriptor identifiers (tool_name / decision) embedded in query
)

// maxCoworkCost caps audit_logs.cost (DECIMAL(10,6) → max 9999.999999). A
// client-supplied cost_usd beyond it is nonsense; clamp instead of failing the
// INSERT.
const maxCoworkCost = 9999.999999

var (
	errUnsupportedContentType = errors.New("unsupported content-type (want application/x-protobuf or application/json)")
	errOTLPBodyTooLarge       = errors.New("otlp body exceeds limit")
)

// registerCoworkOTELIngest mounts the authenticated OTLP ingest routes (logs +
// metrics). It creates its own subrouter with apiAuthMiddleware so inbound
// telemetry is authenticated and org/tenant-tagged from the license (mirrors
// the hitl mount). otelIngestRejectObserver wraps OUTSIDE the auth middleware
// (mux applies Use() in order, first = outermost) so auth 401s — previously
// silent, #2832 — are logged + counted per tenant. In the community build a
// no-op stub with the same name mounts 501s instead.
func registerCoworkOTELIngest(r *mux.Router) {
	sub := r.NewRoute().Subrouter()
	sub.Use(otelIngestRejectObserver, apiAuthMiddleware)
	sub.HandleFunc(coworkOTELLogsPath, coworkOTELLogsHandler).Methods(http.MethodPost)
	sub.HandleFunc(coworkOTELMetricsPath, coworkOTELMetricsHandler).Methods(http.MethodPost)
	log.Printf("[CoworkOTEL] enterprise OTLP ingest mounted at POST %s + POST %s (authenticated)", coworkOTELLogsPath, coworkOTELMetricsPath)
}

// coworkOTELLogsHandler receives an OTLP/HTTP ExportLogsServiceRequest (protobuf
// or JSON), maps each log record to a canonical audit_logs row (redacted +
// signed), and returns an OTLP ExportLogsServiceResponse.
func coworkOTELLogsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := OrgIDFromContext(ctx)
	tenantID := TenantIDFromContext(ctx)
	clientID := ClientIDFromContext(ctx)

	// Defense-in-depth: the route is behind apiAuthMiddleware, but in a
	// non-community deployment an empty org means the tenant tag is missing —
	// reject rather than write an untagged (ingest-hole) row. Community mode has
	// no license and legitimately runs with the "community" tenant.
	if !isCommunityMode() && orgID == "" {
		writeJSONError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	ct := r.Header.Get("Content-Type")
	body, err := readLimited(r.Body, maxCoworkOTLPBody)
	if err != nil {
		if errors.Is(err, errOTLPBodyTooLarge) {
			writeJSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSONError(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	req, err := parseCoworkOTLPLogs(ct, body)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errUnsupportedContentType) {
			status = http.StatusUnsupportedMediaType
		}
		writeJSONError(w, "invalid OTLP logs payload: "+err.Error(), status)
		return
	}

	accepted, rejected := processCoworkLogs(ctx, orgID, tenantID, clientID, req)
	log.Printf("[CoworkOTEL] ingest org=%s tenant=%s accepted=%d rejected=%d",
		logSanitize(orgID), logSanitize(tenantID), accepted, rejected)

	writeOTLPLogsResponse(w, ct, int64(rejected))
}

// processCoworkLogs walks the OTLP structure and persists one canonical
// audit_logs row per recognized log record. Unrecognized event names are skipped
// (counted as rejected). Returns (accepted, rejected) record counts.
func processCoworkLogs(ctx context.Context, orgID, tenantID, clientID string, req *collectorlogs.ExportLogsServiceRequest) (accepted, rejected int) {
	if req == nil {
		return 0, 0
	}
	for _, rl := range req.GetResourceLogs() {
		resAttrs := attrsToMap(rl.GetResource().GetAttributes())
		// Resource-level identity is the FALLBACK only (#2838): real Claude Code /
		// Cowork exporters carry session.id / user.email per LOG RECORD, and their
		// resource block has no identity at all. processCoworkRecord prefers the
		// record-level values over these.
		// Sanitize per candidate before picking (an all-control first spelling
		// must not shadow a valid alternate — #2840 R3 L1 class).
		resSessionID := firstNonEmpty(
			truncateOTELString(getStr(resAttrs, "session.id"), maxCoworkSessionIDLen),
			truncateOTELString(getStr(resAttrs, "session_id"), maxCoworkSessionIDLen))
		resUserEmail := firstNonEmpty(
			truncateOTELString(getStr(resAttrs, "user.email"), maxCoworkUserEmailLen),
			truncateOTELString(getStr(resAttrs, "user_email"), maxCoworkUserEmailLen))
		serviceName := getStr(resAttrs, "service.name")
		plane := planeFromService(serviceName)

		for _, sl := range rl.GetScopeLogs() {
			for _, rec := range sl.GetLogRecords() {
				// Bound synchronous INSERTs per request (ingest amplification guard).
				if accepted >= maxCoworkRecordsPerRequest {
					rejected++
					continue
				}
				if processCoworkRecord(ctx, orgID, tenantID, clientID, plane, resSessionID, resUserEmail, rec) {
					accepted++
				} else {
					rejected++
				}
			}
		}
	}
	return accepted, rejected
}

// processCoworkRecord maps one OTLP LogRecord to a canonical audit_logs row.
// resSessionID/resUserEmail are the resource-level FALLBACK values; the record's
// own attributes win (#2838 — that is where real exporters put them).
// Returns true when a row was persisted (recognized event), false otherwise.
func processCoworkRecord(ctx context.Context, orgID, tenantID, clientID, plane, resSessionID, resUserEmail string, rec *logspb.LogRecord) bool {
	if rec == nil {
		return false
	}
	attrs := attrsToMap(rec.GetAttributes())
	base := normalizeEventName(firstNonEmpty(rec.GetEventName(), getStr(attrs, "event.name"), getStr(attrs, "name")))

	// Sanitize each candidate BEFORE the fallback pick: an all-control
	// record-level value ("\x00") is non-empty pre-sanitize and would shadow a
	// valid resource-level fallback into empty attribution (R3 #2840 L1).
	sessionID := firstNonEmpty(
		truncateOTELString(getStr(attrs, "session.id"), maxCoworkSessionIDLen),
		truncateOTELString(getStr(attrs, "session_id"), maxCoworkSessionIDLen),
		truncateOTELString(resSessionID, maxCoworkSessionIDLen))
	// #2922: canonicalized (lower+trim) so OTLP-ingested rows carry the same
	// identity key the role-scoped read path filters on (parity with the MCP
	// and /decide write planes).
	userEmail := sharedidentity.CanonicalEmail(firstNonEmpty(
		truncateOTELString(getStr(attrs, "user.email"), maxCoworkUserEmailLen),
		truncateOTELString(getStr(attrs, "user_email"), maxCoworkUserEmailLen),
		truncateOTELString(resUserEmail, maxCoworkUserEmailLen)))
	// Anthropic account identifiers (record-level, #2838): the documented join
	// keys to Anthropic's Compliance API. Attribution only, stored in
	// policy_details — length-capped so multi-MB junk under these keys can
	// neither bloat the JSONB row nor smuggle unredacted free text (R3 M1).
	accountUUID := truncateOTELString(getStr(attrs, "user.account_uuid"), maxCoworkAccountUUIDLen)
	accountID := truncateOTELString(getStr(attrs, "user.account_id"), maxCoworkAccountIDLen)

	promptID := firstNonEmpty(
		truncateOTELString(getStr(attrs, "prompt.id"), maxCoworkCorrelationIDLen),
		truncateOTELString(getStr(attrs, "prompt_id"), maxCoworkCorrelationIDLen))
	toolName := truncateOTELString(getStr(attrs, "tool_name"), maxCoworkToolNameLen)
	model := truncateOTELString(getStr(attrs, "model"), maxCoworkModelLen)
	inputTokens := getInt(attrs, "input_tokens")
	outputTokens := getInt(attrs, "output_tokens")
	cost := firstNonZeroFloat(getFloat(attrs, "cost_usd"), getFloat(attrs, "cost"))
	durationMs := getInt(attrs, "duration_ms")

	// userID for the policy engine + audit: real identity travels via user_email;
	// the numeric user_id column is a historical 0 (mirrors writeMCPDecisionAudit).
	policyUserID := firstNonEmpty(userEmail, "cowork")
	source := plane // connector label for evaluateOutputPolicies (isGateway bypasses the allowlist)

	verdict := sharedaudit.DecisionAllowed
	var storedContent string
	var redactedFields []string

	// Extract the content field per event type, then redact-at-collector.
	// sanitizeOTELText first (#2840): a client NUL / control byte in the prose
	// would otherwise abort the audit INSERT and lose the row — the audit store
	// must capture the event, sanitized, not drop it. Tab/newline/CR survive.
	var content string
	switch base {
	case evUserPrompt:
		content = sanitizeOTELText(getStr(attrs, "prompt"))
	case evToolResult:
		content = firstNonEmpty(sanitizeOTELText(getStr(attrs, "tool_input")), sanitizeOTELText(getStr(attrs, "tool_parameters")))
	case evAssistantResponse:
		// Model reply text (#2838; present when the org's content capture /
		// OTEL_LOG_* settings include responses). Free text → force-redacted.
		content = sanitizeOTELText(getStr(attrs, "response"))
	}

	if content != "" {
		rr := coworkRedact(ctx, tenantID, policyUserID, source, content)
		storedContent = rr.text
		redactedFields = rr.fields
		verdict = rr.verdict
	}

	// Descriptor / verdict per event type. CONTENT events (user_prompt, tool_result)
	// store the force-redacted content in query. NON-content events store a
	// descriptor built from structural IDENTIFIERS (tool_name, model, decision) —
	// these are not free-form user content and are treated as identifiers (same as
	// the MCP writer stores connector/tool names), so they are not routed through
	// the PII redactor. Genuine user content always flows through coworkRedact above.
	requestType := plane + "_" + base
	query := storedContent
	switch base {
	case evUserPrompt:
		if query == "" {
			query = "(cowork user prompt: content capture off)"
		}
	case evToolResult:
		if query == "" {
			query = "cowork tool_result: " + defaultStr(toolName, "(tool)")
		}
	case evToolDecision:
		decision := firstNonEmpty(
			truncateOTELString(getStr(attrs, "decision"), maxCoworkToolNameLen),
			truncateOTELString(getStr(attrs, "decision_type"), maxCoworkToolNameLen))
		query = "cowork tool_decision: " + defaultStr(toolName, "(tool)") + " → " + defaultStr(decision, "(unknown)")
		if isRejectDecision(decision) {
			verdict = sharedaudit.DecisionBlocked
		}
	case evAssistantResponse:
		if query == "" {
			query = "(cowork assistant response: content capture off)"
		}
	case evAPIRequest:
		query = "cowork api_request: " + defaultStr(model, "(model)")
	case evAPIError:
		query = "cowork api_error: " + defaultStr(model, "(model)")
		verdict = sharedaudit.DecisionError
	default:
		// Unrecognized event — do not fabricate an audit row.
		return false
	}

	decisionID := uuid.New().String()
	row := coworkAuditRow{
		decisionID:     decisionID,
		orgID:          orgID,
		tenantID:       tenantID,
		clientID:       clientID,
		userEmail:      userEmail,
		accountUUID:    accountUUID,
		accountID:      accountID,
		userRole:       roleForPlane(plane),
		plane:          plane,
		requestType:    requestType,
		query:          query,
		policyDecision: verdict,
		correlationID:  promptID,
		sessionID:      sessionID,
		redactedFields: redactedFields,
		model:          model,
		responseTimeMs: durationMs,
		tokensUsed:     clampCoworkTokens(inputTokens, outputTokens),
		cost:           clampCoworkCost(cost),
		eventName:      base,
		timestamp:      recordTimestamp(rec),
	}
	// Persist-then-sign, and count a failed persist as REJECTED (R3 H1): ACKing
	// an event whose row was never stored is an audit-evasion channel, and a
	// chain entry must never reference a row that does not exist.
	if !writeCoworkAuditLog(ctx, usageDB, row) {
		return false
	}

	// Sign + hash-chain the canonical row into decision_chain (#2722/#2732). Reuses
	// the existing wiring; best-effort, off the hot path, never reimplemented. The
	// OTEL plane has no policy MATCH (it observes + redacts), so policyIDs is nil;
	// the redacted field names travel in reasons for the audit trail (not as
	// policy ids, which would mis-attribute PolicyTriggered on a block).
	reasons := []string{"cowork otel ingest: " + base}
	if len(redactedFields) > 0 {
		reasons = append(reasons, "redacted: "+strings.Join(redactedFields, ","))
	}
	recordSignedDecision(ctx, decisionID, orgID, tenantID, stageForEvent(base), verdict, nil, reasons, durationMs)
	return true
}

// clampCoworkTokens folds client-supplied int64 token counts into the int32
// audit_logs.tokens_used column without overflow (negative or absurd values
// clamp instead of failing the INSERT — R3 H1).
func clampCoworkTokens(in, out int64) int {
	sum := in + out
	if in > 0 && out > 0 && sum < 0 { // int64 overflow
		return int(math.MaxInt32)
	}
	if sum < 0 {
		return 0
	}
	if sum > math.MaxInt32 {
		return int(math.MaxInt32)
	}
	return int(sum)
}

// clampCoworkCost bounds a client-supplied cost to what audit_logs.cost
// (DECIMAL(10,6)) can hold; NaN/Inf/negative become 0.
func clampCoworkCost(c float64) float64 {
	if math.IsNaN(c) || math.IsInf(c, 0) || c < 0 {
		return 0
	}
	if c > maxCoworkCost {
		return maxCoworkCost
	}
	return c
}

// coworkRedactResult is the outcome of redact-at-collector for one content field.
type coworkRedactResult struct {
	text    string   // content to persist (masked, withheld, or original)
	fields  []string // redacted field/type names for the audit trail
	verdict string   // canonical policy_decision
}

// coworkRedact is the redaction seam (overridable in tests). It defaults to the
// engine-backed redactor so production reuses the SAME response-plane redaction
// path as check-output (no new regex).
var coworkRedact = coworkRedactDefault

// coworkRedactDefault FORCE-redacts free text for storage and fails closed.
//
// The collector is a STORAGE redactor, not a live-flow PEP: the deployment's
// PII_ACTION (warn/log/block/redact) governs what happens to content flowing to
// the user on the enforcement plane — it must NOT govern what we persist to the
// audit store, which must never hold raw PII. Using check-output's
// evaluateOutputPolicies directly is WRONG here: under the default PII_ACTION=warn
// it detects-but-does-not-modify, so raw PII would land in audit_logs (R3 HIGH).
//
// Instead we reuse the SAME engine primitives (UnifiedPolicyEngine.EvaluateResponse
// + the enterprise Indonesia checksum masker) but FORCE the PII categories to
// redact via ActionOverrides, and run the checksum-validated Indonesia (OJK/UU-PDP)
// masker unconditionally. No new regex is introduced. Fail-closed: if detection is
// disabled we cannot guarantee masking, so raw content is WITHHELD.
func coworkRedactDefault(ctx context.Context, tenantID, userID, source, content string) coworkRedactResult {
	if content == "" {
		return coworkRedactResult{text: "", verdict: sharedaudit.DecisionAllowed}
	}

	// Fail-closed availability gate. BOTH conditions must hold to persist content:
	//   (1) MCP detection is enabled — else no redaction pass runs at all; and
	//   (2) the global static policy engine is initialized — it is the generic-PII
	//       (SSN / email / phone) detector. The Indonesia checksum masker below is
	//       engine-independent, but on its own it CANNOT clear generic PII, so
	//       without the engine we cannot guarantee masking and must WITHHOLD (else a
	//       US SSN / email / phone would land raw). The engine is initialized at boot
	//       on every enterprise deployment; a nil engine is a degenerate/misconfigured
	//       state, and we fail closed on it rather than persist unverified content.
	if !ResolveMCPDetectionConfig(ctx, OrgIDFromContext(ctx)).Enabled {
		return coworkRedactResult{text: "[redaction-unavailable: content withheld]", verdict: sharedaudit.DecisionError}
	}
	engine := sharedpolicy.GetGlobalEngine()
	if engine == nil {
		return coworkRedactResult{text: "[redaction-unavailable: content withheld]", verdict: sharedaudit.DecisionError}
	}
	// #2820: fail closed on a policy-LOAD error. EnabledPIICategories below
	// returns nil on BOTH "no PII categories" and a load error, so without this
	// gate a transient load failure would SKIP the generic-PII pass and persist
	// raw content (email / SSN / phone). PoliciesLoadable distinguishes the two;
	// a storage redactor must never hold content it could not scan.
	if err := engine.PoliciesLoadable(ctx, tenantID, sharedpolicy.OrgScopePtr(OrgIDFromContext(ctx)), sharedpolicy.PhaseResponse); err != nil {
		return coworkRedactResult{text: "[redaction-unavailable: content withheld]", verdict: sharedaudit.DecisionError}
	}

	working := content
	anyRedacted := false
	var fields []string

	// Static-engine PII redaction, FORCED to redact (storage plane), reusing the
	// engine. Category-scoped to the tenant's enabled PII policies; the override map
	// coerces every one of those categories to ActionRedact regardless of the
	// deployment's PII_ACTION, so warn/log/block deployments still mask before store.
	{
		piiCats := engine.EnabledPIICategories(ctx, tenantID, sharedpolicy.OrgScopePtr(OrgIDFromContext(ctx)), sharedpolicy.PhaseResponse)
		if len(piiCats) > 0 {
			overrides := make(map[sharedpolicy.PolicyCategory]sharedpolicy.Action, len(piiCats))
			for _, c := range piiCats {
				overrides[c] = sharedpolicy.ActionRedact
			}
			res := engine.EvaluateResponse(ctx, []map[string]interface{}{{"statement": working}}, sharedpolicy.EvalOptions{
				TenantID: tenantID,
				// #3048 R3 HIGH-3 (N1): evaluate under the SAME org scope the
				// PoliciesLoadable + EnabledPIICategories derivations above use
				// (OrgIDFromContext(ctx)); on app-role with org≠tenant an
				// org-custom tenant-tier PII category was derived but its
				// pattern was RLS-invisible at evaluation → raw content
				// persisted to storage (violates the invariant at
				// pii_detector.go:1027).
				OrganizationID:  sharedpolicy.OrgScopePtr(OrgIDFromContext(ctx)),
				UserID:          userID,
				ConnectorName:   source,
				Categories:      piiCats,
				ActionOverrides: overrides,
				MaxRedactions:   100,
			})
			// #2820: second line of defense — if the load raced to failure
			// between PoliciesLoadable and here (cache expiry mid-request), the
			// scan did not run; withhold rather than persist unscanned content.
			if res != nil && res.EvaluationError {
				return coworkRedactResult{text: "[redaction-unavailable: content withheld]", verdict: sharedaudit.DecisionError}
			}
			if res != nil && res.Redacted {
				if rows, ok := res.Content.([]map[string]interface{}); ok && len(rows) > 0 {
					if out, ok := rows[0]["statement"].(string); ok && out != working {
						working = out
						anyRedacted = true
						fields = append(fields, sharedpolicy.GetRedactedFieldPaths(res)...)
					}
				}
			}
		}
	}

	// Enterprise Indonesia checksum PII (NIK / NPWP) — the design partner's
	// critical PII. Masked UNCONDITIONALLY (the static engine does not carry the
	// checksum-validated NIK detector), independent of PII_ACTION. Same primitive
	// redactInputStatement uses to fulfill a redact_pii obligation.
	if idResult := checkIndonesiaResponsePII(working, false); idResult != nil && idResult.HasPII {
		if masked, changed := maskJSONSafe(working, redactIndonesiaPIIInString); changed {
			working = masked
			anyRedacted = true
			fields = append(fields, indonesiaDetectedTypeNames(idResult)...)
		}
	}

	if anyRedacted {
		return coworkRedactResult{text: working, fields: fields, verdict: sharedaudit.DecisionRedacted}
	}
	// A redactor examined the content and found nothing in scope to mask.
	return coworkRedactResult{text: content, verdict: sharedaudit.DecisionAllowed}
}

// coworkAuditRow is the canonical audit_logs row for one OTEL event.
type coworkAuditRow struct {
	decisionID     string
	orgID          string
	tenantID       string
	clientID       string
	userEmail      string
	accountUUID    string // OTEL user.account_uuid — Anthropic Compliance API join key (#2838)
	accountID      string // OTEL user.account_id (tagged form)
	userRole       string
	plane          string
	requestType    string
	query          string
	policyDecision string
	correlationID  string
	sessionID      string
	redactedFields []string
	model          string
	responseTimeMs int64
	tokensUsed     int
	cost           float64
	eventName      string
	timestamp      time.Time
}

// writeCoworkAuditLog persists a canonical audit_logs row for a Cowork/Claude Code
// OTEL event. It writes to the SAME audit_logs table every other plane uses
// (single audit source), carrying the OTEL-native usage fields (model / tokens /
// cost) that already exist on audit_logs since migration 059, plus session_id
// (migration 129) and correlation_id (= prompt.id, migration 121). Returns true
// only when the row was PERSISTED — the caller counts a failed persist as
// rejected and skips the chain entry (R3 H1: never ACK an unstored event).
func writeCoworkAuditLog(ctx context.Context, db *sql.DB, row coworkAuditRow) bool {
	if db == nil || row.decisionID == "" {
		return false
	}

	if row.userEmail == "" {
		row.userEmail = "unknown@axonflow.local"
	}
	if row.userRole == "" {
		row.userRole = "service"
	}
	if row.clientID == "" {
		row.clientID = "unknown"
	}
	if row.tenantID == "" {
		row.tenantID = "unknown"
	}
	if row.query == "" {
		row.query = "(empty)"
	}
	if row.timestamp.IsZero() {
		row.timestamp = time.Now().UTC()
	}

	details := map[string]interface{}{
		"decision_id": row.decisionID,
		"source":      "cowork_otel",
		"plane":       row.plane,
		"event_name":  row.eventName,
	}
	if row.correlationID != "" {
		details["correlation_id"] = row.correlationID
	}
	if row.sessionID != "" {
		details["session_id"] = row.sessionID
	}
	if row.accountUUID != "" {
		details["user_account_uuid"] = row.accountUUID
	}
	if row.accountID != "" {
		details["user_account_id"] = row.accountID
	}
	if len(row.redactedFields) > 0 {
		details["redacted_fields"] = row.redactedFields
	}
	if row.model != "" {
		details["model"] = row.model
	}
	if row.tokensUsed > 0 {
		details["tokens_used"] = row.tokensUsed
	}
	if row.cost > 0 {
		details["cost"] = row.cost
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Printf("[CoworkOTEL] audit: marshal policy_details failed: %v", err)
		return false
	}

	var redactedFieldsArg interface{}
	if len(row.redactedFields) > 0 {
		if b, mErr := json.Marshal(row.redactedFields); mErr == nil {
			redactedFieldsArg = b
		}
	}
	queryHash := coworkSHA256Hex(row.query)

	_, err = db.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, provider, model, response_time_ms,
			tokens_used, cost, decision_id, plane, correlation_id, redacted_fields,
			session_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
	`,
		"audit_cowork_"+row.decisionID,      // id (distinct prefix → no PK collision)
		row.decisionID,                      // request_id
		row.timestamp,                       // timestamp (event time when present)
		0,                                   // user_id (numeric; real identity via user_email)
		row.userEmail,                       // user_email (OTEL attribution, unspoofable for Claude Code)
		row.userRole,                        // user_role
		row.clientID,                        // client_id
		row.tenantID,                        // tenant_id (from auth, not telemetry)
		nullIfEmptyStr(row.orgID),           // org_id (from auth, not telemetry)
		row.requestType,                     // request_type — e.g. "cowork_user_prompt"
		row.query,                           // query — REDACTED content or non-PII descriptor
		queryHash,                           // query_hash
		row.policyDecision,                  // policy_decision — canonical vocab
		detailsJSON,                         // policy_details (JSONB)
		nullIfEmptyStr("cowork_otel"),       // provider
		nullIfEmptyStr(row.model),           // model (OTEL usage)
		nullIfZeroInt64(row.responseTimeMs), // response_time_ms
		nullIfZeroInt(row.tokensUsed),       // tokens_used (OTEL usage)
		nullIfZeroFloat(row.cost),           // cost (OTEL usage)
		row.decisionID,                      // decision_id (first-class column)
		row.plane,                           // plane (cowork / claude_code)
		nullIfEmptyStr(row.correlationID),   // correlation_id (= OTEL prompt.id)
		redactedFieldsArg,                   // redacted_fields (JSONB or NULL)
		nullIfEmptyStr(row.sessionID),       // session_id (= OTEL session.id, migration 129)
	)
	if err != nil {
		log.Printf("[CoworkOTEL] audit: insert failed: %v", err)
		return false
	}
	return true
}

// ------------------------------- parsing/helpers ----------------------------

func parseCoworkOTLPLogs(contentType string, body []byte) (*collectorlogs.ExportLogsServiceRequest, error) {
	req := &collectorlogs.ExportLogsServiceRequest{}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.Contains(ct, "application/x-protobuf"), strings.Contains(ct, "application/protobuf"), ct == "":
		// OTLP/HTTP default is protobuf.
		if err := proto.Unmarshal(body, req); err != nil {
			return nil, err
		}
	case strings.Contains(ct, "application/json"):
		if err := protojson.Unmarshal(body, req); err != nil {
			return nil, err
		}
	default:
		return nil, errUnsupportedContentType
	}
	return req, nil
}

func writeOTLPLogsResponse(w http.ResponseWriter, contentType string, rejected int64) {
	resp := &collectorlogs.ExportLogsServiceResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &collectorlogs.ExportLogsPartialSuccess{
			RejectedLogRecords: rejected,
			ErrorMessage:       "unrecognized OTEL event names skipped",
		}
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(ct, "application/json") {
		b, err := protojson.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
		return
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeProtobuf)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// readLimited reads up to limit bytes, returning errOTLPBodyTooLarge if the body
// exceeds it.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errOTLPBodyTooLarge
	}
	return body, nil
}

func attrsToMap(kvs []*commonpb.KeyValue) map[string]*commonpb.AnyValue {
	m := make(map[string]*commonpb.AnyValue, len(kvs))
	for _, kv := range kvs {
		if kv != nil {
			m[kv.GetKey()] = kv.GetValue()
		}
	}
	return m
}

func getStr(m map[string]*commonpb.AnyValue, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return v.GetStringValue()
	}
	return ""
}

func getInt(m map[string]*commonpb.AnyValue, key string) int64 {
	if v, ok := m[key]; ok && v != nil {
		return v.GetIntValue()
	}
	return 0
}

func getFloat(m map[string]*commonpb.AnyValue, key string) float64 {
	if v, ok := m[key]; ok && v != nil {
		return v.GetDoubleValue()
	}
	return 0
}

// normalizeEventName strips the surface prefix ("cowork." / "claude_code.") and
// lowercases the event name so it matches the canonical constants.
func normalizeEventName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, p := range []string{"claude_code.", "cowork.", "claude_desktop."} {
		n = strings.TrimPrefix(n, p)
	}
	return n
}

// planeFromService derives the audit plane from the OTEL service.name resource
// attribute. Defaults to cowork (the Desktop surface) when unknown.
func planeFromService(serviceName string) string {
	s := strings.ToLower(serviceName)
	switch {
	case strings.Contains(s, "claude") && strings.Contains(s, "code"):
		return PlaneClaudeCode
	case strings.Contains(s, "cowork"), strings.Contains(s, "desktop"):
		return PlaneCowork
	default:
		return PlaneCowork
	}
}

func roleForPlane(plane string) string {
	if plane == PlaneClaudeCode {
		return "developer"
	}
	return "user"
}

// stageForEvent maps an event to the decision stage recorded in the signed chain
// (drives DecisionType). Prompt/api events are llm-shaped; tool events are tool-shaped.
func stageForEvent(base string) string {
	switch base {
	case evToolResult, evToolDecision:
		return DecisionStageTool
	default:
		return DecisionStageLLM
	}
}

func isRejectDecision(d string) bool {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "reject", "rejected", "deny", "denied", "block", "blocked", "user_reject", "user_abort":
		return true
	}
	return false
}

func recordTimestamp(rec *logspb.LogRecord) time.Time {
	if ns := rec.GetTimeUnixNano(); ns > 0 {
		return time.Unix(0, int64(ns)).UTC()
	}
	return time.Now().UTC()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstNonZeroFloat(vals ...float64) float64 {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func coworkSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func nullIfEmptyStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZeroInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullIfZeroInt64(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullIfZeroFloat(v float64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

// logSanitize is a thin alias so this file does not import logutil directly for a
// single call; it strips CR/LF to keep log lines single-line.
func logSanitize(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}
