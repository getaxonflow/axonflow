// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"axonflow/platform/agent/license"
	"axonflow/platform/shared/audit"
)

// V1.1 decision-list endpoint (issue #1982 / project_v1_1_decision_record_2026_05_07).
//
// GET /api/v1/decisions returns the caller's recent decisions, summarized to
// five fields per entry. The tenant-id filter is in the SQL WHERE clause —
// same shape as explainDecisionHandler (#1623 retro: post-fetch authorization
// silently fails open whenever the caller can present a header that matches
// the row).
//
// Tier-gated behavior:
//   - Lookback window (DecisionListWindowHours) bounds how far back the
//     `since` filter may extend. Defaults to "tier window from now."
//   - Page size (DecisionListMaxPage) caps the explicit `limit` parameter.
//     A request with limit > tier max returns 429 with the V1 upgrade
//     envelope per feedback_429_no_upgrade_hint_is_conversion_gap.md.
//
// Effective-tier resolution:
//
//   - X-Axonflow-Effective-Tier header (set by the agent in the SaaS Plugin
//     path from auth.Client.EffectiveTier) takes precedence — this is how a
//     SaaS Free buyer gets the 24h/5 cap on a deployment whose process-wide
//     license is Enterprise.
//
//   - Falls back to tierChecker.Tier() (the deployment-wide license) when
//     the header is absent — covers self-hosted Community / Evaluation /
//     Enterprise without any agent change.

// DecisionListItem is a single row in the GET /api/v1/decisions response.
// Five-field summary per ADR-043 §"List companion endpoint" — full
// explanation is fetched separately via the per-id explain endpoint.
type DecisionListItem struct {
	DecisionID string    `json:"decision_id"`
	Timestamp  time.Time `json:"timestamp"`
	// Decision is the canonical policy_decision verdict (audit.All():
	// "allowed"|"blocked"|"redacted"|"needs_approval"|"error"). The raw
	// audit_logs value is run through audit.Normalize on read so legacy/historical
	// rows (e.g. "allow"/"deny"/"require_approval") surface as the canonical
	// spelling and the feed never shows a divergent verdict (#2636/#2653).
	Decision      string `json:"decision"`
	PolicyID      string `json:"policy_id,omitempty"`
	ToolSignature string `json:"tool_signature,omitempty"`

	// Context is the sanitized request context the PEP attached to the
	// decision (a design partner's Layer-2 audit headers — canonical snake_case
	// keys, string values; written by the agent at policy_details->'context').
	// The list summary truncates to decisionListContextMaxKeys keys (sorted)
	// to keep the row small; the full map is available via the per-id explain
	// endpoint. omitempty so pre-#2509 rows + decisions with no context keep
	// the original byte-shape. (#2509 / epic #2508)
	Context map[string]string `json:"context,omitempty"`
}

// decisionListContextMaxKeys bounds how many request-context keys the LIST
// summary returns per decision. The agent already caps the persisted map at
// 10 keys; the list view trims further to the 5 most commonly-correlated keys
// so the summary stays compact. Full context (up to the persisted cap) is
// retrievable via GET /api/v1/decisions/:id/explain.
const decisionListContextMaxKeys = 5

// DecisionListResponse is the wire shape returned on success.
type DecisionListResponse struct {
	Decisions []DecisionListItem `json:"decisions"`
}

// V1.1 limit-type identifier for the upgrade envelope. Matches the
// pattern set by community_saas_ratelimit_response.go LimitType*
// constants in the agent package — kept locally here so the orchestrator
// doesn't depend on agent-package privates.
const limitTypeDecisionListSize = "decision_list_size"

// V1.1 wording for the decision-list cap-hit envelope. Mirrors the
// tone established by umbrella #1958: factual, names the Free cap and
// the Pro replacement value, no coercive language.
const wordingDecisionListSize = "Free tier shows the last 5 decisions in 24h. Pro raises this to 100 decisions in the last 30 days."

// V1 Plugin Pro upgrade-prompt URLs — duplicated from
// platform/agent/community_saas_ratelimit_response.go because both files
// are part of the same "6-surface drift" group per
// feedback_cross_surface_drift_check_categorized.md. Updates to either
// constant must update both surfaces in the same release train.
const (
	v11UpgradeCompareURL = "https://getaxonflow.com/pricing/"
	v11UpgradeBuyURL     = "https://buy.stripe.com/bJe28qbztcdVchjdkw8k800"
)

// decisionListUpgrade is the upgrade-prompt block carried in the 429
// response body. Same shape as upgradeBlock in
// community_saas_ratelimit_response.go so plugins parse one envelope
// type across all V1/V1.1 limit-hit paths.
type decisionListUpgrade struct {
	Tier       string `json:"tier"`
	Wording    string `json:"wording"`
	CompareURL string `json:"compare_url"`
	BuyURL     string `json:"buy_url"`
}

type decisionListLimitEnvelope struct {
	Error     string              `json:"error"`
	LimitType string              `json:"limit_type"`
	Tier      string              `json:"tier"`
	Limit     int                 `json:"limit"`
	Remaining int                 `json:"remaining"`
	Upgrade   decisionListUpgrade `json:"upgrade"`
}

// listDecisionsHandler handles GET /api/v1/decisions.
func listDecisionsHandler(w http.ResponseWriter, r *http.Request) {
	callerTenant := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if callerTenant == "" {
		// Same fail-closed shape as explainDecisionHandler (#1623 retro):
		// no trusted tenant scope on the request → reject. The agent gateway
		// always sets this after authentication; bare-orchestrator callers
		// must include it explicitly.
		sendErrorResponse(w, "X-Tenant-ID header is required", http.StatusUnauthorized)
		return
	}

	tier, limits := resolveDecisionListTier(r)

	// Parse + validate query parameters.
	q := r.URL.Query()

	// limit: defaults to tier max page when absent. A caller-supplied limit
	// that exceeds the tier max returns the upgrade envelope (429) — the
	// product UX directs Free users to Pro rather than silently capping.
	requestedLimit := limits.DecisionListMaxPage
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			sendErrorResponse(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		// V1.1 tier matrix has no -1 sentinel for MaxPage — every tier
		// (including Enterprise=1000) carries a finite ceiling. The
		// guard is defensive: a future tier added with MaxPage=-1
		// would mean "uncapped", and the code path skips the cap-hit
		// envelope entirely instead of treating -1 as "smaller than
		// every positive limit."
		if limits.DecisionListMaxPage != -1 && parsed > limits.DecisionListMaxPage {
			writeDecisionListLimitError(w, string(tier), limits.DecisionListMaxPage)
			return
		}
		requestedLimit = parsed
	}

	// since: defaults to "tier-window ago." A caller-supplied `since` that
	// reaches further back than the tier permits is silently clamped to the
	// tier window — the wire shape doesn't grow a "your window was clamped"
	// signal yet (additive in V1.2 if needed). For Enterprise (window = -1)
	// no clamp is applied; only audit retention bounds the lookback.
	now := time.Now().UTC()
	var tierWindowStart time.Time
	if limits.DecisionListWindowHours == -1 {
		// Sentinel: unbounded. Use the zero time so the SQL `>=` predicate
		// matches every row in the table; the tenant + retention are the
		// only floors.
		tierWindowStart = time.Time{}
	} else {
		tierWindowStart = now.Add(-time.Duration(limits.DecisionListWindowHours) * time.Hour)
	}
	since := tierWindowStart
	if rawSince := strings.TrimSpace(q.Get("since")); rawSince != "" {
		parsed, err := time.Parse(time.RFC3339, rawSince)
		if err != nil {
			sendErrorResponse(w, "since must be RFC3339 (e.g. 2026-05-01T00:00:00Z)", http.StatusBadRequest)
			return
		}
		// Clamp to the tier window when the caller asks for more than the
		// tier allows. Enterprise (sentinel) has no clamp.
		if limits.DecisionListWindowHours != -1 && parsed.Before(tierWindowStart) {
			parsed = tierWindowStart
		}
		since = parsed
	}

	// The decision filter is validated against the canonical verdict vocabulary
	// (audit.All()). This both ACCEPTS the canonical values every writer now
	// emits — including needs_approval, which the old allow/deny/require_approval
	// allowlist rejected with a 400 — and REJECTS phantoms like the legacy
	// "require_approval" spelling (no row carries it; it normalizes to
	// needs_approval, which is the value to filter on) and the wire-only
	// "allow"/"deny" (the agent Decision-API verdicts, converted to
	// allowed/blocked before the audit write). For the SQL we expand the
	// canonical value to every DB spelling it covers (audit.Spellings) so a
	// legacy/historical row that predates the canonical cutover still matches —
	// canonical-first, NOT the divergence-codifying expansion of PR #2637.
	decisionFilter := strings.TrimSpace(q.Get("decision"))
	if decisionFilter != "" && !audit.IsCanonical(decisionFilter) {
		sendErrorResponse(w, "decision must be one of: "+strings.Join(audit.All(), ", "), http.StatusBadRequest)
		return
	}
	// Non-nil empty slice when there is no filter: pq.Array of a nil slice
	// serializes to SQL NULL, and `cardinality(NULL) = 0` evaluates to NULL (not
	// TRUE), which would silently drop EVERY row. An empty array serializes to
	// '{}', whose cardinality is 0 → the "no filter" arm matches all rows.
	decisionVals := []string{}
	if decisionFilter != "" {
		decisionVals = audit.Spellings(audit.Normalize(decisionFilter))
	}

	policyIDFilter := strings.TrimSpace(q.Get("policy_id"))
	toolSigFilter := strings.TrimSpace(q.Get("tool_signature"))

	rows, err := queryDecisionList(callerTenant, since, decisionVals, policyIDFilter, toolSigFilter, requestedLimit)
	if err != nil {
		log.Printf("list decisions: query failed: tenant=%q err=%v", callerTenant, err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(DecisionListResponse{Decisions: rows})
}

// resolveDecisionListTier picks the tier governing this request. SaaS callers
// reach the orchestrator via the agent reverse proxy, which sets
// X-Axonflow-Effective-Tier from auth.Client.EffectiveTier — that's how a
// SaaS Free buyer gets the Free cap on a deployment whose process-wide
// license is Enterprise. Self-hosted callers fall through to the
// process-wide tierChecker.
func resolveDecisionListTier(r *http.Request) (license.Tier, license.TierLimits) {
	if h := strings.TrimSpace(r.Header.Get("X-Axonflow-Effective-Tier")); h != "" {
		t := license.Tier(h)
		// Only honor known SaaS Plugin tiers from the header. Self-hosted
		// tier names appearing in this header would be an agent-side bug;
		// fail closed to the deployment tier rather than trust an
		// unrecognized claim.
		switch t {
		case license.TierFree, license.TierPro, license.TierPremium:
			return t, license.GetTierLimits(t)
		}
	}
	if tierChecker != nil {
		t := tierChecker.Tier()
		return t, license.GetTierLimits(t)
	}
	return license.TierCommunity, license.GetTierLimits(license.TierCommunity)
}

// queryDecisionList runs the tenant-scoped SELECT with the optional filters
// applied as parameterized predicates. tenant_id is in the WHERE clause —
// same defense as explainDecisionHandler (#1623 retro). Filters are passed
// as positional args; absent filters short-circuit with TRUE so the index
// usage stays predictable.
func queryDecisionList(tenantID string, since time.Time, decisionVals []string, policyID, toolSig string, limit int) ([]DecisionListItem, error) {
	if usageDB == nil {
		return []DecisionListItem{}, nil
	}

	// SQL: pull only the five projected fields. The COALESCE on policy_id
	// matches the same shape used by explain_handler.go — `policy_id`
	// scalar takes precedence; fall back to the first element of the
	// `policy_ids` array. policy_details is JSONB so all of these read
	// without a join. Filter clauses use the `$N::text = ''` short-circuit
	// pattern so absent filters compile to a constant TRUE.
	//
	// #2592 / ADR-058 Phase 1: decision_id is now a first-class indexed column.
	// Read it via COALESCE(column, policy_details->>'decision_id') so the feed
	// uses the column when present yet still surfaces JSONB-only rows
	// (historical rows pre-backfill, plus any writer that hasn't cut over) —
	// NO flag-day. The WHERE predicate mirrors the same fallback. The partial
	// index idx_audit_logs_decision_id (WHERE decision_id IS NOT NULL) backs
	// the column arm of the predicate.
	const q = `
		SELECT
			COALESCE(decision_id, policy_details->>'decision_id')  AS decision_id,
			timestamp,
			policy_decision                                        AS decision,
			COALESCE(
				policy_details->>'policy_id',
				(policy_details->'policy_ids'->>0)
			)                                                      AS policy_id,
			COALESCE(policy_details->>'tool_signature', '')        AS tool_signature,
			policy_details->'context'                              AS context
		FROM audit_logs
		WHERE tenant_id = $1
		  AND timestamp >= $2
		  AND (decision_id IS NOT NULL OR policy_details->>'decision_id' IS NOT NULL)
		  AND (cardinality($3::text[]) = 0 OR policy_decision = ANY($3))
		  AND ($4::text = '' OR (
		        policy_details->>'policy_id' = $4
		        OR policy_details->'policy_ids' @> to_jsonb($4::text)
		      ))
		  AND ($5::text = '' OR policy_details->>'tool_signature' = $5)
		ORDER BY timestamp DESC
		LIMIT $6
	`

	// Enterprise's -1 sentinel is treated as "no LIMIT" by capping at a
	// large but finite value. PostgreSQL has no LIMIT ALL via $param so
	// 100k is a safe ceiling that still fits a single response without
	// streaming machinery (the page-size cap of 1000 above means callers
	// only land here when explicitly requesting more — defense in depth).
	effectiveLimit := limit
	if effectiveLimit <= 0 {
		effectiveLimit = 100000
	}

	rows, err := usageDB.Query(q, tenantID, since, pq.Array(decisionVals), policyID, toolSig, effectiveLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]DecisionListItem, 0, 16)
	for rows.Next() {
		var (
			item        DecisionListItem
			policyIDCol sql.NullString
			toolSigCol  sql.NullString
			contextCol  sql.NullString // policy_details->'context' (JSONB or NULL)
		)
		if err := rows.Scan(&item.DecisionID, &item.Timestamp, &item.Decision, &policyIDCol, &toolSigCol, &contextCol); err != nil {
			return nil, err
		}
		// Normalize the raw policy_decision so a legacy/historical row surfaces
		// the canonical verdict (audit.All()), matching the canonical-only filter
		// allowlist and the documented wire shape.
		item.Decision = audit.Normalize(item.Decision)
		// Drop the recognized non-verdict marker: an override grant/revoke
		// lifecycle row is not a PEP decision and must never appear in the
		// verdict-centric feed. Today no override writer populates a decision_id
		// (so the WHERE clause already excludes these rows), but guard on read so
		// the "feed emits only audit.All()" contract holds structurally even if a
		// future writer attaches a decision_id to a lifecycle row.
		if item.Decision == audit.DecisionOverrideLifecycle {
			continue
		}
		if policyIDCol.Valid {
			item.PolicyID = policyIDCol.String
		}
		if toolSigCol.Valid {
			item.ToolSignature = toolSigCol.String
		}
		// Decode the context JSONB and truncate to the list cap. A malformed
		// or non-object value is dropped (logged) rather than failing the
		// whole list — the explain endpoint surfaces the raw record if needed.
		if contextCol.Valid && contextCol.String != "" && contextCol.String != "null" {
			var ctxMap map[string]string
			if err := json.Unmarshal([]byte(contextCol.String), &ctxMap); err != nil {
				log.Printf("list decisions: context decode failed (decision=%q): %v", item.DecisionID, err)
			} else if len(ctxMap) > 0 {
				item.Context = truncateContextMap(ctxMap, decisionListContextMaxKeys)
			}
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// writeDecisionListLimitError emits the V1.1 decision-list cap-hit envelope
// at HTTP 429. Mirrors the headers + body shape locked by umbrella #1958
// (writeRateLimitError / writeFreeLimitError) so plugin-side parsers
// implement one envelope type. limit-type identifier is V1.1-specific.
func writeDecisionListLimitError(w http.ResponseWriter, tier string, limit int) {
	envelope := decisionListLimitEnvelope{
		Error:     wordingDecisionListSize,
		LimitType: limitTypeDecisionListSize,
		Tier:      tier,
		Limit:     limit,
		Remaining: 0,
		Upgrade: decisionListUpgrade{
			Tier:       "Pro",
			Wording:    wordingDecisionListSize,
			CompareURL: v11UpgradeCompareURL,
			BuyURL:     v11UpgradeBuyURL,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Axonflow-Tier-Limit", limitTypeDecisionListSize)
	w.Header().Set("X-Axonflow-Upgrade-URL", v11UpgradeCompareURL)
	w.WriteHeader(http.StatusTooManyRequests)
	if err := json.NewEncoder(w).Encode(envelope); err != nil {
		log.Printf("[V1.1 decision-list envelope] tier=%s encode failed: %v", tier, err)
	}
}

// truncateContextMap returns a copy of m with at most n entries, choosing the
// keys in sorted order so the kept subset is deterministic across requests
// (map iteration order in Go is randomized). n <= 0 returns nil. When len(m)
// <= n the original map is returned unchanged. Used by the LIST endpoint to
// keep the per-decision summary compact; the explain endpoint returns the
// full map.
func truncateContextMap(m map[string]string, n int) map[string]string {
	if len(m) == 0 || n <= 0 {
		return nil
	}
	if len(m) <= n {
		return m
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, n)
	for _, k := range keys[:n] {
		out[k] = m[k]
	}
	return out
}
