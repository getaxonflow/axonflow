//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// OJK export section queries (#3242, epic #2892).
//
// Before this file, queryPolicyViolations / queryLLMCalls / queryDecisionChains
// were literal `return []T{}, 0, nil` stubs, and hitl_oversight / pii_redactions
// had no query at all. Requesting any of them produced a successful, empty,
// indistinguishable-from-"nothing happened" section in a regulator export.
//
// # Tenancy posture -- read this before adding a query here
//
// audit_logs is NOT row-level-security protected (core migration 101
// deliberately left it open for the cross-org cleanup worker). There is NO
// database backstop on these reads: the org predicate in the SQL below IS the
// tenant boundary. Every query in this file therefore:
//
//   - takes the org resolved by resolveOrgID (header-only, trimmed),
//   - refuses a blank org before issuing any statement,
//   - predicates on ONE tenancy column, chosen to match what the WRITER stamps,
//   - and wraps RLS-gated tables (hitl_approval_queue,
//     indonesia_pii_detection_events) in withOrgScope so the policy can match.
//
// The pre-existing `WHERE (tenant_id = $1 OR org_id = $1)` conflation in
// queryCrossBorderTransfers is NOT cloned here. Under a v9 enterprise license
// org_id and tenant_id are different values (#3071), so an OR across both
// columns matches a row whose TENANT happens to equal the caller's ORG -- a
// cross-tenant match that no RLS policy would catch on this table.
//
// # Bounds
//
// Every query carries an explicit LIMIT. An unbounded regulator export over a
// five-year window is a memory incident waiting to happen, and a truncated
// section that says nothing about being truncated is a worse lie than an empty
// one -- so a section that hits its limit is reported as truncated in the
// section note.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// ojkOrgPredicate is the audit_logs tenancy predicate, used VERBATIM by every
// audit_logs read in this module.
//
// It is not `org_id = $1`, and it is emphatically not the old
// `(tenant_id = $1 OR org_id = $1)`. Both of those are wrong, in opposite
// directions:
//
//   - The bare OR is a CROSS-TENANT LEAK. Under a v9 enterprise license org_id
//     and tenant_id are different values (#3071), so it returns any row whose
//     TENANT happens to equal the caller's ORG. audit_logs has no RLS
//     (core/101 left it open for the cross-org cleanup worker), so nothing
//     downstream catches it.
//
//   - `org_id = $1` alone SILENTLY DROPS a real corpus. audit_logs.org_id is
//     nullable and no core migration constrains it -- core/156's NOT NULL sweep
//     does not cover audit_logs -- so a client credential carrying no
//     organisation writes a blank org_id (writeDecisionAuditRow binds a plain
//     Go string). On exactly the single-identifier deployment where resolveOrgID
//     falls back to X-Tenant-ID, every one of those rows disappears from the
//     export, and because zero-with-no-error is classified enabled_empty the
//     pack asserts "the honest answer is zero rows". That is a FALSE claim of
//     honesty -- the same defect this workstream exists to remove.
//
// The clause below matches:
//  1. rows explicitly owned by this organisation, and
//  2. rows with NO organisation attribution at all whose tenant is this
//     identifier.
//
// It can never match a row belonging to a DIFFERENT organisation: clause 2
// requires the row's org to be blank, and a row owned by org B has org B's
// non-blank org_id. The cross-org test seeds precisely that row and fails if it
// is returned.
// SCOPE OF ARM 2, stated precisely because it is a tenancy predicate on a table
// with no RLS. It returns a row iff that row records NO owning organisation at
// all AND its tenant equals the caller's identifier. It therefore cannot return
// a row that names a different owner. It CAN return an unowned row whose tenant
// string happens to equal the caller's org string -- there is no schema
// constraint making the org and tenant namespaces disjoint. That is the
// deliberate trade: an unowned row has no better claimant, and the alternative
// (dropping it) is the silent-empty defect. Operators who need the narrower
// behaviour should give audit_logs.org_id a NOT NULL + non-blank constraint,
// after which arm 2 matches nothing.
//
// btrim, not a bare `= ”`: without it a WHITESPACE-ONLY org_id is matched by
// neither arm -- not by arm 1 (resolveOrgID trims, so no caller can present
// '   ') and not by arm 2 (COALESCE('   ',”) is not ”) -- leaving those rows
// invisible to every possible caller forever, which is the same class of loss
// this predicate exists to prevent.
//
// PLAN NOTE: arm 2 costs an index path on tenant_id. audit_logs has
// idx_audit_logs_org_id and idx_audit_logs_tenant_id, so the planner bitmap-ORs
// them; a deployment with a large audit_logs and a caller identifier that
// collides with a high-cardinality tenant will scan that tenant's rows to
// discard them. A partial index on (tenant_id) WHERE btrim(COALESCE(org_id,”))
// = ” makes arm 2 cheap; it is deliberately NOT added here because creating an
// index on a large production audit_logs is a lock event that belongs in a
// planned migration, not in a compliance-reporting change.
const ojkOrgPredicate = `(org_id = $1 OR (btrim(COALESCE(org_id, '')) = '' AND tenant_id = $1))`

// ojkSectionLimit bounds each section's row count. Chosen to match the sibling
// SEBI/EU-AI-Act exporters (100k) so a customer moving between regulator packs
// sees the same ceiling.
const ojkSectionLimit = 100000

// errOrgScopeRequired is returned before any statement is issued when the
// resolved org is blank. A blank org predicate would alias every blank-org row
// in the table.
var errOrgScopeRequired = errors.New("ojk: organization scope is required for an org-scoped export read")

// sectionResult is what every section query returns to the dispatcher.
type sectionResult struct {
	count int
	// truncated is true when the query returned exactly ojkSectionLimit rows,
	// so the section is reported as truncated rather than silently short.
	truncated bool
	// unavailable is true when the backing table does not exist on this
	// deployment (report_state = not_available), as distinct from an honest
	// zero.
	unavailable bool
	// err is a hard failure; the section reports not_available WITH the error.
	err error
}

// isUndefinedTableErr reports whether err is Postgres 42P01 (undefined_table).
//
// ONLY 42P01. An undefined COLUMN (42703) is deliberately not treated as an
// absent store: that is a schema drift the operator must see as a query failure,
// not as "this deployment cannot serve the section".
//
// It matches on SQLSTATE, not on error text. The sibling SEBI helper
// (isTableNotExistsError) substring-matches "relation", which is present in a
// great many unrelated Postgres errors -- including permission denied for
// relation X -- so it classifies a PRIVILEGE failure as "table absent" and
// reports a confident empty section. That is the same fail-open shape as
// probing information_schema under a role that cannot see the table.
func isUndefinedTableErr(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "42P01"
	}
	// sqlmock and the sqlite-shaped test doubles carry no SQLSTATE, so a textual
	// fallback is needed for them. It is deliberately NOT the bare word
	// "relation", which "permission denied for relation X" also contains -- that
	// is the fail-open the sibling SEBI helper has.
	//
	// It is imprecise in the other direction: "does not exist" also matches an
	// undefined column/function/type/role. That imprecision is confined to
	// drivers with no SQLSTATE, i.e. test doubles; production is lib/pq
	// everywhere, so the errors.As branch above decides every real case.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such table")
}

// -----------------------------------------------------------------------------
// policy_violations
// -----------------------------------------------------------------------------

// queryPolicyViolations returns the org's refusing/modifying governance
// decisions in the window.
//
// SOURCE: the canonical audit_logs decision rows, filtered to the verdicts that
// mean the platform acted (blocked / redacted / needs_approval). Deliberately
// NOT the legacy `policy_violations` table: the Indonesia enforcement paths
// (gateway pre-check, /api/v1/decide, MCP) write audit_logs decision rows, not
// policy_violations rows, so a policy_violations read would have returned an
// empty Indonesia section on a stack where blocking demonstrably happened. The
// Indonesia PII block path stamps policy_ids = ["indonesia_pii_protection"],
// which surfaces here as the policy id.
//
// TENANCY: uses the shared ojkOrgPredicate (see its doc comment). Both the agent
// (writeDecisionAuditRow) and the orchestrator (AuditLogger) stamp
// req.Client.OrgID into org_id, and the predicate additionally reaches rows that
// recorded no organisation at all, by their tenant.
//
// audit_logs has no RLS, so no withOrgScope wrap is possible or useful -- the
// predicate below is the whole boundary.
func (s *ojkAuditExportServiceImpl) queryPolicyViolations(ctx context.Context, orgID string, start, end time.Time) ([]OJKPolicyViolationRecord, sectionResult) {
	records := []OJKPolicyViolationRecord{}
	if strings.TrimSpace(orgID) == "" {
		return records, sectionResult{err: errOrgScopeRequired}
	}

	rows, qErr := s.db.QueryContext(ctx, `
		SELECT id,
		       timestamp,
		       COALESCE(policy_details->'policy_ids'->>0, '')  AS policy_id,
		       policy_decision,
		       COALESCE(policy_details->>'reason', '')         AS reason,
		       COALESCE(plane, policy_details->>'plane', '')   AS plane,
		       COALESCE(tenant_id, '')                         AS tenant_id
		  FROM audit_logs
		 WHERE `+ojkOrgPredicate+`
		   AND timestamp >= $2
		   AND timestamp <= $3
		   AND policy_decision IN ('blocked', 'redacted', 'needs_approval')
		 ORDER BY timestamp DESC, id DESC
		 LIMIT $4`,
		orgID, start, end, ojkSectionLimit,
	)
	if qErr != nil {
		if isUndefinedTableErr(qErr) {
			return records, sectionResult{unavailable: true, err: fmt.Errorf("audit_logs is not present on this deployment: %w", qErr)}
		}
		return records, sectionResult{err: qErr}
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			id       string
			ts       time.Time
			policyID string
			verdict  string
			reason   string
			plane    string
			tenantID string
		)
		if scanErr := rows.Scan(&id, &ts, &policyID, &verdict, &reason, &plane, &tenantID); scanErr != nil {
			return records, sectionResult{err: scanErr}
		}
		records = append(records, OJKPolicyViolationRecord{
			ID:         id,
			Timestamp:  ts.UTC(),
			PolicyID:   policyID,
			PolicyName: ojkPolicyDisplayName(policyID),
			Severity:   ojkSeverityForVerdict(verdict),
			Action:     verdict,
			// Reason is the platform's own text. The caller's query is on the
			// same row and is deliberately not read: a governance pack does not
			// need to reproduce the prompt that was refused.
			Description: reason,
			Plane:       plane,
			TenantID:    tenantID,
		})
	}
	if err := rows.Err(); err != nil {
		return records, sectionResult{err: err}
	}
	return records, sectionResult{count: len(records), truncated: len(records) == ojkSectionLimit}
}

// ojkPolicyDisplayName gives the well-known Indonesia policy ids a readable
// name and otherwise returns the id unchanged. It NEVER invents a name for an
// id it does not recognise -- a fabricated policy name in a regulator export is
// worse than a raw identifier.
func ojkPolicyDisplayName(policyID string) string {
	switch policyID {
	case "indonesia_pii_protection":
		return "Indonesia PII Protection (NIK / NPWP / bank account)"
	case "sys_pii_indonesia_ktp":
		return "Indonesian KTP Detection"
	case "":
		return ""
	default:
		return policyID
	}
}

// ojkSeverityForVerdict maps the canonical audit verdict to a severity band.
// It is a presentation mapping of a value the row DOES carry, not an inferred
// risk rating: blocked/redacted/needs_approval are the only inputs, because the
// query filters to exactly those.
func ojkSeverityForVerdict(verdict string) string {
	switch verdict {
	case "blocked":
		return "high"
	case "redacted":
		return "medium"
	case "needs_approval":
		return "medium"
	default:
		return "unknown"
	}
}

// -----------------------------------------------------------------------------
// llm_calls
// -----------------------------------------------------------------------------

// queryLLMCalls returns the org's LLM-plane activity in the window, METADATA
// ONLY.
//
// SOURCE: audit_logs rows with plane='llm' -- the orchestrator AuditLogger's
// LLM-forward writer, which is the only writer that populates provider, model,
// tokens and cost. Deliberately NOT llm_call_audits: that table's columns
// (prompt_tokens/completion_tokens/latency_ms/estimated_cost_usd, no
// policy_decision, no tenant_id) do not match what SEBI's exporter selects from
// it, so that read errors at runtime -- exactly the sort of silently-empty
// section this workstream removes.
//
// The `query` and `response_sample` columns are on the same row and are NOT
// read: OJK AI governance asks which model was invoked under which verdict, not
// what was said.
func (s *ojkAuditExportServiceImpl) queryLLMCalls(ctx context.Context, orgID string, start, end time.Time) ([]OJKLLMCallRecord, sectionResult) {
	records := []OJKLLMCallRecord{}
	if strings.TrimSpace(orgID) == "" {
		return records, sectionResult{err: errOrgScopeRequired}
	}

	rows, qErr := s.db.QueryContext(ctx, `
		SELECT id,
		       timestamp,
		       COALESCE(model, '')          AS model_id,
		       COALESCE(provider, '')       AS provider,
		       COALESCE(tokens_used, 0)     AS tokens_used,
		       COALESCE(cost, 0)            AS cost,
		       COALESCE(response_time_ms, 0) AS response_time_ms,
		       policy_decision,
		       COALESCE(transfer_basis, '') AS transfer_basis,
		       COALESCE(data_residency, '') AS data_residency,
		       COALESCE(tenant_id, '')      AS tenant_id
		  FROM audit_logs
		 WHERE `+ojkOrgPredicate+`
		   AND timestamp >= $2
		   AND timestamp <= $3
		   AND COALESCE(plane, policy_details->>'plane') = 'llm'
		 ORDER BY timestamp DESC, id DESC
		 LIMIT $4`,
		orgID, start, end, ojkSectionLimit,
	)
	if qErr != nil {
		if isUndefinedTableErr(qErr) {
			return records, sectionResult{unavailable: true, err: fmt.Errorf("audit_logs is not present on this deployment: %w", qErr)}
		}
		return records, sectionResult{err: qErr}
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			rec      OJKLLMCallRecord
			ts       time.Time
			cost     float64
			latency  int64
			tokens   int
			decision string
		)
		if scanErr := rows.Scan(
			&rec.ID, &ts, &rec.ModelID, &rec.Provider, &tokens, &cost, &latency,
			&decision, &rec.TransferBasis, &rec.DataResidency, &rec.TenantID,
		); scanErr != nil {
			return records, sectionResult{err: scanErr}
		}
		rec.Timestamp = ts.UTC()
		rec.TotalTokens = tokens
		rec.Cost = cost
		rec.LatencyMS = latency
		rec.PolicyDecision = decision
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return records, sectionResult{err: err}
	}
	return records, sectionResult{count: len(records), truncated: len(records) == ojkSectionLimit}
}

// -----------------------------------------------------------------------------
// decision_chain
// -----------------------------------------------------------------------------

// queryDecisionChains returns the org's governance decision steps in the
// window, chronologically, plus the same steps grouped into logical chains.
//
// Mirrors SEBI's exportDecisionChain (#2588/#2598): the source is the canonical
// audit_logs decision rows (identified by a non-null decision id), NOT the
// legacy decision_chain table, whose only writer is instantiated in tests.
// correlation_id is COALESCEd with its dual-written JSONB copy so the grouping
// still resolves if the column is ever rolled back.
//
// Ordering is (timestamp ASC, id ASC) so both the flat list and each chain's
// steps read in step order.
func (s *ojkAuditExportServiceImpl) queryDecisionChains(ctx context.Context, orgID string, start, end time.Time) ([]OJKDecisionChainRecord, sectionResult) {
	records := []OJKDecisionChainRecord{}
	if strings.TrimSpace(orgID) == "" {
		return records, sectionResult{err: errOrgScopeRequired}
	}

	rows, qErr := s.db.QueryContext(ctx, `
		SELECT id,
		       timestamp,
		       COALESCE(decision_id, policy_details->>'decision_id', '')       AS decision_id,
		       COALESCE(correlation_id, policy_details->>'correlation_id', '') AS correlation_id,
		       COALESCE(policy_details->>'stage', '')                          AS stage,
		       COALESCE(plane, policy_details->>'plane', '')                   AS plane,
		       policy_decision,
		       COALESCE(model, '')                                             AS model_id,
		       COALESCE(tenant_id, '')                                         AS tenant_id
		  FROM audit_logs
		 WHERE `+ojkOrgPredicate+`
		   AND timestamp >= $2
		   AND timestamp <= $3
		   AND COALESCE(decision_id, policy_details->>'decision_id') IS NOT NULL
		 ORDER BY timestamp ASC, id ASC
		 LIMIT $4`,
		orgID, start, end, ojkSectionLimit,
	)
	if qErr != nil {
		if isUndefinedTableErr(qErr) {
			return records, sectionResult{unavailable: true, err: fmt.Errorf("audit_logs is not present on this deployment: %w", qErr)}
		}
		return records, sectionResult{err: qErr}
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			rec     OJKDecisionChainRecord
			ts      time.Time
			verdict string
		)
		if scanErr := rows.Scan(
			&rec.ID, &ts, &rec.DecisionID, &rec.CorrelationID, &rec.Stage,
			&rec.Plane, &verdict, &rec.ModelID, &rec.TenantID,
		); scanErr != nil {
			return records, sectionResult{err: scanErr}
		}
		rec.Timestamp = ts.UTC()
		rec.Outcome = verdict
		rec.RequiresReview = verdict == "needs_approval"
		// RiskLevel is intentionally left empty: canonical decision rows do not
		// carry a risk rating and a regulator export must not invent one.
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return records, sectionResult{err: err}
	}
	return records, sectionResult{count: len(records), truncated: len(records) == ojkSectionLimit}
}

// groupOJKDecisionChains reconstructs logical chains from the flat,
// chronologically-ordered steps. Steps sharing a non-empty correlation_id
// collapse into one chain in step order; steps without one become singleton
// chains. Pure function so the grouping is unit-testable without a database.
func groupOJKDecisionChains(records []OJKDecisionChainRecord) []OJKDecisionChain {
	if len(records) == 0 {
		return nil
	}
	groups := make([]OJKDecisionChain, 0, len(records))
	indexByCorrelation := make(map[string]int, len(records))
	for _, r := range records {
		if key := r.CorrelationID; key != "" {
			if i, ok := indexByCorrelation[key]; ok {
				g := &groups[i]
				g.Steps = append(g.Steps, r)
				g.StepCount = len(g.Steps)
				if r.Timestamp.After(g.EndedAt) {
					g.EndedAt = r.Timestamp
				}
				if r.Timestamp.Before(g.StartedAt) {
					g.StartedAt = r.Timestamp
				}
				continue
			}
			indexByCorrelation[key] = len(groups)
		}
		groups = append(groups, OJKDecisionChain{
			CorrelationID: r.CorrelationID,
			StepCount:     1,
			StartedAt:     r.Timestamp,
			EndedAt:       r.Timestamp,
			Steps:         []OJKDecisionChainRecord{r},
		})
	}
	return groups
}

// -----------------------------------------------------------------------------
// hitl_oversight
// -----------------------------------------------------------------------------

// queryHITLOversight returns the org's recorded human-oversight decisions.
//
// SOURCE: hitl_approval_queue -- the same store the evidence exporter reads
// (evidence_export_handler.go queryHITLApprovals). That table is ENABLE RLS
// with `FOR ALL USING (org_id = get_current_org_id())` (core/025), so under
// axonflow_app_role a bare read matches ZERO rows: the withOrgScope wrap is
// load-bearing here, not decorative. The explicit org_id predicate is kept
// ALONGSIDE it -- RLS is the backstop, the predicate is the intent.
//
// Only REVIEWED rows are exported (reviewed_at IS NOT NULL). A still-pending
// approval request is not evidence that human oversight occurred, and an
// expired one is: it is included, with its status, because a lapsed oversight
// gate is exactly what a regulator wants to see.
//
// The queue also stores original_query (the caller's raw prompt). It is NOT
// read: this section evidences that a human reviewed a gated decision, not what
// the prompt said.
func (s *ojkAuditExportServiceImpl) queryHITLOversight(ctx context.Context, orgID string, start, end time.Time) ([]OJKHITLRecord, sectionResult) {
	records := []OJKHITLRecord{}
	if strings.TrimSpace(orgID) == "" {
		return records, sectionResult{err: errOrgScopeRequired}
	}

	var res sectionResult
	err := withOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, `
			SELECT id,
			       request_id::text,
			       created_at,
			       trigger_reason,
			       COALESCE(triggered_policy_id, '')   AS triggered_policy_id,
			       COALESCE(triggered_policy_name, '') AS triggered_policy_name,
			       COALESCE(severity, '')              AS severity,
			       COALESCE(reviewer_id, '')           AS reviewer_id,
			       COALESCE(reviewer_role, '')         AS reviewer_role,
			       status,
			       reviewed_at,
			       COALESCE(tenant_id, '')             AS tenant_id
			  FROM hitl_approval_queue
			 WHERE org_id = $1
			   AND created_at >= $2
			   AND created_at <= $3
			   AND reviewed_at IS NOT NULL
			 ORDER BY created_at DESC, id DESC
			 LIMIT $4`,
			orgID, start, end, ojkSectionLimit,
		)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var (
				rec        OJKHITLRecord
				id         int64
				createdAt  time.Time
				reviewedAt sql.NullTime
			)
			if scanErr := rows.Scan(
				&id, &rec.RequestID, &createdAt, &rec.TriggerReason,
				&rec.TriggeredPolicyID, &rec.TriggeredPolicyName, &rec.Severity,
				&rec.ReviewerID, &rec.ReviewerRole, &rec.Decision, &reviewedAt, &rec.TenantID,
			); scanErr != nil {
				return scanErr
			}
			rec.ID = fmt.Sprintf("%d", id)
			rec.Timestamp = createdAt.UTC()
			if reviewedAt.Valid {
				ra := reviewedAt.Time.UTC()
				rec.ReviewedAt = &ra
				rec.ReviewTimeMS = ra.Sub(createdAt.UTC()).Milliseconds()
			}
			records = append(records, rec)
		}
		return rows.Err()
	})
	if err != nil {
		if isUndefinedTableErr(err) {
			return records, sectionResult{unavailable: true, err: fmt.Errorf("hitl_approval_queue is not present on this deployment: %w", err)}
		}
		return records, sectionResult{err: err}
	}
	res.count = len(records)
	res.truncated = len(records) == ojkSectionLimit
	return records, res
}

// -----------------------------------------------------------------------------
// pii_redactions
// -----------------------------------------------------------------------------

// queryPIIRedactions returns the org's Indonesia PII detection events.
//
// SOURCE: indonesia_pii_detection_events (enterprise migration 137), written by
// the Indonesia detector on the gateway / decision / MCP planes via the
// platform/agent seam. Before #3242 this section had NO source at all -- it was
// not even a case in the dispatcher's switch, so requesting it produced a
// successful empty section.
//
// The table is ENABLE RLS keyed on app.current_org_id, so the withOrgScope wrap
// is load-bearing: without it an app-role read matches zero rows.
//
// Only masked values exist in the table, so only masked values can be exported.
// The raw detected value is never written (see the migration's column comment
// and indonesiaPIIEventsFrom, which copies named fields rather than the struct).
func (s *ojkAuditExportServiceImpl) queryPIIRedactions(ctx context.Context, orgID string, start, end time.Time) ([]OJKPIIRedactionRecord, sectionResult) {
	records := []OJKPIIRedactionRecord{}
	if strings.TrimSpace(orgID) == "" {
		return records, sectionResult{err: errOrgScopeRequired}
	}

	err := withOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, `
			SELECT id,
			       detected_at,
			       pii_type,
			       ojk_category,
			       severity,
			       masked_value,
			       confidence,
			       action,
			       plane,
			       COALESCE(decision_id, '')    AS decision_id,
			       COALESCE(correlation_id, '') AS correlation_id,
			       tenant_id
			  FROM indonesia_pii_detection_events
			 WHERE org_id = $1
			   AND detected_at >= $2
			   AND detected_at <= $3
			 ORDER BY detected_at DESC, id DESC
			 LIMIT $4`,
			orgID, start, end, ojkSectionLimit,
		)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var (
				rec        OJKPIIRedactionRecord
				detectedAt time.Time
				confidence float64
			)
			if scanErr := rows.Scan(
				&rec.ID, &detectedAt, &rec.PIIType, &rec.OJKCategory, &rec.Severity,
				&rec.MaskedValue, &confidence, &rec.Action, &rec.Plane,
				&rec.DecisionID, &rec.CorrelationID, &rec.TenantID,
			); scanErr != nil {
				return scanErr
			}
			rec.Timestamp = detectedAt.UTC()
			rec.Confidence = confidence
			// The Indonesia detector masks in place (leading/trailing digits
			// retained per type); naming it makes the column meaningful to an
			// auditor instead of an unexplained blank.
			rec.RedactionMethod = "indonesia_detector_mask"
			records = append(records, rec)
		}
		return rows.Err()
	})
	if err != nil {
		if isUndefinedTableErr(err) {
			// The enterprise/137 migration has not been applied on this
			// deployment. That is not "no PII was detected" -- report it as
			// not_available so the section never reads as a clean zero.
			return records, sectionResult{unavailable: true, err: fmt.Errorf("indonesia_pii_detection_events is not present on this deployment (enterprise migration 137 not applied): %w", err)}
		}
		return records, sectionResult{err: err}
	}
	return records, sectionResult{count: len(records), truncated: len(records) == ojkSectionLimit}
}
