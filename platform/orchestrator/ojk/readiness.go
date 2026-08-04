//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// Derived compliance readiness and dashboard (#3242, epic #2892).
//
// # What this replaces
//
// ValidateComplianceReadiness returned five checks of which FOUR were
// unconditional `Status: "pass"` string literals. The PII check asserted
// "Indonesia PII detection patterns registered (NIK, NPWP legacy, ...)" without
// querying anything; the human-oversight check asserted "HITL approval gates
// active via Plans API"; the audit check asserted "Agent + orchestrator audit
// logging active"; the breach check asserted an endpoint exists. Only retention
// could ever fail, so the score was 80 or 100 on every deployment in the world,
// including one with no database and no traffic. GetDashboard was worse: it
// returned literal TotalAuditRecords: 0, ActivePolicies: 8, RecentViolations: 0.
//
// # The rule this file follows
//
// A check either MEASURES the thing it names, or it reports OJKCheckUnknown and
// says what it could not observe. It never asserts a fact the emitting service
// cannot see. Concretely:
//
//   - Every check that can be measured runs a query and reports the observed
//     number alongside the verdict.
//   - A query that fails (missing table, permission denied) yields unknown --
//     never a pass, and never a confident zero.
//   - Unknown checks are EXCLUDED from the score denominator and BLOCK Ready,
//     so a half-observable deployment cannot present as ready.
//
// # Scoring
//
// score = round(100 * (pass + 0.5*warning) / TOTAL checks. An `unknown` check
// contributes ZERO to the numerator and STILL counts in the denominator.
//
// The first version of this scored over the measurable set only, and R3 found
// the consequence by execution: a deployment with no database could measure
// exactly one of five dimensions, that one passed, and it scored 100 -- strictly
// worse than the literal-pass code it replaced. A compliance score must fall as
// observability falls, because "we can evidence one of five required dimensions"
// is a WORSE posture than "we can evidence four of five", not a better one.
// MeasuredChecks / UnknownChecks stay on the response so the split is visible.
//
// Ready additionally requires no failures AND no unknowns. The warning
// half-credit exists so "the control is configured but has never fired" is
// distinguishable from both "working" and "broken" without collapsing to a pass.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// errNoDatabase is what every measurement query returns when the module was
// constructed without a database handle. It flows into the readiness checks as
// OJKCheckUnknown and into the dashboard as OJKCountUnavailable -- never as a
// pass and never as a confident zero, which is the whole contract of this file.
var errNoDatabase = errors.New("database connection not available")

// requireDB is the single nil guard every measurement query calls FIRST.
// *sql.DB methods panic on a nil receiver, so without it a DB-less module
// (NewOJKModule leaves AuditService nil, but a direct NewOJKAuditExportService
// caller can supply nil) crashes the orchestrator on a readiness poll.
func (s *ojkAuditExportServiceImpl) requireDB() error {
	if s.db == nil {
		return errNoDatabase
	}
	return nil
}

// readinessWindowDays is the trailing window the activity-based checks measure
// over. Named so the number in the Details text and the number in the query can
// never drift apart.
const readinessWindowDays = 90

// ValidateComplianceReadiness derives the OJK/UU PDP readiness assessment for
// one organisation. orgID is the resolved organisation (resolveOrgID).
func (s *ojkAuditExportServiceImpl) ValidateComplianceReadiness(ctx context.Context, orgID string) (*OJKComplianceReadinessResponse, error) {
	if strings.TrimSpace(orgID) == "" {
		return nil, errOrgScopeRequired
	}

	since := time.Now().UTC().AddDate(0, 0, -readinessWindowDays)

	checks := []OJKComplianceCheck{
		s.checkDataRetention(),
		s.checkPIIDetection(ctx, orgID, since),
		s.checkHumanOversight(ctx, orgID, since),
		s.checkAuditLogging(ctx, orgID, since),
		s.checkBreachNotification(ctx, orgID),
	}

	passes, warnings, fails, unknowns := 0, 0, 0, 0
	for _, c := range checks {
		switch c.Status {
		case OJKCheckPass:
			passes++
		case OJKCheckWarning:
			warnings++
		case OJKCheckFail:
			fails++
		default:
			unknowns++
		}
	}

	measurable := len(checks) - unknowns
	score := 0
	if len(checks) > 0 {
		// Denominator is EVERY check, not just the measurable ones: an
		// unobservable dimension must drag the score down, never inflate it.
		// Integer arithmetic on a doubled numerator keeps the half-credit exact
		// without floating point.
		score = ((2*passes + warnings) * 100) / (2 * len(checks))
	}

	recommendations := make([]string, 0, 4)
	for _, c := range checks {
		switch c.Status {
		case OJKCheckFail:
			recommendations = append(recommendations, fmt.Sprintf("%s: %s", c.Name, c.Details))
		case OJKCheckUnknown:
			recommendations = append(recommendations,
				fmt.Sprintf("%s could not be measured on this deployment: %s", c.Name, c.Details))
		}
	}
	if len(recommendations) == 0 {
		recommendations = nil
	}

	return &OJKComplianceReadinessResponse{
		Ready:           fails == 0 && unknowns == 0 && score >= OJKReadinessReadyScore,
		Score:           score,
		Framework:       OJKFrameworkCombined,
		Checks:          checks,
		Recommendations: recommendations,
		MeasuredChecks:  measurable,
		UnknownChecks:   unknowns,
	}, nil
}

// checkDataRetention is the one check that was already real: it reads the
// effective retention configuration. No query is needed, so it is never
// unknown.
func (s *ojkAuditExportServiceImpl) checkDataRetention() OJKComplianceCheck {
	days := s.getEffectiveRetentionDays()
	observed := int64(days)
	c := OJKComplianceCheck{
		Name:        "Data Retention",
		Description: "OJK requires minimum 5-year retention of AI decision records",
		Observed:    &observed,
	}
	if days < IndonesiaRetentionDays {
		c.Status = OJKCheckFail
		c.Details = fmt.Sprintf("Retention is configured at %d days; OJK/UU PDP requires at least %d (5 years). Raise AXONFLOW retention configuration.", days, IndonesiaRetentionDays)
		return c
	}
	c.Status = OJKCheckPass
	c.Details = fmt.Sprintf("Retention configured at %d days (minimum %d).", days, IndonesiaRetentionDays)
	return c
}

// checkPIIDetection measures whether Indonesia PII governance is actually
// operating for this org.
//
// It queries TWO observable things and refuses to assert anything else:
//  1. how many enabled Indonesia-PII policy rows this org can see, and
//  2. how many Indonesia PII detection events were recorded in the window.
//
// The old literal claimed the eight detector patterns were "registered" -- a
// property of the compiled binary that the orchestrator cannot observe from the
// database at all, and which was printed identically on a community build where
// the enterprise detector is not linked in.
//
// Verdicts: policies enabled AND events recorded -> pass. Policies enabled but
// no events -> warning (configured, never exercised in the window: it may be
// correct, but it is not evidence of a working control). No policies visible ->
// fail. Either query unusable -> unknown.
func (s *ojkAuditExportServiceImpl) checkPIIDetection(ctx context.Context, orgID string, since time.Time) OJKComplianceCheck {
	c := OJKComplianceCheck{
		Name:        "PII Detection",
		Description: "NIK, NPWP, and bank-account detection must be active per UU PDP",
	}

	policies, policyErr := s.countIndonesiaPIIPolicies(ctx, orgID)
	if policyErr != nil {
		c.Status = OJKCheckUnknown
		c.Details = fmt.Sprintf("could not read enabled Indonesia PII policies for this organization: %v", policyErr)
		return c
	}

	events, eventErr := s.countIndonesiaPIIEvents(ctx, orgID, since)
	if eventErr != nil {
		c.Status = OJKCheckUnknown
		c.Details = fmt.Sprintf("read %d enabled Indonesia PII policies, but could not read detection events: %v", policies, eventErr)
		return c
	}

	observed := events
	c.Observed = &observed
	switch {
	case policies == 0:
		c.Status = OJKCheckFail
		c.Details = fmt.Sprintf("No enabled Indonesia PII policy is visible to this organization (%d detection events recorded in the last %d days). Seed the pii-indonesia policy set.", events, readinessWindowDays)
	case events == 0:
		c.Status = OJKCheckWarning
		c.Details = fmt.Sprintf("%d enabled Indonesia PII policies are visible, but no detection event was recorded in the last %d days. The control is configured; this window contains no evidence that it fired.", policies, readinessWindowDays)
	default:
		c.Status = OJKCheckPass
		c.Details = fmt.Sprintf("%d enabled Indonesia PII policies visible; %d detection events recorded in the last %d days.", policies, events, readinessWindowDays)
	}
	return c
}

// checkHumanOversight measures recorded human review.
//
// Observable: how many hitl_approval_queue rows this org has in the window, and
// how many of them were actually REVIEWED. The old literal asserted "HITL
// approval gates active via Plans API" on every deployment, including ones with
// the queue table absent.
//
// Verdicts: reviewed rows exist -> pass. Rows queued but none reviewed ->
// FAIL (a gate that queues and is never reviewed is an oversight failure, not a
// quiet period). No rows at all -> warning (nothing required oversight in the
// window; that is a legitimate state, not evidence of a working control).
// Query unusable -> unknown.
func (s *ojkAuditExportServiceImpl) checkHumanOversight(ctx context.Context, orgID string, since time.Time) OJKComplianceCheck {
	c := OJKComplianceCheck{
		Name:        "Human Oversight",
		Description: "OJK AI Governance requires human oversight for material decisions",
	}

	queued, reviewed, err := s.countHITLActivity(ctx, orgID, since)
	if err != nil {
		c.Status = OJKCheckUnknown
		c.Details = fmt.Sprintf("could not read the human-oversight queue: %v", err)
		return c
	}

	observed := reviewed
	c.Observed = &observed
	switch {
	case queued == 0:
		c.Status = OJKCheckWarning
		c.Details = fmt.Sprintf("No decision required human oversight in the last %d days, so this window contains no evidence either way.", readinessWindowDays)
	case reviewed == 0:
		c.Status = OJKCheckFail
		c.Details = fmt.Sprintf("%d oversight requests were queued in the last %d days and NONE was reviewed. Gated decisions are not receiving human review.", queued, readinessWindowDays)
	default:
		c.Status = OJKCheckPass
		c.Details = fmt.Sprintf("%d of %d oversight requests queued in the last %d days were reviewed.", reviewed, queued, readinessWindowDays)
	}
	return c
}

// checkAuditLogging measures whether the audit trail is receiving rows for this
// org. The old literal asserted "Agent + orchestrator audit logging active"
// unconditionally.
//
// Verdicts: rows in the window -> pass. Zero rows -> warning (no governed
// traffic is a legitimate state for a new org and must not read as a failure,
// but it is equally not evidence that logging works). Query unusable ->
// unknown.
func (s *ojkAuditExportServiceImpl) checkAuditLogging(ctx context.Context, orgID string, since time.Time) OJKComplianceCheck {
	c := OJKComplianceCheck{
		Name:        "Audit Logging",
		Description: "Complete audit trail of AI inputs, outputs, and actions",
	}

	rows, err := s.countAuditRows(ctx, orgID, since)
	if err != nil {
		c.Status = OJKCheckUnknown
		c.Details = fmt.Sprintf("could not read the audit trail: %v", err)
		return c
	}

	observed := rows
	c.Observed = &observed
	if rows == 0 {
		c.Status = OJKCheckWarning
		c.Details = fmt.Sprintf("The audit trail is readable but holds no row for this organization in the last %d days. No governed traffic was recorded.", readinessWindowDays)
		return c
	}
	c.Status = OJKCheckPass
	c.Details = fmt.Sprintf("%d audit records for this organization in the last %d days.", rows, readinessWindowDays)
	return c
}

// checkBreachNotification measures the UU PDP Art. 46 posture from the breach
// store itself. The old literal asserted the endpoint exists -- which says
// nothing about whether any breach met its deadline.
//
// Verdicts: any effectively-overdue breach -> FAIL (that is a live Art. 46
// failure, and it is the one thing this check must never soften). No breaches
// recorded -> pass with the store confirmed reachable. Breaches recorded, none
// overdue -> pass. Store unreachable -> unknown.
func (s *ojkAuditExportServiceImpl) checkBreachNotification(ctx context.Context, orgID string) OJKComplianceCheck {
	c := OJKComplianceCheck{
		Name:        "Breach Notification",
		Description: "UU PDP Art. 46 requires notification within 3x24 hours",
	}

	total, overdue, err := s.countBreachNotifications(ctx, orgID)
	if err != nil {
		c.Status = OJKCheckUnknown
		c.Details = fmt.Sprintf("could not read the breach-notification store: %v", err)
		return c
	}

	observed := int64(overdue)
	c.Observed = &observed
	if overdue > 0 {
		c.Status = OJKCheckFail
		c.Details = fmt.Sprintf("%d of %d recorded breaches are past the 3x24 hour notification window without a timely submission. Submit or acknowledge them via /api/v1/ojk/breach.", overdue, total)
		return c
	}
	c.Status = OJKCheckPass
	c.Details = fmt.Sprintf("Breach store reachable; %d breaches recorded, none past the 3x24 hour window.", total)
	return c
}

// -----------------------------------------------------------------------------
// Measurement queries
// -----------------------------------------------------------------------------

// countIndonesiaPIIPolicies counts the ENABLED Indonesia-PII policy rows this
// org can see.
//
// static_policies is ENABLE RLS keyed on org_id (core/018), and system/global
// policies carry org_id='global' (core/153+154) rather than the caller's org.
// So "what this org can see" is genuinely TWO scoped reads: one at scope
// 'global' for the system tier, one at the caller's own scope. A single
// unwrapped read returns zero rows under axonflow_app_role, which is precisely
// how a check like this ends up reporting a confident wrong answer.
//
// When the caller's org IS 'global' the second read is skipped so rows are not
// counted twice.
func (s *ojkAuditExportServiceImpl) countIndonesiaPIIPolicies(ctx context.Context, orgID string) (int64, error) {
	if err := s.requireDB(); err != nil {
		return 0, err
	}
	const q = `SELECT COUNT(*) FROM static_policies
	            WHERE enabled = true
	              AND org_id = $1
	              AND category = 'pii-indonesia'`

	countAt := func(scope string) (int64, error) {
		var n int64
		err := withOrgScope(ctx, s.db, scope, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, q, scope).Scan(&n)
		})
		return n, err
	}

	total, err := countAt(ojkGlobalPolicyScope)
	if err != nil {
		return 0, fmt.Errorf("counting global-tier pii-indonesia policies: %w", err)
	}
	if orgID == ojkGlobalPolicyScope {
		return total, nil
	}
	own, err := countAt(orgID)
	if err != nil {
		return 0, fmt.Errorf("counting org-tier pii-indonesia policies: %w", err)
	}
	return total + own, nil
}

// ojkGlobalPolicyScope is the org key system/global policy rows carry
// (core/153 backfill + core/154 trigger). Naming it makes the two-scope read
// above legible instead of a magic string.
const ojkGlobalPolicyScope = "global"

// countIndonesiaPIIEvents counts Indonesia PII detection events for the org
// since a cutoff. RLS-gated (enterprise/137), so the wrap is load-bearing.
func (s *ojkAuditExportServiceImpl) countIndonesiaPIIEvents(ctx context.Context, orgID string, since time.Time) (int64, error) {
	if err := s.requireDB(); err != nil {
		return 0, err
	}
	var n int64
	err := withOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM indonesia_pii_detection_events
			  WHERE org_id = $1 AND detected_at >= $2`,
			orgID, since,
		).Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// countHITLActivity returns (queued, reviewed) oversight requests for the org
// since a cutoff. hitl_approval_queue is ENABLE RLS (core/025), so the wrap is
// load-bearing: an unwrapped read returns zero under axonflow_app_role, which
// would turn "oversight is working" into a fabricated failure.
func (s *ojkAuditExportServiceImpl) countHITLActivity(ctx context.Context, orgID string, since time.Time) (queued, reviewed int64, err error) {
	if dbErr := s.requireDB(); dbErr != nil {
		return 0, 0, dbErr
	}
	e := withOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT COUNT(*), COUNT(*) FILTER (WHERE reviewed_at IS NOT NULL)
			   FROM hitl_approval_queue
			  WHERE org_id = $1 AND created_at >= $2`,
			orgID, since,
		).Scan(&queued, &reviewed)
	})
	if e != nil {
		return 0, 0, e
	}
	return queued, reviewed, nil
}

// countAuditRows counts audit_logs rows for the org since a cutoff.
// audit_logs has no RLS, so the org predicate here IS the boundary.
func (s *ojkAuditExportServiceImpl) countAuditRows(ctx context.Context, orgID string, since time.Time) (int64, error) {
	if err := s.requireDB(); err != nil {
		return 0, err
	}
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE `+ojkOrgPredicate+` AND timestamp >= $2`,
		orgID, since,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// countAuditRowsTotal counts every audit_logs row for the org (no window), for
// the dashboard's lifetime total.
func (s *ojkAuditExportServiceImpl) countAuditRowsTotal(ctx context.Context, orgID string) (int64, error) {
	if err := s.requireDB(); err != nil {
		return 0, err
	}
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE `+ojkOrgPredicate, orgID,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// countRecentViolations counts refusing/modifying decisions for the org since a
// cutoff -- the same verdict set the policy_violations export section uses, so
// the dashboard number and the report section can never disagree about what a
// "violation" is.
func (s *ojkAuditExportServiceImpl) countRecentViolations(ctx context.Context, orgID string, since time.Time) (int64, error) {
	if err := s.requireDB(); err != nil {
		return 0, err
	}
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_logs
		  WHERE `+ojkOrgPredicate+`
		    AND timestamp >= $2
		    AND policy_decision IN ('blocked', 'redacted', 'needs_approval')`,
		orgID, since,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// -----------------------------------------------------------------------------
// Dashboard
// -----------------------------------------------------------------------------

// GetDashboard returns the org's OJK compliance dashboard.
//
// Every count is derived from an org-scoped query. Where a count cannot be
// derived it is reported as OJKCountUnavailable (-1) and named in Unavailable,
// rather than as a confident 0 -- the previous implementation returned literal
// zeros and a literal ActivePolicies: 8 regardless of what the deployment
// actually had.
//
// The whole dashboard is NOT failed by one unavailable count: a partial
// dashboard that names its gaps is more useful than a 500.
func (s *ojkAuditExportServiceImpl) GetDashboard(ctx context.Context, orgID string) (*OJKDashboardResponse, error) {
	if strings.TrimSpace(orgID) == "" {
		return nil, errOrgScopeRequired
	}
	// A nil DB is NOT an error here. Every count below degrades to
	// OJKCountUnavailable and names itself in Unavailable, which is the honest
	// answer; erroring would leave a caller unable to distinguish "no database"
	// from "no data", the exact ambiguity this workstream removes.

	since := time.Now().UTC().AddDate(0, 0, -OJKDashboardRecentDays)
	resp := &OJKDashboardResponse{
		Framework:   OJKFrameworkCombined,
		LastUpdated: time.Now().UTC(),
	}

	// The compliance score is the readiness score, so the dashboard headline and
	// the readiness endpoint can never disagree.
	if readiness, err := s.ValidateComplianceReadiness(ctx, orgID); err == nil {
		resp.ComplianceScore = readiness.Score
		resp.RetentionStatus = ojkRetentionStatusFrom(readiness)
		// The score is REAL (an unknown check scores zero), so it does not belong
		// in Unavailable -- every entry there carries -1 in its field, and
		// mixing "could not measure" with "measured over less than everything"
		// would leave a consumer unable to trust either. The dedicated count is
		// the honest channel: "we scored 20" and "we scored 20 and four of five
		// dimensions could not be read at all" are different statements.
		resp.ReadinessUnknownChecks = readiness.UnknownChecks
	} else {
		resp.ComplianceScore = OJKCountUnavailable
		resp.RetentionStatus = "unknown"
		resp.Unavailable = append(resp.Unavailable, "compliance_score")
	}

	if n, err := s.countAuditRowsTotal(ctx, orgID); err == nil {
		resp.TotalAuditRecords = n
	} else {
		resp.TotalAuditRecords = OJKCountUnavailable
		resp.Unavailable = append(resp.Unavailable, "total_audit_records")
	}

	// active_policies and the breach counts below take IDENTICAL arguments to the
	// calls the readiness pass just made (both are whole-org, window-free), so
	// these are the two that can be reused without changing what they mean.
	if n, err := s.countIndonesiaPIIPolicies(ctx, orgID); err == nil {
		resp.ActivePolicies = int(n)
	} else {
		resp.ActivePolicies = OJKCountUnavailable
		resp.Unavailable = append(resp.Unavailable, "active_policies")
	}

	if n, err := s.countRecentViolations(ctx, orgID, since); err == nil {
		resp.RecentViolations = int(n)
	} else {
		resp.RecentViolations = OJKCountUnavailable
		resp.Unavailable = append(resp.Unavailable, "recent_violations")
	}

	// This IS re-queried, and the first attempt to de-duplicate it was wrong.
	// The PII Detection readiness check counts over readinessWindowDays (90);
	// this field is documented and consumed as a count over
	// OJKDashboardRecentDays (30). Reusing the readiness observation silently
	// over-reported by up to 3x next to a 30-day RecentViolations, and the
	// comment that justified it ("both trailing windows") was simply false.
	// Two different windows are two different queries.
	if n, err := s.countIndonesiaPIIEvents(ctx, orgID, since); err == nil {
		resp.IndonesiaPIIEvents = int(n)
	} else {
		resp.IndonesiaPIIEvents = OJKCountUnavailable
		resp.Unavailable = append(resp.Unavailable, "indonesia_pii_events")
	}

	if total, overdue, err := s.countBreachNotifications(ctx, orgID); err == nil {
		resp.BreachNotifications = total
		resp.OverdueBreachNotifications = overdue
	} else {
		resp.BreachNotifications = OJKCountUnavailable
		resp.OverdueBreachNotifications = OJKCountUnavailable
		resp.Unavailable = append(resp.Unavailable, "breach_notifications")
	}

	return resp, nil
}

// ojkRetentionStatusFrom derives the dashboard's retention label from the
// readiness check that measured it, rather than from a second, independently
// drifting copy of the same rule (the old code hard-coded "compliant").
func ojkRetentionStatusFrom(readiness *OJKComplianceReadinessResponse) string {
	for _, c := range readiness.Checks {
		if c.Name != "Data Retention" {
			continue
		}
		switch c.Status {
		case OJKCheckPass:
			return "compliant"
		case OJKCheckFail:
			return "non_compliant"
		default:
			return c.Status
		}
	}
	return "unknown"
}

// calculateComplianceScore is the 0..1 form of the readiness score, embedded in
// every export summary. It returns 0 when readiness could not be computed --
// and because readiness now blocks on unknowns, a deployment that cannot
// measure itself scores low rather than reporting a fabricated 0.8.
func (s *ojkAuditExportServiceImpl) calculateComplianceScore(ctx context.Context, orgID string) float64 {
	readiness, err := s.ValidateComplianceReadiness(ctx, orgID)
	if err != nil {
		return 0.0
	}
	return float64(readiness.Score) / 100.0
}
