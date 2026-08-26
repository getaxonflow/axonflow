// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// FinCrime seam integration (ADR-061 / #3328/#3329): the decide-plane verdict
// folding for the Fraud & Risk Add-on plus the HITLBridge adapter that routes
// scorer above-threshold decisions into the approval queue. Untagged: on
// community builds the fincrime engine is nil, every Result here is nil, and
// each function is a strict pass-through.

package agent

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"axonflow/platform/agent/fincrime"
	"axonflow/platform/agent/hitl"
	sharedpolicy "axonflow/platform/shared/policy"
)

// hitlServiceBridgeAdapter adapts the long-lived *hitl.Service to the agent's
// HITLService bridge interface. Only the fields both build variants declare
// are mapped; the bridge consumes RequestID/Status/ExpiresAt.
type hitlServiceBridgeAdapter struct {
	svc *hitl.Service
}

func (a hitlServiceBridgeAdapter) CreateApprovalRequest(ctx context.Context, input HITLCreateInput) (*HITLApprovalRequest, error) {
	req, err := a.svc.CreateApprovalRequest(ctx, hitl.CreateApprovalInput{
		OrgID:               input.OrgID,
		TenantID:            input.TenantID,
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		OriginalQuery:       input.OriginalQuery,
		RequestType:         input.RequestType,
		RequestContext:      input.RequestContext,
		TriggeredPolicyID:   input.TriggeredPolicyID,
		TriggeredPolicyName: input.TriggeredPolicyName,
		TriggerReason:       input.TriggerReason,
		Severity:            input.Severity,
		EUAIActArticle:      input.EUAIActArticle,
		ComplianceFramework: input.ComplianceFramework,
		RiskClassification:  input.RiskClassification,
		ExpiresIn:           input.ExpiresIn,
	})
	if err != nil {
		return nil, err
	}
	return &HITLApprovalRequest{
		RequestID: req.RequestID,
		OrgID:     req.OrgID,
		TenantID:  req.TenantID,
		Status:    req.Status,
		ExpiresAt: req.ExpiresAt,
	}, nil
}

func (a hitlServiceBridgeAdapter) GetApprovalRequest(ctx context.Context, requestID uuid.UUID) (*HITLApprovalRequest, error) {
	req, err := a.svc.GetApprovalRequest(ctx, requestID)
	if err != nil {
		return nil, err
	}
	return &HITLApprovalRequest{
		RequestID: req.RequestID,
		OrgID:     req.OrgID,
		TenantID:  req.TenantID,
		Status:    req.Status,
		ExpiresAt: req.ExpiresAt,
	}, nil
}

// applyFinCrimeToDecideVerdict folds the fincrime seam result into the
// /decide verdict triple AFTER mapPolicyResultToVerdict and the PII redaction
// merge, and BEFORE circuit-breaker recording and the seam-capability gate.
//
// Rules (ADR-061 Decision 3, advisory-only mapping):
//   - nil result: everything unchanged (the non-fincrime fast path).
//   - RequiresApproval on an allow verdict: verdict becomes needs_approval
//     (enterprise only; community mode auto-allows because HITL is
//     enterprise-gated, mirroring mapPolicyResultToVerdict). Obligations are
//     dropped, matching the invariant that only allow verdicts carry
//     obligations (the approver makes the redact call at queue exit).
//   - There is NO deny transition here, ever: the scorer and the MVP
//     validation step-up can only escalate allow to needs_approval.
//   - Reasons and triggeredPolicies always gain the fincrime attribution so
//     even an already-needs_approval verdict records why fincrime also fired.
//
// Returns the possibly-updated triple plus the fincrime policy ids appended
// to triggeredPolicies (never removed or reordered: deny hoisting happens on
// the blocking id, which fincrime never produces).
func applyFinCrimeToDecideVerdict(
	fc *fincrime.Result,
	verdict string,
	reasons []string,
	obligations []DecisionObligation,
	triggeredPolicies []string,
	communityMode bool,
) (string, []string, []DecisionObligation, []string) {
	if fc == nil {
		return verdict, reasons, obligations, triggeredPolicies
	}
	reasons = append(reasons, fc.Reasons...)
	// Deduplicate: the ctx audit holder may have folded the pack-row match
	// ids into fc.PolicyIDs (StampPackMatches shares the Result), and those
	// ids are already in triggeredPolicies from the shared engine.
	seen := make(map[string]bool, len(triggeredPolicies))
	for _, id := range triggeredPolicies {
		seen[id] = true
	}
	for _, id := range fc.PolicyIDs {
		if !seen[id] {
			triggeredPolicies = append(triggeredPolicies, id)
			seen[id] = true
		}
	}
	if fc.RequiresApproval && verdict == VerdictAllow && !communityMode {
		verdict = VerdictNeedsApproval
		obligations = []DecisionObligation{}
	}
	return verdict, reasons, obligations, triggeredPolicies
}

// createFinCrimeApprovalForDecision routes a fincrime-driven needs_approval
// decision into the HITL approval queue through the bridge, so the verdict is
// a reviewable queue entry and not just a wire response. At most one entry
// per decision, attributed to the policy that drove the step-up, in
// precedence order: the ML score (scorer above threshold), the
// protocol-integrity validation, then the first fincrime PACK row whose
// require_approval match produced the verdict. A needs_approval verdict with
// NO fincrime involvement (e.g. an EU AI Act require_approval policy)
// returns "" and is untouched: pre-existing platform semantics for those
// policies are not this seam's to change.
//
// The needs_approval verdict stands regardless; a creation failure leaves the
// PEP holding the request and nothing fails open. Since #3509 the failure is
// no longer silent: this path is one caller of the shared enqueueApproval
// chokepoint (hitl_policy_enqueue.go), which classifies and COUNTS a
// cap-reached, tier-disabled or failed write instead of logging one
// undifferentiated line. The ROW it writes is unchanged - same request_type,
// same descriptor (the raw query, see below), same attribution, same severity,
// same framework - so the outcome an operator or a suite can observe in
// Postgres is byte-identical to the pre-change path.
//
// The raw query in original_query is deliberately LEFT ALONE here. The
// policy-authored planes store a descriptor instead (hitlQueryDescriptor
// explains why: original_query egresses to a customer-configured notify_url),
// and this path arguably should too - but changing it would alter the row this
// function writes, which is exactly the FinCrime drift #3509's work is
// required not to introduce. Raised on #3509 as a follow-up rather than made
// here.
//
// Returns the approval request id ("" when none created).
func createFinCrimeApprovalForDecision(
	ctx context.Context,
	orgID, tenantID, clientID, userID string,
	query string,
	fc *fincrime.Result,
	staticResult *sharedpolicy.RequestResult,
) string {
	if fincrimeHITLBridge == nil {
		return ""
	}
	var policyID, policyName, reason string
	switch {
	case fc != nil && fc.RequiresApproval:
		policyID = fincrime.PolicyIDMandatoryFields
		policyName = "FinCrime Mandatory Field Validation (protocol integrity)"
		if fc.RiskScore != nil {
			if above, ok := fc.RiskScore["above_threshold"].(bool); ok && above {
				policyID = fincrime.PolicyIDMLFraudScore
				policyName = "FinCrime ML Fraud Score (Engine B, advisory)"
			}
		}
		reason = "fincrime review required"
		if len(fc.Reasons) > 0 {
			reason = fc.Reasons[0]
		}
	default:
		policyID, policyName = firstFinCrimePackApprovalMatch(staticResult)
		if policyID == "" {
			return ""
		}
		reason = fmt.Sprintf("fincrime policy %s requires human approval", policyID)
	}
	// EUAIActArticle is left empty so the bridge default ("Article 14", the EU
	// AI Act human-oversight article this queue implements) applies; the
	// column is VARCHAR(10) and a longer free-text value fails the insert.
	// RiskClassification and ExpiresIn are likewise left empty so the bridge
	// computes mapSeverityToRisk("high") and DefaultApprovalExpiration - the
	// identical values the previous CreateApprovalFromPolicy call passed.
	res := enqueueApproval(ctx, "fincrime", HITLCreateInput{
		OrgID:               orgID,
		TenantID:            tenantID,
		ClientID:            clientID,
		UserID:              userID,
		OriginalQuery:       query,
		RequestType:         "fincrime_review",
		TriggeredPolicyID:   policyID,
		TriggeredPolicyName: policyName,
		TriggerReason:       reason,
		Severity:            "high",
		ComplianceFramework: "AML/CFT",
	})
	return res.RequestID
}

// decideApprovalIsPolicyAuthored reports whether a needs_approval on this
// request is raised by a plain require_approval policy rather than by the
// FinCrime seam, using exactly the two conditions
// createFinCrimeApprovalForDecision itself branches on.
//
// It exists so the #3509 grant path can be scoped to policy-authored step-ups
// without duplicating the seam's precedence rules: a false here means the seam
// will own this decision, and a true means it will return "" and leave it
// untouched. Keeping the predicate in this file, next to the switch it
// mirrors, is deliberate - a future change to the seam's arms that forgets
// this function is a change made one line away from it.
func decideApprovalIsPolicyAuthored(fc *fincrime.Result, sr *sharedpolicy.RequestResult) bool {
	if fc != nil && fc.RequiresApproval {
		return false
	}
	packID, _ := firstFinCrimePackApprovalMatch(sr)
	return packID == ""
}

// firstFinCrimePackApprovalMatch returns the id/name of the first
// fincrime-category require_approval match, or empty strings.
func firstFinCrimePackApprovalMatch(sr *sharedpolicy.RequestResult) (string, string) {
	if sr == nil {
		return "", ""
	}
	for _, m := range sr.MatchedPolicies {
		if m.Category == sharedpolicy.CategoryFinCrime && m.Action == sharedpolicy.ActionRequireApproval {
			return m.PolicyID, m.PolicyName
		}
	}
	return "", ""
}

// finCrimeApprovalReason formats the approval-id reason surfaced to the PEP so
// callers can poll the HITL queue for the created entry.
func finCrimeApprovalReason(approvalID string) string {
	return fmt.Sprintf("fincrime approval request %s pending human review", approvalID)
}

// finCrimeParametersFromContext lifts the documented fincrime context objects
// out of DecideRequest.Context into the parameters map handed to the shared
// evaluation path, so the FinCrime Policy Pack rows evaluate over the same
// canonical parameter JSON on /decide as on the MCP planes (where callers
// place the same keys in request parameters).
//
// Returns nil when the caller sent neither key: /decide then passes the same
// nil parameters it always has, and both the static engine's parameter scan
// and the fincrime seam are byte-identical to today for non-fincrime traffic.
// Only the two documented keys are lifted; the rest of the request context
// remains audit-only (canonicalizeRequestContext), never evaluated.
func finCrimeParametersFromContext(reqContext map[string]interface{}) map[string]interface{} {
	if len(reqContext) == 0 {
		return nil
	}
	var out map[string]interface{}
	if v, ok := reqContext[fincrime.TransactionContextKey]; ok {
		out = map[string]interface{}{fincrime.TransactionContextKey: v}
	}
	if v, ok := reqContext[fincrime.CohortContextKey]; ok {
		if out == nil {
			out = map[string]interface{}{}
		}
		out[fincrime.CohortContextKey] = v
	}
	return out
}
