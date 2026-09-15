// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// THE WORKFLOW STEP GATE DECIDES ON THE ANCHORED ENGINE (#4254, PRD v11 §1.1).
//
// Every step a workflow control plane gates is presented to the engine as the
// shipped action its step type maps to (step_action_admission.go), decided
// through the ONE enforcer this process installs, and answered as the gate
// decision its callers already speak.
//
// WHAT THIS PLANE PRESENTS, AND WHAT IT DOES NOT:
//
//   - the caller: the organization and client the agent authenticated, read
//     from the X-Org-ID and X-Client-ID headers the orchestrator's HTTP boundary
//     installs on the request context (installWCPPlaneSubject) and admitted as a
//     credential subject: the subject the multi-agent plane decides for too. A
//     step with no subject installed is refused as subject_unverifiable and never
//     decided;
//   - the facts: the dynamic condition matcher's, through the fact producer -
//     the environment, the risk floor, the caller-context arguments and each
//     row's content verdict (PRD v11 §1.2 ruling R2);
//   - NO CONTENT. This plane builds its policy request with no content field
//     and never has, so it presents none and says so: EmptyContent tells the
//     enforcer to state every registry detector known-false, and the producer's
//     presentsNoContent does the same for the dynamic ones. Both are statements
//     about the plane, not detectors run over an empty string. Presenting a
//     step's input is the v11.1.0 follow-up (#4249).
//
// TWO VOCABULARIES, DELIBERATELY NOT MERGED. The gate answers in
// workflow_control's own terms - allow, block, require_approval - because its
// callers, its persisted rows and its wire already speak them. The decision
// counter takes the agent's terms - allow, deny, needs_approval, unavailable -
// because every other enforcing plane reports in those and a series that
// disagrees stops aggregating. `require_approval` and `needs_approval` are the
// same outcome named for two different surfaces; conflating them is a mistake
// this tree has already paid for once (explain_handler.go).
//
// THE COUNTER'S FOUR VALUES ARE SPELLED OUT AT THIS SEAM'S CALL SITES. Three of
// them are constants already: platform/agent/decision_handler.go exports
// VerdictAllow, VerdictDeny and VerdictNeedsApproval, which this package imports
// (the response plane's seam records with them), and platform/shared/pep
// declares the same three. "unavailable" has no verdict constant anywhere. This
// seam, the multi-agent seam and the route seam still spell all four as
// literals; giving the four labels one home is a v11.1.0 row (#4249).

// wcpSeamScope is the enforcement scope this seam decides.
var wcpSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneWCP, "")

// wcpPlaneSubjectKey carries the credential subject a workflow step is decided
// for (#4254). The step gate's evaluator interface receives no request, so the
// orchestrator's HTTP boundary installs the subject on the request context
// (installWCPPlaneSubject), as the multi-agent plane's handlers do.
type wcpPlaneSubjectKey struct{}

// withWCPPlaneSubject installs the subject every step gated with ctx is decided
// for.
func withWCPPlaneSubject(ctx context.Context, subject func(now time.Time) (anchoredenforcer.Subject, bool)) context.Context {
	return context.WithValue(ctx, wcpPlaneSubjectKey{}, subject)
}

func wcpPlaneSubjectFrom(ctx context.Context) func(now time.Time) (anchoredenforcer.Subject, bool) {
	if ctx == nil {
		return nil
	}
	subject, _ := ctx.Value(wcpPlaneSubjectKey{}).(func(now time.Time) (anchoredenforcer.Subject, bool))
	return subject
}

// installWCPPlaneSubject installs, on every request, the credential subject the
// workflow step gate decides for: the organization and client the agent's proxy
// authentication Set on its hop (X-Org-ID, X-Client-ID). Every path into the
// step gate runs on a request context - the gate route and both checkpoint
// resumes - so one middleware reaches them all. It is never the tenant:
// X-Tenant-ID is caller-held on the agent's internal-service hop (R3 A-H1).
func installWCPPlaneSubject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(withWCPPlaneSubject(r.Context(), headerCredentialSubject(r.Header))))
	})
}

// This seam registers its own scope, so two seams landing separately add
// disjoint entries and neither edits the other's file.
func init() {
	orchestratorEnforcingScopes = append(orchestratorEnforcingScopes, wcpSeamScope)
}

// The fact producer this plane decides from, built once per process from the
// dynamic engine the process wired. Replaceable so a seam test can install its
// own rows without a database.
var (
	wcpFactsOnce sync.Once
	wcpFacts     *dynamicFactProducer
	wcpFactsErr  error

	newWCPFactProducer = func() (*dynamicFactProducer, error) {
		if dynamicPolicyEngine == nil {
			return nil, errors.New("the dynamic policy engine is not wired, so this plane's facts cannot be produced")
		}
		p, err := newDynamicFactProducer(dynamicPolicyEngine.ListActivePoliciesForTenant)
		if err != nil {
			return nil, err
		}
		// THE STEP GATE PRESENTS NO CONTENT (see the file comment).
		p.presentsNoContent = true
		return p, nil
	}
)

func wcpFactProducer() (*dynamicFactProducer, error) {
	wcpFactsOnce.Do(func() { wcpFacts, wcpFactsErr = newWCPFactProducer() })
	return wcpFacts, wcpFactsErr
}

// stepGateEvaluationFor decides one step on the anchored engine and answers in
// the gate's own terms, with the PolicyEvaluationResult the enqueue path still
// reads beside it.
//
// It FAILS CLOSED. A plane that cannot reach a verdict blocks the step and says
// which dependency was unavailable: admitting a step because the engine could
// not answer would turn an outage into a governance decision.
func stepGateEvaluationFor(ctx context.Context, step *workflow_control.StepGateContext, req OrchestratorRequest) (*workflow_control.StepGateEvaluation, *PolicyEvaluationResult) {
	evaluation, result, verdict := stepGateDecide(ctx, step, req)
	return stampStepGateDecision(evaluation, verdict), result
}

// stepGateDecide is stepGateEvaluationFor's decision, with the verdict the engine
// gave: nil when the plane failed closed before the engine answered. Every
// answer is stamped with the anchored decision in the one caller (PRD v11 §5.7).
func stepGateDecide(ctx context.Context, step *workflow_control.StepGateContext, req OrchestratorRequest) (*workflow_control.StepGateEvaluation, *PolicyEvaluationResult, *anchoredenforcer.Verdict) {
	enforcer := orchestratorEnforcer()
	if enforcer == nil {
		evaluation, result := stepGateUnavailable(anchoredenforcer.CauseNotWired)
		return evaluation, result, nil
	}
	subject := wcpPlaneSubjectFrom(ctx)
	if subject == nil {
		// No boundary installed a subject for this request, so there is no one
		// to decide the step for. Refused as the identity plane refuses an
		// unverifiable subject, and never decided for anyone (R3 A-H1).
		// Counted as the enforcer counts the same cause, "unavailable" (R3 B-L1).
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "unavailable", anchoredenforcer.CauseSubjectUnverifiable)
		ids := []string{anchoredenforcer.CauseSubjectUnverifiable}
		return stepGateBlocked(anchoredenforcer.CauseSubjectUnverifiable+": no credential subject was installed for this step", ids), blockedPolicyResult(ids), nil
	}
	facts, err := stepGateFacts(ctx, req)
	if err != nil {
		anchoredenforcer.FailClosed(wcpSeamScope, step.OrgID, anchoredenforcer.CauseEvaluation, err)
		if errors.Is(err, errDynamicFactsUnavailable) {
			evaluation, result := stepGateSegmentResolutionFailed()
			return evaluation, result, nil
		}
		evaluation, result := stepGateUnavailable(anchoredenforcer.CauseEvaluation)
		return evaluation, result, nil
	}
	action, actionErr := actionForWCPStep(step.StepType)

	v := enforcer.Evaluate(ctx, anchoredenforcer.Call{
		Scope:     wcpSeamScope,
		OrgID:     step.OrgID,
		RequestID: req.RequestID,
		Action:    action,
		ActionErr: actionErr,
		Subject:   subject,
		// No content, stated as the plane's contract rather than computed.
		Query:        "",
		EmptyContent: true,
		Facts:        facts,
	})

	switch {
	case v.Unavailable != "":
		// evaluate already logged the cause.
		evaluation, result := stepGateUnavailable(v.Unavailable)
		return evaluation, result, &v
	case v.Refusal != nil:
		// The identity plane refused this step's subject. Named as every other
		// plane names it: the admission's reason, then its detail.
		reason := strings.ToLower(string(v.Refusal.Reason))
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "deny", reason)
		return stepGateBlocked(reason+": "+v.Refusal.Detail, []string{reason}), blockedPolicyResult([]string{reason}), &v
	}
	evaluation, result := stepGateFromDecision(v, dbRiskCalculator.CalculateRiskScore(req), time.Now())
	return evaluation, result, &v
}

// stepGateFacts produces the facts the dynamic rows governing this caller read.
func stepGateFacts(ctx context.Context, req OrchestratorRequest) (contract.AttributeSet, error) {
	producer, err := wcpFactProducer()
	if err != nil {
		return nil, err
	}
	facts, _, err := producer.Produce(ctx, req)
	return facts, err
}

// stepGateFromDecision answers the engine's decision in the gate's terms.
//
// A CHALLENGE IS A HOLD, NEVER A REFUSAL (PRD v11 §1 item 13). This plane can
// hold, so a challenge becomes require_approval and the step stays pending; it
// is never mapped to a block.
//
// riskScore is the platform's risk floor for this step. It rides on the result
// because the HITL queue derives a held step's severity from it: a typed
// approval carries no severity of its own, unlike the dynamic row's
// require_approval config it replaces (#4254).
func stepGateFromDecision(v anchoredenforcer.Verdict, riskScore float64, now time.Time) (*workflow_control.StepGateEvaluation, *PolicyEvaluationResult) {
	dec := v.Decision
	if dec == nil {
		return stepGateUnavailable(anchoredenforcer.CauseEvaluation)
	}
	deciding := anchoredenforcer.DecidingPolicies(dec)
	reason := string(dec.Reason)

	switch dec.State {
	case contract.StateAllow:
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "allow", reason)
		result := allowedPolicyResult(deciding)
		result.RiskScore = riskScore
		return &workflow_control.StepGateEvaluation{
			Decision:          workflow_control.GateDecisionAllow,
			Reason:            "No matching policies",
			PolicyIDs:         deciding,
			PoliciesEvaluated: stepGatePolicyMatches(deciding, workflow_control.GateDecisionAllow, reason),
			PoliciesMatched:   []workflow_control.PolicyMatch{},
		}, result

	case contract.StateChallenge:
		// A challenge carries its approval requirement. One that carries none is a
		// decision the contract rejects, so it is withheld as an evaluation failure
		// rather than held with no terms and the queue's default expiry (R3 B-L2).
		if dec.Approval == nil {
			return stepGateUnavailable(anchoredenforcer.CauseEvaluation)
		}
		// TIMEOUT IS DENY. That is the approval requirement's own contract, so
		// an approval whose expiry has already passed when the step would be
		// queued has timed out before anyone could grant it. The step is
		// withheld, named, and no queue row is written. This applies the
		// engine's rule; it is not a verdict the seam authors.
		if dec.Approval != nil && !dec.Approval.ExpiresAt.IsZero() && !dec.Approval.ExpiresAt.After(now) {
			return stepGateApprovalExpired(dec.DecisionID, dec.Approval.ExpiresAt)
		}
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "needs_approval", reason)
		blocking := anchoredenforcer.BlockingConstraint(dec.Determining, anchoredenforcer.UnknownConstraints(dec))
		result := heldPolicyResult(deciding, blocking)
		result.RiskScore = riskScore
		result.hold = &stepGateHold{decisionID: dec.DecisionID, approval: dec.Approval}
		return &workflow_control.StepGateEvaluation{
			Decision:          workflow_control.GateDecisionRequireApproval,
			Reason:            "Step requires human approval",
			PolicyIDs:         deciding,
			PoliciesEvaluated: stepGatePolicyMatches(deciding, workflow_control.GateDecisionRequireApproval, reason),
			PoliciesMatched:   stepGatePolicyMatches(deciding, workflow_control.GateDecisionRequireApproval, reason),
		}, result

	default:
		// DENY and ERROR both withhold the step. An ERROR is a constraint the
		// engine could not evaluate, which is not a permit: unknown input never
		// becomes an admission (ADR-065 invariant 4).
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "deny", reason)
		unknown := anchoredenforcer.UnknownConstraints(dec)
		detail := "Step blocked by policy"
		if len(unknown) > 0 && v.Act != nil {
			if reasons := anchoredenforcer.UnknownConstraintReasons(v.Act, unknown); len(reasons) > 0 {
				detail = strings.Join(reasons, "; ")
			}
		}
		ids := deciding
		if blocking := anchoredenforcer.BlockingConstraint(dec.Determining, unknown); blocking != "" {
			ids = append([]string{blocking}, deciding...)
		}
		ids = dedupeStepGateIDs(ids)
		return stepGateBlocked(detail, ids), blockedPolicyResult(ids)
	}
}

// stepGateUnavailable is the fail-closed answer: the step is withheld and the
// cause is named, never admitted because the plane could not decide.
func stepGateUnavailable(cause string) (*workflow_control.StepGateEvaluation, *PolicyEvaluationResult) {
	anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "unavailable", cause)
	message := anchoredenforcer.CauseMessages[cause]
	if message == "" {
		message = cause
	}
	ids := []string{"decision_enforcement_unavailable"}
	result := blockedPolicyResult(ids)
	result.EvaluationError = true
	return stepGateBlocked(fmt.Sprintf("%s (%s)", message, cause), ids), result
}

// stepGateSegmentResolutionFailed is the fail-closed answer when the caller's
// governance segments could not be resolved, so which dynamic rows govern the
// caller - and therefore which facts to state - cannot be established.
//
// It keeps the id and the reason this plane has always answered for that
// outage (ADR-060 #2989 P3b). `segment_resolution_failed` is a machine-readable
// convention other routes share and that the audit row and the step-gate
// runtime suite key off, so the move to the anchored engine does not rename it.
func stepGateSegmentResolutionFailed() (*workflow_control.StepGateEvaluation, *PolicyEvaluationResult) {
	anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "unavailable", anchoredenforcer.CauseEvaluation)
	ids := []string{"segment_resolution_failed"}
	result := blockedPolicyResult(ids)
	result.EvaluationError = true
	return stepGateBlocked("segment resolution unavailable - request denied (fail-closed, ADR-060 #2989 P3b)", ids), result
}

// stepGateBlocked is one withheld step.
func stepGateBlocked(reason string, ids []string) *workflow_control.StepGateEvaluation {
	return &workflow_control.StepGateEvaluation{
		Decision:          workflow_control.GateDecisionBlock,
		Reason:            reason,
		PolicyIDs:         ids,
		PoliciesEvaluated: stepGatePolicyMatches(ids, workflow_control.GateDecisionBlock, reason),
		PoliciesMatched:   stepGatePolicyMatches(ids, workflow_control.GateDecisionBlock, reason),
	}
}

// stepGatePolicyMatches projects the policies a decision names.
//
// IDS AND REASONS, NOT LEGACY METADATA. An anchored decision names the policies
// that decided it; it carries no risk level, no override flag and no matched
// rule, because those were the dynamic row's own columns. Those fields are
// omitempty and are therefore absent from the response and the persisted row
// under the engine, which is a shape change worth stating rather than
// discovering (#4254 release notes).
func stepGatePolicyMatches(ids []string, decision workflow_control.GateDecision, reason string) []workflow_control.PolicyMatch {
	out := make([]workflow_control.PolicyMatch, 0, len(ids))
	for _, id := range ids {
		out = append(out, workflow_control.PolicyMatch{
			PolicyID:   id,
			PolicyName: id,
			Action:     string(decision),
			Reason:     reason,
		})
	}
	return out
}

func dedupeStepGateIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup || id == "" {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// The PolicyEvaluationResult the HITL enqueue path still reads. The typed
// approval replaces its severity and policy attribution in the commit that
// makes the hold typed; here it carries what the decision named, so the queue
// keeps being fed exactly as before.
func allowedPolicyResult(ids []string) *PolicyEvaluationResult {
	return &PolicyEvaluationResult{Allowed: true, AppliedPolicies: ids, RequiredActions: []string{}}
}

func blockedPolicyResult(ids []string) *PolicyEvaluationResult {
	return &PolicyEvaluationResult{Allowed: false, AppliedPolicies: ids, RequiredActions: []string{}}
}

func heldPolicyResult(ids []string, blocking string) *PolicyEvaluationResult {
	severityPolicy := blocking
	if severityPolicy == "" && len(ids) > 0 {
		severityPolicy = ids[0]
	}
	return &PolicyEvaluationResult{
		Allowed:          false,
		AppliedPolicies:  ids,
		RequiredActions:  []string{"require_approval"},
		SeverityPolicyID: severityPolicy,
	}
}

// stepGateApprovalExpired withholds a step whose approval timed out before it
// could be queued, in the subject refusal's shape: the reason, then its detail.
// The detail names the decision and the expiry, so the step's recorded decision
// and its audit row say which approval lapsed and when.
func stepGateApprovalExpired(decisionID string, expiresAt time.Time) (*workflow_control.StepGateEvaluation, *PolicyEvaluationResult) {
	reason := string(contract.ReasonApprovalExpired)
	anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "deny", reason)
	ids := []string{reason}
	return stepGateBlocked(approvalExpiredReason(decisionID, expiresAt), ids), blockedPolicyResult(ids)
}

// approvalExpiredReason is the reason a step whose approval timed out is
// withheld with, on every plane that holds: the reason code, the decision and
// the expiry, and nothing of the requirement.
func approvalExpiredReason(decisionID string, expiresAt time.Time) string {
	return string(contract.ReasonApprovalExpired) + ": decision " + decisionID +
		" requires an approval that expired at " + expiresAt.UTC().Format(time.RFC3339) +
		", and a timed-out approval is a deny"
}

// stepGateHold is what a challenge holds a step with: the decision that held
// it and the approval requirement it must satisfy (PRD v11 §1 item 13).
type stepGateHold struct {
	decisionID string
	approval   *contract.ApprovalRequirement
}

// requestContext is the hold as the approval queue row records it.
//
// THE CLAUSES ARE NEVER FLATTENED. A requirement is a conjunction of threshold
// clauses, and merging their pools invents a refusal the policy does not
// require (contract.ApprovalRequirement), so every clause is its own element,
// with its own quorum and its own eligible groups, even when there is one.
// An expiry is recorded only when one was declared: an absent expires_at means
// none, never a zero time. plane names the plane that held the step. Neither
// plane that holds carries a correlation id.
func (h *stepGateHold) requestContext(plane string) map[string]interface{} {
	out := map[string]interface{}{
		"plane":       plane,
		"decision_id": h.decisionID,
	}
	if h.approval == nil {
		return out
	}
	clauses := make([]map[string]interface{}, 0, len(h.approval.AllOf))
	for _, clause := range h.approval.AllOf {
		eligible := make([]string, 0, len(clause.Eligible))
		for _, group := range clause.Eligible {
			eligible = append(eligible, group.String())
		}
		clauses = append(clauses, map[string]interface{}{"quorum": clause.Quorum, "eligible": eligible})
	}
	out["approval_clauses"] = clauses
	out["separation_of_duties"] = h.approval.SeparationOfDuties
	if !h.approval.ExpiresAt.IsZero() {
		out["expires_at"] = h.approval.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return out
}
