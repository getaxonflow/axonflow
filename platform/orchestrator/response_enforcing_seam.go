// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// THE ORCHESTRATOR RESPONSE PLANE'S ENFORCING SEAM (PRD v11 §1.1, §1.2).
//
// The anchored engine authors the verdict on every LLM response
// /api/v1/process returns: the orchestrator_response scope, decided through the
// enforcer every enforcing process shares (anchored_enforcement.go). It is the
// sibling of the agent's MCP response pass, and has its shape.
//
// # THE DETECTOR LAYER STAYS; THE VERDICT HALF IS GONE
//
// The shared engine's response evaluation still runs first, over the same
// categories the plane admits (PII and sensitive data), because its detector
// facts are the anchored engine's inputs. Its verdict is never read: nothing
// here consults Blocked, BlockReason or the content it masked. A permit that
// composed a field_redact is discharged by masking what the detectors behind
// its determining requirements matched, on the ORIGINAL content, through the
// platform's redactor (sharedpolicy.RedactDecided).
//
// # WHAT A RESPONSE GETS
//
//   - allow with no mandatory redaction: the response as the provider sent it,
//     recorded "allowed";
//   - allow with a field_redact: the response masked by the redactor, recorded
//     "redacted";
//   - deny: the response withheld, recorded "blocked", naming the reason and
//     the constraint that decided it;
//   - a challenge: this plane holds nothing for approval, so the response is
//     withheld with reason approval_required naming the plane (PRD v11 §1.13);
//   - a redaction nothing here can discharge, an activation that cannot be
//     read, a subject that cannot be admitted, or no enforcer at all: the
//     response is withheld naming the cause, and counted. Nothing is ever
//     released because it could not be decided.
//
// # THE SUBJECT
//
// The handler installs the request's subject on the context before the pass
// runs (withResponsePlaneSeam). A pass reached with none installed cannot be
// decided for, and fails closed.
//
// Edition: community-visible, no build tag.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"axonflow/platform/agent"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/anchoredenforcer"
	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
)

// orchestratorResponseScope is the scope this seam cuts over: the
// orchestrator's response plane, which evaluates the response phase alone.
var orchestratorResponseScope = legacycompile.MustScopeFor(legacycompile.PlaneOrchestratorResponse, legacycompile.PhaseResponse)

func init() {
	orchestratorEnforcingScopes = append(orchestratorEnforcingScopes, orchestratorResponseScope)
}

// orchestratorResponsePassName names this pass in a refusal of an obligation it
// cannot discharge.
const orchestratorResponsePassName = "the orchestrator response pass"

// responsePlaneSeam is what the handler installs on a request's context before
// the response pass runs: the request it belongs to and the subject it is
// decided for.
type responsePlaneSeam struct {
	requestID string
	subject   func(now time.Time) (anchoredenforcer.Subject, bool)
}

type responsePlaneSeamKey struct{}

// withResponsePlaneSeam installs the response pass's request and subject.
func withResponsePlaneSeam(ctx context.Context, requestID string, subject func(now time.Time) (anchoredenforcer.Subject, bool)) context.Context {
	return context.WithValue(ctx, responsePlaneSeamKey{}, &responsePlaneSeam{requestID: requestID, subject: subject})
}

func responsePlaneSeamFrom(ctx context.Context) *responsePlaneSeam {
	s, _ := ctx.Value(responsePlaneSeamKey{}).(*responsePlaneSeam)
	return s
}

// headerCredentialSubject is the subject a response forwarded by the agent is
// decided for: the credential principal headerCredentialPrincipal builds from
// the organization and client the agent's proxy authentication stamped. A
// request missing either header has no subject, which the enforcer refuses as
// subject_unverifiable rather than deciding for anyone.
func headerCredentialSubject(h http.Header) func(now time.Time) (anchoredenforcer.Subject, bool) {
	return func(now time.Time) (anchoredenforcer.Subject, bool) {
		principal, err := headerCredentialPrincipal(h, now)
		if err != nil {
			return anchoredenforcer.Subject{}, false
		}
		return anchoredenforcer.Subject{Principal: principal, Credential: true}, true
	}
}

// responseRedactor is the redaction the pass discharges a field_redact with,
// replaceable so a test can make the discharge fail.
var responseRedactor = func(ctx context.Context, engine *sharedpolicy.UnifiedPolicyEngine, content interface{}, opts sharedpolicy.EvalOptions, policyIDs []string) (*sharedpolicy.ResponseResult, error) {
	return engine.RedactDecided(ctx, content, sharedpolicy.PhaseResponse, opts, policyIDs)
}

// decideResponse is THE ONE PLACE the orchestrator response plane's verdict is
// authored. It returns the content to release (the original, or the masked
// content) and the record the handler's wire and audit writers read.
func decideResponse(ctx context.Context, user UserContext, content interface{}) (interface{}, *RedactionInfo) {
	info := &RedactionInfo{Engine: anchoredenforcer.EngineAnchored}
	withhold := func(cause string, err error) (interface{}, *RedactionInfo) {
		if err != nil {
			anchoredenforcer.FailClosed(orchestratorResponseScope, user.OrgID, cause, err)
		}
		info.Verdict = responseVerdictBlocked
		info.DecisionReason = cause
		info.ValidationError = "response withheld: " + anchoredenforcer.CauseMessages[cause]
		anchoredenforcer.RecordEnforcement(orchestratorResponseScope, anchoredenforcer.EngineAnchored, "unavailable", cause)
		return content, info
	}

	enforcer := orchestratorEnforcer()
	if enforcer == nil {
		return withhold(anchoredenforcer.CauseNotWired, errors.New("the orchestrator response pass has no enforcer wired in this process"))
	}
	seam := responsePlaneSeamFrom(ctx)
	if seam == nil {
		return withhold(anchoredenforcer.CauseSubjectUnverifiable, errors.New("the response pass was reached with no request subject installed on its context"))
	}
	engine := sharedpolicy.GetGlobalEngine()
	if engine == nil {
		return withhold(anchoredenforcer.CauseEvaluation, errors.New("the response pass has no detector engine installed to produce its facts"))
	}

	// THE DETECTOR PASS. It evaluates the plane's admitted categories and keeps
	// only the facts; a response it could not scan is withheld (#2820).
	facts, opts, err := responseDetectorPass(ctx, engine, user, content)
	if err != nil {
		return withhold(anchoredenforcer.CauseEvaluation, err)
	}
	var observation *sharedpolicy.Observation
	if facts != nil {
		observation = facts.Observation
	}

	query, err := responseQuery(content)
	if err != nil {
		return withhold(anchoredenforcer.CauseRequest, fmt.Errorf("the response content does not encode: %w", err))
	}
	v := enforcer.Evaluate(ctx, anchoredenforcer.Call{
		Scope: orchestratorResponseScope, OrgID: user.OrgID, RequestID: seam.requestID,
		Action: authoringcatalog.ActionLLMCompletion, Subject: seam.subject,
		Query: query, Observation: observation, EmptyContent: query == "",
	})
	switch {
	case v.Unavailable != "":
		return withhold(v.Unavailable, nil) // Evaluate logged the cause
	case v.Refusal != nil:
		reason := strings.ToLower(string(v.Refusal.Reason))
		info.Verdict, info.DecisionReason = responseVerdictBlocked, reason
		info.ValidationError = reason + ": " + v.Refusal.Detail
		if v.Act != nil {
			info.PolicyBundle = v.Act.PolicyBundle
		}
		anchoredenforcer.RecordEnforcement(orchestratorResponseScope, anchoredenforcer.EngineAnchored, agent.VerdictDeny, reason)
		return content, info
	}
	info.SubjectType, info.PolicyBundle = v.SubjectType, v.Act.PolicyBundle
	dec := v.Decision

	if dec.State != contract.StateAllow {
		unknown := anchoredenforcer.UnknownConstraints(dec)
		reason := string(dec.Reason)
		text := strings.Join(append([]string{reason}, anchoredenforcer.UnknownConstraintReasons(v.Act, unknown)...), "; ")
		if dec.State == contract.StateChallenge {
			reason = string(contract.ReasonApprovalRequired)
			text = anchoredenforcer.ApprovalRequiredReason(orchestratorResponseScope)
		}
		info.Verdict, info.DecisionReason, info.ValidationError = responseVerdictBlocked, reason, text
		info.BlockingPolicyID = anchoredenforcer.BlockingConstraint(dec.Determining, unknown)
		anchoredenforcer.RecordEnforcement(orchestratorResponseScope, anchoredenforcer.EngineAnchored, agent.VerdictDeny, reason)
		return content, info
	}

	ids, unsupported, err := anchoredenforcer.ContentRedactionPolicies(dec, v.Act.Policy, observation, orchestratorResponsePassName, anchoredenforcer.DischargesAsResponseContent)
	if err != nil {
		return withhold(anchoredenforcer.CauseObligation, err)
	}
	if unsupported != "" {
		reason := string(contract.ReasonUnsupportedObligation)
		info.Verdict, info.DecisionReason, info.ValidationError = responseVerdictBlocked, reason, unsupported
		anchoredenforcer.RecordEnforcement(orchestratorResponseScope, anchoredenforcer.EngineAnchored, agent.VerdictDeny, reason)
		return content, info
	}
	reason := string(dec.Reason)
	if len(ids) == 0 {
		info.Verdict, info.DecisionReason = responseVerdictAllowed, reason
		anchoredenforcer.RecordEnforcement(orchestratorResponseScope, anchoredenforcer.EngineAnchored, agent.VerdictAllow, reason)
		return content, info
	}
	redacted, err := responseRedactor(ctx, engine, content, opts, ids)
	if err != nil {
		return withhold(anchoredenforcer.CauseObligation, err)
	}
	info.Verdict, info.DecisionReason = responseVerdictRedacted, reason
	info.HasRedactions = true
	info.RedactionCount = len(redacted.RedactedFields)
	for _, field := range redacted.RedactedFields {
		info.RedactedFields = append(info.RedactedFields, field.Path)
	}
	anchoredenforcer.RecordEnforcement(orchestratorResponseScope, anchoredenforcer.EngineAnchored, agent.VerdictAllow, reason)
	return redacted.Content, info
}

// responseDetectorPass runs the shared engine's response evaluation over the
// plane's admitted categories - every enabled PII category and the sensitive
// data category (legacycompile's responseProcessorAdmission) - for its detector
// facts. It returns nil facts when no such category is enabled: the anchored
// engine then reads every detector as unknown, which withholds the response
// unless it is empty. An error is a response that could not be scanned.
func responseDetectorPass(ctx context.Context, engine *sharedpolicy.UnifiedPolicyEngine, user UserContext, content interface{}) (*sharedpolicy.ResponseResult, sharedpolicy.EvalOptions, error) {
	orgScope := sharedpolicy.OrgScopePtr(user.OrgID)
	if err := engine.PoliciesLoadable(ctx, user.TenantID, orgScope, sharedpolicy.PhaseResponse); err != nil {
		return nil, sharedpolicy.EvalOptions{}, fmt.Errorf("the response-phase detectors could not be loaded: %w", err)
	}
	categories := append(append([]sharedpolicy.PolicyCategory{},
		engine.EnabledPIICategories(ctx, user.TenantID, orgScope, sharedpolicy.PhaseResponse)...),
		engine.EnabledSensitiveDataCategories(ctx, user.TenantID, orgScope, sharedpolicy.PhaseResponse)...)
	gateway := ResolveGatewayDetectionConfig(ctx, user.OrgID)
	opts := sharedpolicy.EvalOptions{
		TenantID:        user.TenantID,
		OrgID:           user.OrgID,
		OrgScope:        orgScope,
		UserID:          fmt.Sprintf("%d", user.ID),
		Categories:      categories,
		SkipCategories:  gateway.SkipCategories,
		ActionOverrides: gateway.BuildActionOverrides(),
		MaxRedactions:   100,
		// No governance segment is resolved on this plane, so segment-scoped rows
		// are excluded (#3266).
		Segments: nil,
	}
	if len(categories) == 0 {
		// Never EvaluateResponse with empty Categories: that evaluates every
		// policy, which is not what this plane admits.
		return nil, opts, nil
	}
	result := engine.EvaluateResponse(ctx, content, opts)
	if result.EvaluationError {
		return nil, opts, errors.New("the response-phase scan could not complete")
	}
	return result, opts, nil
}

// responseQuery is the content as the anchored engine evaluates it (args.query):
// a text response as sent, and any other shape as its JSON encoding. Empty
// content is the empty string, which the engine decides as known-empty.
func responseQuery(content interface{}) (string, error) {
	switch c := content.(type) {
	case nil:
		return "", nil
	case string:
		return c, nil
	}
	b, err := json.Marshal(content)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// logResponsePlaneDecision writes the one log line a decided response gets.
func logResponsePlaneDecision(orgID string, info *RedactionInfo) {
	if info == nil {
		return
	}
	log.Printf("[ResponsePlane] org=%s verdict=%s engine=%s reason=%s blocking=%s",
		logutil.Sanitize(orgID), info.Verdict, info.Engine, info.DecisionReason, info.BlockingPolicyID)
}
