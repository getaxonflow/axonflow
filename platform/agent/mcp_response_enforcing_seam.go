// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// THE MCP RESPONSE PASS'S ENFORCING SEAM (#3564, wave one).
//
// The anchored engine authors this pass's verdict: the RESPONSE pass of the MCP
// plane - evaluateOutputPolicies, reached from resources/query, tools/execute,
// POST /api/v1/mcp/check-output and the MCP server's check_output tool. It runs
// through the one enforcer decision_enforcing_seam.go builds. The request pass
// is the mcp:request scope's (mcp_request_enforcing_seam.go), through the same
// enforcer.
//
// # WHY THE RESPONSE PASS CAN BE CUT OVER
//
// Three facts, each derived rather than assumed:
//
//   - THE RESTRICTION. activation.RestrictToScope(mcp:response) binds the
//     shipped controls whose rows load in the response phase and whose
//     categories the pass's call sites admit. The request pass's
//     security-sqli controls and the request-only KTP control are not in it,
//     because their detectors never run here.
//   - THE DISCHARGE. The mcp profile advertises field_redact@1, and activation
//     refuses any scope whose profile cannot discharge a mandatory obligation in
//     its restriction. What performs the redaction is the platform's own
//     redactor, through sharedpolicy.RedactDecided.
//   - THE SUBJECT. A REST route carrying a verified user token, and a server
//     session whose per-user token a validator accepted, are evaluated for that
//     user. A caller with no per-user identity is evaluated for its client
//     credential (the credential principal, PRD v11 §1.6).
//
// # HOW THE VERDICT IS APPLIED
//
// The shared engine's response pass produces a sharedpolicy.ResponseResult,
// and applyResponseStaticResult maps it onto the outcome every caller reads.
// The anchored engine produces the SAME shape: a refusal is a blocked result, a
// permit is the content with exactly the decision's redactions applied, and it
// REPLACES the shared engine's result before anything reads it. EvaluateResponse
// still runs first: its detector facts are the anchored engine's inputs.
//
// # THE REDACTION IS THE DECISION'S, NEVER LEGACY'S
//
// A permit that composed a field_redact is discharged by masking what the
// detectors behind its determining redaction requirements matched - read off
// the decision, the activated policies and the detector facts - on the
// ORIGINAL content. The shared engine's redaction set is never borrowed: it is
// what the legacy actions redacted, and the decision is what the anchored
// engine enforces. A redaction requirement that names no detector this pass
// matched cannot be discharged, and the response is withheld.
//
// # WHAT DIFFERS FROM THE LEGACY ENGINE, STATED
//
//   - Detection overrides (#4045) reach the engine. A redaction a recorded
//     override makes mandatory is discharged or refused, never degraded to the
//     obligation-fallback posture; on this pass field_redact is discharged
//     inline.
//   - ADR-044 session overrides are a legacy-engine lever: an anchored refusal
//     carries no matched legacy policy, so no override applies to it.
//   - A response-phase category with no enabled policy scans nothing, so a
//     control reading its detector is UNKNOWN and the response is withheld -
//     #4032's class. The process-level narrowings that produced it refuse to
//     boot (refuseNarrowedDetection).
//   - args.query on this pass is the content being released, because that is
//     what the pass evaluates; a response has no statement of its own.
//
// The SQLi response scan, the Indonesia checksum detector and the exfiltration
// limits are not policy-engine verdicts, and they run exactly as before.
//
// # EMPTY CONTENT IS DECIDED, NOT WITHHELD
//
// A response with no content - an execute whose command returned no message, a
// query that returned no rows - gives the shared engine nothing to scan, so its
// detector facts say no detector ran. Left there, every detector-reading
// control is UNKNOWN and the anchored engine would withhold a response that
// carries nothing. But a content detector over no content has a determined
// answer, so the request says the content is empty and the detector signals the
// activated policies read are KNOWN false (see anchoredRequest). The grant and
// the identity still decide: an ungranted principal is refused an empty
// response too.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/anchoredenforcer"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// mcpResponseSeamScope is the scope this seam cuts over: the MCP plane's
// response phase, and only it.
var mcpResponseSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse)

// mcpResponseSeam is what a response-pass entry point installs on its context
// before it evaluates the response: the request the pass belongs to and the
// subject and enforcement profile it arrived with. The seam records back what
// the anchored engine decided, and the entry point's response body and audit
// writers read that record.
//
// It rides the context rather than evaluateOutputPolicies' signature for the
// fincrime seam's reason: the same request-scoped facts reach every writer that
// is handed the context, and an entry point that forgot to install it cannot be
// decided for - the seam fails closed on its absence.
type mcpPassSeam struct {
	requestID string
	subject   func(time.Time) (decisionSubject, bool)
	// handshake is the enforcement point the request admitted, zero when it
	// presented none: the engine decides under its profile, and a refusal it
	// cannot discharge names its capability gap.
	handshake pepHandshakeResolution

	mu          sync.Mutex
	ran         bool
	engine      string
	subjectType string
	bundle      string
	// packs are the add-on policy packs that composed into bundle (PRD v11
	// §1.9): the request pass records them from its enforcement, the response
	// pass from the activation that decided it (notePacks, #4196).
	packs  []string
	reason string
	// capabilityScoped is the capability scoping the pass's evaluation applied,
	// for the audit row; nil when it scoped out none.
	capabilityScoped *sharedpolicy.CapabilityScoping
	// legacyValidators is what a checksum validator did to the response before
	// the anchored engine decided it (#4122), for the body and the audit row.
	legacyValidators []LegacyValidatorAction
	// identities, documentVersion and actionName are what the anchored decision
	// named, for the audit row (PRD v11 §1.14, stampAnchoredIdentity).
	identities      []PolicyIdentity
	documentVersion int
	actionName      string
}

type mcpResponseSeamKey struct{}

func withMCPResponseSeam(ctx context.Context, requestID string, subject func(time.Time) (decisionSubject, bool), handshake pepHandshakeResolution) context.Context {
	return context.WithValue(ctx, mcpResponseSeamKey{}, &mcpPassSeam{requestID: requestID, subject: subject, handshake: handshake})
}

func mcpResponseSeamFrom(ctx context.Context) *mcpPassSeam {
	s, _ := ctx.Value(mcpResponseSeamKey{}).(*mcpPassSeam)
	return s
}

func (s *mcpPassSeam) record(engine, bundle, reason, subjectType string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ran, s.engine, s.bundle, s.reason, s.subjectType = true, engine, bundle, reason, subjectType
}

// recordRequestPass records the request pass's anchored decision from its one
// enforcement, so the bundle, the policy packs that composed into it (#4196)
// and what the decision named (PRD v11 §1.14) cannot disagree. reason is the
// one the entry point answered with, which a projection's refusal replaces.
func (s *mcpPassSeam) recordRequestPass(enforced requestPassEnforcement, reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ran, s.engine, s.bundle, s.reason, s.subjectType = true, enforced.engine, enforced.policyBundle, reason, enforced.subjectType
	s.packs = append([]string(nil), enforced.policyPacks...)
	s.identities, s.documentVersion, s.actionName = enforced.policyIdentities, enforced.documentVersion, enforced.actionName
}

// noteIdentity keeps what the anchored decision named, for the audit row.
func (s *mcpPassSeam) noteIdentity(act *activation.Activation, evaluated []string, action string) {
	if s == nil || act == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities, s.documentVersion, s.actionName = anchoredPolicyIdentities(act, evaluated), act.DocumentVersion, act.ActionName(action)
}

// notePacks keeps the policy packs that composed into the bundle the response
// pass decided under, for its body and its audit row (#4196): the names
// /api/v1/decide carries, from the activation that decided. Nil - so omitted -
// when no pack binds.
func (s *mcpPassSeam) notePacks(act *activation.Activation) {
	if s == nil || act == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packs = act.PackRefs()
}

// noteScoping keeps the capability scoping the pass's evaluation applied, for
// the audit row.
func (s *mcpPassSeam) noteScoping(o *sharedpolicy.Observation) {
	if s == nil || o == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capabilityScoped = o.CapabilityScoped
}

// noteLegacyValidator records a checksum validator that acted on the response
// before the anchored engine decided it (#4122).
func (s *mcpPassSeam) noteLegacyValidator(validator, action string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.legacyValidators = append(s.legacyValidators, LegacyValidatorAction{Validator: validator, Action: action})
}

// legacyValidatorsActed is what noteLegacyValidator recorded, whether or not the
// pass itself ran: a validator that blocked ahead of the seam acted on a
// response the anchored engine never decided, and the body must still say so.
func (s *mcpPassSeam) legacyValidatorsActed() []LegacyValidatorAction {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]LegacyValidatorAction(nil), s.legacyValidators...)
}

// wireFields is the `engine`, `subject_type` and `policy_bundle` a response
// BODY carries: set once the pass decided, and empty - so omitted - for a body
// written before it ran or outside one.
func (s *mcpPassSeam) wireFields() (engine, subjectType, policyBundle string) {
	if s == nil {
		return "", "", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ran {
		return "", "", ""
	}
	return s.engine, s.subjectType, s.bundle
}

// packsRecorded is the `policy_packs` a response body carries beside
// policy_bundle: set once the pass decided under a bundle a pack composed
// into, nil - so omitted - otherwise.
func (s *mcpPassSeam) packsRecorded() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ran || len(s.packs) == 0 {
		return nil
	}
	return append([]string(nil), s.packs...)
}

// stamp adds wireFields to a JSON response body built as a map.
func (s *mcpPassSeam) stamp(body map[string]interface{}) {
	engine, subjectType, policyBundle := s.wireFields()
	for key, value := range map[string]string{"engine": engine, "subject_type": subjectType, "policy_bundle": policyBundle} {
		if value != "" {
			body[key] = value
		}
	}
	if acted := s.legacyValidatorsActed(); len(acted) > 0 {
		body["legacy_validators"] = acted
	}
	if packs := s.packsRecorded(); len(packs) > 0 {
		body["policy_packs"] = packs
	}
}

// hasActed reports whether the pass decided, or a checksum validator acted on
// its content ahead of it.
func (s *mcpPassSeam) hasActed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ran || len(s.legacyValidators) > 0
}

// postureSeam is the MCP pass whose record an audit row carries. A connector
// route runs the request pass and then the response pass: a row written after
// the response pass decided - or after a validator acted ahead of it -
// describes the response, and every other row describes the request pass
// (withMCPRequestSeam).
func postureSeam(ctx context.Context) *mcpPassSeam {
	response, request := mcpResponseSeamFrom(ctx), mcpRequestSeamFrom(ctx)
	if request == nil || response.hasActed() {
		return response
	}
	return request
}

// mergeEnforcementPosture writes the deciding MCP pass's engine, subject type,
// policy bundle and machine reason onto an audit row's policy_details
// (postureSeam). It is a no-op for a row written before a pass ran or outside
// one, and an entry the writer set wins.
func mergeEnforcementPosture(ctx context.Context, details map[string]interface{}) map[string]interface{} {
	s := postureSeam(ctx)
	if s == nil || details == nil {
		return details
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A validator that acted ahead of the pass is recorded even when the pass
	// never ran: its block is the only author of that response.
	if len(s.legacyValidators) > 0 {
		if _, set := details["legacy_validators"]; !set {
			details["legacy_validators"] = append([]LegacyValidatorAction(nil), s.legacyValidators...)
		}
	}
	if !s.ran {
		return details
	}
	for key, value := range map[string]string{
		"engine": s.engine, "subject_type": s.subjectType, "policy_bundle": s.bundle, "decision_reason": s.reason,
	} {
		if _, set := details[key]; value != "" && !set {
			details[key] = value
		}
	}
	if _, set := details["policy_packs"]; len(s.packs) > 0 && !set {
		details["policy_packs"] = append([]string(nil), s.packs...)
	}
	if detail := capabilityScopedDetail(s.capabilityScoped); detail != nil {
		if _, set := details["capability_scoped"]; !set {
			details["capability_scoped"] = detail
		}
	}
	stampAnchoredIdentity(details, s.identities, s.documentVersion, s.actionName)
	return details
}

// sessionSubject is the credential an MCP server session presents: the
// per-user token a validator accepted when the session was created, or - when
// none was - the session's client credential, admitted as the credential
// principal.
func sessionSubject(session *mcpSession) func(time.Time) (decisionSubject, bool) {
	return func(now time.Time) (decisionSubject, bool) {
		if session == nil {
			return decisionSubject{}, false
		}
		if vid := session.identityInputs.validatedToken; vid != nil {
			return decisionSubject{legacy: sharedidentity.ValidatedIdentityPrincipal(session.orgID, vid)}, true
		}
		legacy, ok := authResultPrincipal(&AuthResult{Kind: session.authKind, OrgID: session.orgID, ClientID: session.clientID}, now)
		return decisionSubject{legacy: legacy, credential: true}, ok
	}
}

// enforceMCPResponse is THE ONE PLACE the MCP response pass's verdict is
// authored: it replaces out.StaticResult with the anchored engine's.
//
// content is what the pass evaluated and would release; opts are the options
// the shared engine's evaluation ran under, which the redaction reuses so both
// scan the same policies.
func enforceMCPResponse(ctx context.Context, orgID string, out *OutputPolicyOutcome, content []map[string]interface{}, opts sharedpolicy.EvalOptions) {
	seam := mcpResponseSeamFrom(ctx)
	var observation *sharedpolicy.Observation
	evaluated := 0
	if out.StaticResult != nil {
		observation, evaluated = out.StaticResult.Observation, out.StaticResult.PoliciesEvaluated
	}
	seam.noteScoping(observation)
	// withhold fails the pass CLOSED. The response plane has no 503 channel: a
	// response the anchored engine could not decide is withheld, the shape the
	// #2820 load-failure withhold already has.
	withhold := func(cause string, err error) {
		if err != nil {
			failClosed(mcpResponseSeamScope, orgID, cause, err)
		}
		out.StaticResult = &sharedpolicy.ResponseResult{
			Blocked: true, EvaluationError: true,
			BlockReason:       "response withheld: " + enforceCauseMessages[cause],
			PoliciesEvaluated: evaluated, Observation: observation,
		}
		seam.record(decisionEngineAnchored, "", "", "")
		recordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, "unavailable", cause)
	}

	e := anchoredEnforcerInstance.Load()
	if e == nil {
		withhold(enforceCauseNotWired, errors.New("the MCP response pass has no enforcer wired in this process"))
		return
	}
	if seam == nil {
		withhold(enforceCauseSubjectUnverifiable, errors.New("the response pass was reached with no request subject installed on its context"))
		return
	}
	query, err := json.Marshal(content)
	if err != nil {
		withhold(enforceCauseRequest, fmt.Errorf("the response content does not encode: %w", err))
		return
	}

	v := e.evaluate(ctx, anchoredCall{
		scope: mcpResponseSeamScope, orgID: orgID, requestID: seam.requestID,
		action: authoringcatalog.ActionToolCall, subject: seam.subject, query: string(query),
		observation: observation, emptyContent: len(content) == 0, pep: seam.handshake.pep.Profile(),
	})
	switch {
	case v.unavailable != "":
		withhold(v.unavailable, nil) // evaluate logged the cause
		return
	case v.refusal != nil:
		reason := strings.ToLower(string(v.refusal.Reason))
		out.StaticResult = blockedResponse(reason+": "+v.refusal.Detail, "", "", evaluated, observation)
		seam.record(decisionEngineAnchored, v.act.PolicyBundle, reason, "")
		seam.noteIdentity(v.act, nil, authoringcatalog.ActionToolCall)
		seam.notePacks(v.act)
		recordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, VerdictDeny, reason)
		return
	}

	result, verdict, reason, err := anchoredResponse(ctx, v, seam.handshake, content, opts, evaluated, observation)
	if err != nil {
		withhold(enforceCauseObligation, err)
		return
	}
	out.StaticResult = result
	seam.record(decisionEngineAnchored, v.act.PolicyBundle, reason, v.subjectType)
	seam.noteIdentity(v.act, decidingPolicies(v.decision), authoringcatalog.ActionToolCall)
	seam.notePacks(v.act)
	recordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason)
}

// anchoredResponse renders an anchored decision as the response pass's
// ResponseResult, with its verdict and reason for the record. An error means a
// permit whose redaction could not be discharged.
//
// A CHALLENGE IS A REFUSAL WITH REASON approval_required, NAMING THE PLANE (PRD
// v11 §1.13): this pass holds nothing for approval, so the response is withheld
// with the reason that says an approval is what is missing.
func anchoredResponse(ctx context.Context, v anchoredVerdict, handshake pepHandshakeResolution, content []map[string]interface{}, opts sharedpolicy.EvalOptions,
	evaluated int, observation *sharedpolicy.Observation) (*sharedpolicy.ResponseResult, string, string, error) {
	dec := v.decision
	reason := string(dec.Reason)
	if dec.State != contract.StateAllow {
		// An unknown_constraint refusal names the binding constraint as blocking
		// and each constraint it could not evaluate (#4227, PRD v11 §1.14).
		unknown := unknownConstraints(dec)
		blocking, blockingName := blockingConstraint(dec.Determining, unknown), ""
		if blocking != "" {
			if p, ok := v.act.Policy(blocking); ok {
				blockingName = p.Name
			}
		}
		text := strings.Join(append([]string{reason}, unknownConstraintReasons(v.act, unknown)...), "; ")
		if dec.State == contract.StateChallenge {
			reason = string(contract.ReasonApprovalRequired)
			text = approvalRequiredReason(mcpResponseSeamScope)
		}
		// An invariant-8 refusal names the admitted enforcement point's
		// capability gap and counts it (applyAnchoredCapabilityRefusal).
		if dec.Reason == contract.ReasonUnsupportedObligation && dec.Trace != nil {
			text = strings.Join(applyAnchoredCapabilityRefusal(PlaneMCP, handshake, dec.Trace.Undischarged, []string{text}), "; ")
		}
		return blockedResponse(text, blocking, blockingName, evaluated, observation), VerdictDeny, reason, nil
	}
	ids, unsupported, err := responseRedactionPolicies(dec, v.act.Policy, observation)
	if err != nil {
		return nil, "", "", err
	}
	if unsupported != "" {
		return blockedResponse(unsupported, "", "", evaluated, observation), VerdictDeny, string(contract.ReasonUnsupportedObligation), nil
	}
	if len(ids) == 0 {
		return &sharedpolicy.ResponseResult{
			Content: content, RedactedFields: []sharedpolicy.RedactedField{}, MatchedPolicies: []sharedpolicy.PolicyMatch{},
			PoliciesEvaluated: evaluated, Observation: observation,
		}, VerdictAllow, reason, nil
	}
	engine := sharedpolicy.GetGlobalEngine()
	if engine == nil {
		return nil, "", "", errors.New("the decision requires a redaction and no policy engine is installed to apply it")
	}
	redacted, err := engine.RedactDecided(ctx, content, sharedpolicy.PhaseResponse, opts, ids)
	if err != nil {
		return nil, "", "", err
	}
	redacted.Observation = observation
	return redacted, VerdictAllow, reason, nil
}

// blockedResponse is a refused response. blockingName is the blocking policy's
// own display name, empty when it declares none: the MCP audit writer stamps a
// non-empty BlockedBy.Name onto the row's policy_names (mcpOutputDecisionVerdict),
// and an identifier is never presented as a name (PRD v11 §1.14).
func blockedResponse(reason, blockingPolicyID, blockingName string, evaluated int, observation *sharedpolicy.Observation) *sharedpolicy.ResponseResult {
	result := &sharedpolicy.ResponseResult{Blocked: true, BlockReason: reason, PoliciesEvaluated: evaluated, Observation: observation}
	if blockingPolicyID != "" {
		result.BlockedBy = &sharedpolicy.CompiledPolicy{PolicyID: blockingPolicyID, Name: blockingName}
	}
	return result
}

// dischargesAsResponseContent reports whether a field_redact target names the
// content this pass evaluated (anchoredenforcer.DischargesAsResponseContent).
func dischargesAsResponseContent(target string) bool {
	return anchoredenforcer.DischargesAsResponseContent(target)
}

// contentRedactionPolicies names the shared engine's detectors whose matches a
// permit's redactions require masking (anchoredenforcer.ContentRedactionPolicies).
func contentRedactionPolicies(dec *contract.Decision, activated func(id string) (pdp.Policy, bool), observation *sharedpolicy.Observation,
	pass string, discharges func(target string) bool) ([]string, string, error) {
	return anchoredenforcer.ContentRedactionPolicies(dec, activated, observation, pass, discharges)
}

// sendMCPResponseRefusal answers a connector route's response-pass refusal
// (sendMCPPassRefusal).
func sendMCPResponseRefusal(ctx context.Context, w http.ResponseWriter, message string) {
	sendMCPPassRefusal(w, mcpResponseSeamFrom(ctx), http.StatusForbidden, message)
}

// sendMCPPassRefusal answers an MCP connector route's refusal with
// sendErrorResponse's envelope, blocked when the route refuses (403) - a request
// that could not be decided (503) blocked nothing - plus the engine, subject
// type and policy bundle the pass recorded, when one ran, and any checksum
// validator that acted ahead of it. seam is nil for a refusal no pass authored.
func sendMCPPassRefusal(w http.ResponseWriter, seam *mcpPassSeam, status int, message string) {
	engine, subjectType, policyBundle := seam.wireFields()
	policyPacks := seam.packsRecorded()
	legacyValidators := seam.legacyValidatorsActed()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(struct {
		ClientResponse
		Engine           string                  `json:"engine,omitempty"`
		SubjectType      string                  `json:"subject_type,omitempty"`
		PolicyBundle     string                  `json:"policy_bundle,omitempty"`
		PolicyPacks      []string                `json:"policy_packs,omitempty"`
		LegacyValidators []LegacyValidatorAction `json:"legacy_validators,omitempty"`
	}{ClientResponse{Success: false, Error: message, Blocked: status == http.StatusForbidden}, engine, subjectType, policyBundle, policyPacks, legacyValidators}); err != nil {
		log.Printf("Error encoding error response: %v", err)
	}
}

// redactsContent reports whether a requirement attaches a field_redact a pass
// discharges by masking (anchoredenforcer.RedactsContent).
func redactsContent(p pdp.Policy, discharges func(target string) bool) bool {
	return anchoredenforcer.RedactsContent(p, discharges)
}

// mcpResponsePassName names this pass in a refusal of an obligation it cannot
// discharge.
const mcpResponsePassName = "the MCP response pass"

// responseRedactionPolicies is contentRedactionPolicies for this pass: the
// content is the response it releases.
func responseRedactionPolicies(dec *contract.Decision, activated func(id string) (pdp.Policy, bool), observation *sharedpolicy.Observation) ([]string, string, error) {
	return contentRedactionPolicies(dec, activated, observation, mcpResponsePassName, dischargesAsResponseContent)
}
