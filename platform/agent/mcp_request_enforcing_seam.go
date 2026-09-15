// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// THE MCP REQUEST PASS'S ENFORCING SEAM (#3564, W3-H; PRD v11 §1.1, §1.7).
//
// The anchored engine authors the verdict of the MCP plane's REQUEST pass: the
// statement a tool call is about to run. Four entry points reach it:
// POST /api/v1/mcp/check-input and the MCP server's check_policy tool, which
// answer an enforcement point that runs the tool itself, and the two connector
// routes that run the statement in this process, /mcp/resources/query and
// /mcp/tools/execute. It runs through the request path every single-phase pass
// shares, enforceRequestPass: a scope and a mapping, never a second seam.
//
// # WHAT DECIDES, AND WHAT NO LONGER DOES
//
// The shared engine's request pass (evaluateInputPolicies) is the detector
// input and nothing else: its detector facts are what the anchored engine
// decides from. Nothing else authors a verdict here any more. The orchestrator
// round trip that once evaluated an organization's own tenant rules for this
// pass, the FinCrime evaluation and the session-override flip are gone with
// the engines they belonged to (PRD v11 §1.2, §1.7); the CHANGELOG states each.
//
// # THE WIRES DIFFER, SO THE PROJECTION IS PER WIRE
//
//   - check-input and check_policy hand their caller the statement to forward.
//     A permit whose decision composed a redaction of the statement is
//     discharged here: the statement comes back masked by exactly what the
//     detectors behind the decision's determining redaction requirements
//     matched, through the platform's own redactor (maskMCPStatement).
//   - The connector routes run the statement themselves, and masking a
//     statement before running it changes what it does. So they can discharge
//     no obligation, and a permit that carries one refuses the request (ADR-065
//     invariant 8): staticPolicyResult with mcpConnectorRouteWire.
//
// # IT FAILS CLOSED
//
// A request the engine could not decide is refused 503 on the REST routes and
// answered with an error naming the cause on check_policy; nothing decides it
// instead (PRD v11 §1.7).
//
// # A CHALLENGE
//
// This plane holds nothing for approval, so the engine's challenge answers a
// deny with reason approval_required naming the plane (PRD v11 §1.13,
// mapAnchoredDecision).
//
// # THE CHECKSUM VALIDATOR RUNS BEFORE THE PASS, NAMED (#4122)
//
// On check-input and check_policy the Indonesia checksum validator masks the
// identifiers it finds under the organization's pii=redact posture BEFORE the
// engine decides, and is named in legacy_validators on the body and the audit
// row - the response pass's shape. #4122 makes the validators detector facts
// the engine decides from, and removes it.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	sharedpolicy "axonflow/platform/shared/policy"
)

// mcpRequestSeamScope is the scope this seam cuts over: the MCP plane's request
// phase, and only it.
var mcpRequestSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseRequest)

// mcpConnectorRouteWire names the connector routes in a refusal their wire
// cannot express (requestPassWires).
const mcpConnectorRouteWire = "an MCP connector route, which runs the statement itself"

// mcpRequestPassName names this pass in a refusal of an obligation it cannot
// discharge.
const mcpRequestPassName = "the MCP request pass"

type mcpRequestSeamKey struct{}

// withMCPRequestSeam installs the request pass's record on a context, beside the
// response pass's: a connector route runs both passes, and each audit row
// carries the record of the pass that decided it (mergeEnforcementPosture).
func withMCPRequestSeam(ctx context.Context) context.Context {
	return context.WithValue(ctx, mcpRequestSeamKey{}, &mcpPassSeam{})
}

func mcpRequestSeamFrom(ctx context.Context) *mcpPassSeam {
	s, _ := ctx.Value(mcpRequestSeamKey{}).(*mcpPassSeam)
	return s
}

// enforceMCPRequest authors the request pass's verdict for one statement and
// records it on the request's seam, for the body and every audit row the entry
// point writes after it. The final verdict is counted by the entry point, once
// its wire has projected the decision (recordAnchoredEnforcement).
func enforceMCPRequest(ctx context.Context, in requestPassInput, handshake pepHandshakeResolution) requestPassEnforcement {
	in.stage = DecisionStageTool
	in.pep = handshake.pep.Profile()
	enforced := enforceRequestPass(ctx, mcpRequestSeamScope, in)
	// An invariant-8 refusal names the admitted enforcement point's capability
	// gap and counts it (applyAnchoredCapabilityRefusal).
	enforced.reasons = applyAnchoredCapabilityRefusal(PlaneMCP, handshake, enforced.undischarged, enforced.reasons)
	if enforced.unavailable != "" {
		mcpRequestSeamFrom(ctx).record(enforced.engine, "", "", "")
		return enforced
	}
	mcpRequestSeamFrom(ctx).recordRequestPass(enforced, enforced.reasonCode)
	return enforced
}

// dischargesAsRequestContent reports whether a field_redact target names the
// statement this pass evaluated: the evaluated-content target the corpus
// compiles for every scope.
func dischargesAsRequestContent(target string) bool {
	return target == legacycompile.DefaultContentTarget
}

// errNoRedactionEngine is maskMCPStatement's error when no shared engine is
// installed to apply a redaction the decision requires: the enforcer is not
// wired, an outage, never the caller's refusal (#4264).
var errNoRedactionEngine = errors.New("the decision requires a redaction of the statement and no policy engine is installed to apply it")

// maskMCPStatement discharges a permit's redaction of the statement on a wire
// that hands it back. The statement comes back masked by exactly what the
// detectors behind the decision's determining redaction requirements matched,
// never by what a legacy action would have redacted.
//
// refusal is set when the decision attaches a mandatory obligation this wire
// cannot discharge, and the caller refuses it unsupported_obligation (ADR-065
// invariant 8):
//   - an obligation this pass discharges in no way (contentRedactionPolicies);
//   - a redaction that masks nothing in the statement. The request pass also
//     scans the request's parameters, so a match there composes the redaction
//     while the statement carries none of it, and this wire hands back only the
//     statement;
//   - a redaction that would also mask a parameter, which this wire cannot hand
//     back masked (parametersTheRedactionMasks).
//
// The first of the last two answered 503, an outage, and a client that fails
// open on a 5xx ran the tool on the unmasked request; the second answered a
// permit with the statement masked and the parameters handed back as they were
// (#4264). A detector row whose pattern changed between the detection and the
// redaction also masks nothing: the pass cannot tell it apart, and refusing
// forwards nothing. A row REMOVED in between is an error instead (the redactor
// no longer loads it), an outage.
//
// An error is a redaction the pass could not attempt - no engine installed to
// apply it (errNoRedactionEngine), rows it could not load, a requirement or
// detector the engine no longer holds, a redactor that returned no text - and
// the caller fails it closed as an outage.
func maskMCPStatement(ctx context.Context, enforced requestPassEnforcement, statement string, opts sharedpolicy.EvalOptions, observation *sharedpolicy.Observation) (masked string, redacted bool, refusal string, err error) {
	if enforced.decision == nil || enforced.act == nil || enforced.verdict != VerdictAllow {
		return statement, false, "", nil
	}
	ids, unsupported, err := contentRedactionPolicies(enforced.decision, enforced.act.Policy, observation, mcpRequestPassName, dischargesAsRequestContent)
	if err != nil || unsupported != "" {
		return statement, false, unsupported, err
	}
	if len(ids) == 0 {
		return statement, false, "", nil
	}
	engine := sharedpolicy.GetGlobalEngine()
	if engine == nil {
		return statement, false, "", errNoRedactionEngine
	}
	redact := func(row map[string]interface{}) (map[string]interface{}, bool, error) {
		result, err := engine.RedactDecided(ctx, []map[string]interface{}{row}, sharedpolicy.PhaseRequest, opts, ids)
		if err != nil {
			return nil, false, err
		}
		rows, _ := result.Content.([]map[string]interface{})
		if len(rows) != 1 {
			return nil, false, errors.New("the redactor returned no row")
		}
		return rows[0], result.Redacted, nil
	}
	maskedRow, didMask, err := redact(map[string]interface{}{"statement": statement})
	if err != nil {
		return statement, false, "", err
	}
	out, ok := maskedRow["statement"].(string)
	if !ok {
		return statement, false, "", errors.New("the redactor returned no statement")
	}
	redactText := func(text string) (string, bool, error) {
		result, err := engine.RedactDecided(ctx, text, sharedpolicy.PhaseRequest, opts, ids)
		if err != nil {
			return "", false, err
		}
		out, ok := result.Content.(string)
		if !ok {
			return "", false, errors.New("the redactor returned no text")
		}
		return out, result.Redacted, nil
	}
	params, paramsErr := parametersTheRedactionMasks(opts.Parameters, redactText)
	refusal, err = redactionOutcome(enforced.decision, didMask, params, paramsErr)
	if refusal != "" || err != nil {
		return statement, false, refusal, err
	}
	return out, true, "", nil
}

// redactionOutcome decides what a permit's redaction of the request means for
// this wire, from what the redactor did to the statement and what it would do
// to the parameters. It is a pure function so the ORDER can be tested.
//
// THE ORDER IS THE POINT (#4264, R3 round 3). A statement the redaction masked
// nothing in is a refusal that is already CERTAIN: this wire hands back only
// the statement, so there is nothing to hand over whatever the parameters hold.
// The parameter probe must therefore never turn that refusal into an outage.
// It can fail on its own - RedactDecided loads the policies per call, so a row
// removed between the statement's redaction and the probe's errors - and
// returning that error first would answer 503, the class a client that fails
// open on a 5xx runs the tool on, which is the defect this change removes. The
// probe's error is reported only where it decides something: after a statement
// the redactor DID mask, where the answer would otherwise be a permit.
func redactionOutcome(dec *contract.Decision, didMask bool, params []string, paramsErr error) (string, error) {
	if !didMask {
		why := "it masks nothing in the statement, the only content this wire hands back"
		if paramsErr == nil && len(params) > 0 {
			why += fmt.Sprintf("; it masks the request's parameters (%s), which this wire cannot hand back masked", strings.Join(params, ", "))
		}
		return undischargeableRedaction(dec, why), nil
	}
	if paramsErr != nil {
		return "", paramsErr
	}
	if len(params) > 0 {
		return undischargeableRedaction(dec, fmt.Sprintf("it also masks the request's parameters (%s), which this wire cannot hand back masked", strings.Join(params, ", "))), nil
	}
	return "", nil
}

// parametersTheRedactionMasks names the request parameters a permit's
// redaction would mask. Each parameter is redacted ON ITS OWN, as the text the
// request pass scanned it as (sharedpolicy.ParameterScanText, the one
// definition the scan uses), by the same policies as the statement: the scan
// evaluates each parameter's text alone, so a pattern anchored to the start or
// end of that text matches here as it matched there. A parameter the scan
// skips is skipped here, and nothing else is.
func parametersTheRedactionMasks(parameters map[string]interface{}, redactText func(string) (string, bool, error)) ([]string, error) {
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var masked []string
	for _, key := range keys {
		text, scanned := sharedpolicy.ParameterScanText(parameters[key])
		if !scanned {
			continue
		}
		out, didMask, err := redactText(text)
		if err != nil {
			return nil, err
		}
		// Anything but the text handed back unchanged counts as masked: the
		// direction that refuses.
		if didMask || out != text {
			masked = append(masked, key)
		}
	}
	return masked, nil
}

// undischargeableRedaction is the refusal of a permit whose redaction of the
// request this wire cannot discharge, naming each obligation as this pass names
// one it refuses (contentRedactionPolicies): its type, its target and the
// policy that attached it.
func undischargeableRedaction(dec *contract.Decision, why string) string {
	var named []string
	for _, o := range dec.Obligations {
		if o.Mandatory && o.Type == contract.ObFieldRedact && dischargesAsRequestContent(o.Target) {
			named = append(named, fmt.Sprintf("the mandatory %s obligation on %q attached by %s", o.Type, o.Target, o.SourcePolicy))
		}
	}
	sort.Strings(named)
	// Never empty: a redaction to discharge requires such an obligation, and
	// contentRedactionPolicies applies the same filter.
	subject := strings.Join(slices.Compact(named), "; ")
	return fmt.Sprintf("%s: %s cannot be discharged on %s: %s", contract.ReasonUnsupportedObligation, subject, mcpRequestPassName, why)
}

// anchoredPolicyMatches names the controls that determined an anchored verdict,
// by corpus id and the name each carries (#4127), for the richer block
// check-input and check_policy answer with. A session override applies to none
// of them - an anchored refusal carries no legacy row - so none is offered.
func anchoredPolicyMatches(enforced requestPassEnforcement) []RicherPolicyMatch {
	names := policyIdentityNames(enforced.policyIdentities)
	out := make([]RicherPolicyMatch, 0, len(enforced.evaluatedPolicies))
	for _, id := range enforced.evaluatedPolicies {
		out = append(out, RicherPolicyMatch{PolicyID: id, PolicyName: names[id]})
	}
	return out
}

// maskIndonesiaBeforeTheRequestPass runs the Indonesia checksum validator over a
// statement check-input or check_policy will hand back, before the anchored
// engine decides it: the response pass's shape, until #4122 routes the
// validators through the engine. Under the organization's pii=redact posture
// the identifiers it finds are masked, the engine decides the masked statement,
// and the validator is named in legacy_validators. Under any other posture it
// detects and modifies nothing. Either way the detection event records what it
// did.
func maskIndonesiaBeforeTheRequestPass(ctx context.Context, orgID, tenantID, decisionID, statement string, cfg ModeDetectionConfig) string {
	if !cfg.Enabled || statement == "" {
		return statement
	}
	result := checkIndonesiaPII(statement, false)
	if result == nil || !result.HasPII {
		return statement
	}
	masked, changed := statement, false
	if cfg.PIIAction == DetectionActionRedact {
		masked, changed = maskJSONSafe(statement, redactIndonesiaPIIInString)
	}
	if changed {
		mcpRequestSeamFrom(ctx).noteLegacyValidator(legacyValidatorIndonesia, legacyActionMasked)
	}
	// "redacted" is recorded only when nothing the detector finds survives the
	// mask, the response pass's rule (indonesiaPIIRemainsAfterMask).
	clean := changed && !indonesiaPIIRemainsAfterMask(nil, masked)
	recordIndonesiaPIIEvents(ctx, orgID, tenantID, decisionID, "", PlaneMCP, indonesiaPIIActionForEnforcedPlane(false, clean), result)
	return masked
}

// refuseMCPConnectorRequest answers a connector route's request-pass refusal,
// or reports a permit, and counts the final verdict. A connector route runs the
// statement itself, so it discharges no obligation: a permit carrying one is
// refused unsupported_obligation (staticPolicyResult). A refusal writes the
// route's satellite entry and its canonical audit row (emit) and is encoded
// with the pass's engine, subject type and policy bundle. A request the engine
// could not decide is 503 and decides nothing (PRD v11 §1.7).
func refuseMCPConnectorRequest(ctx context.Context, w http.ResponseWriter, enforced requestPassEnforcement,
	auditEntry *MCPQueryAuditEntry, startTime time.Time,
	emit func(verdict string, policyIDs, reasons, redactedFields []string, policyNames map[string]string)) bool {
	seam := mcpRequestSeamFrom(ctx)
	if enforced.unavailable != "" {
		recordAnchoredEnforcement(mcpRequestSeamScope, enforced.engine, "unavailable", enforced.unavailable)
		emit(mcpVerdictError, []string{"decision_enforcement_unavailable"}, []string{enforced.unavailable}, nil, nil)
		sendMCPPassRefusal(w, seam, http.StatusServiceUnavailable, enforceCauseMessages[enforced.unavailable])
		return true
	}
	result, reason := enforced.staticPolicyResult(mcpRequestSeamScope)
	if !result.Blocked {
		recordAnchoredEnforcement(mcpRequestSeamScope, enforced.engine, VerdictAllow, reason)
		return false
	}
	// The projection may refuse a permit, so the record says why the request
	// was refused, not what the engine's reason for the permit was.
	seam.recordRequestPass(enforced, reason)
	recordAnchoredEnforcement(mcpRequestSeamScope, enforced.engine, VerdictDeny, reason)
	auditEntry.RequestBlocked = true
	auditEntry.RequestBlockReason = result.Reason
	auditEntry.DurationMs = time.Since(startTime).Milliseconds()
	logMCPQueryAudit(*auditEntry)
	emit(mcpVerdictBlocked, result.TriggeredPolicies, []string{result.Reason}, nil, policyIdentityNames(enforced.policyIdentities))
	sendMCPPassRefusal(w, seam, http.StatusForbidden, "Request blocked: "+result.Reason)
	return true
}

// anchoredRequestResult renders the request pass's anchored permit as the
// RequestResult a connector route's policy_info merges with the response pass's
// (sharedpolicy.BuildPolicyInfo): the controls that determined it, by corpus id
// and name, over the count the detector pass evaluated. Never the shared
// engine's own verdict, which decides nothing on this pass.
func anchoredRequestResult(enforced requestPassEnforcement, detected *sharedpolicy.RequestResult) *sharedpolicy.RequestResult {
	out := &sharedpolicy.RequestResult{MatchedPolicies: []sharedpolicy.PolicyMatch{}}
	if detected != nil {
		out.PoliciesEvaluated, out.ProcessingTimeMs = detected.PoliciesEvaluated, detected.ProcessingTimeMs
	}
	names := policyIdentityNames(enforced.policyIdentities)
	for _, id := range enforced.evaluatedPolicies {
		out.MatchedPolicies = append(out.MatchedPolicies, sharedpolicy.PolicyMatch{PolicyID: id, PolicyName: names[id]})
	}
	return out
}

// mcpStatementVerdict is the request pass projected onto a wire that hands its
// caller the statement to forward (check-input, check_policy).
type mcpStatementVerdict struct {
	// unavailable is the cause, when nothing could be decided.
	unavailable string
	allowed     bool
	reasonCode  string
	blockReason string
	// statement is what the caller forwards: masked when redacted.
	statement string
	redacted  bool
}

// projectMCPStatement projects the request pass onto check-input and
// check_policy: the verdict, and the statement the caller forwards - masked by
// the checksum validator ahead of the pass and by the decision's own redaction
// (maskMCPStatement). original is the statement the caller sent, evaluated the
// one the engine decided. A redaction this wire cannot discharge - one it cannot
// hand over, or one of content outside the statement it hands back - refuses
// (unsupported_obligation, #4264); one the pass could not attempt fails closed
// as an outage (enforcer_not_wired, evaluation_failed). Every refusal the
// projection adds is recorded on the pass's seam, so the body and the audit row
// name it.
func projectMCPStatement(ctx context.Context, orgID string, enforced requestPassEnforcement, handshake pepHandshakeResolution,
	original, evaluated string, opts sharedpolicy.EvalOptions, observation *sharedpolicy.Observation) mcpStatementVerdict {
	seam := mcpRequestSeamFrom(ctx)
	refuse := func(reason string) mcpStatementVerdict {
		code := string(contract.ReasonUnsupportedObligation)
		seam.recordRequestPass(enforced, code)
		return mcpStatementVerdict{reasonCode: code, blockReason: reason}
	}
	switch {
	case enforced.unavailable != "":
		return mcpStatementVerdict{unavailable: enforced.unavailable}
	case enforced.verdict != VerdictAllow:
		return mcpStatementVerdict{reasonCode: enforced.reasonCode, blockReason: strings.Join(enforced.reasons, "; ")}
	}
	// A statement the validator masked is handed to the enforcement point to
	// substitute, so one that declared it cannot discharge a field_redact is
	// refused, as #3766 refused it before (applyMCPRedactionRefusal).
	if evaluated != original {
		if reason, denied := applyMCPRedactionRefusal(handshake, true); denied {
			return refuse(fmt.Sprintf("%s: the %s checksum validator masked the statement, and this enforcement point cannot substitute it; %s",
				contract.ReasonUnsupportedObligation, legacyValidatorIndonesia, reason))
		}
	}
	masked, _, refusal, err := maskMCPStatement(ctx, enforced, evaluated, opts, observation)
	switch {
	case err != nil:
		// A redaction the pass could not attempt is an outage, never the
		// caller's refusal (#4264): no engine to apply it is the enforcer not
		// wired, anything else the engine failing to evaluate the request.
		cause := enforceCauseEvaluation
		if errors.Is(err, errNoRedactionEngine) {
			cause = enforceCauseNotWired
		}
		failClosed(mcpRequestSeamScope, orgID, cause, err)
		seam.record(enforced.engine, "", "", "")
		return mcpStatementVerdict{unavailable: cause}
	case refusal != "":
		return refuse(refusal)
	}
	return mcpStatementVerdict{allowed: true, reasonCode: enforced.reasonCode, statement: masked, redacted: masked != original}
}
