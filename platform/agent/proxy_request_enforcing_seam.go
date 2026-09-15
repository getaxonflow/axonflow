// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// THE /api/request PROXY'S ENFORCING SEAM (#3564, wave two; one pass since #4253).
//
// The fourth scope the anchored engine authors a verdict on: the policy verdict
// of clientRequestHandler, whose shared-engine evaluation is the detector input
// (legacycompile.PlaneProxyRequest). It has decide's shape - one request phase
// read from the runtime phase columns, the organization's overrides passed, a
// per-user token in the body - so it runs through decide's request path,
// enforceRequestPass, and projects the answer onto the StaticPolicyResult the
// rest of the handler reads (requestPassEnforcement.staticPolicyResult).
//
// # ONE PASS, ONE VERDICT
//
// /api/request is decided by this pass alone (#4253, PRD v11 §1 item 1). A
// second pass used to run after an anchored approval: it read the stored action
// column and the organization's legacy per-policy overrides, and it refused or
// held under engine=legacy. It is retired with the proxy_tier plane. What it
// refused on a shipped row - a system row whose stored action is block - this
// scope enforces as block (legacycompile's proxy_request PlaneSpec), so the
// anchored engine refuses it and names the policy. An organization's legacy
// per-policy override decides nothing here any more; its successor is the
// organization's typed document.
//
// # WHY PHASE 1 CAN BE CUT OVER
//
// Four facts, each derived rather than assumed:
//
//   - THE RESTRICTION. activation.RestrictToScope(proxy_request) keeps the
//     shipped controls whose rows load in the request phase and whose categories
//     Phase 1 admits. On the shipped corpus none of them carries a mandatory
//     obligation, and TestEveryEnforcingSeamActivatesOnBothEditions activates the
//     scope in both editions.
//   - THE DISCHARGE. /api/request tells its caller no obligation: it forwards
//     the request or refuses it. So the seam delivers nothing, and an obligation
//     the decision attaches refuses the request.
//   - THE SUBJECT. The handler resolves the body's user_token before any policy
//     runs and refuses one that does not verify, as the pre-check does. A
//     request with no per-user identity is evaluated for its client credential
//     (the credential principal, PRD v11 §1.6).
//   - THE ACTION. Every /api/request is recorded under the llm stage - its audit
//     rows name that stage whatever the request_type - so
//     it is evaluated as that stage's registered action.
//
// # WHAT DIFFERS FROM THE LEGACY ENGINE, STATED
//
//   - An approval hold: an anchored CHALLENGE is a refusal (mapAnchoredDecision),
//     so the agent's pass on /api/request never holds a request, raises no queue
//     entry and spends no approval grant. The typed approval challenge holds in the orchestrator
//     (#4254).
//   - Detection narrowed for the process refuses to boot (#4032), as on
//     decide.
//   - Phase 1 does not evaluate the admin-access category for an administrator.
//     No control this restriction keeps reads an admin-access detector, which
//     TestTheProxyRestrictionKeepsNoControlTheAdministratorSkipHides holds, so the
//     skip leaves no control UNKNOWN.
//   - A REDACTION IS A REFUSAL HERE, WHERE LEGACY FORWARDS. This wire tells its
//     caller no obligation, so staticPolicyResult refuses a decision carrying a
//     field_redact with contract.ReasonUnsupportedObligation. The legacy engine
//     on this plane never reads RequiresRedaction at all - there is no such read
//     in clientRequestHandler - so the same control forwards the request
//     UNREDACTED. This is fail-closed where legacy failed open, but it is a real
//     divergence and its population is MEASURED rather than assumed: of the 66 controls this
//     restriction keeps, ZERO carry a field_redact obligation, mandatory or
//     optional, after #4087 bound each scope the action its legacy engine
//     enforces. TestTheProxyRestrictionBindsNoRedaction holds that count and is
//     proven to red against a planted obligation, so the day a redact-bound
//     control lands on this plane the guard says so rather than the divergence
//     shipping silently. By contrast mcp:response keeps 19 such obligations, so
//     the counting is demonstrably able to find them.
//
// The circuit breaker and the budget check are not policy-engine verdicts,
// and they run exactly as before; segment resolution went with the gate (#4253).

import (
	"encoding/json"
	"log"
	"net/http"

	"axonflow/platform/decision/legacycompile"
)

// proxyRequestSeamScope is the scope this seam cuts over: Phase 1 of the proxy,
// a whole plane that evaluates one phase.
var proxyRequestSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneProxyRequest, "")

// proxyRequestWire names this pass in a refusal its wire cannot express.
const proxyRequestWire = "/api/request"

// proxyResponse is /api/request's response with the engine that authored its
// verdict, the type of the principal it was evaluated for and the digest of
// the policy set that decided it (PRD v11 §1.4, §1.6). It embeds
// ClientResponse rather than adding the members to it, because ClientResponse
// is every agent route's envelope and only this route's seam decides them.
type proxyResponse struct {
	ClientResponse
	Engine       string `json:"engine,omitempty"`
	SubjectType  string `json:"subject_type,omitempty"`
	PolicyBundle string `json:"policy_bundle,omitempty"`
	// ResponsePlane is the SEPARATE decision the orchestrator response
	// plane made on the LLM response this route forwarded back. Absent on
	// every answer no response-plane decision covers, including every
	// refusal of the request itself.
	ResponsePlane *responsePlaneDecision `json:"response_plane,omitempty"`
}

// responsePlaneDecision is the orchestrator response plane's decision on one
// forwarded LLM response (PRD v11 §1.1): the engine that authored it (always
// anchored), the type of principal it was decided for, the digest of the policy
// set that decided it, and the verdict. It is NOT this route's request pass -
// the members above are - and the agent decides none of it: the response is
// decided on the orchestrator, for the client credential this hop carried, after
// the request was already allowed through.
type responsePlaneDecision struct {
	Engine       string `json:"engine"`
	SubjectType  string `json:"subject_type,omitempty"`
	PolicyBundle string `json:"policy_bundle,omitempty"`
	Verdict      string `json:"verdict,omitempty"`
}

// responsePlaneVerdictBlocked names a response the plane WITHHELD. The
// orchestrator spells the three verdicts allowed, redacted and blocked
// (orchestrator responseVerdict*); this route acts on the third alone.
const responsePlaneVerdictBlocked = "blocked"

// responsePlaneOf reads that decision from the orchestrator's own answer.
//
// THE ENGINE IS WHAT MAKES IT A DECISION. An answer carrying no engine is not
// one the response plane decided - an orchestrator error, a route the plane does
// not cover, an orchestrator older than the plane - and is reported as NO
// decision rather than as an empty one, so a caller can never read an absent
// decision as an allowed one. A member the orchestrator did not send stays empty
// and is omitted from the wire; nothing here substitutes a default.
func responsePlaneOf(orch map[string]interface{}) *responsePlaneDecision {
	if orch == nil {
		return nil
	}
	engine, _ := orch["engine"].(string)
	if engine == "" {
		return nil
	}
	subjectType, _ := orch["subject_type"].(string)
	policyBundle, _ := orch["policy_bundle"].(string)
	verdict, _ := orch["verdict"].(string)
	return &responsePlaneDecision{Engine: engine, SubjectType: subjectType, PolicyBundle: policyBundle, Verdict: verdict}
}

// proxyResponseFor is the body one /api/request response encodes.
func proxyResponseFor(response ClientResponse, enforced requestPassEnforcement) proxyResponse {
	return proxyResponse{ClientResponse: response, Engine: enforced.engine, SubjectType: enforced.subjectType, PolicyBundle: enforced.policyBundle}
}

// writeProxyResponse encodes one /api/request response with what the seam
// decided.
func writeProxyResponse(w http.ResponseWriter, status int, response ClientResponse, enforced requestPassEnforcement) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(proxyResponseFor(response, enforced)); err != nil {
		log.Printf("Error encoding /api/request response: %v", err)
	}
}
