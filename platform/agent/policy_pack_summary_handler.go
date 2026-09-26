// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/activationinputs"
	logutil "axonflow/platform/shared/logger"
)

// THE POLICY SUMMARY'S INSTALLED-PACK COUNT (#4249).
//
// GET /api/v1/policy-packs/summary answers activationinputs.Summary for the
// decide scope, counted from the activation this agent enforces on the
// organization: its active document, its recorded overrides and the policy
// packs this process installed (anchoredenforcer.Enforcer.ActiveActivation).
// Only the agent loads packs, so the orchestrator's and the customer portal's
// /api/v1/typed-policies/active/summary read this to count them
// (activationinputs.WithAgentPacks) and never load a pack themselves.
//
// packs_counted is always true here: this is the process that knows which packs
// are installed, so a deployment that installed none (every Community one)
// answers a counted zero, not an unknown.
//
// INTERNAL BY ITS CREDENTIAL, NOT ITS PATH. Only the internal-service credential
// (serviceauth.ServiceIDHeader and ServiceTokenHeader) is answered; any other
// caller, a tenant's included, gets 401. The organization is the one the
// internal caller resolved and names in X-Org-ID. The route is not under
// /api/v1/typed-policies, which the agent forwards whole to the orchestrator
// (proxy.go): there it would shadow the tenant route or loop the orchestrator's
// read back to itself (activationinputs.AgentSummaryPath).
func policyPackSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if AuthKindFromContext(r.Context()) != AuthKindInternalService {
		writeJSONError(w, "this route answers the internal-service credential only", http.StatusUnauthorized)
		return
	}
	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		writeJSONError(w, "X-Org-ID names the organization whose summary is read, and it is missing", http.StatusBadRequest)
		return
	}
	e := anchoredEnforcerInstance.Load()
	if e == nil {
		writePolicyPackSummaryUnavailable(w, orgID, "decision_enforcement_unavailable", nil)
		return
	}
	act, cause, err := e.ActiveActivation(r.Context(), decideSeamScope, orgID)
	if err != nil {
		writePolicyPackSummaryUnavailable(w, orgID, cause, err)
		return
	}
	summary, err := activationinputs.SummaryOf(act, decideSeamScope, true)
	if err != nil {
		writePolicyPackSummaryUnavailable(w, orgID, "summary_unavailable", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Success bool `json:"success"`
		activationinputs.Summary
	}{Success: true, Summary: summary})
}

// writePolicyPackSummaryUnavailable answers 503 naming the cause; the error
// itself goes to the log only, since it can name a database.
func writePolicyPackSummaryUnavailable(w http.ResponseWriter, orgID, cause string, err error) {
	if err != nil {
		log.Printf("[PolicyPackSummary] org %s: the summary could not be counted (%s): %v", logutil.Sanitize(orgID), cause, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false, "reason": cause,
		"error": "what this agent enforces on the organization could not be counted just now; retry in a few seconds",
	})
}

// policyPackSummaryPath is the route's path, spelled here as a literal so the
// route census can read it (openapi_route_parity_enterprise_test.go resolves a
// path only from a literal or a constant of the registering package). It is
// activationinputs.AgentSummaryPath, the path the readers call, and a test holds
// the two equal.
const policyPackSummaryPath = "/api/v1/policy-packs/summary"

// RegisterPolicyPackSummaryHandler registers the summary route behind the
// agent's auth middleware, which admits the internal-service credential; the
// handler answers nothing else.
func RegisterPolicyPackSummaryHandler(r *mux.Router) {
	r.Handle(policyPackSummaryPath, apiAuthMiddleware(http.HandlerFunc(policyPackSummaryHandler))).Methods(http.MethodGet)
}
