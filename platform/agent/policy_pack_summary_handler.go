// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"axonflow/platform/decision/activation"
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
// internal caller resolved and apiAuthMiddleware stamped into request context.
// Mutable routing headers are never authority. The route is not under
// /api/v1/typed-policies, which the agent forwards whole to the orchestrator
// (proxy.go): there it would shadow the tenant route or loop the orchestrator's
// read back to itself (activationinputs.AgentSummaryPath).
func policyPackSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if AuthKindFromContext(r.Context()) != AuthKindInternalService {
		writeJSONError(w, "this route answers the internal-service credential only", http.StatusUnauthorized)
		return
	}
	orgID := OrgIDFromContext(r.Context())
	if orgID == "" {
		writeJSONError(w, "authenticated organization is missing", http.StatusBadRequest)
		return
	}
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		writeJSONError(w, "authenticated tenant is missing", http.StatusBadRequest)
		return
	}
	e := anchoredEnforcerInstance.Load()
	if e == nil {
		writePolicyPackSummaryUnavailable(w, orgID, "decision_enforcement_unavailable", nil)
		return
	}
	var identity paymentExceptionModuleIdentity
	moduleScoped := false
	var actErr error
	var cause string
	var act *activation.Activation
	auth, authenticated := authResultFromContext(r.Context())
	if authenticated && auth.Client != nil && auth.Client.Name == "Hosted Outcome Service" {
		moduleID := r.URL.Query().Get("module")
		var packs []activation.InstalledPack
		var resolvedIdentity paymentExceptionModuleIdentity
		var resolveErr error
		switch moduleID {
		case paymentExceptionModuleID:
			packs, resolvedIdentity, resolveErr = activePaymentExceptionPolicy(
				r.Context(), usageDB, orgID, tenantID)
		case supportRefundModuleID:
			var refundIdentity supportRefundModuleIdentity
			packs, refundIdentity, resolveErr = activeSupportRefundPolicy(
				r.Context(), usageDB, orgID, tenantID)
			resolvedIdentity = paymentExceptionModuleIdentity(refundIdentity)
		default:
			writeJSONError(w, "an exact outcome module is required", http.StatusBadRequest)
			return
		}
		if resolveErr != nil {
			writePolicyPackSummaryUnavailable(w, orgID, "module_policy_unavailable", resolveErr)
			return
		}
		identity, moduleScoped = resolvedIdentity, true
		act, cause, actErr = e.ActiveActivationForPacks(
			r.Context(), decideSeamScope, orgID, tenantID, packs)
	} else {
		act, cause, actErr = e.ActiveActivation(r.Context(), decideSeamScope, orgID)
	}
	if actErr != nil {
		writePolicyPackSummaryUnavailable(w, orgID, cause, actErr)
		return
	}
	summary, err := activationinputs.SummaryOf(act, decideSeamScope, true)
	if err != nil {
		writePolicyPackSummaryUnavailable(w, orgID, "summary_unavailable", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Success        bool   `json:"success"`
		OrganizationID string `json:"organization_id"`
		TenantID       string `json:"tenant_id"`
		PolicyBundle   string `json:"policy_bundle"`
		ModuleScoped   bool   `json:"module_scoped"`
		ModuleID       string `json:"module_id,omitempty"`
		GrantID        string `json:"grant_id,omitempty"`
		PolicyID       string `json:"policy_id,omitempty"`
		PolicyVersion  string `json:"policy_version,omitempty"`
		PolicySchema   string `json:"policy_schema_sha256,omitempty"`
		PolicyArtifact string `json:"policy_artifact_sha256,omitempty"`
		activationinputs.Summary
	}{Success: true, OrganizationID: orgID, TenantID: tenantID,
		PolicyBundle: act.PolicyBundle, ModuleScoped: moduleScoped,
		ModuleID: identity.moduleID, GrantID: identity.grantID,
		PolicyID: identity.policyID, PolicyVersion: identity.policyVersion,
		PolicySchema:   identity.policySchemaSHA256,
		PolicyArtifact: identity.policyArtifactSHA256, Summary: summary})
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
