// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"

	"axonflow/platform/shared/legacyfreeze"
)

// The core/172 legacy policy freeze is classified and answered by package
// legacyfreeze, which the agent imports too (#4084). What stays here is one
// method per handler type, binding that type's own error envelope.

// writeLegacyFreezeError answers the freeze and reports whether it did.
//
// Every legacy policy WRITE route calls it - create, update, delete and bulk
// import. That is four routes and not the two the issue named: core/172 revokes
// INSERT, UPDATE, DELETE and TRUNCATE, and PolicyRepository writes
// dynamic_policies from Create, Update, Delete, createPolicyTx and
// updatePolicyTx, so update and delete return the same bare 500 that create
// does.
//
// It runs AFTER the tier check and BEFORE the generic 500, so a tier refusal
// keeps its own rendering and an unclassified error keeps today's.
func (h *PolicyAPIHandler) writeLegacyFreezeError(w http.ResponseWriter, err error, op, tenantID string) bool {
	return legacyfreeze.Answer(w, err, "PolicyAPI", op, tenantID, h.writeError)
}

// writeLegacyFreezeError is the same answer for the deprecated
// /api/v1/dynamic-policies family and its /api/v1/tenant-policies successor
// (#4036).
//
// WHY A SECOND METHOD RATHER THAN ONE SHARED RECEIVER. DynamicPolicyAPIHandler
// and PolicyAPIHandler are distinct types over the same PolicyServicer, and
// their writeError implementations DIFFER: PolicyAPIHandler renders the typed
// PolicyAPIError, this one renders an untyped map. Unifying them would change
// the response shape of every route in dynamic_policy_handlers.go, which is a
// wider change than this issue and would be invisible in a diff that looks like
// a refactor. So the classification and the log line are shared; the envelope
// stays each handler's own.
func (h *DynamicPolicyAPIHandler) writeLegacyFreezeError(w http.ResponseWriter, err error, op, tenantID string) bool {
	return legacyfreeze.Answer(w, err, "DynamicPolicyAPI", op, tenantID, h.writeError)
}

// writeLegacyFreezeError is the same answer for POST
// /api/v1/templates/{id}/apply (#4088).
//
// Applying a template CREATES a policy through PolicyRepository.Create, the
// same write the policy routes make, so core/172 refuses it identically. It is
// the third handler type over that write and was the one surface left
// answering 500 after #4036; the portal proxies it
// (orchestrator_proxy_allowlist.go), so the refusal reaches a customer.
func (h *TemplateAPIHandler) writeLegacyFreezeError(w http.ResponseWriter, err error, op, tenantID string) bool {
	return legacyfreeze.Answer(w, err, "TemplateAPI", op, tenantID, h.writeError)
}

// refuseLegacyWriteWhenRevoked answers a legacy policy write with the freeze
// BEFORE the request body is read, when the connection the write would go
// through may not write dynamic_policies, and reports whether it did (#4237).
// The create, update and bulk-import routes of both handler types call it.
//
// WHY BEFORE THE READ. writeLegacyFreezeError classifies the database's
// refusal of the write, so a body that failed validation never reached the
// write and was answered 400, or a bare 500 on the import, instead of the
// freeze, on a deployment where no legacy write can succeed whatever the body
// says. So the database is asked first (legacyfreeze.MayWrite), after
// authentication and before the body.
//
// WHY CONDITIONAL. core/172 revokes the write from the application roles only.
// An owner-role deployment still writes (PRD v11 §5 item 5, the ADR-065
// amendment of 2026-09-08), and on one the route proceeds exactly as before.
//
// WHY AN UNANSWERED PROBE FALLS THROUGH RATHER THAN REFUSING. Where the freeze
// is in force the database still refuses the write itself, and
// writeLegacyFreezeError still answers that 409, so falling through can cost a
// malformed body the 409 (it gets its 400) but can never let a frozen write
// succeed. Refusing on an unanswered probe would instead turn a database blip
// into a retirement notice on a deployment that may write.
func refuseLegacyWriteWhenRevoked(w http.ResponseWriter, r *http.Request, svc PolicyServicer, logPrefix, op, orgID, tenantID string, write legacyfreeze.ErrorWriter) bool {
	return legacyfreeze.RefuseWhenRevoked(w, r, svc.MayWriteLegacyPolicies, logPrefix, op, orgID, tenantID, write)
}

// refuseLegacyWriteWhenRevoked binds the policy routes' envelope, which is
// also what the agent's proxied routes of the same paths answer.
func (h *PolicyAPIHandler) refuseLegacyWriteWhenRevoked(w http.ResponseWriter, r *http.Request, op, orgID, tenantID string) bool {
	return refuseLegacyWriteWhenRevoked(w, r, h.service, "PolicyAPI", op, orgID, tenantID, h.writeError)
}

// refuseLegacyWriteWhenRevoked binds the envelope of the deprecated
// dynamic-policy family and its tenant-policy successor, which share one
// handler.
func (h *DynamicPolicyAPIHandler) refuseLegacyWriteWhenRevoked(w http.ResponseWriter, r *http.Request, op, orgID, tenantID string) bool {
	return refuseLegacyWriteWhenRevoked(w, r, h.service, "DynamicPolicyAPI", op, orgID, tenantID, h.writeError)
}

// refuseLegacyWriteWhenRevoked binds template apply's
// envelope. Applying a template creates a policy through PolicyRepository.Create,
// so it asks the same pool the policy routes ask.
func (h *TemplateAPIHandler) refuseLegacyWriteWhenRevoked(w http.ResponseWriter, r *http.Request, op, orgID, tenantID string) bool {
	return legacyfreeze.RefuseWhenRevoked(w, r, h.service.MayWriteLegacyPolicies, "TemplateAPI", op, orgID, tenantID, h.writeError)
}

// MayWriteLegacyPolicies asks the policy repository's pool, the one
// ApplyTemplate's PolicyRepository.Create writes through (#4237).
func (s *TemplateService) MayWriteLegacyPolicies(ctx context.Context) (bool, error) {
	return s.policyRepo.MayWriteLegacyPolicies(ctx)
}

// refuseSessionOverrideWrite answers a session override write with the freeze,
// always (#4252): the write reaches no frozen table, so it is RefuseOverride's
// fixed answer rather than a classified database error.
func refuseSessionOverrideWrite(w http.ResponseWriter, op, tenantID string) {
	legacyfreeze.RefuseOverride(w, "OverrideAPI", op, tenantID, writeCodedError)
}

// writeCodedError renders the coded envelope, {error: {code, message}} (the
// CodedErrorResponse the policy routes' freeze answers in), for a handler that
// is a function rather than a method on one of the typed handlers.
func writeCodedError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(PolicyAPIError{Error: PolicyAPIErrorDetail{Code: code, Message: message}})
}
