// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"net/http"

	"axonflow/platform/shared/legacyfreeze"
)

// writeLegacyFreezeError answers the core/172 legacy policy freeze on the
// system-policy write routes and reports whether it did (#4084).
//
// Create, update, delete and the enabled toggle all write static_policies,
// which core/172 made read-only to the application roles - and the agent's
// default connection IS an application role (AXONFLOW_DB_USE_APP_ROLE,
// db_connection.go). Before this, each of the four fell through to its
// switch's default arm and answered a bare 500 for a write path that was
// retired on purpose, while the orchestrator answered the same refusal 409.
// The classification, status, code and remedy are package legacyfreeze's; only
// the envelope is the agent's.
func writeLegacyFreezeError(w http.ResponseWriter, err error, op, tenantID string) bool {
	return legacyfreeze.Answer(w, err, "StaticPolicyAPI", op, tenantID, writeCodedJSONError)
}

// writeOverrideFreezeError refuses a per-policy override write (PRD v11 §1.5).
// No route writes policy_overrides in v11 and core/172 does not revoke it, so
// this is the handler's refusal, not a classified database error.
func writeOverrideFreezeError(w http.ResponseWriter, op, tenantID string) {
	legacyfreeze.RefuseOverride(w, "StaticPolicyAPI", op, tenantID, writeCodedJSONError)
}

// errNoStaticPolicyPool is what the probe reports when the repository has no
// pool. It falls through (legacyfreeze.RefuseWhenRevoked), so a handler built
// without a database behaves exactly as it did before the guard.
var errNoStaticPolicyPool = errors.New("static policy repository has no database pool")

// MayWriteLegacyPolicies reports whether r.db, the pool the system-policy
// writes go through, may write static_policies (legacyfreeze.MayWrite, #4237).
func (r *StaticPolicyRepository) MayWriteLegacyPolicies(ctx context.Context) (bool, error) {
	if r == nil || r.db == nil {
		return false, errNoStaticPolicyPool
	}
	return legacyfreeze.MayWrite(ctx, r.db, "static_policies")
}

// refuseLegacyWriteWhenRevoked answers the system-policy create, update and
// toggle with the freeze before the body is read - and, for update and toggle,
// before the row is looked up - where the connection may not write
// static_policies (#4237). Delete takes no body; its lookup answers an unknown
// id before writeLegacyFreezeError classifies the write (#4249).
func (h *StaticPolicyAPIHandler) refuseLegacyWriteWhenRevoked(w http.ResponseWriter, r *http.Request, op, orgID, tenantID string) bool {
	return legacyfreeze.RefuseWhenRevoked(w, r, h.policyRepo.MayWriteLegacyPolicies, "StaticPolicyAPI", op, orgID, tenantID, writeCodedJSONError)
}

// writeCodedJSONError writes the agent's error envelope with a STRING code.
//
// writeJSONError, which every other route in this file uses, puts the numeric
// HTTP status in `code`, so it cannot carry LEGACY_POLICY_WRITE_FROZEN - and a
// caller reading `.error.code` is exactly how the orchestrator's refusal is
// recognised. Changing writeJSONError would change the envelope of every agent
// route that uses it; this writer is additive and serves the freeze alone, with
// the same two keys, so a client that reads only `.error.message` sees no
// difference and one that reads `.error.code` gets a code it can act on.
func writeCodedJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSONResponse(w, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}, status)
}
