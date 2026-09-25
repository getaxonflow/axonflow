// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"net/http"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// boundStepRequestBody bounds a multi-agent route's body before it is decoded
// (workflow_control/request_body_cap.go). A body over the bound is refused 413
// whole, in these routes' flat {success, error} family, and recorded under
// scope; an unreadable body is their 400. It returns false when the handler must
// stop.
func boundStepRequestBody(w http.ResponseWriter, r *http.Request, scope legacycompile.EnforcementScope) bool {
	err := workflow_control.ReadBoundedBody(w, r)
	switch {
	case err == nil:
		return true
	case errors.Is(err, workflow_control.ErrRequestTooLarge):
		recordStepBodyRefused(scope)
		sendErrorResponse(w, workflow_control.RequestTooLarge+": "+workflow_control.RequestTooLargeMessage, http.StatusRequestEntityTooLarge)
	default:
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
	}
	return false
}

// recordStepBodyRefused records a step-plane request refused for its body's
// size, as the anchored planes record every refusal.
func recordStepBodyRefused(scope legacycompile.EnforcementScope) {
	anchoredenforcer.RecordEnforcement(scope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictDeny, workflow_control.RequestTooLarge)
}
