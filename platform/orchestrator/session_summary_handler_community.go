//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Community-edition stub for the session-summary reporting endpoint (#2759,
// WS-7). Session-level usage reporting is an Enterprise feature (HARD RULE
// 11); the community build mounts the same route returning 501 so callers
// get a clear signal rather than a 404. The enterprise implementation lives
// in session_summary_handler.go (//go:build enterprise).

package orchestrator

import "net/http"

// sessionSummaryHandler (community) serves GET /api/v1/audit/session-summary
// with a 501, mirroring the same symbol name the enterprise build defines so
// run.go's route registration is a single unconditional line in both builds.
func sessionSummaryHandler(w http.ResponseWriter, r *http.Request) {
	sendErrorResponse(w, "session summary reporting is an Enterprise feature", http.StatusNotImplemented)
}
