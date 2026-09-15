// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"log"
	"net/http"
)

// writePreCheckResponse is the ONLY way a PreCheckResponse reaches the wire,
// and that is the point rather than a convenience.
//
// #3897 §1 asked for `decision_id` on this plane, with `context_id` retained as
// a deprecated alias. The obvious implementation - set both fields at each
// construction site - had SIX sites across two files and would have been wrong
// the first time a seventh was added, which is the same class of defect as the
// divergence it fixes. Worse, one of the six writes a 402 rather than a 200 and
// looked nothing like the other five, so a mechanical sweep over the common
// shape missed it.
//
// Minting the alias HERE means the two names cannot disagree: there is one
// stored value and one place that copies it.
//
// WHY NOT A MarshalJSON ON PreCheckResponse, which is the tidier trick: a type
// carrying its own MarshalJSON is a LEAF to the OpenAPI field-parity walker
// (openapi_schema_parity_test.go, wireLeafStruct), so giving this type one
// would make every member of the pre-check contract invisible to the guard
// that exists to compare it against the published document. The tidier trick
// would have blinded #3896 to fix #3897.
func writePreCheckResponse(w http.ResponseWriter, status int, response PreCheckResponse) {
	// The canonical name, derived from the deprecated one so the two cannot
	// drift. If a caller has already set DecisionID explicitly, ContextID still
	// wins: there is exactly one identifier, and it is the one every audit,
	// signing and telemetry path was keyed on.
	response.DecisionID = response.ContextID

	// The canonical verdict (#3897 §2), derived here for the same reason the
	// decision id is: one place, so it cannot disagree with the `approved`
	// bool beside it or with the verdict recorded on the decision.
	response.Verdict = preCheckVerdict(response)

	w.Header().Set("Content-Type", "application/json")
	if status != http.StatusOK {
		// Set the status only when it is not the default. WriteHeader writes
		// the status line, after which header mutations are silently dropped -
		// so Content-Type above must come first, and calling WriteHeader
		// unconditionally would be harmless but noisier in the access log.
		w.WriteHeader(status)
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("❌ [Pre-check] Failed to encode response: %v", err)
	}
}
