// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

// Audit non-repudiation verification endpoints (#2722).
//
// These are READ-ONLY verification surfaces over the signed decision_chain.
// They are not policy enforcement points (no decision engine call, no deny
// path), so they are intentionally outside the audit-coverage gate
// (TestEveryPolicyEnforcementPointAudits).
//
//   GET /api/v1/audit/chains/{chainID}/verify   verify a chain's linkage + sigs
//   GET /api/v1/audit/records/{recordID}/verify  verify ONE record standalone
//   GET /api/v1/audit/signing-key                publish the current public key
//
// All three are org-scoped via apiAuthMiddleware: the org is taken from the
// authenticated request context, never from a path/query parameter, and the
// underlying reads run under RLS so a caller can only verify chains/records
// belonging to its own org.

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// RegisterAuditVerificationHandlers mounts the verification endpoints behind
// apiAuthMiddleware (so org/tenant are derived from auth credentials). tracker
// must be non-nil; when it carries no signing key, signature fields verify as
// unsigned and the signing-key endpoint reports that none is configured.
func RegisterAuditVerificationHandlers(router *mux.Router, tracker *DecisionChainTracker) {
	if router == nil || tracker == nil {
		return
	}
	sub := router.NewRoute().Subrouter()
	sub.Use(apiAuthMiddleware)
	h := &auditVerificationHandler{tracker: tracker}
	sub.HandleFunc("/api/v1/audit/chains/{chainID}/verify", h.verifyChain).Methods("GET")
	sub.HandleFunc("/api/v1/audit/records/{recordID}/verify", h.verifyRecord).Methods("GET")
	sub.HandleFunc("/api/v1/audit/signing-key", h.signingKey).Methods("GET")
}

type auditVerificationHandler struct {
	tracker *DecisionChainTracker
}

func (h *auditVerificationHandler) verifyChain(w http.ResponseWriter, r *http.Request) {
	orgID := OrgIDFromContext(r.Context())
	if orgID == "" {
		writeAuditVerifyError(w, http.StatusUnauthorized, "missing authenticated org context")
		return
	}
	chainID := mux.Vars(r)["chainID"]
	if _, err := uuid.Parse(chainID); err != nil {
		writeAuditVerifyError(w, http.StatusBadRequest, "chainID must be a valid UUID")
		return
	}

	result, found, err := h.tracker.VerifyChain(r.Context(), orgID, chainID)
	if err != nil {
		writeAuditVerifyError(w, http.StatusInternalServerError, "verification failed")
		return
	}
	if !found {
		writeAuditVerifyError(w, http.StatusNotFound, "no decision chain found for this id in your organization")
		return
	}
	writeAuditVerifyJSON(w, http.StatusOK, result)
}

func (h *auditVerificationHandler) verifyRecord(w http.ResponseWriter, r *http.Request) {
	orgID := OrgIDFromContext(r.Context())
	if orgID == "" {
		writeAuditVerifyError(w, http.StatusUnauthorized, "missing authenticated org context")
		return
	}
	recordID := mux.Vars(r)["recordID"]
	if _, err := uuid.Parse(recordID); err != nil {
		writeAuditVerifyError(w, http.StatusBadRequest, "recordID must be a valid UUID")
		return
	}

	result, found, err := h.tracker.VerifyRecord(r.Context(), orgID, recordID)
	if err != nil {
		writeAuditVerifyError(w, http.StatusInternalServerError, "verification failed")
		return
	}
	if !found {
		writeAuditVerifyError(w, http.StatusNotFound, "no decision record found for this id in your organization")
		return
	}
	writeAuditVerifyJSON(w, http.StatusOK, result)
}

// signingKey publishes the current public verification key so an external
// auditor can re-verify any record's signature offline.
func (h *auditVerificationHandler) signingKey(w http.ResponseWriter, r *http.Request) {
	if OrgIDFromContext(r.Context()) == "" {
		writeAuditVerifyError(w, http.StatusUnauthorized, "missing authenticated org context")
		return
	}
	keyID, pub := h.tracker.PublicSigningKey()
	resp := map[string]interface{}{
		"algorithm":      "ed25519",
		"signing_key_id": keyID,
		"public_key":     pub,
		"configured":     pub != "",
		// How to verify a record offline with this key:
		//   chain_hash = sha256_hex( record_digest + "|" + prev_hash )
		//   ed25519.Verify(public_key, ascii_bytes(chain_hash), base64_decode(record_signature))
		"verification_note": "ed25519.Verify(public_key, []byte(chain_hash), base64decode(record_signature)); chain_hash is returned by the per-record verify endpoint",
	}
	writeAuditVerifyJSON(w, http.StatusOK, resp)
}

func writeAuditVerifyJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAuditVerifyError(w http.ResponseWriter, status int, msg string) {
	writeAuditVerifyJSON(w, status, map[string]string{"error": msg})
}
