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

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// reqWithOrg builds a GET request whose context carries the authenticated org
// (as apiAuthMiddleware would set it) plus the given mux path vars.
func reqWithOrg(org string, vars map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/x", nil)
	ctx := context.WithValue(r.Context(), ContextKeyOrgID, org)
	r = r.WithContext(ctx)
	return mux.SetURLVars(r, vars)
}

func TestVerifyChainHandler(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org = "org-1"
	chain := uuid.New().String()
	for i := 1; i <= 3; i++ {
		if err := tr.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	h := &auditVerificationHandler{tracker: tr}

	// 200 valid chain.
	rec := httptest.NewRecorder()
	h.verifyChain(rec, reqWithOrg(org, map[string]string{"chainID": chain}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var res ChainVerificationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !res.Valid || res.TotalRecords != 3 {
		t.Errorf("valid=%v total=%d, want true/3", res.Valid, res.TotalRecords)
	}
	if res.PublicKey == "" {
		t.Error("expected published public key in response")
	}

	// 404 unknown chain (valid uuid, not present).
	rec = httptest.NewRecorder()
	h.verifyChain(rec, reqWithOrg(org, map[string]string{"chainID": uuid.New().String()}))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown chain status = %d, want 404", rec.Code)
	}

	// 400 malformed chain id.
	rec = httptest.NewRecorder()
	h.verifyChain(rec, reqWithOrg(org, map[string]string{"chainID": "not-a-uuid"}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad chain id status = %d, want 400", rec.Code)
	}

	// 401 no org context.
	rec = httptest.NewRecorder()
	h.verifyChain(rec, reqWithOrg("", map[string]string{"chainID": chain}))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-org status = %d, want 401", rec.Code)
	}

	// 404 cross-org: another org cannot verify this chain.
	rec = httptest.NewRecorder()
	h.verifyChain(rec, reqWithOrg("org-other", map[string]string{"chainID": chain}))
	if rec.Code != http.StatusNotFound {
		t.Errorf("cross-org status = %d, want 404", rec.Code)
	}
}

func TestVerifyRecordHandler(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org = "org-1"
	chain := uuid.New().String()
	if err := tr.RecordDecision(ctx, sampleEntry(org, chain, 1)); err != nil {
		t.Fatalf("record: %v", err)
	}
	recordID := tr.memoryChainForOrg(org, chain)[0].ID
	h := &auditVerificationHandler{tracker: tr}

	rec := httptest.NewRecorder()
	h.verifyRecord(rec, reqWithOrg(org, map[string]string{"recordID": recordID}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var res RecordVerificationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !res.Valid || !res.Signed || !res.SignatureValid {
		t.Errorf("expected valid signed record, got %+v", res)
	}
	if res.ChainHash == "" || res.PublicKey == "" {
		t.Error("expected chain_hash and public_key in response for offline re-verification")
	}

	// 400 malformed record id.
	rec = httptest.NewRecorder()
	h.verifyRecord(rec, reqWithOrg(org, map[string]string{"recordID": "nope"}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad record id status = %d, want 400", rec.Code)
	}
}

func TestSigningKeyHandler(t *testing.T) {
	tr := newSigningTracker(t)
	h := &auditVerificationHandler{tracker: tr}

	rec := httptest.NewRecorder()
	h.signingKey(rec, reqWithOrg("org-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["configured"] != true {
		t.Error("expected configured=true with a signing key")
	}
	if body["algorithm"] != "ed25519" {
		t.Errorf("algorithm = %v, want ed25519", body["algorithm"])
	}

	// Unsigned tracker reports not configured.
	trUnsigned, _ := NewDecisionChainTracker(DecisionChainTrackerConfig{SystemID: "t"})
	h2 := &auditVerificationHandler{tracker: trUnsigned}
	rec = httptest.NewRecorder()
	h2.signingKey(rec, reqWithOrg("org-1", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["configured"] != false {
		t.Error("expected configured=false without a signing key")
	}

	// 401 without org.
	rec = httptest.NewRecorder()
	h.signingKey(rec, reqWithOrg("", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-org status = %d, want 401", rec.Code)
	}
}
