// Copyright 2025 AxonFlow
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

// Real-Postgres integration test for #2643: the REAL handleDecide, over a LIVE
// Postgres (no sqlmock), must persist a canonical audit_logs decision row for
// every early-return deny — decode error, empty query, cross-tenant and
// cross-org impersonation — and those rows must be queryable by the predicates
// the orchestrator decisions feed uses (decision_id present, policy_decision
// filter). This is the in-process complement to runtime-e2e/2643_decide_earlydeny_audit/
// (which adds the live HTTP + orchestrator-feed layer); it exercises the same
// write+read path end-to-end against a real database.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (testcontainers postgres).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"axonflow/platform/testutil"
)

func TestHandleDecide_EarlyDeny_PersistsToRealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres integration test")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pg.DB

	// audit_logs with the exact columns writeDecisionAuditLog's INSERT targets
	// (the union of migrations 059 + 119 + 121 + this PR's redacted_fields). A
	// minimal faithful shape keeps the test independent of the full chain while
	// exercising the real INSERT verbatim.
	if _, err := db.Exec(`
		CREATE TABLE audit_logs (
			id              VARCHAR(255) PRIMARY KEY,
			request_id      VARCHAR(255),
			timestamp       TIMESTAMPTZ,
			user_id         INTEGER,
			user_email      VARCHAR(255),
			user_role       VARCHAR(255),
			client_id       VARCHAR(255),
			tenant_id       VARCHAR(255),
			org_id          VARCHAR(255),
			request_type    VARCHAR(255),
			query           TEXT,
			query_hash      VARCHAR(255),
			policy_decision VARCHAR(50) NOT NULL,
			policy_details  JSONB,
			decision_id     VARCHAR(255),
			plane           VARCHAR(50),
			obligations     JSONB,
			correlation_id  VARCHAR(255),
			redacted_fields JSONB
		)`); err != nil {
		t.Fatalf("create audit_logs: %v", err)
	}

	origDB := usageDB
	usageDB = db
	t.Cleanup(func() { usageDB = origDB })

	// enterpriseReq builds a handler request with enterprise identity stamped
	// into context (mirrors apiAuthMiddleware) and a raw body (so we can also
	// send malformed JSON).
	enterpriseReq := func(rawBody, ctxTenant, ctxOrg string) *http.Request {
		req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBufferString(rawBody))
		req.Header.Set("Content-Type", "application/json")
		ctx := req.Context()
		ctx = context.WithValue(ctx, ContextKeyTenantID, ctxTenant)
		ctx = context.WithValue(ctx, ContextKeyOrgID, ctxOrg)
		ctx = context.WithValue(ctx, ContextKeyClientID, "auth-client")
		ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
		return req.WithContext(ctx)
	}

	call := func(rawBody, ctxTenant, ctxOrg string) (int, string) {
		req := enterpriseReq(rawBody, ctxTenant, ctxOrg)
		rr := httptest.NewRecorder()
		handleDecide(rr, req)
		var resp map[string]interface{}
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		did, _ := resp["decision_id"].(string)
		return rr.Code, did
	}

	type rowFields struct {
		decision, plane, securityEvent, attemptedTenant, attemptedOrg, tenantCol string
	}
	readRow := func(decisionID string) (rowFields, bool) {
		var f rowFields
		err := db.QueryRow(`
			SELECT policy_decision, COALESCE(plane,''),
			       COALESCE(policy_details->>'security_event',''),
			       COALESCE(policy_details->>'attempted_tenant_id',''),
			       COALESCE(policy_details->>'attempted_org_id',''),
			       COALESCE(tenant_id,'')
			  FROM audit_logs WHERE decision_id = $1`, decisionID).
			Scan(&f.decision, &f.plane, &f.securityEvent, &f.attemptedTenant, &f.attemptedOrg, &f.tenantCol)
		if err != nil {
			return f, false
		}
		return f, true
	}

	const authTenant, authOrg = "auth-tenant", "auth-org"

	// --- decode error → error row -------------------------------------------
	code, decodeID := call(`{not valid json`, authTenant, authOrg)
	if code != http.StatusBadRequest || decodeID == "" {
		t.Fatalf("decode error: got HTTP %d id=%q want 400 + decision_id", code, decodeID)
	}
	if f, ok := readRow(decodeID); !ok {
		t.Errorf("decode-error deny wrote NO audit_logs row (decision_id=%s)", decodeID)
	} else if f.decision != AuditVerdictError || f.plane != PlaneDecision {
		t.Errorf("decode-error row: got %s|%s want %s|%s", f.decision, f.plane, AuditVerdictError, PlaneDecision)
	}

	// --- empty query → error row --------------------------------------------
	code, emptyID := call(`{"stage":"llm","query":""}`, authTenant, authOrg)
	if code != http.StatusBadRequest || emptyID == "" {
		t.Fatalf("empty query: got HTTP %d id=%q want 400 + decision_id", code, emptyID)
	}
	if f, ok := readRow(emptyID); !ok {
		t.Errorf("empty-query deny wrote NO audit_logs row (decision_id=%s)", emptyID)
	} else if f.decision != AuditVerdictError {
		t.Errorf("empty-query row decision: got %s want %s", f.decision, AuditVerdictError)
	}

	// --- tenant impersonation → blocked row w/ attempted-vs-actual ----------
	code, tImpID := call(`{"stage":"llm","caller_identity":{"tenant_id":"victim-tenant"},"target":{"type":"llm","model":"gpt-4o"},"query":"hello"}`, authTenant, authOrg)
	if code != http.StatusForbidden || tImpID == "" {
		t.Fatalf("tenant impersonation: got HTTP %d id=%q want 403 + decision_id", code, tImpID)
	}
	if f, ok := readRow(tImpID); !ok {
		t.Errorf("tenant-impersonation deny wrote NO audit_logs row (decision_id=%s)", tImpID)
	} else {
		if f.decision != AuditVerdictBlocked || f.plane != PlaneDecision {
			t.Errorf("tenant-impersonation row: got %s|%s want %s|%s", f.decision, f.plane, AuditVerdictBlocked, PlaneDecision)
		}
		if f.securityEvent != "tenant_impersonation" || f.attemptedTenant != "victim-tenant" {
			t.Errorf("tenant-impersonation attempted-vs-actual: event=%q attempted=%q (want tenant_impersonation/victim-tenant)", f.securityEvent, f.attemptedTenant)
		}
		if f.tenantCol != authTenant {
			t.Errorf("tenant-impersonation row tenant_id COLUMN: got %q want actual %q", f.tenantCol, authTenant)
		}
	}

	// --- org impersonation → blocked row ------------------------------------
	code, oImpID := call(`{"stage":"llm","caller_identity":{"tenant_id":"auth-tenant","org_id":"victim-org"},"target":{"type":"llm","model":"gpt-4o"},"query":"hello"}`, authTenant, authOrg)
	if code != http.StatusForbidden || oImpID == "" {
		t.Fatalf("org impersonation: got HTTP %d id=%q want 403 + decision_id", code, oImpID)
	}
	if f, ok := readRow(oImpID); !ok {
		t.Errorf("org-impersonation deny wrote NO audit_logs row (decision_id=%s)", oImpID)
	} else if f.decision != AuditVerdictBlocked || f.securityEvent != "org_impersonation" || f.attemptedOrg != "victim-org" {
		t.Errorf("org-impersonation row: decision=%s event=%q attempted_org=%q", f.decision, f.securityEvent, f.attemptedOrg)
	}

	// --- the decisions-feed predicate finds every early-deny row ------------
	// (decision_id IS NOT NULL — the WHERE the orchestrator decisions list uses).
	var feedCount int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE plane='decision' AND decision_id IS NOT NULL`).Scan(&feedCount); err != nil {
		t.Fatalf("count feed rows: %v", err)
	}
	if feedCount != 4 {
		t.Errorf("decisions-feed-visible early-deny rows: got %d want 4", feedCount)
	}

	// --- no legacy allow/deny ever persisted on the decision plane ----------
	var legacy int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE plane='decision' AND policy_decision IN ('allow','deny','denied')`).Scan(&legacy); err != nil {
		t.Fatalf("count legacy: %v", err)
	}
	if legacy != 0 {
		t.Errorf("legacy allow/deny rows on decision plane: got %d want 0", legacy)
	}
}
