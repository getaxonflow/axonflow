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
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

// nonEmptyArg is a sqlmock argument matcher asserting a non-empty string value.
type nonEmptyArg struct{}

func (nonEmptyArg) Match(v driver.Value) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// decisionChainTestCols mirrors the projection in decisionChainColumns, in scan
// order, for building sqlmock rows.
var decisionChainTestCols = []string{
	"id", "chain_id", "request_id", "parent_request_id", "step_number",
	"org_id", "tenant_id", "client_id", "user_id",
	"decision_type", "decision_outcome", "system_id",
	"model_provider", "model_id",
	"policies_evaluated", "policy_triggered",
	"risk_level", "requires_human_review", "processing_time_ms",
	"input_hash", "output_hash", "audit_hash",
	"data_sources", "created_at",
	"chain_seq", "prev_hash", "record_signature", "signing_key_id",
}

// addEntryRow appends a sealed DecisionEntry to a sqlmock Rows in column order.
func addEntryRow(rows *sqlmock.Rows, e DecisionEntry) *sqlmock.Rows {
	return rows.AddRow(
		e.ID, e.ChainID, e.RequestID, e.ParentRequestID, e.StepNumber,
		e.OrgID, e.TenantID, e.ClientID, e.UserID,
		string(e.DecisionType), string(e.DecisionOutcome), e.SystemID,
		e.ModelProvider, e.ModelID,
		"{}", e.PolicyTriggered,
		string(e.RiskLevel), e.RequiresHumanReview, e.ProcessingTimeMs,
		e.InputHash, e.OutputHash, e.AuditHash,
		"{}", e.CreatedAt,
		e.ChainSeq, e.PrevHash, e.RecordSignature, e.SigningKeyID,
	)
}

// TestRecordToDBPersistsSignature proves the DB write path actually persists a
// genesis prev_hash + a non-empty Ed25519 signature + key id (not just that the
// INSERT ran). Inverse of "no-write" tautology: we assert the exact columns.
func TestRecordToDBPersistsSignature(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	tracker, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB:             db,
		SystemID:       "test/1.0.0",
		AsyncQueueSize: -1,
		SigningKey:     testSigningKey(t),
	})
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}

	// 29 INSERT args; assert the chain columns specifically.
	args := make([]driver.Value, 29)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[25] = sqlmock.AnyArg() // chain_seq ($26)
	args[26] = genesisPrevHash  // prev_hash ($27), first record = genesis
	args[27] = nonEmptyArg{}    // record_signature ($28)
	args[28] = nonEmptyArg{}    // signing_key_id ($29)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM decision_chain`).
		WillReturnRows(sqlmock.NewRows([]string{"id"})) // empty: genesis
	mock.ExpectExec("INSERT INTO decision_chain").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = tracker.RecordDecision(context.Background(), sampleEntry("org-1", "11111111-1111-1111-1111-111111111111", 1))
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestVerifyChainDBMode exercises the RLS-scoped fetch + scan + verify path
// against a mocked Postgres, using records sealed by a real signing tracker.
func TestVerifyChainDBMode(t *testing.T) {
	// 1) Seal two real records in memory mode to get valid chain fields.
	mem := newSigningTracker(t)
	ctx := context.Background()
	const org = "org-1"
	chain := "22222222-2222-2222-2222-222222222222"
	for i := 1; i <= 2; i++ {
		if err := mem.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("seal record %d: %v", i, err)
		}
	}
	sealed := mem.memoryChainForOrg(org, chain)

	// 2) DB-mode tracker sharing the same key, so signatures verify.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	dbTracker, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB:             db,
		SystemID:       "test/1.0.0",
		AsyncQueueSize: -1,
		SigningKey:     testSigningKey(t),
	})
	if err != nil {
		t.Fatalf("new db tracker: %v", err)
	}

	cols := []string{
		"id", "chain_id", "request_id", "parent_request_id", "step_number",
		"org_id", "tenant_id", "client_id", "user_id",
		"decision_type", "decision_outcome", "system_id",
		"model_provider", "model_id",
		"policies_evaluated", "policy_triggered",
		"risk_level", "requires_human_review", "processing_time_ms",
		"input_hash", "output_hash", "audit_hash",
		"data_sources", "created_at",
		"chain_seq", "prev_hash", "record_signature", "signing_key_id",
	}
	rows := sqlmock.NewRows(cols)
	for _, e := range sealed {
		rows.AddRow(
			e.ID, e.ChainID, e.RequestID, e.ParentRequestID, e.StepNumber,
			e.OrgID, e.TenantID, e.ClientID, e.UserID,
			string(e.DecisionType), string(e.DecisionOutcome), e.SystemID,
			e.ModelProvider, e.ModelID,
			"{}", e.PolicyTriggered,
			string(e.RiskLevel), e.RequiresHumanReview, e.ProcessingTimeMs,
			e.InputHash, e.OutputHash, e.AuditHash,
			"{}", e.CreatedAt,
			e.ChainSeq, e.PrevHash, e.RecordSignature, e.SigningKeyID,
		)
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM decision_chain`).
		WithArgs(chain).
		WillReturnRows(rows)
	mock.ExpectCommit()

	res, found, err := dbTracker.VerifyChain(ctx, org, chain)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !found {
		t.Fatal("expected chain found")
	}
	if !res.Valid {
		t.Fatalf("expected valid DB chain, got break: %s", res.BreakReason)
	}
	if res.TotalRecords != 2 || res.SignedRecords != 2 {
		t.Errorf("total=%d signed=%d, want 2/2", res.TotalRecords, res.SignedRecords)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestVerifyRecordDBMode covers the RLS-scoped single-record fetch + standalone
// signature verification against a mocked Postgres.
func TestVerifyRecordDBMode(t *testing.T) {
	mem := newSigningTracker(t)
	ctx := context.Background()
	const org = "org-1"
	chain := "33333333-3333-3333-3333-333333333333"
	if err := mem.RecordDecision(ctx, sampleEntry(org, chain, 1)); err != nil {
		t.Fatalf("seal: %v", err)
	}
	sealed := mem.memoryChainForOrg(org, chain)[0]

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	dbTracker, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB: db, SystemID: "test/1.0.0", AsyncQueueSize: -1, SigningKey: testSigningKey(t),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM decision_chain WHERE id`).
		WithArgs(sealed.ID).
		WillReturnRows(addEntryRow(sqlmock.NewRows(decisionChainTestCols), sealed))
	mock.ExpectCommit()

	res, found, err := dbTracker.VerifyRecord(ctx, org, sealed.ID)
	if err != nil || !found {
		t.Fatalf("VerifyRecord found=%v err=%v", found, err)
	}
	if !res.Valid || !res.Signed || !res.SignatureValid {
		t.Errorf("expected valid signed record, got %+v", res)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet: %v", err)
	}
}

// TestRecordToDBNonGenesis covers the append-onto-existing-chain branch: the
// tail read returns a row, so prev_hash links to it and chain_seq increments.
func TestRecordToDBNonGenesis(t *testing.T) {
	mem := newSigningTracker(t)
	ctx := context.Background()
	const org = "org-1"
	chain := "44444444-4444-4444-4444-444444444444"
	if err := mem.RecordDecision(ctx, sampleEntry(org, chain, 1)); err != nil {
		t.Fatalf("seal: %v", err)
	}
	existing := mem.memoryChainForOrg(org, chain)[0]

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	dbTracker, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		DB: db, SystemID: "test/1.0.0", AsyncQueueSize: -1, SigningKey: testSigningKey(t),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	args := make([]driver.Value, 29)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[24] = sqlmock.AnyArg()      // created_at
	args[25] = existing.ChainSeq + 1 // chain_seq increments
	args[26] = chainHashOf(existing) // prev_hash links to the tail
	args[27] = nonEmptyArg{}         // record_signature
	args[28] = nonEmptyArg{}         // signing_key_id

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM decision_chain`).
		WillReturnRows(addEntryRow(sqlmock.NewRows(decisionChainTestCols), existing))
	mock.ExpectExec("INSERT INTO decision_chain").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := dbTracker.RecordDecision(ctx, sampleEntry(org, chain, 2)); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet: %v", err)
	}
}

// TestRegisterAuditVerificationHandlers smoke-tests route mounting: a request to
// a registered path must reach apiAuthMiddleware (not 404). nil inputs no-op.
func TestRegisterAuditVerificationHandlers(t *testing.T) {
	RegisterAuditVerificationHandlers(nil, nil) // must not panic

	router := mux.NewRouter()
	tr := newSigningTracker(t)
	RegisterAuditVerificationHandlers(router, tr)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/signing-key", nil)
	router.ServeHTTP(rec, req)
	// Route is mounted; without credentials apiAuthMiddleware rejects it, so we
	// must NOT see a 404 (which would mean the route was never registered).
	if rec.Code == http.StatusNotFound {
		t.Errorf("route not registered (got 404)")
	}
}
