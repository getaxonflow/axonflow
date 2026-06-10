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

package orchestrator

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #2590 deterministic CI coverage for the config-governed retention executor.
//
// These tests lock, red-on-revert:
//   - dry-run (default) issues SELECT COUNT, NEVER a DELETE;
//   - enforce issues a DELETE per governed table;
//   - the per-table age column is correct (timestamp vs created_at);
//   - the cutoff timestamp equals now - effective_retention_days;
//   - an active per-org override produces a scoped DELETE plus a default bucket
//     that EXCLUDES the override org.
//
// Real prune/keep semantics against a live Postgres live in
// audit_cleanup_retention_integration_test.go.

// cutoffArg matches a time.Time argument that is ~now minus `days`. It locks the
// retention window math: flipping the AddDate sign or the day count fails here.
type cutoffArg struct{ days int }

func (c cutoffArg) Match(v driver.Value) bool {
	ts, ok := v.(time.Time)
	if !ok {
		return false
	}
	want := time.Now().UTC().AddDate(0, 0, -c.days)
	delta := want.Sub(ts)
	return delta > -2*time.Second && delta < 2*time.Second
}

// realDefaultDays mirrors the audit_retention_defaults seed (migration 026) so
// the cutoff assertions use each table's true default.
func realDefaultDays(dataType string) int {
	if dataType == "decision_chain" {
		return 2555 // EU AI Act 7y
	}
	return 1825 // SEBI 5y
}

// expectRetentionPass programs sqlmock for one full executor pass over all six
// governed tables with NO per-org overrides, asserting the cutoff window and the
// dry-run/enforce branch. Returns the total rows the run should report
// (rowsPerTable per table).
func expectRetentionPass(mock sqlmock.Sqlmock, enforce bool, rowsPerTable int64) int64 {
	var total int64
	for _, rt := range retentionGovernedTables {
		days := realDefaultDays(rt.dataType)
		mock.ExpectQuery("SELECT retention_days FROM audit_retention_defaults WHERE data_type = $1").
			WithArgs(rt.dataType).
			WillReturnRows(sqlmock.NewRows([]string{"retention_days"}).AddRow(days))
		mock.ExpectQuery("SELECT org_id, retention_days FROM audit_retention_config WHERE data_type = $1 AND is_active = true").
			WithArgs(rt.dataType).
			WillReturnRows(sqlmock.NewRows([]string{"org_id", "retention_days"}))

		where := rt.tsColumn + " < $1"
		if enforce {
			mock.ExpectExec("DELETE FROM " + rt.table + " WHERE " + where).
				WithArgs(cutoffArg{days}).
				WillReturnResult(sqlmock.NewResult(0, rowsPerTable))
		} else {
			mock.ExpectQuery("SELECT COUNT(*) FROM " + rt.table + " WHERE " + where).
				WithArgs(cutoffArg{days}).
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(rowsPerTable))
		}
		total += rowsPerTable
	}
	return total
}

func newRetentionMock(t *testing.T) (sqlmock.Sqlmock, *AuditCleanupService, func()) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	svc := NewAuditCleanupService(db, &mockLicenseChecker{auditRetentionDays: 3650})
	return mock, svc, func() { _ = db.Close() }
}

// TestRetention_DryRunCountsNotDeletes asserts the DEFAULT posture: every
// governed table is COUNTed, nothing is DELETEd. If someone makes the executor
// delete-by-default, the unexpected DELETE fails the ordered mock.
func TestRetention_DryRunCountsNotDeletes(t *testing.T) {
	mock, svc, done := newRetentionMock(t)
	defer done()
	// enforce defaults to false — do NOT call SetRetentionEnforce.

	want := expectRetentionPass(mock, false /* enforce */, 4)

	results, err := svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != len(retentionGovernedTables) {
		t.Fatalf("expected %d table results, got %d", len(retentionGovernedTables), len(results))
	}
	var total int64
	for _, r := range results {
		if r.Enforced {
			t.Errorf("%s: expected dry-run (Enforced=false)", r.Table)
		}
		total += r.Rows
	}
	if total != want {
		t.Errorf("dry-run total = %d, want %d", total, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// TestRetention_EnforceIssuesDeletes asserts enforce mode DELETEs each governed
// table at the correct cutoff window.
func TestRetention_EnforceIssuesDeletes(t *testing.T) {
	mock, svc, done := newRetentionMock(t)
	defer done()
	svc.SetRetentionEnforce(true)

	want := expectRetentionPass(mock, true /* enforce */, 7)

	results, err := svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var total int64
	for _, r := range results {
		if !r.Enforced {
			t.Errorf("%s: expected enforce (Enforced=true)", r.Table)
		}
		total += r.Rows
	}
	if total != want {
		t.Errorf("enforce total = %d, want %d", total, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// TestRetention_PerOrgOverride asserts an ACTIVE override that EXTENDS retention
// beyond the regulatory floor is honored: (a) a scoped DELETE at the longer
// override window and (b) a default bucket that EXCLUDES that org (at the floor).
// Exercised on decision_chain (floor 2555d, override 3650d > floor).
func TestRetention_PerOrgOverride(t *testing.T) {
	mock, svc, done := newRetentionMock(t)
	defer done()
	svc.SetRetentionEnforce(true)

	const overrideOrg = "org-extended-retention"
	const overrideDays = 3650 // > decision_chain floor (2555) → honored verbatim

	var want int64
	for _, rt := range retentionGovernedTables {
		days := realDefaultDays(rt.dataType)
		mock.ExpectQuery("SELECT retention_days FROM audit_retention_defaults WHERE data_type = $1").
			WithArgs(rt.dataType).
			WillReturnRows(sqlmock.NewRows([]string{"retention_days"}).AddRow(days))

		overrideRows := sqlmock.NewRows([]string{"org_id", "retention_days"})
		if rt.dataType == "decision_chain" {
			overrideRows.AddRow(overrideOrg, overrideDays)
		}
		mock.ExpectQuery("SELECT org_id, retention_days FROM audit_retention_config WHERE data_type = $1 AND is_active = true").
			WithArgs(rt.dataType).
			WillReturnRows(overrideRows)

		if rt.dataType == "decision_chain" {
			// (a) per-org scoped delete at the 3650-day (extended) override window.
			mock.ExpectExec("DELETE FROM decision_chain WHERE org_id = $1 AND created_at < $2").
				WithArgs(overrideOrg, cutoffArg{overrideDays}).
				WillReturnResult(sqlmock.NewResult(0, 3))
			// (b) default bucket EXCLUDING the override org, at the 2555-day floor.
			mock.ExpectExec("DELETE FROM decision_chain WHERE created_at < $1 AND (org_id IS NULL OR NOT org_id = ANY($2))").
				WithArgs(cutoffArg{days}, sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 5))
			want += 8
		} else {
			mock.ExpectExec("DELETE FROM " + rt.table + " WHERE " + rt.tsColumn + " < $1").
				WithArgs(cutoffArg{days}).
				WillReturnResult(sqlmock.NewResult(0, 1))
			want++
		}
	}

	results, err := svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var total int64
	var decisionChainRows int64
	for _, r := range results {
		total += r.Rows
		if r.Table == "decision_chain" {
			decisionChainRows = r.Rows
		}
	}
	if decisionChainRows != 8 {
		t.Errorf("decision_chain rows = %d, want 8 (3 override + 5 default)", decisionChainRows)
	}
	if total != want {
		t.Errorf("total = %d, want %d", total, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// TestRetention_SubFloorOverrideClampedToFloor is the regulatory-floor guard
// (R3 HIGH). A POSITIVE active override BELOW the framework floor (30d vs the
// decision_chain 2555d EU-AI-Act floor) must NOT delete rows still inside the
// mandated window: the scoped DELETE must use the FLOOR cutoff, not the 30-day
// override. Red-on-revert — remove the max(days, defaultDays) clamp and the
// per-org DELETE fires at cutoffArg{30}, failing this matcher.
func TestRetention_SubFloorOverrideClampedToFloor(t *testing.T) {
	mock, svc, done := newRetentionMock(t)
	defer done()
	svc.SetRetentionEnforce(true)

	const overrideOrg = "org-too-aggressive"
	const subFloorDays = 30 // far below the 2555d EU-AI-Act floor

	for _, rt := range retentionGovernedTables {
		days := realDefaultDays(rt.dataType)
		mock.ExpectQuery("SELECT retention_days FROM audit_retention_defaults WHERE data_type = $1").
			WithArgs(rt.dataType).
			WillReturnRows(sqlmock.NewRows([]string{"retention_days"}).AddRow(days))

		overrideRows := sqlmock.NewRows([]string{"org_id", "retention_days"})
		if rt.dataType == "decision_chain" {
			overrideRows.AddRow(overrideOrg, subFloorDays)
		}
		mock.ExpectQuery("SELECT org_id, retention_days FROM audit_retention_config WHERE data_type = $1 AND is_active = true").
			WithArgs(rt.dataType).
			WillReturnRows(overrideRows)

		if rt.dataType == "decision_chain" {
			// per-org DELETE clamped UP to the 2555d floor (NOT the 30d override).
			mock.ExpectExec("DELETE FROM decision_chain WHERE org_id = $1 AND created_at < $2").
				WithArgs(overrideOrg, cutoffArg{days}). // cutoffArg{days}==floor, NOT subFloorDays
				WillReturnResult(sqlmock.NewResult(0, 1))
			// default bucket excluding the override org, also at the floor.
			mock.ExpectExec("DELETE FROM decision_chain WHERE created_at < $1 AND (org_id IS NULL OR NOT org_id = ANY($2))").
				WithArgs(cutoffArg{days}, sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 1))
		} else {
			mock.ExpectExec("DELETE FROM " + rt.table + " WHERE " + rt.tsColumn + " < $1").
				WithArgs(cutoffArg{days}).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}
	}

	if _, err := svc.CleanupRetentionGovernedAudits(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// TestRetention_InactiveOverrideUsesDefault asserts an is_active=false config row
// is NOT treated as an override: the query filters on is_active = true, so the
// org falls into the default bucket (no scoped delete, no exclusion). Mirrors
// get_effective_retention_days().
func TestRetention_InactiveOverrideUsesDefault(t *testing.T) {
	mock, svc, done := newRetentionMock(t)
	defer done()
	svc.SetRetentionEnforce(true)

	// The overrides query returns ZERO rows because is_active=true filters out
	// the inactive row at the DB. Programmed identically to the no-override pass
	// → the default bucket is a plain time-only DELETE (no ANY-exclusion).
	want := expectRetentionPass(mock, true, 2)

	results, err := svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var total int64
	for _, r := range results {
		total += r.Rows
	}
	if total != want {
		t.Errorf("total = %d, want %d", total, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// TestRetention_NilDB is a no-op guard.
func TestRetention_NilDB(t *testing.T) {
	svc := NewAuditCleanupService(nil, &mockLicenseChecker{})
	results, err := svc.CleanupRetentionGovernedAudits(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results with nil db, got %v", results)
	}
}

// TestRetention_AdminPoolRouting asserts retentionDB() prefers the injected
// BYPASSRLS admin pool and falls back to the primary pool otherwise.
func TestRetention_AdminPoolRouting(t *testing.T) {
	primary, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock primary: %v", err)
	}
	defer primary.Close()
	admin, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock admin: %v", err)
	}
	defer admin.Close()

	svc := NewAuditCleanupService(primary, &mockLicenseChecker{})
	if svc.retentionDB() != primary {
		t.Error("expected primary pool when no admin pool set")
	}
	svc.SetRetentionAdminDB(admin)
	if svc.retentionDB() != admin {
		t.Error("expected admin pool when set")
	}
}

// TestRetention_EnforceFlagFromEnv locks the env gate default-closed.
func TestRetention_EnforceFlagFromEnv(t *testing.T) {
	t.Setenv(EnvAuditRetentionEnforce, "")
	if auditRetentionEnforceEnabled() {
		t.Error("empty env should be dry-run (false)")
	}
	for _, v := range []string{"true", "TRUE", "1", "yes", "on", " On "} {
		t.Setenv(EnvAuditRetentionEnforce, v)
		if !auditRetentionEnforceEnabled() {
			t.Errorf("%q should enable enforce", v)
		}
	}
	for _, v := range []string{"false", "0", "no", "off", "maybe"} {
		t.Setenv(EnvAuditRetentionEnforce, v)
		if auditRetentionEnforceEnabled() {
			t.Errorf("%q should NOT enable enforce", v)
		}
	}
}
