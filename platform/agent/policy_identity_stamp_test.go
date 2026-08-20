// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedaudit "axonflow/platform/shared/audit"
	sharedpolicy "axonflow/platform/shared/policy"
)

// ---------------------------------------------------------------------------
// stampPolicyIdentityNames (#3365): the single writer-side name normalizer.
// ---------------------------------------------------------------------------

func TestStampPolicyIdentityNames_EvalNameWinsOverBuiltin(t *testing.T) {
	details := map[string]interface{}{}
	stampPolicyIdentityNames(details,
		[]string{"circuit_breaker"},
		map[string]string{"circuit_breaker": "Threaded Name"})
	names, ok := details["policy_names"].([]string)
	if !ok || len(names) != 1 || names[0] != "Threaded Name" {
		t.Fatalf("evaluation-time name must win over the builtin table, got %v", details["policy_names"])
	}
}

func TestStampPolicyIdentityNames_BuiltinFillAndUnknownSkipped(t *testing.T) {
	details := map[string]interface{}{}
	stampPolicyIdentityNames(details,
		[]string{"rbi_kill_switch", "some_unknown_policy", "sys_pii_iban"},
		map[string]string{"sys_pii_iban": "IBAN Detection"})
	names, _ := details["policy_names"].([]string)
	if len(names) != 2 {
		t.Fatalf("expected 2 names (builtin + threaded, unknown skipped), got %v", names)
	}
	if names[0] != "RBI kill switch" || names[1] != "IBAN Detection" {
		t.Fatalf("names must follow policy_ids order: %v", names)
	}
}

func TestStampPolicyIdentityNames_NoResolvableName_OmitsKey(t *testing.T) {
	details := map[string]interface{}{}
	stampPolicyIdentityNames(details, []string{"totally_unknown"}, nil)
	if _, present := details["policy_names"]; present {
		t.Fatalf("an unresolvable id must NOT create a policy_names key (ids-only rows keep the reader's marker)")
	}
	stampPolicyIdentityNames(details, nil, map[string]string{"x": "X"})
	if _, present := details["policy_names"]; present {
		t.Fatalf("empty policy_ids must not stamp names")
	}
}

func TestStampPolicyIdentityNames_DuplicateNamesCollapse(t *testing.T) {
	// user_token_rejected and user_token_invalid share one builtin label; the
	// display list mirrors the reader's joinLabels de-duplication.
	details := map[string]interface{}{}
	stampPolicyIdentityNames(details, []string{"user_token_rejected", "user_token_invalid"}, nil)
	names, _ := details["policy_names"].([]string)
	if len(names) != 1 || names[0] != "User token validation guard" {
		t.Fatalf("duplicate display names must collapse: %v", names)
	}
}

func TestPolicyNamesFromMatches_SkipsEmptyAndFirstWins(t *testing.T) {
	m := policyNamesFromMatches([]sharedpolicy.PolicyMatch{
		{PolicyID: "a", PolicyName: "First"},
		{PolicyID: "a", PolicyName: "Second"},
		{PolicyID: "b", PolicyName: ""},
		{PolicyID: "", PolicyName: "orphan"},
	})
	if len(m) != 1 || m["a"] != "First" {
		t.Fatalf("first-wins per id, empties skipped: %v", m)
	}
	if policyNamesFromMatches(nil) != nil {
		t.Fatalf("nil matches must return nil")
	}
}

func TestPolicyNamesFromDynamic(t *testing.T) {
	m := policyNamesFromDynamic(&sharedpolicy.DynamicPolicyInfo{
		MatchedPolicies: []sharedpolicy.DynamicPolicyMatch{
			{PolicyID: "dyn-1", PolicyName: "Rate limit"},
			{PolicyID: "dyn-2"},
		},
	})
	if len(m) != 1 || m["dyn-1"] != "Rate limit" {
		t.Fatalf("dynamic names: %v", m)
	}
	if policyNamesFromDynamic(nil) != nil {
		t.Fatalf("nil info must return nil")
	}
}

func TestMergePolicyNames_DstWins(t *testing.T) {
	dst := map[string]string{"a": "keep"}
	got := mergePolicyNames(dst, map[string]string{"a": "lose", "b": "add"})
	if got["a"] != "keep" || got["b"] != "add" {
		t.Fatalf("dst entries must win: %v", got)
	}
	if mergePolicyNames(nil, nil) != nil {
		t.Fatalf("nil+nil must stay nil")
	}
}

// ---------------------------------------------------------------------------
// stampMissingPolicyVersions (#3365): post-merge, missing-only, best-effort.
// ---------------------------------------------------------------------------

func TestStampMissingPolicyVersions_AddsMissingOnly_FinCrimeEntryWins(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// fincrime_ml_fraud_score already carries the seam's MODEL version string;
	// only sys_pii_iban may be looked up, and the existing entry must survive
	// untouched (the demo-critical interaction: a write-time row-version
	// lookup must never displace the scorer's model version).
	mock.ExpectQuery("SELECT policy_id, version").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"policy_id", "version"}).AddRow("sys_pii_iban", 3))

	details := map[string]interface{}{
		"policy_ids":      []string{"sys_pii_iban", "fincrime_ml_fraud_score", "circuit_breaker"},
		"policy_versions": map[string]interface{}{"fincrime_ml_fraud_score": "0.1.0"},
	}
	stampMissingPolicyVersions(context.Background(), db, details)

	versions, ok := details["policy_versions"].(map[string]interface{})
	if !ok {
		t.Fatalf("policy_versions missing/retyped: %T", details["policy_versions"])
	}
	if versions["fincrime_ml_fraud_score"] != "0.1.0" {
		t.Fatalf("existing (fincrime seam) version must win: %v", versions)
	}
	if versions["sys_pii_iban"] != 3 {
		t.Fatalf("missing id must gain its row version: %v", versions)
	}
	if _, has := versions["circuit_breaker"]; has {
		t.Fatalf("builtin guard ids have no row and must not be queried/stamped: %v", versions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestStampMissingPolicyVersions_AllBuiltinOrCovered_NoQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	// No ExpectQuery: any DB round trip fails the test via ExpectationsWereMet
	// plus the unexpected-call error path leaving no policy_versions.

	details := map[string]interface{}{
		"policy_ids":      []string{"circuit_breaker", "covered"},
		"policy_versions": map[string]interface{}{"covered": 7},
	}
	stampMissingPolicyVersions(context.Background(), db, details)
	versions := details["policy_versions"].(map[string]interface{})
	if len(versions) != 1 || versions["covered"] != 7 {
		t.Fatalf("nothing to look up: map must be untouched, got %v", versions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no DB call expected: %v", err)
	}
}

func TestStampMissingPolicyVersions_DBErrorDegradesToNoKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	mock.ExpectQuery("SELECT policy_id, version").WillReturnError(os.ErrDeadlineExceeded)

	details := map[string]interface{}{"policy_ids": []string{"sys_pii_iban"}}
	stampMissingPolicyVersions(context.Background(), db, details)
	if _, has := details["policy_versions"]; has {
		t.Fatalf("a failed lookup must not create a policy_versions key")
	}
}

func TestStampMissingPolicyVersions_JSONRoundTripShapes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	mock.ExpectQuery("SELECT policy_id, version").
		WillReturnRows(sqlmock.NewRows([]string{"policy_id", "version"}).AddRow("b", 2))

	// []interface{} ids + map[string]string versions: the shapes a details map
	// can carry after a fincrime merge / defensive re-decode.
	details := map[string]interface{}{
		"policy_ids":      []interface{}{"a", "b"},
		"policy_versions": map[string]string{"a": "1"},
	}
	stampMissingPolicyVersions(context.Background(), db, details)
	versions := details["policy_versions"].(map[string]interface{})
	if versions["a"] != "1" || versions["b"] != 2 {
		t.Fatalf("coerced shapes must merge: %v", versions)
	}
}

// ---------------------------------------------------------------------------
// Builtin-table census guards.
// ---------------------------------------------------------------------------

// TestBuiltinPolicyDisplayNames_NeverShadowSeededPolicies walks every core
// migration and fails if a builtin guard id ever appears as a seeded
// static_policies policy_id: the builtin table exists precisely because these
// ids have NO row, and a collision would let the code-defined name mask a
// customer-visible seeded display name.
func TestBuiltinPolicyDisplayNames_NeverShadowSeededPolicies(t *testing.T) {
	// Scan EVERY seed location (all migration trees + the ee policy packs),
	// and scan the WHOLE FILE of any .sql that inserts into static_policies:
	// statement-level extraction was tried and failed open (a regex pattern
	// containing a semicolon truncated the captured statement; industry
	// migrations were skipped entirely). Whole-file scanning over-approximates
	// toward failing CLOSED - a false positive here is a prompt to inspect,
	// never a silent miss.
	roots := []string{
		filepath.Join("..", "..", "migrations"),
		filepath.Join("..", "..", "ee", "policy-packs"),
	}
	var seedFiles []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".sql") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(strings.ToLower(string(b)), "insert into static_policies") {
				seedFiles = append(seedFiles, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(seedFiles) == 0 {
		t.Fatalf("guard self-check: no static_policies seed files found; the scan is broken and every assertion below would be vacuous")
	}
	var corpus strings.Builder
	for _, f := range seedFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		corpus.Write(b)
		corpus.WriteString("\n")
	}
	sql := corpus.String()
	// Self-checks: the corpus must SEE known seeded rows from each tree it
	// claims to cover, or the extraction is broken.
	for _, known := range []string{"'sys_pii_indonesia_ktp'", "'fincrime_payment_tool_authorization_gate'"} {
		if !strings.Contains(sql, known) {
			t.Fatalf("guard self-check: %s not visible in the scanned corpus; the scan is broken and every assertion below would be vacuous", known)
		}
	}
	for id := range builtinPolicyDisplayNames {
		// A seeded row would carry the id as a quoted SQL literal.
		if strings.Contains(sql, "'"+id+"'") {
			t.Errorf("builtin guard id %q appears in a static_policies seed file: it may now be a seeded policy row whose real display name this table would shadow; remove it from builtinPolicyDisplayNames and thread the evaluation-time name instead (or, if this is a non-policy literal in a seed file, inspect and adjust the guard deliberately)", id)
		}
	}
}

func TestBuiltinPolicyDisplayNames_NonEmptyValues(t *testing.T) {
	for id, name := range builtinPolicyDisplayNames {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" {
			t.Errorf("builtin table entry %q -> %q must be non-empty", id, name)
		}
	}
}

// ---------------------------------------------------------------------------
// Writer-level pin: writeDecisionAuditLog end to end (#3365) - the version
// SELECT runs before the INSERT, and the marshaled policy_details carries
// policy_names + policy_versions for the same ids as policy_ids.
// ---------------------------------------------------------------------------

type captureJSONArg struct{ dst *[]byte }

func (c captureJSONArg) Match(v driver.Value) bool {
	switch t := v.(type) {
	case []byte:
		*c.dst = append((*c.dst)[:0], t...)
		return true
	case string:
		*c.dst = []byte(t)
		return true
	}
	return false
}

func TestWriteDecisionAuditLog_StampsNamesAndVersions(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT policy_id, version").
		WillReturnRows(sqlmock.NewRows([]string{"policy_id", "version"}).
			AddRow("sys_pii_indonesia_ktp", 2))

	var detailsJSON []byte
	args := make([]driver.Value, 20)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13] = captureJSONArg{dst: &detailsJSON} // policy_details (14th INSERT arg)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	writeDecisionAuditLog(context.Background(), db,
		"dec-e2e-3365", "org-1", "tenant-1", "llm", "blocked",
		[]string{"sys_pii_indonesia_ktp", "rbi_kill_switch"},
		[]string{"blocked by policy"},
		nil, false,
		decisionAuditInput{policyNames: map[string]string{
			"sys_pii_indonesia_ktp": "Indonesian KTP Detection",
		}})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected version SELECT then audit INSERT: %v", err)
	}
	var details map[string]interface{}
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		t.Fatalf("policy_details not JSON: %v (raw=%s)", err, detailsJSON)
	}
	names, _ := details["policy_names"].([]interface{})
	if len(names) != 2 || names[0] != "Indonesian KTP Detection" || names[1] != "RBI kill switch" {
		t.Fatalf("policy_names not persisted: %v", details["policy_names"])
	}
	versions, _ := details["policy_versions"].(map[string]interface{})
	if len(versions) != 1 || versions["sys_pii_indonesia_ktp"] != float64(2) {
		t.Fatalf("policy_versions not persisted (builtin guard id must have no entry): %v", details["policy_versions"])
	}
	// Reader round trip: the exporters resolve id AND version from this row.
	id, ver := sharedaudit.ExtractPolicyIdentity(detailsJSON)
	if id != "sys_pii_indonesia_ktp" || ver != "2" {
		t.Fatalf("shared reader must resolve id+version from the written shape: got (%q, %q)", id, ver)
	}
}

func TestWriteDecisionAuditLog_AllowVerdictSkipsVersionLookup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()
	// ONLY the INSERT is expected: an allow write must not pay the version
	// batch read (acted-verdict gate). An unexpected SELECT would surface via
	// ExpectationsWereMet ordering.
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	writeDecisionAuditLog(context.Background(), db,
		"dec-allow-3365", "org-1", "tenant-1", "llm", "allow",
		[]string{"sys_pii_indonesia_ktp"}, nil, nil, false,
		decisionAuditInput{policyNames: map[string]string{"sys_pii_indonesia_ktp": "Indonesian KTP Detection"}})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("allow write must be a single INSERT with no version SELECT: %v", err)
	}
}

func TestActedAuditVerdict(t *testing.T) {
	for v, want := range map[string]bool{
		"blocked": true, "deny": true, "redacted": true, "needs_approval": true,
		"allow": false, "allowed": false, "error": false, "": false,
	} {
		if got := actedAuditVerdict(v); got != want {
			t.Errorf("actedAuditVerdict(%q) = %v, want %v", v, got, want)
		}
	}
}
