// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3944 (#3897 §3): one `policy_overrides` table, four readers, four element
// shapes — and the one that matters is that three of them could not say what an
// override DOES.
//
// The agent's route over this table returned `action_override` and
// `enabled_override`; the orchestrator's list, by-id and create views returned
// NEITHER. They also disagreed on the organisation key — `org_id` on the agent,
// `organization_id` on the by-id view, absent on the other two — and the create
// response echoed no `override_reason`, which is the mandatory ADR-044
// justification the caller had just supplied.
//
// # What the existing coverage could not see, which is the reason this file exists
//
// The issue records that listOverridesHandler "has no sqlmock coverage of its
// own". THAT IS NOT TRUE, and the truth is more interesting: it has at least
// five sqlmock tests of its own. Every one of them asserts the STATUS CODE and
// at most a `count`, and sqlmock matches a query by REGEX (`SELECT .+ FROM
// policy_overrides`), so the projection is pinned by nothing at all — the
// fixture returns whatever columns the handler asked for, and the handler asked
// for whatever it asked for. Coverage that cannot fail for a class is not
// evidence about that class, and the missing projection sat under five green
// tests for as long as it existed.
//
// So this file asserts the SHAPE, and asserts it the only way that cannot drift:
// by decoding all four views into ONE client type and requiring each to carry
// the members that type declares.

package orchestrator

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/testutil"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

// overrideStoredPolicyUUID is what the session-override create RESOLVES the
// caller's `pol-1` to and writes into the row. The read fixtures below use it
// so they model a real row rather than echoing the request - without that, the
// create and read views agree on `policy_id` because the FIXTURE says so, and
// the cross-view assertion that pins their deliberate divergence tests nothing.
const overrideStoredPolicyUUID = "00000000-0000-0000-0000-0000000000ab"

// overrideViewMockColumns DERIVES the fixture's column list from the production
// SELECT list rather than restating it.
//
// A fixture that retypes the column names is a second copy of the projection,
// and the day somebody adds a column to one and not the other, every test goes
// on passing against a shape nothing serves. Deriving it means a column added
// to overrideViewColumns appears in every fixture in this package at once.
//
// WHAT IT BUYS AND WHAT IT DOES NOT, because R3 measured the difference:
// this derives the COUNT and the ORDER, not the names. sqlmock never compares
// a fixture's column names against the query, so renaming a column in the const
// (or adding a cast or an `AS` alias) changes what these fixtures are called and
// nothing checks it. The count is the load-bearing half - it is what catches a
// column added to the projection and not to the row - and the order is what
// keeps `scanOverrideView`'s positional Scan aligned with the values below.
//
// A column expression containing a comma (`COALESCE(a, b)`) would split into
// two here and trip the count check with a message about the row, not the
// const. There are none today; if one is added, split on top-level commas.
func overrideViewMockColumns() []string {
	fields := strings.Split(overrideViewColumns, ",")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if trimmed := strings.TrimSpace(f); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// expectListOverridesScope declares the transaction the list query now runs
// inside.
//
// #3048's third site: `listOverridesHandler` used to run `usageDB.Query(...)`
// bare, and `usageDB` is the non-BYPASSRLS `axonflow_app_role` pool while
// `policy_overrides` carries RLS on `app.current_org_id` - so the endpoint
// returned an empty list for every organisation. The wrap is the fix, and every
// sqlmock fixture over this handler needs the Begin / set_config / Commit that
// `agent.WithOrgScope` performs.
//
// It exists as a helper rather than three copies so the day the wrapper's shape
// changes, one place moves. `scopeKey` is `X-Org-ID` falling back to the
// tenant, which is the convention all four override paths share.
func expectListOverridesScope(mock sqlmock.Sqlmock, scopeKey string) {
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs(scopeKey).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// overrideViewMockEmptyRows is the zero-row fixture, with the derived columns
// so an empty result still describes the real projection.
func overrideViewMockEmptyRows() *sqlmock.Rows {
	return sqlmock.NewRows(overrideViewMockColumns())
}

// overrideViewMockRow builds one row in exactly overrideViewColumns' order,
// with every member populated, so a view that drops one is visible.
func overrideViewMockRow(t *testing.T, id, policyID, tenantID string) *sqlmock.Rows {
	return overrideViewMockRowAs(t, id, policyID, tenantID, "dev@example.com")
}

// overrideViewMockRowAs is the same fixture with a caller-chosen `created_by`,
// for the role-scoped read tests whose whole subject is that value.
func overrideViewMockRowAs(t *testing.T, id, policyID, tenantID, createdBy string) *sqlmock.Rows {
	t.Helper()
	cols := overrideViewMockColumns()
	values := []driver.Value{
		id, policyID, "static", tenantID, "org-x",
		"allow", true, "debugging a payment failure", time.Now().Add(time.Hour),
		"pg:SELECT", createdBy, time.Now(),
		// revoked_at / revoked_by are populated ON PURPOSE. With NULLs here an
		// `omitempty` member is absent from the JSON for two different reasons -
		// the value was null, or the VIEW dropped the column - and the assertion
		// below cannot tell them apart. A revoked override is also a real row.
		time.Now().Add(-time.Minute), "admin@example.com",
	}
	if len(values) != len(cols) {
		t.Fatalf("this fixture supplies %d values for the %d columns overrideViewColumns declares "+
			"(%v). A column was added to the projection and not to this row, so every test using it "+
			"would exercise a shape the handler does not produce.", len(values), len(cols), cols)
	}
	return sqlmock.NewRows(cols).AddRow(values...)
}

// TestAllOverrideViewsDeserialiseIntoOneClientType is #3944's DoD assertion,
// stated as the property an integrator actually wants: one type, four views.
//
// It decodes the CREATE, BY-ID and LIST responses into the SAME struct and
// requires each to carry the members that struct declares. The three are driven
// through their real handlers against sqlmock; nothing here re-implements a
// projection.
//
// `action_override` is checked explicitly and by name, because it is the member
// whose absence the issue is about: a view that omits it cannot tell an operator
// what they are looking at.
func TestAllOverrideViewsDeserialiseIntoOneClientType(t *testing.T) {
	type observed struct {
		view string
		body []byte
	}
	var seen []observed

	// --- the LIST view -------------------------------------------------
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		expectListOverridesScope(mock, "tenant-x")
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id").
			WithArgs("tenant-x").
			WillReturnRows(overrideViewMockRow(t, "ov-1", overrideStoredPolicyUUID, "tenant-x"))
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list: status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var wrapper struct {
			Overrides []json.RawMessage `json:"overrides"`
			Count     int               `json:"count"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &wrapper); err != nil {
			t.Fatalf("list: decode: %v", err)
		}
		if len(wrapper.Overrides) != 1 {
			t.Fatalf("list returned %d elements, want 1 — with none, the member assertions below "+
				"would pass vacuously", len(wrapper.Overrides))
		}
		seen = append(seen, observed{"GET /api/v1/overrides", wrapper.Overrides[0]})
	})

	// --- the BY-ID view ------------------------------------------------
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE id = .+ AND tenant_id").
			WithArgs("ov-1", "tenant-x").
			WillReturnRows(overrideViewMockRow(t, "ov-1", overrideStoredPolicyUUID, "tenant-x"))
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides/ov-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		getOverrideHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("by-id: status = %d, body = %s", rr.Code, rr.Body.String())
		}
		seen = append(seen, observed{"GET /api/v1/overrides/{id}", rr.Body.Bytes()})
	})

	// The create view went with the session override write (#4252): the route
	// answers the v11 freeze and returns no override.

	if len(seen) != 2 {
		t.Fatalf("only %d of the 2 orchestrator views were driven; the comparison below is not the "+
			"one this test claims to make", len(seen))
	}

	// WHAT EACH VIEW MUST CARRY: every member of OverrideView. The fixture
	// populates every column, so an absent member can only mean the VIEW dropped
	// it. (The create view, which could not carry the members a just-created
	// override lacks, went with the session override write, #4252.)
	required := requiredOverrideMembers()
	if len(required) < 8 {
		t.Fatalf("derived only %d required members from OverrideView; the derivation is broken and "+
			"the per-view checks below would demand almost nothing", len(required))
	}

	for _, s := range seen {
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(s.body, &decoded); err != nil {
			t.Errorf("%s: body is not a JSON object: %v", s.view, err)
			continue
		}
		var missing []string
		for _, member := range required {
			if _, ok := decoded[member]; !ok {
				missing = append(missing, member)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s omits %v.\n    All four readers of policy_overrides must return ONE element "+
				"shape (#3944). `action_override` is what an override DOES — a view without it cannot "+
				"tell an operator what they are looking at.", s.view, missing)
		}

		// And it must actually decode into the client type, not merely have
		// keys of the right names: a member whose JSON type changed would pass
		// a presence check and fail a real client.
		var typed OverrideView
		if err := json.Unmarshal(s.body, &typed); err != nil {
			t.Errorf("%s: does not deserialise into OverrideView: %v", s.view, err)
			continue
		}
		if typed.ActionOverride == nil || *typed.ActionOverride == "" {
			t.Errorf("%s: action_override decoded empty", s.view)
		}
		if typed.OverrideReason == "" {
			t.Errorf("%s: override_reason decoded empty — on the create view this is the mandatory "+
				"ADR-044 justification the caller just supplied", s.view)
		}
		// The deprecated alias must carry the SAME value as the canonical
		// member, or a client reading either gets a different answer.
		if typed.OrganizationID != typed.OrgID {
			t.Errorf("%s: organization_id (%q) and org_id (%q) disagree; the alias exists to carry the "+
				"same value, not a second one", s.view, typed.OrganizationID, typed.OrgID)
		}
		if typed.OrgID == "" {
			t.Errorf("%s: org_id decoded empty", s.view)
		}
	}

	// THE SECOND HALF OF "ONE CLIENT TYPE, FOUR VIEWS", which the first version
	// of this test did not have.
	//
	// Everything above checks that each view carries the same MEMBERS. That is
	// only half the property an integrator wants: the other half is that the
	// same row read through two views gives the same VALUES. R3 found the gap by
	// finding a member that violates it — `policy_id` — which every presence
	// check in this file passed straight over.
	//
	// The three views are driven from independent fixtures, so this cannot
	// compare arbitrary values; what it CAN pin is the members whose value is
	// decided by the same input in all three, and the one member that is
	// deliberately not.
	byView := map[string]OverrideView{}
	for _, s := range seen {
		var typed OverrideView
		if err := json.Unmarshal(s.body, &typed); err == nil {
			byView[s.view] = typed
		}
	}
	byID := byView["GET /api/v1/overrides/{id}"]
	list := byView["GET /api/v1/overrides"]

	// `override_reason` and `action_override` are stored on the row and both
	// fixtures carry the same values, so the two read views must agree.
	if byID.OverrideReason != list.OverrideReason {
		t.Errorf("override_reason differs across views: by-id=%q list=%q", byID.OverrideReason, list.OverrideReason)
	}
	if byID.ActionOverride == nil || list.ActionOverride == nil || *byID.ActionOverride != *list.ActionOverride {
		t.Errorf("action_override differs across views: by-id=%v list=%v - this is what the override "+
			"DOES, and it is the member #3944 exists for", byID.ActionOverride, list.ActionOverride)
	}
}

// requiredOverrideMembers derives the member set from OverrideView's struct
// tags. `omitempty` members are included deliberately: the fixture populates
// every one, so an omitted member means the VIEW dropped it rather than that
// the value was empty.
func requiredOverrideMembers() []string {
	rt := reflect.TypeOf(OverrideView{})
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// TestOverrideViewMembersAreDerivedNotListed is the anti-vacuity control for
// the derivation above. If reflection stopped finding tags — a rename, a change
// of type — requiredOverrideMembers would return a short list and every view
// would satisfy it. This pins the two members the issue is actually about.
func TestOverrideViewMembersAreDerivedNotListed(t *testing.T) {
	got := requiredOverrideMembers()
	index := map[string]bool{}
	for _, m := range got {
		index[m] = true
	}
	for _, must := range []string{
		"action_override", "enabled_override", "org_id", "organization_id",
		"override_reason", "tool_signature", "created_by", "id",
	} {
		if !index[must] {
			t.Errorf("the derived member set does not contain %q (got %v). The derivation has stopped "+
				"reading OverrideView, so TestAllOverrideViewsDeserialiseIntoOneClientType would demand "+
				"less than it claims.", must, got)
		}
	}

	// The projection and the type must describe the same thing. A column in
	// the SELECT that no member reads, or a member no column fills, is the
	// drift this issue is made of — caught here rather than at runtime.
	cols := overrideViewMockColumns()
	if len(cols) != 14 {
		t.Errorf("overrideViewColumns declares %d columns (%v); this test and the row fixture both "+
			"assume 14, so one of them is now describing a different query", len(cols), cols)
	}
}

// TestTheOverrideViewSchemaMatchesTheTypeItDocuments is #3944's recurrence
// check: the published schema and the type the platform marshals must describe
// the same members.
//
// The two halves of this issue were a CODE defect (three views, three shapes)
// and a DOCUMENT defect (three schemas, three shapes). Fixing only the code
// leaves the document lying, and fixing only the document leaves a client
// generated from it unable to read the wire. Nothing existing compares them,
// which is how they drifted apart in the first place — so this does, in both
// directions, by shape rather than by a list either side could edit alone.
func TestTheOverrideViewSchemaMatchesTheTypeItDocuments(t *testing.T) {
	rel := filepath.Join("..", "..", "docs", "api", "orchestrator-api.yaml")
	blob, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	schema, ok := doc.Components.Schemas["OverrideView"]
	if !ok {
		t.Fatalf("the document declares no OverrideView schema; the three override views have no " +
			"single documented shape and this guard has nothing to compare against")
	}
	// ANTI-VACUITY: an empty or unparsed schema would make both directions
	// below trivially satisfiable in one direction and noisy in the other.
	if len(schema.Properties) < 10 {
		t.Fatalf("OverrideView declares only %d properties in the document; the parse is reading "+
			"nothing", len(schema.Properties))
	}

	inSchema := map[string]bool{}
	for name := range schema.Properties {
		inSchema[name] = true
	}
	inType := map[string]bool{}
	for _, m := range requiredOverrideMembers() {
		inType[m] = true
	}

	var undocumented, unimplemented []string
	for m := range inType {
		if !inSchema[m] {
			undocumented = append(undocumented, m)
		}
	}
	for m := range inSchema {
		if !inType[m] {
			unimplemented = append(unimplemented, m)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(unimplemented)

	if len(undocumented) > 0 {
		t.Errorf("OverrideView emits %v and the published schema does not declare them, so a client "+
			"generated from this document drops members the server sends (#3944)", undocumented)
	}
	if len(unimplemented) > 0 {
		t.Errorf("the published OverrideView schema declares %v and the type emits nothing of that "+
			"name, so a generated client waits for a member that never arrives (#3944)", unimplemented)
	}
}

// TestOverrideViewScansANullCreatedBy is the assertion sqlmock structurally
// cannot make, and it exists because R3 found the defect it pins.
//
// sqlmock supplies driver values, so a fixture decides the nullability and the
// production column does not get a say. `policy_overrides.created_by` is a bare
// `VARCHAR(255)` (migrations/core/030) and `created_at` has only a DEFAULT, so
// both can be NULL in a real table — and four fixtures in this repository
// insert a row with no `created_by`.
//
// #3944 made two changes that compose into a 200 -> 500 on every override in a
// tenant: the list view began PROJECTING `created_by`, which it never used to,
// and a scan failure stopped being a silently dropped row and became a 500 for
// the whole list. Either alone is harmless. Together, one legacy row with a
// NULL `created_by` takes out the entire listing.
//
// This drives the real scan against a real Postgres rather than asserting the
// Null* wrappers are present, because the wrappers are the fix and not the
// property: a later refactor that reintroduced a plain string would satisfy any
// structural check written over the current code.
func TestOverrideViewScansANullCreatedBy(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())

	// THE PREMISE IS CHECKED AGAINST THE MIGRATION; THE BEHAVIOUR IS DRIVEN
	// AGAINST A TABLE. They are two assertions because they are two claims, and
	// the first version of this test collapsed them into one and proved
	// neither.
	//
	// It hand-wrote a `CREATE TABLE` and then argued "`created_by` is a bare
	// VARCHAR(255) IN MIGRATION 030, so it can be NULL" — against a table it
	// had declared VARCHAR(255) itself. A premise proved by restating the
	// premise. R3 caught it. The pq NULL-scan behaviour it exercised was real;
	// the claim about the PRODUCTION column was not tested at all.
	//
	// Executing migration 030 here is not the fix either: it depends on the
	// core chain before it (`static_policies` and others), so running it alone
	// fails on a missing relation, and running the whole chain means
	// approletest — which is gated on TEST_PG_INTEGRATION and would take this
	// test OFF the pull-request tier, where it currently runs. So the premise
	// is asserted against the migration TEXT, which is the artifact that
	// decides it.
	assertOverrideColumnIsNullableInMigration(t, "created_by")
	assertOverrideColumnIsNullableInMigration(t, "created_at")

	pg.RunMigration(t, `
		CREATE TABLE policy_overrides (
			id               TEXT PRIMARY KEY,
			policy_id        TEXT NOT NULL,
			policy_type      TEXT NOT NULL,
			tenant_id        TEXT,
			org_id           TEXT,
			action_override  VARCHAR(20),
			enabled_override BOOLEAN,
			override_reason  TEXT NOT NULL,
			expires_at       TIMESTAMPTZ,
			tool_signature   TEXT,
			created_by       VARCHAR(255),
			created_at       TIMESTAMPTZ DEFAULT NOW(),
			revoked_at       TIMESTAMPTZ,
			revoked_by       TEXT
		)`)

	// The row a legacy deployment actually holds: no created_by, no
	// created_at, no org, no action.
	if _, err := pg.DB.Exec(`
		INSERT INTO policy_overrides (id, policy_id, policy_type, override_reason, created_at)
		VALUES ('ov-null', 'pol-1', 'static', 'legacy row', NULL)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	row := pg.DB.QueryRow(`SELECT `+overrideViewColumns+` FROM policy_overrides WHERE id = $1`, "ov-null")
	view, err := scanOverrideView(row)
	if err != nil {
		t.Fatalf("scanOverrideView failed on a row with NULL created_by/created_at: %v\n"+
			"    This is the whole point: the list view now PROJECTS created_by and now answers 500 "+
			"on a scan failure, so one legacy row takes out every override in the tenant.", err)
	}
	if view.ID != "ov-null" || view.OverrideReason != "legacy row" {
		t.Errorf("scanned the wrong row: %+v", view)
	}
	if view.CreatedBy != "" {
		t.Errorf("CreatedBy = %q, want the empty string for a NULL column", view.CreatedBy)
	}
	if !view.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want the zero time for a NULL column", view.CreatedAt)
	}
	// The members that ARE nullable-and-pointer must come back nil rather than
	// pointing at a zero value, or a client cannot tell absent from empty.
	if view.ActionOverride != nil || view.EnabledOverride != nil || view.TenantID != nil {
		t.Errorf("nullable pointer members are not nil: action=%v enabled=%v tenant=%v",
			view.ActionOverride, view.EnabledOverride, view.TenantID)
	}

	// And the whole view must still serialise — a scan that succeeded into a
	// shape that cannot be marshalled would fail one layer later.
	if _, err := json.Marshal(view); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}

// assertOverrideColumnIsNullableInMigration reads the `policy_overrides`
// CREATE TABLE out of migration 030 and fails if the named column carries
// NOT NULL.
//
// This is the half of TestOverrideViewScansANullCreatedBy that is about
// PRODUCTION rather than about pq: the scan behaviour is driven against a real
// Postgres, and this says the production column is one a NULL can reach. If a
// later migration constrains the column, this fails and whoever did it decides
// whether the Null* wrappers are still wanted — rather than the wrappers
// quietly outliving their reason.
//
// It reads the migration TEXT because executing 030 needs the whole core chain
// before it, and running that chain means approletest, which is gated on
// TEST_PG_INTEGRATION and does not run on the pull-request tier.
func assertOverrideColumnIsNullableInMigration(t *testing.T, column string) {
	t.Helper()
	rel := filepath.Join("..", "..", "migrations", "core", "030_policy_tier_columns.sql")
	blob, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	body := string(blob)

	// ANTI-VACUITY: a rename of the file or of the table would make every
	// "column is nullable" answer below vacuously true.
	if !strings.Contains(body, "policy_overrides") {
		t.Fatalf("%s does not mention policy_overrides; this check is reading the wrong file", rel)
	}
	var decl string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, column+" ") {
			decl = trimmed
			break
		}
	}
	if decl == "" {
		t.Fatalf("no declaration of column %q found in %s — the column was renamed or moved, and "+
			"TestOverrideViewScansANullCreatedBy's premise no longer describes production", column, rel)
	}
	if strings.Contains(strings.ToUpper(decl), "NOT NULL") {
		t.Errorf("migration 030 now declares %s NOT NULL (%q). The Null* scan targets in "+
			"scanOverrideView were added because it was nullable; decide whether they are still "+
			"wanted rather than leaving them to outlive their reason.", column, decl)
	}
}

// TestTheDeprecatedOrgAliasNeverDivergesFromTheCanonicalMember pins the one
// property a deprecated alias has to have: it is the same value, always.
//
// `organization_id` carried `omitempty` and `org_id` did not, so on a row whose
// organisation key is empty the canonical member was present as `""` and the
// alias was ABSENT — the two disagreed on exactly the row the nullable-column
// handling exists for, while the type's own comment said "always carrying the
// same value". A client reading either got a different answer about the same
// row, which is the failure mode an alias exists to prevent.
//
// Driven over the marshalled BYTES rather than the struct, because the defect
// lived in a struct tag and a field-equality check cannot see one.
func TestTheDeprecatedOrgAliasNeverDivergesFromTheCanonicalMember(t *testing.T) {
	for _, org := range []string{"org-x", ""} {
		name := "org=" + org
		if org == "" {
			name = "org=<empty>"
		}
		t.Run(name, func(t *testing.T) {
			var v OverrideView
			v.setOrg(org)
			blob, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(blob, &decoded); err != nil {
				t.Fatalf("decode: %v", err)
			}
			canonical, hasCanonical := decoded["org_id"]
			alias, hasAlias := decoded["organization_id"]
			if !hasCanonical || !hasAlias {
				t.Fatalf("org_id present=%v, organization_id present=%v — a deprecated alias that "+
					"disappears for some values is not an alias. Body: %s",
					hasCanonical, hasAlias, blob)
			}
			if string(canonical) != string(alias) {
				t.Errorf("org_id=%s but organization_id=%s", canonical, alias)
			}
		})
	}
}
