// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/rls"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
	"axonflow/platform/shared/authoringvocabulary"
)

// THE POSTURE IS DRIVEN IN BOTH DIRECTIONS AGAINST A REAL DATABASE (#3975).
//
// #3975 was measured on a booted Community stack: publish and activate both
// returned 200 and `GET /active` returned 404 after a restart, because
// migrations/enterprise/155 never ran there and the route built the in-process
// store. The fix is migrations/core/176 plus the durable backend reaching this
// route, and what makes the fix checkable is that /edition now REPORTS which
// store is in force.
//
// # Why both directions, in one file, on one handler shape
//
// A test that only drove the configured case would pass on a handler that
// reported "database" unconditionally - which is the same defect one level up,
// and the exact shape the portal's own comment records: `"persistence":
// "process"` was a LITERAL there and kept saying "process" after the durable
// store was wired. A field that cannot observe the thing it names is worse
// than no field, because it is believed. So the nil-db direction is asserted
// here too, and it is a legitimate posture rather than a failure: no
// DATABASE_URL, or a connection that failed, keeps the in-process store, which
// is precisely what shipped before #3975.
//
// # And why a row is counted rather than the label trusted
//
// `persistence: "database"` is a claim about storage, and the cheapest way for
// it to be false is for the label to be right while nothing was written.
// workspaceFor only marks a workspace durable after authoringstore.New,
// AuthorizeKey and LoadTrust have all succeeded - AuthorizeKey being the first
// step that actually touches the database - so this asserts the signing-key row
// EXISTS for the organization the request was stamped with. Without that, a
// regression which reordered those steps would keep this test green while
// producing artifacts whose signing key was recorded nowhere.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).

// realPGRouteHandler builds the route handler over a supplied connection.
//
// It mirrors newRouteHandler rather than calling it, because that helper hard-
// codes the in-process posture (db: nil) which is one of the two things under
// test here. Both literals name db explicitly, as
// TestEveryTypedAuthoringHandlerLiteralDeclaresItsDB requires.
func realPGRouteHandler(t *testing.T, db *sql.DB) *TypedAuthoringRouteHandler {
	t.Helper()
	// THE DEPLOYMENT VOCABULARY, resolved through the handler's own lazy path
	// (#3895). It was the conformance FIXTURE, which may be published against
	// and can never be ACTIVATED - and this suite drives activation, so a
	// fixture here would make it assert the fixture refusal instead of the
	// persistence posture it names.
	h := &TypedAuthoringRouteHandler{
		db:           db,
		catalogValue: authoringcatalog.SourceDeployment,
		deploymentFor: func() authoringvocabulary.CatalogDeployment {
			return authoringvocabulary.CatalogDeployment{HasDirectory: true}
		},
		profileFor:     func(context.Context) authoring.Profile { return mustProfile(t, authoring.EditionCommunity) },
		workspaces:     map[string]*typedAuthoringWorkspace{},
		openForSigning: authoringstore.OpenForSigning,
	}
	if snap, err := h.vocabulary(); err != nil || snap == nil {
		t.Fatalf("the deployment vocabulary must resolve: %v", err)
	}
	return h
}

// editionPosture drives GET /edition and returns the two posture fields.
func editionPosture(t *testing.T, h *TypedAuthoringRouteHandler) (persistence, custody string, status int) {
	t.Helper()
	rr := call(t, routerFor(h), http.MethodGet, TypedAuthoringRoutePrefix+"/edition", nil, gatewayHeaders())
	if rr.Code != http.StatusOK {
		return "", "", rr.Code
	}
	var body struct {
		Persistence string `json:"persistence"`
		Custody     string `json:"signing_key_custody"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding /edition: %v; body=%s", err, rr.Body.String())
	}
	return body.Persistence, body.Custody, rr.Code
}

func TestTheEditionEndpointReportsTheDurablePostureBothWays_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	// THE premise: FORCE RLS binds a non-owner, and the durable path runs every
	// statement inside rls.WithOrgScope. As the owner, none of it would be
	// evidence.
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	// ANTI-VACUITY: the tables must exist from migrations/core ALONE. That is
	// #3975's claim, and if core/176 were absent the durable direction below
	// would fall back and report "process" for a reason that has nothing to do
	// with the code under test.
	for _, table := range []string{"typed_policy_artifacts", "typed_policy_activations", "typed_policy_signing_keys"} {
		var present bool
		if err := appDB.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Fatalf("%s does not exist after applying migrations/core alone; core/176 is what makes typed authoring durable on every edition (#3975)", table)
		}
	}

	t.Run("with a database it reports database", func(t *testing.T) {
		h := realPGRouteHandler(t, appDB)
		persistence, custody, status := editionPosture(t, h)
		if status != http.StatusOK {
			t.Fatalf("/edition answered %d", status)
		}
		if persistence != "database" {
			t.Errorf("persistence is %q with a live connection and migrations/core/176 applied; expected \"database\". "+
				"workspaceFor marks a workspace durable only after New, AuthorizeKey and LoadTrust all succeed, so this "+
				"reports the store a publish would actually get", persistence)
		}
		// The private half never leaves the process, whatever the storage says.
		if custody != "process" {
			t.Errorf("signing_key_custody is %q, expected \"process\": each process mints its own key and records only "+
				"the public half, so custody does not change when persistence does", custody)
		}

		// THE LABEL IS NOT THE EVIDENCE. AuthorizeKey is the first step that
		// touches the database, so a row for this org proves the durable chain
		// ran rather than that a boolean was set.
		//
		// COUNTED INSIDE AN ORG SCOPE, BECAUSE THAT IS HOW PRODUCTION READS.
		// The first version of this counted on the bare pool and got 0 for every
		// organization, then reported that the workspace had claimed durability
		// without writing anything. It had written: typed_policy_signing_keys is
		// FORCE ROW LEVEL SECURITY on `org_id = current_setting(
		// 'app.current_org_id', true)`, which is NULL when the GUC is unset, so
		// every row is invisible and the count is a confident zero. Here that
		// produced a false FAILURE; the same mistake on a check that EXPECTED
		// zero would have produced a false pass, silently, forever.
		var scoped int
		if err := rls.WithOrgScope(context.Background(), appDB, testOrg, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT count(*) FROM typed_policy_signing_keys WHERE org_id = $1`, testOrg).Scan(&scoped)
		}); err != nil {
			t.Fatalf("counting signing keys inside the org scope: %v", err)
		}
		if scoped == 0 {
			t.Error("persistence reports \"database\" but no signing-key row exists for this organization; the workspace " +
				"claimed durability without AuthorizeKey having written anything, which would produce artifacts whose " +
				"signing key is recorded nowhere")
		}

		// AND THE UNSCOPED READ IS ASSERTED TO BE BLIND, so the instrument's own
		// failure mode is pinned rather than remembered. If this ever returns a
		// row, the isolation this whole surface depends on has stopped binding -
		// and the scoped count above would stop being evidence of anything.
		var unscoped int
		if err := appDB.QueryRow(`SELECT count(*) FROM typed_policy_signing_keys`).Scan(&unscoped); err != nil {
			t.Fatalf("counting signing keys without a scope: %v", err)
		}
		if unscoped != 0 {
			t.Errorf("an unscoped read returned %d signing-key row(s); FORCE ROW LEVEL SECURITY must hide every row from "+
				"a connection that has set no org scope, and this test's scoped count is only meaningful because it does", unscoped)
		}
	})

	// A RESTART IS A NEW PROCESS WITH A NEW KEY, AND THAT IS THE CASE THAT
	// BROKE. Clearing the workspace cache is what a restart does to this
	// handler: the next resolve mints a fresh ephemeral key and re-authorizes
	// against a database that already holds the previous process's row.
	//
	// With the key identifier derived from the ORGANIZATION alone, the second
	// build presented the same id with different material, AuthorizeKey refused
	// it (ErrKeyAlreadyAuthorized, whose read-back exists precisely to stop one
	// process taking over another's identity), the chain fell back to the
	// in-process store, and a publication made before the restart was
	// unreachable after it - #3975's symptom reintroduced by its own fix. It
	// survived every unit test and every single-boot integration test, because
	// the durable store works exactly once per organization.
	//
	// Deriving the identifier from the public key fixes it, and this asserts the
	// property rather than the format: durability must survive a rebuild.
	t.Run("durability survives a new process minting a new key", func(t *testing.T) {
		h := realPGRouteHandler(t, appDB)

		first, _, status := editionPosture(t, h)
		if status != http.StatusOK || first != "database" {
			t.Fatalf("the first workspace build reports persistence=%q (status %d); the restart case below is only meaningful from a durable start", first, status)
		}

		// What a restart does: the process's in-memory workspaces are gone,
		// the database rows are not.
		h.mu.Lock()
		h.workspaces = map[string]*typedAuthoringWorkspace{}
		h.mu.Unlock()

		second, _, status := editionPosture(t, h)
		if status != http.StatusOK {
			t.Fatalf("/edition answered %d after the workspace cache was cleared", status)
		}
		if second != "database" {
			t.Errorf("persistence is %q after a rebuild that minted a new key, expected \"database\". "+
				"A second process re-authorizing under a key identifier that is fixed per organization is refused "+
				"(ErrKeyAlreadyAuthorized) and falls back to the in-process store - which makes durable storage work "+
				"exactly once per organization and loses every publication across a restart (#3975)", second)
		}

		// AND BOTH KEYS ARE RECORDED, not one replaced by the other: LoadTrust
		// returns every authorized key, which is what lets an artifact signed by
		// the previous process still verify in this one.
		var keys int
		if err := rls.WithOrgScope(context.Background(), appDB, testOrg, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT count(*) FROM typed_policy_signing_keys WHERE org_id = $1`, testOrg).Scan(&keys)
		}); err != nil {
			t.Fatalf("counting signing keys: %v", err)
		}
		if keys < 2 {
			t.Errorf("after two workspace builds the organization has %d signing-key row(s), expected at least 2; "+
				"each process records its own public half so artifacts signed by an earlier one still verify", keys)
		}
	})

	t.Run("without a database it reports process", func(t *testing.T) {
		// nil is the legitimate posture: no DATABASE_URL, or a connection that
		// failed at boot. It must say so rather than claim durability.
		h := realPGRouteHandler(t, nil)
		persistence, custody, status := editionPosture(t, h)
		if status != http.StatusOK {
			t.Fatalf("/edition answered %d", status)
		}
		if persistence != "process" {
			t.Errorf("persistence is %q with no connection; expected \"process\". A deployment without a database keeps "+
				"the in-process store - which is what shipped before #3975 - and the field exists to say so", persistence)
		}
		if custody != "process" {
			t.Errorf("signing_key_custody is %q, expected \"process\"", custody)
		}
	})
}

// A TRANSIENT DATABASE ERROR MUST NOT PERMANENTLY DOWNGRADE AN ORGANIZATION.
//
// workspaceFor used to fall back to the in-process store on ANY failure of the
// durable chain and then CACHE that workspace. So one unreachable moment - a
// restart, a failover, a connection blip - downgraded the organization for the
// life of the process, and the next publish returned 200 into memory and was
// lost on the following restart. That is #3975's own symptom arriving through
// nothing worse than a hiccup, and no test could see it: they drive a healthy
// backend or no backend at all, never a backend that fails once.
//
// The rule is that once a database is CONFIGURED, persistence is not optional.
// So the degraded workspace is not cached (the next request retries) and writes
// are refused with 503 storage_unavailable rather than accepted into a store
// that cannot keep them. The active-document read is refused the same way
// (#4255), because the in-process store is empty; /edition reports
// "unavailable" so nothing mistakes the in-process view for a durable one.
//
// THE SEAM IS A FIELD FOR THE SAME REASON profileFor IS: a failing durable open
// cannot be produced through a real handle, because a bad handle fails every
// time rather than once.
func TestATransientStorageFailureRefusesTheWriteAndThenRecovers_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	h := realPGRouteHandler(t, appDB)

	// Fails ONCE, then delegates to the real chain. A stub that always failed
	// could not show recovery; one that never failed could not show refusal.
	var calls int
	h.openForSigning = func(ctx context.Context, db *sql.DB, root pdp.Root, orgID, prefix string,
		pub ed25519.PublicKey, by string) (*authoringstore.Store, authoring.TrustSource, string, error) {
		calls++
		if calls == 1 {
			return nil, nil, "", errors.New("simulated transient failure: connection refused")
		}
		return authoringstore.OpenForSigning(ctx, db, root, orgID, prefix, pub, by)
	}

	r := routerFor(h)

	// [1] THE WRITE IS REFUSED, not accepted into memory.
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("publish during a storage outage returned %d, want 503. Accepting it would put the artifact in memory "+
			"and lose it on the next restart, which is the defect this refusal exists to prevent. body=%s",
			rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "storage_unavailable") {
		t.Errorf("the refusal does not carry reason=storage_unavailable, so a caller cannot tell an outage from a "+
			"malformed document: %s", rr.Body.String())
	}

	// [2] THE DEGRADED WORKSPACE WAS NOT CACHED. This is what makes the retry
	//     possible; caching it is precisely what made a transient failure
	//     permanent.
	h.mu.Lock()
	cached := len(h.workspaces)
	h.mu.Unlock()
	if cached != 0 {
		t.Errorf("a degraded workspace was cached (%d held); the organization would stay downgraded for the life of "+
			"the process and every later publish would be accepted into memory", cached)
	}

	// [3] THE NEXT REQUEST RECOVERS, with no restart and no intervention.
	rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("publish after the database recovered returned %d, want 200; the refusal must be transient, not sticky. body=%s",
			rr.Code, rr.Body.String())
	}
	if calls < 2 {
		t.Fatalf("the durable open was attempted %d time(s); the second request did not retry, so the recovery above "+
			"was not a retry at all", calls)
	}

	// [4] AND IT IS GENUINELY DURABLE - the posture says so and a row backs it.
	persistence, _, status := editionPosture(t, h)
	if status != http.StatusOK || persistence != "database" {
		t.Errorf("after recovery /edition reports persistence=%q (status %d), want \"database\"", persistence, status)
	}
	var keys int
	if scopeErr := rls.WithOrgScope(context.Background(), appDB, testOrg, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM typed_policy_signing_keys WHERE org_id = $1`, testOrg).Scan(&keys)
	}); scopeErr != nil {
		t.Fatalf("counting signing keys: %v", scopeErr)
	}
	if keys == 0 {
		t.Error("no signing-key row exists after recovery, so the durable chain did not actually run")
	}
}
