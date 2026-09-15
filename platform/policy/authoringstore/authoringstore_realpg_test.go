// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/rls"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// Migration 155 and the durable store, against a real Postgres under the
// APP ROLE.
//
// The app-role posture is the premise, not a detail. Every guarantee this
// migration makes - FORCE ROW LEVEL SECURITY, the org-isolation policy, the
// append-only privilege revoke - is invisible to a superuser connection, so a
// suite run as the owner would be green on a database where none of it worked.
// approletest.AssertCurrentUser is what stops this file proving nothing.

const (
	orgA = "org-alpha"
	orgB = "org-beta"

	// #3975 moved this package out of ee/, so the repo root is three levels up
	// rather than four, and migrations/core/176 owns these tables rather than
	// migrations/enterprise/155.
	migration176     = "../../../migrations/core/176_typed_authoring_persistence.sql"
	migration176Down = "../../../migrations/core/176_typed_authoring_persistence_down.sql"
	// 155 is kept only to prove its down is now a NO-OP; see
	// TestMigration155DownIsANoOpAndLeavesTheTables_RealPG.
	migration155Down = "../../../migrations/enterprise/155_typed_authoring_persistence_down.sql"
	coreMigrations   = "../../../migrations/core"
)

type harness struct {
	env       *approletest.Env
	masterDB  *sql.DB
	appRoleDB *sql.DB
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	keyID     string
	catalog   *authoring.Catalog
}

func setup(t *testing.T) *harness {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, coreMigrations)

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = masterDB.Close() })
	// NOTHING IS APPLIED HERE. Until #3975 this line applied
	// migrations/enterprise/155, because the core chain did not carry these
	// tables; migrations/core/176 does, and approletest.Setup has just applied
	// every core migration. Asserting it rather than assuming it is the point:
	// "a community deployment's own migrations create durable typed-authoring
	// storage" IS the defect #3975 reported, so it is checked here on every run
	// of this suite instead of being implied by later tests happening to pass.
	for _, table := range []string{"typed_policy_artifacts", "typed_policy_activations", "typed_policy_signing_keys"} {
		var present bool
		if err := masterDB.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Fatalf("%s does not exist after applying migrations/core alone; core/176 is what makes typed authoring durable on every edition (#3975)", table)
		}
	}

	appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appRoleDB.Close() })
	// THE premise: if this is not really app_role, nothing below is evidence.
	approletest.AssertCurrentUser(t, appRoleDB, "axonflow_app_role")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Resolve returns ONE snapshot rather than a loose catalog (#3895): the
	// authoring view, the admission registry, the digest and the registry
	// version now come out of a single call, so a consumer cannot hold a
	// catalog whose digest belongs to a different resolution. Deployment{} is
	// ignored for SourceConformance, whose fixture world declares its own
	// realms; passing the real one here would describe a deployment this
	// fixture is not.
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceConformance, authoringcatalog.Deployment{})
	if err != nil || snap == nil || snap.Catalog == nil {
		t.Fatalf("building the conformance catalog: %v", err)
	}
	cat := snap.Catalog
	// DERIVED, not "test-key-1". The fixture minted a fresh key per run and
	// labelled it with a constant - the precise shape that made durable storage
	// work exactly once per organization in two production callers (#3962,
	// #3975). AuthorizeKey now refuses it, and this fixture was the first thing
	// the refusal caught.
	return &harness{env: env, masterDB: masterDB, appRoleDB: appRoleDB, priv: priv, pub: pub, keyID: KeyIDFor("test", orgA, pub), catalog: cat}
}

func applySQL(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("applying %s: %v", path, err)
	}
}

// storeFor builds a durable store for one organization over the APP ROLE
// connection, with a trust store carrying this run's key.
func (h *harness) storeFor(t *testing.T, org string) *Store {
	t.Helper()
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, h.keyID, h.pub)
	s, err := New(h.appRoleDB, org, authoring.StaticTrust(trust))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// publish builds and signs one artifact at a chosen version and instant.
func (h *harness) publish(t *testing.T, version int, at time.Time) *authoring.Artifact {
	t.Helper()
	raw := fmt.Sprintf(`{
	  "root": "organization",
	  "version": %d,
	  "attributes": [{"path": "signal.detector.probe", "type": "any", "optional": false}],
	  "policies": [{
	    "id": "test:probe:v%d",
	    "authority": "constraint",
	    "root": "organization",
	    "scope": {"organization": true},
	    "actions": {"any": true},
	    "where": {"kind": "compare", "path": "signal.detector.probe", "op": "eq", "literal": true}
	  }]
	}`, version, version)
	var policy pdp.Document
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatal(err)
	}
	meta := authoring.Metadata{
		DocumentID: "durable-store-probe",
		Title:      "Durable store probe",
		Author:     contract.MustParseID(contract.KindPrincipal, "User::portal:alice@example.com"),
	}
	doc, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: policy}, h.catalog)
	if err != nil {
		t.Fatalf("the probe document must validate: %v\n%v", err, findings)
	}
	art, findings, err := authoring.Publish(context.Background(), doc, h.catalog, authoring.PublishOptions{
		// EXPLICIT because this calls the PACKAGE function rather than
		// API.Publish, which injects the edition from the profile it was
		// constructed with. #3943 made an unset Edition a refusal, in the same
		// block as an unset Root - so a helper that predates it fails here
		// rather than publishing something unbounded, which is the intended
		// behaviour and is why this line is added rather than the check relaxed.
		Profile:    mustEnterpriseProfile(t),
		Root:       pdp.RootOrganization,
		KeyID:      h.keyID,
		PrivateKey: h.priv,
		Approvers:  []contract.ID{contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com")},
		Fixtures: []authoring.Fixture{{
			Name:       "the probe detector fires",
			Attributes: probeAttributes(),
			Expect:     map[string]pdp.Verdict{fmt.Sprintf("test:probe:v%d", version): pdp.VerdictMatch},
		}},
		Now: at,
	})
	if err != nil {
		t.Fatalf("the probe artifact must publish: %v\n%v", err, findings)
	}
	return art
}

func probeAttributes() contract.AttributeSet {
	a := contract.Known(true, contract.NamespaceOf("signal.detector.probe").DefaultProvenance(), 1, time.Unix(1_700_000_000, 0).UTC())
	return contract.AttributeSet{"signal.detector.probe": a}
}

// --- storage round trip ---------------------------------------------------

func TestTheDurableStoreRoundTripsAnArtifact_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())

	if err := s.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}
	// Idempotent on (org, root, digest). A second admission of the same
	// content is a no-op, not a primary-key error.
	if err := s.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatalf("re-admitting an identical artifact failed: %v", err)
	}

	got, found, err := s.GetArtifact(ctx, pdp.RootOrganization, art.Digest())
	if err != nil || !found {
		t.Fatalf("GetArtifact: found=%t err=%v", found, err)
	}
	if got.Digest() != art.Digest() {
		t.Fatalf("digest %s came back as %s", art.Digest(), got.Digest())
	}
	if string(got.Source()) != string(art.Source()) {
		t.Fatal("the stored source did not round trip byte-for-byte; what renders back is not what was signed")
	}

	n, err := s.CountArtifacts(ctx, pdp.RootOrganization)
	if err != nil || n != 1 {
		t.Fatalf("CountArtifacts = %d (err %v)", n, err)
	}
	list, err := s.ListArtifacts(ctx, pdp.RootOrganization, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListArtifacts = %d (err %v)", len(list), err)
	}
	bySource, found, err := s.ArtifactBySourceDigest(ctx, pdp.RootOrganization, art.Provenance().SourceDigest)
	if err != nil || !found || bySource.Digest() != art.Digest() {
		t.Fatalf("ArtifactBySourceDigest: found=%t err=%v", found, err)
	}
	if _, found, err := s.ArtifactBySourceDigest(ctx, pdp.RootOrganization, "sha256:nothing"); err != nil || found {
		t.Fatalf("an unknown source digest resolved: found=%t err=%v", found, err)
	}
}

// TestASecondProcessReadsWhatTheFirstPublished is #3776's headline, expressed
// as two independent Store values over one database.
func TestASecondProcessReadsWhatTheFirstPublished_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	first := h.storeFor(t, orgA)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := first.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}

	// A store built fresh, exactly as a restarted process would build one, and
	// with its trust store loaded FROM THE DATABASE rather than handed in.
	seed := h.storeFor(t, orgA)
	if err := seed.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, h.pub, "test"); err != nil {
		t.Fatal(err)
	}
	trust, err := seed.LoadTrust(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(h.appRoleDB, orgA, authoring.StaticTrust(trust))
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := second.GetArtifact(ctx, pdp.RootOrganization, art.Digest())
	if err != nil || !found {
		t.Fatalf("a second process could not read the first's artifact: found=%t err=%v", found, err)
	}
	if got.Digest() != art.Digest() {
		t.Fatalf("the second process read %s, want %s", got.Digest(), art.Digest())
	}
}

// --- org isolation --------------------------------------------------------

func TestOrgIsolationIsEnforcedByRowLevelSecurity_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	a := h.storeFor(t, orgA)
	b := h.storeFor(t, orgB)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())

	if err := a.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}
	if _, found, err := b.GetArtifact(ctx, pdp.RootOrganization, art.Digest()); err != nil || found {
		t.Fatalf("org %s read org %s's artifact: found=%t err=%v", orgB, orgA, found, err)
	}
	if n, err := b.CountArtifacts(ctx, pdp.RootOrganization); err != nil || n != 0 {
		t.Fatalf("org %s counts %d of org %s's artifacts (err %v)", orgB, n, orgA, err)
	}
	// NEGATIVE CONTROL: org A still sees its own row, so the isolation above
	// is about the org predicate and not about the row being absent.
	if n, err := a.CountArtifacts(ctx, pdp.RootOrganization); err != nil || n != 1 {
		t.Fatalf("org %s counts %d of its OWN artifacts (err %v)", orgA, n, err)
	}
}

// --- the activation chain and its compare-and-set -------------------------

func TestTheActivationChainIsAppendOnlyAndCompareAndSet_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}

	act := authoring.Activation{
		Kind: authoring.ActivationPromote, Root: pdp.RootOrganization, Digest: art.Digest(),
		DocumentID: art.Provenance().DocumentID, DocumentVersion: 1,
		Actor: contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com"),
		At:    time.Unix(1_700_000_300, 0).UTC(),
	}
	if err := s.AppendActivation(ctx, pdp.RootOrganization, act, ""); err != nil {
		t.Fatal(err)
	}
	if d, err := s.ActiveDigest(ctx, pdp.RootOrganization); err != nil || d != art.Digest() {
		t.Fatalf("ActiveDigest = %q (err %v)", d, err)
	}

	// THE RACE. A second replica that still believes the root is empty must be
	// refused rather than appending a second first-activation.
	other := h.storeFor(t, orgA)
	err := other.AppendActivation(ctx, pdp.RootOrganization, act, "")
	if !errors.Is(err, authoring.ErrActivationRaced) {
		t.Fatalf("a stale-parent append returned %v; it must be ErrActivationRaced", err)
	}

	// NEGATIVE CONTROL: with the CURRENT tip it succeeds.
	second := act
	second.Kind = authoring.ActivationRollback
	second.PreviousDigest = art.Digest()
	second.Reason = "restoring the previous version"
	if err := other.AppendActivation(ctx, pdp.RootOrganization, second, art.Digest()); err != nil {
		t.Fatalf("an append with the current tip was refused, so the race assertion proves nothing: %v", err)
	}

	history, err := s.Activations(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("expected two activation records, got %d", len(history))
	}
	// The actor round-trips through its canonical string form.
	if history[0].Actor.String() != "User::portal:bob@example.com" {
		t.Fatalf("actor came back as %q", history[0].Actor.String())
	}
	if history[0].Kind != authoring.ActivationPromote || history[1].Kind != authoring.ActivationRollback {
		t.Fatalf("kinds came back as %q, %q", history[0].Kind, history[1].Kind)
	}
	if history[1].PreviousDigest != history[0].Digest {
		t.Fatal("the history is not a chain: the second entry does not name the first")
	}
}

// TestTheActiveDigestIsOrderedBySequenceNotByClock_RealPG pins WHAT breaks a
// tie in the derived active digest.
//
// The active version is derived from the activation history rather than stored
// beside it, which removes a second record of one fact - but a derivation is
// only unambiguous if its ordering is total. Two activations stamped at the
// SAME instant are entirely possible (a clock with second granularity, an
// operator scripting two calls), and "the newest by timestamp" has no answer
// there. The ordering is `seq`, a per-(org, root) integer under a UNIQUE
// constraint, so it is total by construction and independent of any clock.
func TestTheActiveDigestIsOrderedBySequenceNotByClock_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)

	// An empty history has NO active digest, and says so as "" rather than as
	// an error or a zero-value digest.
	if d, err := s.ActiveDigest(ctx, pdp.RootOrganization); err != nil || d != "" {
		t.Fatalf("an empty history gives ActiveDigest %q (err %v); it must be the empty string", d, err)
	}

	one := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	two := h.publish(t, 2, time.Unix(1_700_000_200, 0).UTC())
	for _, a := range []*authoring.Artifact{one, two} {
		if err := s.PutArtifact(ctx, pdp.RootOrganization, a); err != nil {
			t.Fatal(err)
		}
	}

	// THE SAME INSTANT for both activations. If the derivation read the clock,
	// which of these two is active would be decided by a tie-break nobody
	// declared.
	sameInstant := time.Unix(1_700_000_300, 0).UTC()
	actor := contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com")
	first := authoring.Activation{
		Kind: authoring.ActivationPromote, Root: pdp.RootOrganization, Digest: one.Digest(),
		DocumentID: one.Provenance().DocumentID, DocumentVersion: 1, Actor: actor, At: sameInstant,
	}
	if err := s.AppendActivation(ctx, pdp.RootOrganization, first, ""); err != nil {
		t.Fatal(err)
	}
	second := authoring.Activation{
		Kind: authoring.ActivationPromote, Root: pdp.RootOrganization, Digest: two.Digest(),
		PreviousDigest: one.Digest(),
		DocumentID:     two.Provenance().DocumentID, DocumentVersion: 2, Actor: actor, At: sameInstant,
	}
	if err := s.AppendActivation(ctx, pdp.RootOrganization, second, one.Digest()); err != nil {
		t.Fatal(err)
	}

	got, err := s.ActiveDigest(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if got != two.Digest() {
		t.Fatalf("ActiveDigest = %s, want the LATER activation %s; two activations sharing one instant must still order deterministically", got, two.Digest())
	}
	// And the sequence really is what ordered them, read from the column.
	var seqs []int
	rows, err := h.masterDB.QueryContext(ctx,
		`SELECT seq FROM typed_policy_activations WHERE org_id = $1 AND root = $2 ORDER BY seq`, orgA, string(pdp.RootOrganization))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, n)
	}
	if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 2 {
		t.Fatalf("the activation sequence is %v, want [1 2]; it is what makes the derivation total", seqs)
	}
	// The UNIQUE constraint is the reason no two activations can share a
	// sequence number under one root, so the ordering cannot degenerate.
	if _, err := h.masterDB.ExecContext(ctx,
		`INSERT INTO typed_policy_activations
		   (org_id, root, seq, kind, digest, previous_digest, document_id, document_version, actor, activated_at, reason)
		 VALUES ($1, $2, 2, 'promote', $3, $4, 'x', 3, 'User::portal:bob@example.com', NOW(), '')`,
		orgA, string(pdp.RootOrganization), two.Digest(), one.Digest()); err == nil {
		t.Fatal("a second activation took sequence number 2; without the UNIQUE constraint the derived active digest is ambiguous")
	}
}

// --- append-only, on both enforcement paths -------------------------------

// TestTheAppendOnlyTablesRefuseEveryMutation_RealPG proves the refusal TWICE
// for the app role and once more for the owner, because the two mechanisms
// cover different callers: the privilege revoke does not bind the table owner,
// and the trigger does.
func TestTheAppendOnlyTablesRefuseEveryMutation_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}
	act := authoring.Activation{
		Kind: authoring.ActivationPromote, Root: pdp.RootOrganization, Digest: art.Digest(),
		DocumentID: art.Provenance().DocumentID, DocumentVersion: 1,
		Actor: contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com"),
		At:    time.Unix(1_700_000_300, 0).UTC(),
	}
	if err := s.AppendActivation(ctx, pdp.RootOrganization, act, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, h.pub, "test"); err != nil {
		t.Fatal(err)
	}

	// typed_policy_audit holds rows here because the PutArtifact and the
	// AppendActivation above each wrote one in their own transaction
	// (migrations/core/181).
	tables := []string{"typed_policy_artifacts", "typed_policy_activations", "typed_policy_signing_keys", "typed_policy_audit"}

	// EVERY TABLE MUST HOLD A ROW BEFORE ANYTHING IS ATTEMPTED AGAINST IT.
	//
	// This is not tidiness. The row-level guards are BEFORE UPDATE OR DELETE
	// ... FOR EACH ROW triggers, and a FOR EACH ROW trigger does not fire on
	// zero rows - so an UPDATE or a DELETE against an EMPTY table succeeds,
	// affecting nothing, and every assertion below would pass while proving
	// nothing about the guard. Caught by this suite before it was written this
	// way: typed_policy_signing_keys had no rows and the owner's UPDATE and
	// DELETE both "succeeded".
	for _, table := range tables {
		var n int
		if err := h.masterDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatalf("%s is empty, so a FOR EACH ROW trigger cannot fire and every refusal below would be vacuous", table)
		}
	}

	// The row counts BEFORE anything is attempted. TRUNCATE is checked against
	// these afterwards rather than only by its error, because TRUNCATE is the
	// one statement here that BOTH guards can miss: it is a privilege
	// separate from DELETE, so a revoke of INSERT/UPDATE/DELETE leaves it
	// untouched, and a FOR EACH ROW trigger does not fire on it at all. An
	// assertion that only read the error would not notice a TRUNCATE that
	// reported failure after emptying the table.
	before := map[string]int{}
	for _, table := range tables {
		var n int
		if err := h.masterDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		before[table] = n
	}

	for _, table := range tables {
		for _, stmt := range []string{
			fmt.Sprintf("UPDATE %s SET org_id = 'hijacked'", table),
			fmt.Sprintf("DELETE FROM %s", table),
			fmt.Sprintf("TRUNCATE %s", table),
		} {
			t.Run("app_role/"+stmt, func(t *testing.T) {
				if _, err := h.appRoleDB.ExecContext(ctx, stmt); err == nil {
					t.Fatalf("the app role executed %q", stmt)
				}
			})
			t.Run("owner/"+stmt, func(t *testing.T) {
				// The OWNER is not bound by the privilege revoke, so this is
				// the half only the trigger can refuse.
				_, err := h.masterDB.ExecContext(ctx, stmt)
				if err == nil {
					t.Fatalf("the table owner executed %q; the trigger is the only thing that binds the owner", stmt)
				}
				if !strings.Contains(err.Error(), "append-only") &&
					!strings.Contains(err.Error(), "insert-only") &&
					!strings.Contains(err.Error(), "only permitted update") {
					t.Fatalf("the owner's %q failed for the wrong reason: %v", stmt, err)
				}
			})
		}
	}

	// THE EFFECT, NOT ONLY THE ERROR. Every table still holds exactly what it
	// held before the loop above ran, so none of those statements did its work
	// and then reported failure.
	for _, table := range tables {
		var n int
		if err := h.masterDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != before[table] {
			t.Fatalf("%s held %d row(s) before the refused mutations and %d after", table, before[table], n)
		}
	}

	// TRUNCATE IS A SEPARATE PRIVILEGE, asserted directly rather than inferred
	// from the statement having failed. core/098 granted
	// SELECT/INSERT/UPDATE/DELETE and never TRUNCATE, so a migration that
	// revoked only those three would leave a hole neither the grant nor the
	// row-level trigger closes.
	for _, table := range tables {
		for _, role := range []string{"axonflow_app_role", "axonflow_platform_admin"} {
			var held bool
			if err := h.masterDB.QueryRowContext(ctx,
				`SELECT has_table_privilege($1, $2, 'TRUNCATE')`, role, table).Scan(&held); err != nil {
				t.Fatal(err)
			}
			if held {
				t.Fatalf("%s holds TRUNCATE on %s; that is a privilege separate from DELETE and it empties the table rather than editing a row", role, table)
			}
		}
	}

	// NEGATIVE CONTROL: an INSERT still works, so the refusals above are about
	// mutation and not about the tables being unreachable.
	if err := s.PutArtifact(ctx, pdp.RootOrganization, h.publish(t, 2, time.Unix(1_700_000_400, 0).UTC())); err != nil {
		t.Fatalf("an INSERT was refused, so the mutation refusals prove nothing: %v", err)
	}
}

// --- the signing chain ----------------------------------------------------

func TestTheSigningChainOutlivesTheProcessAndCanBeWithdrawn_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)

	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, h.pub, "test"); err != nil {
		t.Fatal(err)
	}
	// Idempotent on IDENTICAL material.
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, h.pub, "test"); err != nil {
		t.Fatalf("re-authorizing the identical key failed: %v", err)
	}
	// REFUSED on different material under the same identifier: that would be
	// one process silently taking over another's signing identity.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// THE OUTER GATE ANSWERS FIRST NOW, and the change of error is the point.
	// Since #3975 an identifier must carry the fingerprint of the material
	// presented with it, so "same id, different material" cannot be reached
	// through this function at all: a derived identifier can only ever collide
	// with its own key, which is the idempotent case asserted above.
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, otherPub, "test"); !errors.Is(err, ErrKeyIDNotDerivedFromKey) {
		t.Fatalf("a second key claimed an existing identifier and was not refused by the derivation gate: %v", err)
	}

	// AND ErrKeyAlreadyAuthorized IS STILL REACHABLE - for a row this function
	// did not write. It is defence in depth rather than dead code: a row
	// inserted directly, by an operator or by a writer that predates the gate,
	// can still pair an identifier with material that does not derive it, and
	// the read-back is what refuses to hand that identity to a later process.
	//
	// Asserted rather than assumed, because a check nothing can reach is
	// indistinguishable from one that works, and deleting it on the strength of
	// "the gate covers it" would remove the only protection for exactly the
	// rows the gate never saw.
	squatted := KeyIDFor("test", orgA, otherPub)
	if err := rls.WithOrgScope(ctx, h.appRoleDB, orgA, func(tx *sql.Tx) error {
		_, insErr := tx.ExecContext(ctx, `
			INSERT INTO typed_policy_signing_keys (org_id, root, key_id, public_key, authorized_by)
			VALUES ($1, $2, $3, $4, 'direct-insert')
		`, orgA, string(pdp.RootOrganization), squatted, []byte(h.pub))
		return insErr
	}); err != nil {
		t.Fatalf("planting a row whose identifier does not derive its material: %v", err)
	}
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, squatted, otherPub, "test"); !errors.Is(err, ErrKeyAlreadyAuthorized) {
		t.Fatalf("the read-back did not refuse an identifier already holding different material: %v", err)
	}
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, otherPub[:16], "test"); err == nil {
		t.Fatal("a 16-byte public key was accepted; an ed25519 key is 32 bytes")
	}

	trust, err := s.LoadTrust(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := trust.PublicKey(pdp.RootOrganization, h.keyID); !ok {
		t.Fatal("the loaded trust store does not carry the key that was just authorized")
	}

	// An artifact signed by that key verifies through a store using the LOADED
	// trust store - which is what "verifiable by a key that outlives the
	// process" means in practice.
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	loaded, err := New(h.appRoleDB, orgA, authoring.StaticTrust(trust))
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}
	if _, found, err := loaded.GetArtifact(ctx, pdp.RootOrganization, art.Digest()); err != nil || !found {
		t.Fatalf("an artifact did not verify against a trust store loaded from the database: found=%t err=%v", found, err)
	}

	// REVOCATION, and its effect on the READ path. Nothing deletes the row -
	// "this key was authorized between these two times" is itself a fact the
	// audit trail needs - and a store built from a trust store loaded AFTER
	// the revocation refuses the artifact.
	if err := s.RevokeKey(ctx, pdp.RootOrganization, h.keyID, ""); err == nil {
		t.Fatal("a revocation with no reason was accepted")
	}
	if err := s.RevokeKey(ctx, pdp.RootOrganization, h.keyID, "key rotation drill"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeKey(ctx, pdp.RootOrganization, h.keyID, "again"); err == nil {
		t.Fatal("a key was revoked twice; un-revoking and re-revoking are not operations")
	}
	after, err := s.LoadTrust(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.PublicKey(pdp.RootOrganization, h.keyID); ok {
		t.Fatal("a revoked key is still in the loaded trust store")
	}
	revoked, err := New(h.appRoleDB, orgA, authoring.StaticTrust(after))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := revoked.GetArtifact(ctx, pdp.RootOrganization, art.Digest()); err == nil {
		t.Fatal("an artifact signed by a REVOKED key still loaded; revocation has no effect on the read path")
	}

	// RE-PRESENTING THE SAME MATERIAL AFTER A REVOCATION IS REFUSED BY NAME.
	// Reporting success would be the worst answer available: LoadTrust reads
	// only unrevoked rows, so the caller would build a trust store that cannot
	// verify its own signatures and every publication would fail at admission
	// with "key is not authorized" - naming a key this call had just confirmed.
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, h.pub, "test"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("re-authorizing a REVOKED key returned %v; it must be ErrKeyRevoked", err)
	}

	// The row survives the revocation, which is the audit half.
	var n int
	if err := h.masterDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM typed_policy_signing_keys WHERE key_id = $1 AND revoked_at IS NOT NULL`, h.keyID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the revoked key row count is %d, want 1; a revocation must not delete the authorization record", n)
	}
}

// TestASigningKeyRowCannotBeRewrittenPastItsRevocationColumns_RealPG pins the
// column-scoped grant AND the trigger, which are separate mechanisms binding
// separate callers.
func TestASigningKeyRowCannotBeRewrittenPastItsRevocationColumns_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, h.keyID, h.pub, "test"); err != nil {
		t.Fatal(err)
	}

	if _, err := h.appRoleDB.ExecContext(ctx,
		`UPDATE typed_policy_signing_keys SET public_key = decode(repeat('00', 32), 'hex')`); err == nil {
		t.Fatal("the app role rewrote a public key; the UPDATE grant is meant to cover only the revocation columns")
	}
	// The owner is not bound by the column grant, so this is the trigger's half.
	if _, err := h.masterDB.ExecContext(ctx,
		`UPDATE typed_policy_signing_keys SET public_key = decode(repeat('00', 32), 'hex')`); err == nil {
		t.Fatal("the table OWNER rewrote a public key; the trigger is the only thing that binds it")
	}
	// NEGATIVE CONTROL: the permitted update works for the app role.
	if _, err := h.appRoleDB.ExecContext(ctx,
		`SELECT set_config('app.current_org_id', $1, false)`, orgA); err != nil {
		t.Fatal(err)
	}
	if _, err := h.appRoleDB.ExecContext(ctx,
		`UPDATE typed_policy_signing_keys SET revoked_at = NOW(), revoked_reason = 'permitted' WHERE key_id = $1`, h.keyID); err != nil {
		t.Fatalf("the app role could not perform the ONE permitted update: %v", err)
	}
}

// --- the migration itself -------------------------------------------------

// TestMigration176IsForwardAndDownCleanAndReAppliable_RealPG runs up, down and
// up again. Re-appliability is the property a partially applied migration
// depends on, and an up that only works on a virgin database is one an operator
// cannot recover with.
//
// It exercises migrations/core/176 since #3975: 176 owns these tables on every
// edition, and its down is the SINGLE rollback path - including on a database
// whose tables were physically created by enterprise/155.
func TestMigration176IsForwardAndDownCleanAndReAppliable_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	// 176 is already applied by setup, as part of migrations/core. Re-applying
	// must be a no-op rather than an error: every statement is IF NOT EXISTS /
	// OR REPLACE / DROP-then-CREATE by design.
	applySQL(t, h.masterDB, migration176)

	s := h.storeFor(t, orgA)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}

	applySQL(t, h.masterDB, migration176Down)
	for _, table := range []string{"typed_policy_artifacts", "typed_policy_activations", "typed_policy_signing_keys"} {
		var present bool
		if err := h.masterDB.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if present {
			t.Fatalf("%s survived the down migration", table)
		}
	}

	// UP AGAIN, on a database that has already carried the tables once. This
	// is the state an operator reaches after a rollback and a re-deploy.
	applySQL(t, h.masterDB, migration176)
	again := h.storeFor(t, orgA)
	if err := again.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatalf("the re-applied migration produced a store that cannot write: %v", err)
	}
	if n, err := again.CountArtifacts(ctx, pdp.RootOrganization); err != nil || n != 1 {
		t.Fatalf("after down-then-up the store counts %d (err %v); the rollback is documented as destroying the data and this confirms it", n, err)
	}
	// typed_policy_audit (core/181) is not 176's and survives its down. The
	// re-stored artifact is the same publish, so its row is restated, not
	// duplicated and not refused.
	trail, err := again.AuditTrail(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 1 || trail[0].Action != authoring.AuditPublish || trail[0].Digest != art.Digest() {
		t.Fatalf("after down-then-up and a re-store the audit trail is %+v, want the one publish row of %s", trail, art.Digest())
	}
}

// TestMigration155DownIsANoOpAndLeavesTheTables_RealPG pins the #3975 ruling.
//
// Two migrations now create one set of tables: enterprise/155, which ran on the
// deployments that applied it, and core/176, which owns them on every edition.
// THEY MUST NOT BOTH DROP. On a database carrying both records, whichever
// rolled back first would destroy the other's state while the other's row still
// claimed to be applied - and the runner skips an applied version before it
// reads the file, so no later migration would repair it.
//
// So 155's down is a no-op that raises a NOTICE naming core/176. This asserts
// exactly that, and it is the inversion of what this suite used to assert: the
// old TestMigration155...ReAppliable applied 155's down and REQUIRED the tables
// to be gone. That assertion is now false, and because this suite is gated
// behind approletest.SkipUnlessEnabled it would have failed only where somebody
// enabled the gate - a stated gap nobody rechecks rather than a red board.
//
// The control is TestMigration176IsForwardAndDownCleanAndReAppliable_RealPG,
// which drops the same three tables through 176's down in the same suite.
// Without it, "the tables survived" is equally consistent with a rollback path
// that cannot drop anything at all.
func TestMigration155DownIsANoOpAndLeavesTheTables_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	s := h.storeFor(t, orgA)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
		t.Fatal(err)
	}

	applySQL(t, h.masterDB, migration155Down)

	for _, table := range []string{"typed_policy_artifacts", "typed_policy_activations", "typed_policy_signing_keys"} {
		var present bool
		if err := h.masterDB.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Fatalf("%s was dropped by enterprise/155's down migration; since #3975 that file is a no-op and core/176 owns the rollback, "+
				"so this rollback has destroyed state another migration still claims to have applied", table)
		}
	}

	// And the ROWS survive too, not just the tables: a down that emptied the
	// tables while leaving them standing would pass the check above and still
	// have destroyed the deployment's policy history.
	if n, err := s.CountArtifacts(ctx, pdp.RootOrganization); err != nil || n != 1 {
		t.Fatalf("after enterprise/155's no-op down the store counts %d artifact(s) (err %v), expected 1", n, err)
	}
}

// mustEnterpriseProfile builds the Enterprise boundary for a suite that is
// about storage rather than about the boundary. authoring.mustProfile is
// unexported and this is a different package, so the equivalent lives here;
// the point of both is that a test which does not care about the edition
// should not be silently choosing one.
func mustEnterpriseProfile(t *testing.T) authoring.Profile {
	t.Helper()
	p, err := authoring.ProfileFor(authoring.EditionEnterprise)
	if err != nil {
		t.Fatalf("building the enterprise profile: %v", err)
	}
	return p
}

// THE REFUSAL, AGAINST A REAL DATABASE, AND WHAT IT LEAVES BEHIND (#3975).
//
// keyid_test.go asserts that AuthorizeKey refuses an identifier not derived
// from its key, using an unconnected handle - which is right for the gate's
// position (it runs before any statement) but cannot say what the store holds
// afterwards. A refusal assertion is not an assertion of the REASON for the
// refusal, and neither is it an assertion that nothing was written: an
// implementation that inserted the row and then returned an error would pass
// the unit test and still hand the next process a poisoned identifier.
//
// So this asserts both halves against postgres: the error, and the absence of
// a row for that identifier under the organization's own scope.
func TestAuthorizeKeyRefusesAnUndrivedIdentifierAndWritesNothing_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const handRolled = "orchestrator-" + orgA // the shape both callers shipped

	err = s.AuthorizeKey(ctx, pdp.RootOrganization, handRolled, pub, "test")
	if !errors.Is(err, ErrKeyIDNotDerivedFromKey) {
		t.Fatalf("an organization-keyed identifier was accepted against a real database (err=%v)", err)
	}

	// NOTHING WAS WRITTEN. Counted under the org scope, because the table is
	// FORCE RLS and an unscoped read returns zero for every organization -
	// which would make this assertion pass against a store that HAD written
	// the row. The scoped read is the only one that can distinguish them.
	var rows int
	if scopeErr := rls.WithOrgScope(ctx, h.appRoleDB, orgA, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT count(*) FROM typed_policy_signing_keys WHERE org_id = $1 AND key_id = $2`,
			orgA, handRolled).Scan(&rows)
	}); scopeErr != nil {
		t.Fatalf("counting signing keys under the org scope: %v", scopeErr)
	}
	if rows != 0 {
		t.Errorf("the refused identifier left %d row(s) in typed_policy_signing_keys; a refusal that writes is worse than "+
			"an acceptance, because the next process inherits an identifier nothing authorized", rows)
	}

	// AND THE DERIVED FORM STILL WORKS on the same store, so the refusal above
	// is about the identifier rather than about this store being broken.
	good := KeyIDFor("orchestrator", orgA, pub)
	if err := s.AuthorizeKey(ctx, pdp.RootOrganization, good, pub, "test"); err != nil {
		t.Fatalf("KeyIDFor's own output was refused against a real database: %v", err)
	}
	if scopeErr := rls.WithOrgScope(ctx, h.appRoleDB, orgA, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT count(*) FROM typed_policy_signing_keys WHERE org_id = $1 AND key_id = $2`,
			orgA, good).Scan(&rows)
	}); scopeErr != nil {
		t.Fatalf("counting signing keys under the org scope: %v", scopeErr)
	}
	if rows != 1 {
		t.Errorf("the derived identifier produced %d row(s), expected exactly 1; without this the refusal above could be "+
			"a store that writes nothing at all", rows)
	}
}
