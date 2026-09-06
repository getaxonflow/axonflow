// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-PostgreSQL coverage for trust-realm persistence (#3550 PR 2, migration
// core/169).
//
// EVERY assertion here needs a real database:
//
//   - The issuer-uniqueness constraint is the CROSS-PROCESS half of
//     RealmRegistry's own refusal. In-process that check is per-replica, so the
//     only place the property can be observed is the database.
//   - The version-advance rule likewise: two replicas can each pass the
//     in-memory check at the same version.
//   - The RLS posture needs a NON-SUPERUSER role. The container superuser
//     bypasses row-level security unconditionally, so an isolation assertion
//     made on that connection passes no matter what the policy says.
//   - "Two organizations may both federate one public IdP" is a claim about a
//     constraint's SCOPE, and a constraint has no scope outside a database.
//
// Gating: TEST_PG_INTEGRATION=1 + docker, via approletest, which provisions the
// real axonflow_app_role (NOBYPASSRLS) production uses.

package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/rls"
	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// applyRealmMigration applies a migration file by repo-relative path.
//
// A local helper rather than the package's existing applyMigrationFile: that
// one lives in provisioning_realpg_test.go, which carries
// //go:build enterprise, and core/169 is core-tree code that must be exercised
// in the community test binary too.
func applyRealmMigration(t *testing.T, db *sql.DB, relPath string) {
	t.Helper()
	sqlBytes, err := os.ReadFile(filepath.Join("..", "..", "..", relPath))
	if err != nil {
		t.Fatalf("read migration %s: %v", relPath, err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply migration %s: %v", relPath, err)
	}
}

// realmFixture builds a valid realm for one organization, with a distinct id
// and issuer.
func realmFixture(org, id, issuer string, version int64) TrustRealm {
	r := fullyPopulatedRealm()
	r.OrgID = org
	r.RealmID = RealmID(id)
	r.CanonicalIssuer = issuer
	r.Version = version
	// DelegateRealms names a realm that need not exist; Validate does not
	// require it to, and leaving the fixture's default would tie every case to
	// the fixture package's realm ids.
	r.DelegateRealms = []RealmID{RealmID(id + "-peer")}
	return r
}

func TestRealmStore_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, filepath.Join("..", "..", "..", "migrations", "core"))

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app-role DSN: %v", err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	// core/169 is part of the chain approletest just applied - it is NOT
	// applied separately here, which is the point: the store runs against the
	// schema a deployment actually gets, in the order it gets it, rather than
	// against a migration replayed in isolation.
	var reg sql.NullString
	if err := appDB.QueryRow(`SELECT to_regclass('identity_trust_realms')::text`).Scan(&reg); err != nil {
		t.Fatalf("probe for identity_trust_realms: %v", err)
	}
	if !reg.Valid {
		t.Fatal("identity_trust_realms is absent after the whole core migration chain; core/169 did not apply")
	}

	store, err := NewDBRealmStore(appDB)
	if err != nil {
		t.Fatalf("NewDBRealmStore: %v", err)
	}
	ctx := context.Background()

	t.Run("a realm round-trips through the database with every field intact", func(t *testing.T) {
		org := "org_roundtrip"
		want := realmFixture(org, "primary", "https://idp.roundtrip.example", 1)
		epoch, err := store.Upsert(ctx, want, "test-admin")
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if epoch != 1 {
			t.Fatalf("epoch = %d after the first write, want 1", epoch)
		}
		got, err := store.Get(ctx, org, want.RealmID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if !realmsEqual(want, got) {
			t.Fatalf("the realm did not survive the database:\n stored %+v\n loaded %+v", want, got)
		}
		// The projected columns agree with the blob they were projected from.
		// They decide nothing - the store reads the realm from `config` alone -
		// but a projection that disagreed would make the issuer constraint
		// guard a different issuer from the one the realm declares.
		var kind, issuer string
		var enabled bool
		var version int64
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx,
				`SELECT kind, canonical_issuer, enabled, version FROM identity_trust_realms WHERE org_id = $1 AND realm_id = $2`,
				org, string(want.RealmID)).Scan(&kind, &issuer, &enabled, &version)
		}); err != nil {
			t.Fatalf("read projections: %v", err)
		}
		if kind != string(want.Kind) || issuer != want.CanonicalIssuer || enabled != want.Enabled || version != want.Version {
			t.Fatalf("projections = kind %q issuer %q enabled %t version %d, want them to match the stored realm",
				kind, issuer, enabled, version)
		}
	})

	t.Run("a re-registration must advance the version", func(t *testing.T) {
		org := "org_versions"
		first := realmFixture(org, "primary", "https://idp.versions.example", 3)
		if _, err := store.Upsert(ctx, first, "admin"); err != nil {
			t.Fatalf("first: %v", err)
		}

		for name, version := range map[string]int64{"same": 3, "lower": 2} {
			t.Run(name, func(t *testing.T) {
				stale := realmFixture(org, "primary", "https://idp.versions.example", version)
				stale.Enabled = false
				if _, err := store.Upsert(ctx, stale, "admin"); err == nil {
					t.Fatal("a re-registration that did not advance the version was accepted; two materially different declarations would share a version and their closures would be indistinguishable in a decision proof and in replay")
				}
				// And the stored realm is untouched.
				got, err := store.Get(ctx, org, "primary")
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				if got.Version != 3 || !got.Enabled {
					t.Fatalf("the refused write changed the stored realm: version %d enabled %t", got.Version, got.Enabled)
				}
			})
		}

		// The control: a higher version IS accepted, and it advances the epoch.
		// Without this the refusals above could be a broken statement rather
		// than the rule under test.
		next := realmFixture(org, "primary", "https://idp.versions.example", 4)
		next.Enabled = false
		epoch, err := store.Upsert(ctx, next, "admin")
		if err != nil {
			t.Fatalf("an advancing re-registration was refused, so the refusals above are not evidence about the version rule: %v", err)
		}
		if epoch != 2 {
			t.Fatalf("epoch = %d after two accepted writes, want 2", epoch)
		}
		got, err := store.Get(ctx, org, "primary")
		if err != nil || got.Enabled {
			t.Fatalf("the advancing write did not apply: %+v err=%v", got, err)
		}
	})

	t.Run("one issuer cannot be declared by two realms in one organization", func(t *testing.T) {
		org := "org_issuers"
		issuer := "https://idp.shared.example"
		if _, err := store.Upsert(ctx, realmFixture(org, "first", issuer, 1), "admin"); err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err := store.Upsert(ctx, realmFixture(org, "second", issuer, 1), "admin")
		if err == nil {
			t.Fatal("two realms in one organization declared the same issuer; an issuer resolving to two realms has no determinate answer")
		}
		if !strings.Contains(err.Error(), "no determinate answer") {
			t.Errorf("the refusal does not explain itself: %v", err)
		}
	})

	t.Run("two organizations may both federate the same public IdP", func(t *testing.T) {
		// The issuer constraint is scoped PER ORGANIZATION on purpose. A global
		// unique index would let whichever customer registered first lock the
		// other out of a shared public identity provider - a cross-tenant
		// denial of service written as a schema decision.
		issuer := "https://accounts.google.example"
		if _, err := store.Upsert(ctx, realmFixture("org_tenant_a", "google", issuer, 1), "admin"); err != nil {
			t.Fatalf("tenant A: %v", err)
		}
		if _, err := store.Upsert(ctx, realmFixture("org_tenant_b", "google", issuer, 1), "admin"); err != nil {
			t.Fatalf("tenant B could not federate the same public IdP as tenant A: %v.\nThe issuer constraint must be per-organization, or one customer's registration locks another out.", err)
		}
	})

	t.Run("removing a realm advances the epoch and makes it unknown again", func(t *testing.T) {
		org := "org_removal"
		if _, err := store.Upsert(ctx, realmFixture(org, "primary", "https://idp.removal.example", 1), "admin"); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		removed, epoch, err := store.Remove(ctx, org, "primary")
		if err != nil {
			t.Fatalf("remove: %v", err)
		}
		if !removed {
			t.Fatal("Remove reported that nothing was removed")
		}
		// THE EPOCH MUST ADVANCE ON A DELETE. This is why it is a stored
		// counter rather than max(version): a maximum over the surviving rows
		// goes DOWN when the highest-versioned realm is removed, and an epoch
		// that goes backwards makes a stale cached closure look current again.
		if epoch != 2 {
			t.Fatalf("epoch = %d after one write and one delete, want 2", epoch)
		}
		if _, err := store.Get(ctx, org, "primary"); !errors.Is(err, ErrRealmNotFound) {
			t.Fatalf("err = %v, want a not-found; a removed realm is UNKNOWN_REALM, not a realm with defaults", err)
		}

		// Removing what is not there is not an error - the end state is the one
		// the caller asked for - but it must NOT advance the epoch, or a
		// no-op invalidates every cached closure in the organization.
		removed, noopEpoch, err := store.Remove(ctx, org, "primary")
		if err != nil {
			t.Fatalf("second remove: %v", err)
		}
		if removed {
			t.Fatal("removing an absent realm reported a removal")
		}
		// AND IT REPORTS THE CURRENT EPOCH, not 0. Load's own comment calls 0
		// the one value no registry ever reports and which a comparison
		// against a bound epoch reads as "older than everything"; the
		// signature invites `epoch, err := ...; if err == nil { use(epoch) }`,
		// and `removed` was the only thing distinguishing that sentinel from a
		// real answer.
		if noopEpoch != 2 {
			t.Fatalf("a no-op Remove reported epoch %d, want the organization's current 2. Returning 0 hands a caller a value that compares older than every bound epoch.", noopEpoch)
		}
		_, after, err := store.Load(ctx, org)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if after != 2 {
			t.Fatalf("epoch = %d after a no-op removal, want it unchanged at 2", after)
		}
	})

	t.Run("realms with no epoch row are REFUSED, not restarted at 1", func(t *testing.T) {
		// THE CARDINAL SIN, reachable by an ordinary restore. The two tables
		// have no foreign key between them, so a restore that repopulates
		// identity_trust_realms and not identity_realm_epochs leaves realms
		// with no epoch. Defaulting to 1 there re-issues epochs ALREADY bound
		// into closures and decision proofs, so an invalidated closure
		// compares equal to a current one and looks current again.
		org := "org_lost_epoch"
		for v := int64(1); v <= 3; v++ {
			r := realmFixture(org, "primary", "https://idp.lostepoch.example", v)
			if _, err := store.Upsert(ctx, r, "admin"); err != nil {
				t.Fatalf("upsert v%d: %v", v, err)
			}
		}
		if _, epoch, err := store.Load(ctx, org); err != nil || epoch != 3 {
			t.Fatalf("precondition: epoch=%d err=%v, want 3", epoch, err)
		}

		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(ctx, `DELETE FROM identity_realm_epochs WHERE org_id = $1`, org)
			return execErr
		}); err != nil {
			t.Fatalf("drop the epoch row: %v", err)
		}

		_, epoch, err := store.Load(ctx, org)
		if err == nil {
			t.Fatalf("a load of an organization with realms and NO epoch row returned epoch %d instead of failing; epochs 1..3 have already been handed out, and re-issuing from 1 makes a stale closure look current", epoch)
		}
		if !strings.Contains(err.Error(), "NO identity-epoch row") {
			t.Errorf("the refusal does not name the cause: %v", err)
		}
		// The control: the same load succeeds once the epoch row is restored
		// ABOVE the highest epoch ever issued, so the refusal above is the
		// missing row and not something ambient.
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(ctx,
				`INSERT INTO identity_realm_epochs (org_id, epoch) VALUES ($1, 4)`, org)
			return execErr
		}); err != nil {
			t.Fatalf("restore the epoch row: %v", err)
		}
		if realms, epoch, err := store.Load(ctx, org); err != nil || epoch != 4 || len(realms) != 1 {
			t.Fatalf("after restoring the epoch row: %d realm(s) epoch=%d err=%v", len(realms), epoch, err)
		}
	})

	t.Run("a lost epoch row cannot be repaired by writing, on any path", func(t *testing.T) {
		// THE GUARD THAT REMOVED ITSELF. Load refused an organization whose
		// epoch row was lost while its realms survived - correctly - but every
		// WRITE path walked into that state and set the epoch back to 1,
		// because bumpEpochSQL's INSERT arm fires whenever the row is absent.
		//
		// The sequence is realistic rather than contrived: replicas refuse to
		// boot after a partial restore, an operator reacts by re-registering a
		// realm, THAT WRITE re-issues epoch 1, every replica loads happily
		// again, and every closure and proof bound to epochs 2..N now compares
		// equal to a current one. The guard disarmed itself in response to
		// somebody reacting to it.
		org := "org_lost_epoch_writes"
		for v := int64(1); v <= 4; v++ {
			if _, err := store.Upsert(ctx, realmFixture(org, "primary", "https://idp.lostwrite.example", v), "admin"); err != nil {
				t.Fatalf("upsert v%d: %v", v, err)
			}
		}
		if _, epoch, err := store.Load(ctx, org); err != nil || epoch != 4 {
			t.Fatalf("precondition: epoch=%d err=%v, want 4", epoch, err)
		}
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(ctx, `DELETE FROM identity_realm_epochs WHERE org_id = $1`, org)
			return execErr
		}); err != nil {
			t.Fatalf("drop the epoch row: %v", err)
		}

		// EVERY write path must refuse, not just the read path.
		if _, err := store.Upsert(ctx, realmFixture(org, "second", "https://idp.lostwrite2.example", 1), "admin"); err == nil {
			t.Error("Upsert re-issued an epoch for an organization whose epoch row was lost while realms remained; epochs 1..4 were already bound into closures and proofs")
		}
		if _, _, err := store.Remove(ctx, org, "primary"); err == nil {
			t.Error("Remove re-issued an epoch for an organization whose epoch row was lost while realms remained")
		}
		if _, _, err := store.Remove(ctx, org, "does-not-exist"); err == nil {
			t.Error("a NO-OP Remove reported an epoch for an organization whose epoch row was lost; it returned 1, a plausible-looking real epoch rather than an obvious sentinel")
		}
		// Nothing slipped through: a refused write must change nothing.
		var realms, epochRows int
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx,
				`SELECT (SELECT count(*) FROM identity_trust_realms WHERE org_id = $1),
				        (SELECT count(*) FROM identity_realm_epochs WHERE org_id = $1)`, org).Scan(&realms, &epochRows)
		}); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if realms != 1 || epochRows != 0 {
			t.Fatalf("after three refused writes: %d realm(s), %d epoch row(s); want 1 and 0", realms, epochRows)
		}

		// THE CONTROL, without which every refusal above could be ambient.
		// Restoring the epoch row ABOVE the highest ever issued makes the same
		// write succeed, and it continues upward rather than restarting.
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(ctx,
				`INSERT INTO identity_realm_epochs (org_id, epoch) VALUES ($1, 5)`, org)
			return execErr
		}); err != nil {
			t.Fatalf("restore the epoch row: %v", err)
		}
		epoch, err := store.Upsert(ctx, realmFixture(org, "second", "https://idp.lostwrite2.example", 1), "admin")
		if err != nil {
			t.Fatalf("an Upsert was refused with the epoch row restored, so the refusals above are not evidence about the precondition: %v", err)
		}
		if epoch != 6 {
			t.Fatalf("epoch = %d after restoring at 5 and writing once, want 6 - it must continue upward, never restart", epoch)
		}
	})

	t.Run("a genuinely fresh organization still starts at 1", func(t *testing.T) {
		// The other side of the precondition: it must NOT refuse an
		// organization with no realms and no epoch row, which is every
		// organization's first write.
		org := "org_first_write"
		epoch, err := store.Upsert(ctx, realmFixture(org, "primary", "https://idp.firstwrite.example", 1), "admin")
		if err != nil {
			t.Fatalf("the first write to a fresh organization was refused: %v", err)
		}
		if epoch != 1 {
			t.Fatalf("epoch = %d on a fresh organization's first write, want 1", epoch)
		}
		if _, e, err := store.Remove(ctx, "org_never_touched_at_all", "nothing"); err != nil || e != 1 {
			t.Fatalf("no-op Remove on an untouched organization: epoch=%d err=%v, want 1 and no error", e, err)
		}
	})

	t.Run("a realm outside the qualifier grammar is refused by Upsert before any row is written", func(t *testing.T) {
		// #3709 row 3. The column's CHECKs enforce only colon-free and
		// non-empty; the full grammar is enforced on the write path, because
		// a stored non-conforming realm would fail the whole organization's
		// LoadRegistry rather than just itself.
		org := "org_grammar"
		bad := realmFixture(org, "acme+prod", "https://idp.grammar.example", 1)
		bad.DelegateRealms = []RealmID{"peer"}
		if _, err := store.Upsert(ctx, bad, "admin"); err == nil {
			t.Fatal("Upsert stored realm id acme+prod, which every principal minted under it would carry as an unparseable qualifier")
		} else if !strings.Contains(err.Error(), "qualifier") {
			t.Errorf("the refusal does not name the qualifier grammar: %v", err)
		}
		// Counted INSIDE the org's RLS scope: a count outside it reads zero
		// under FORCE RLS whether or not a row exists, which would make this
		// assertion pass for the wrong reason.
		var n int
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_trust_realms WHERE org_id = $1`, org).Scan(&n)
		}); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if n != 0 {
			t.Fatalf("a refused Upsert left %d row(s) behind", n)
		}
		// A conforming realm with a NON-conforming delegate is refused too.
		delegate := realmFixture(org, "acme-prod", "https://idp.grammar.example", 1)
		delegate.DelegateRealms = []RealmID{"eu/central"}
		if _, err := store.Upsert(ctx, delegate, "admin"); err == nil {
			t.Fatal("Upsert stored a realm whose delegate realm id eu/central is outside the grammar")
		}
		// The control: the same realm with a legal id and delegate is stored.
		ok := realmFixture(org, "acme-prod", "https://idp.grammar.example", 1)
		ok.DelegateRealms = []RealmID{"peer"}
		if _, err := store.Upsert(ctx, ok, "admin"); err != nil {
			t.Fatalf("the control realm acme-prod was refused, so the refusals above are not evidence about the grammar: %v", err)
		}
	})

	t.Run("a realm id at the validator's bound is storable", func(t *testing.T) {
		// AGAINST THE REAL COLUMN, not against a second copy of its width.
		// The previous check compared maxPrincipalComponent to a hand-copied
		// Go constant, so it was a tautology over two Go values and the schema
		// was free to drift back to VARCHAR(255) - which a mutant confirmed:
		// reverting the column left the entire package green.
		org := "org_long_realm_id"
		longID := strings.Repeat("r", maxPrincipalComponent)
		realm := realmFixture(org, longID, "https://idp.longid.example", 1)
		// realmFixture derives DelegateRealms from the realm id, which would
		// itself exceed the bound and make this case fail for the wrong
		// reason. The delegate is a realm id in its own right and is bounded
		// the same way.
		realm.DelegateRealms = []RealmID{"peer"}
		if err := realm.Validate(); err != nil {
			t.Fatalf("a realm id at maxPrincipalComponent (%d) does not validate, so this case is about the wrong bound: %v", maxPrincipalComponent, err)
		}
		if _, err := store.Upsert(ctx, realm, "admin"); err != nil {
			t.Fatalf("a realm id of %d bytes - which ValidateRealmID ACCEPTS - could not be stored: %v.\nThe column must be at least as wide as the validator, or a realm the type calls valid is unstorable and the failure surfaces as a raw driver error at the INSERT.", maxPrincipalComponent, err)
		}
		got, err := store.Get(ctx, org, RealmID(longID))
		if err != nil {
			t.Fatalf("reading back the long realm id: %v", err)
		}
		if string(got.RealmID) != longID {
			t.Fatalf("the stored realm id came back %d bytes, want %d - it was truncated", len(got.RealmID), len(longID))
		}
	})

	t.Run("a load's realms and epoch always describe each other", func(t *testing.T) {
		// THE RACE THIS PINS WAS REAL AND WAS REPRODUCED, both by the review
		// and by this case against the two-statement version: rls.WithOrgScope
		// opens a READ COMMITTED transaction, where each STATEMENT takes a
		// fresh snapshot, so a Load that read realms and then the epoch could
		// return five realms and the epoch that described six - while its own
		// comment claimed the transaction made them agree.
		//
		// A replica hydrating that answer holds a realm set missing a peer's
		// realm while reporting an epoch that says it is current, so every
		// proof it mints binds a current-looking epoch to a stale
		// configuration.
		//
		// The fixture makes `epoch == len(realms)` the exact invariant: every
		// write is a DISTINCT NEW realm, so each costs exactly one epoch bump
		// and nothing else can move the two apart. Any inequality is the two
		// reads disagreeing.
		org := "org_snapshot"
		const writes = 12
		// SEEDED FIRST, deliberately. Before anything is written an
		// organization has no epoch row and Load reports the documented
		// baseline of 1 for zero realms - a legitimate state that breaks
		// `epoch == len(realms)` and would be counted as a mismatch below.
		// Seeding one realm means every sample is a sample of the property
		// under test. (The first version of this case did not seed and
		// reported the baseline as a defect, which is the loop proving it can
		// fail.)
		if _, err := store.Upsert(ctx, realmFixture(org, "realm-seed", "https://idp.snap-seed.example", 1), "admin"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		// THE WRITER IS PACED BY THE READER, NOT BY THE CLOCK (#3648). The
		// first version raced a free-running writer against a free-running
		// reader and then required `reads >= 3` as an anti-vacuity floor. On
		// CI (run 33623146131 attempt 1) the twelve Upserts finished before
		// the third Load returned and the case failed on ITS OWN FLOOR -
		// "only 2 load(s) ran against the concurrent writer" - while the
		// invariant it pins had held on every load. A floor that depends on
		// the RELATIVE speed of two goroutines is a flake by construction;
		// the same shape passed 50 of 50 locally because a laptop's Load is
		// faster than a loaded runner's. So the writer now waits, after each
		// Upsert, until the reader has completed a Load that finished AFTER
		// that Upsert started: every write is sampled by at least one Load
		// whatever the machine, the two still overlap in time (the Load that
		// releases the writer began before or during the write), and the
		// floor below is structural rather than a bet on speed.
		// readerPacedWriter and its deterministic regression test live in
		// realm_store_pacing_test.go.
		var pacer readerPacedWriter
		done := make(chan error, 1)
		go func() {
			for i := 0; i < writes; i++ {
				mark := pacer.loadsCompleted()
				r := realmFixture(org, fmt.Sprintf("realm-%02d", i), fmt.Sprintf("https://idp.snap-%02d.example", i), 1)
				if _, err := store.Upsert(ctx, r, "admin"); err != nil {
					done <- err
					return
				}
				if err := pacer.awaitLoadAfter(ctx, mark); err != nil {
					done <- fmt.Errorf("waiting for the reader to sample write %d: %w", i, err)
					return
				}
			}
			done <- nil
		}()

		reads, mismatches := 0, 0
		var worst string
		sample := func() {
			realms, epoch, err := store.Load(ctx, org)
			if err != nil {
				t.Fatalf("load during concurrent writes: %v", err)
			}
			reads++
			pacer.recordLoad()
			if epoch != int64(len(realms)) {
				mismatches++
				// The direction discriminates the cause: epoch > realms is a
				// doubled bump (a retried transaction re-running the epoch
				// write), epoch < realms is a genuinely stale epoch read.
				worst = fmt.Sprintf("%d realm(s) with epoch %d (epoch - realms = %+d)", len(realms), epoch, epoch-int64(len(realms)))
			}
		}
		for {
			sample()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("concurrent writer: %v", err)
				}
				sample() // once more, so the settled final state is included
				realms, _, err := store.Load(ctx, org)
				if err != nil {
					t.Fatalf("final load: %v", err)
				}
				if len(realms) != writes+1 {
					t.Fatalf("final load holds %d realm(s), want %d", len(realms), writes+1)
				}
				if reads < writes {
					// Structural now: the pacer releases the writer only after a
					// completed Load, so fewer loads than writes means the pacer
					// is broken, not that the runner was slow.
					t.Fatalf("only %d load(s) ran against %d concurrent writes; the reader-paced writer should have made at least one load per write, so the pacing is broken and this case proves nothing", reads, writes)
				}
				if mismatches != 0 {
					t.Fatalf("%d of %d loads returned realms and an epoch that do not describe each other (worst: %s).\nA replica holding that answer mints proofs binding a current-looking epoch to a stale realm set.", mismatches, reads, worst)
				}
				return
			default:
			}
		}
	})

	t.Run("an organization with nothing stored reports the epoch a fresh registry does", func(t *testing.T) {
		realms, epoch, err := store.Load(ctx, "org_never_configured")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(realms) != 0 {
			t.Fatalf("loaded %d realms for an organization with none", len(realms))
		}
		// 1, not 0. A fresh RealmRegistry starts at 1, and an epoch of 0 - a
		// value no registry ever reports - would read as "older than
		// everything" to any comparison against a bound epoch.
		if epoch != 1 {
			t.Fatalf("epoch = %d for an unconfigured organization, want 1 (what a fresh RealmRegistry reports)", epoch)
		}
	})

	t.Run("loading a registry reproduces the stored configuration, twice", func(t *testing.T) {
		org := "org_hydrate"
		a := realmFixture(org, "alpha", "https://idp.alpha.example", 1)
		b := realmFixture(org, "beta", "https://idp.beta.example", 1)
		for _, r := range []TrustRealm{a, b} {
			if _, err := store.Upsert(ctx, r, "admin"); err != nil {
				t.Fatalf("upsert %s: %v", r.RealmID, err)
			}
		}

		registry, epoch, err := store.LoadRegistry(ctx, org)
		if err != nil {
			t.Fatalf("load registry: %v", err)
		}
		// The STORE's epoch, not the registry's. The registry's counter is per
		// process and counts the registrations this call just made; two
		// replicas that loaded the same configuration must not disagree about
		// the epoch because one had registered something else earlier in its
		// life.
		if epoch != 2 {
			t.Fatalf("LoadRegistry reported epoch %d, want the stored 2 (the registry's own counter would be %d)", epoch, registry.Epoch())
		}
		ids := registry.RealmIDs(org)
		if len(ids) != 2 || ids[0] != "alpha" || ids[1] != "beta" {
			t.Fatalf("registry holds %v, want both stored realms", ids)
		}
		// The EX-47 lookup resolves, which is the whole point of persisting
		// realms: a replica that was told nothing by any other channel still
		// recognises the organization's issuers.
		got, ok := registry.LookupByIssuer(org, "https://idp.alpha.example")
		if !ok || got.RealmID != "alpha" {
			t.Fatalf("issuer lookup after loading: realm %q ok=%t", got.RealmID, ok)
		}

		// IDEMPOTENT. The previous shape registered into a caller's registry
		// and could NOT be called twice - Register refuses a re-registration
		// that does not advance the version - so a store built for replica
		// consistency had no refresh path at all. A second call must produce
		// an equivalent registry, because refreshing is the ordinary case.
		again, epochAgain, err := store.LoadRegistry(ctx, org)
		if err != nil {
			t.Fatalf("a SECOND load of the same unchanged store failed: %v.\nRefreshing is the ordinary case for a store whose purpose is that replicas resolve the same issuers.", err)
		}
		if epochAgain != epoch {
			t.Fatalf("the second load reported epoch %d, want the unchanged %d", epochAgain, epoch)
		}
		if ids := again.RealmIDs(org); len(ids) != 2 || ids[0] != "alpha" || ids[1] != "beta" {
			t.Fatalf("the second load produced %v, want both stored realms", ids)
		}
		// And another organization's issuer does NOT resolve in this one.
		if _, ok := registry.LookupByIssuer("org_tenant_a", "https://idp.alpha.example"); ok {
			t.Fatal("an issuer hydrated for one organization resolved in another")
		}
	})

	t.Run("a row that cannot be decoded fails the whole load", func(t *testing.T) {
		// Skipping the bad row and returning the rest produces a registry
		// quietly missing one realm, and a missing realm is UNKNOWN_REALM for
		// every credential from its issuer - visible only as a wave of denials
		// with no cause attached to any of them.
		org := "org_corrupt"
		good := realmFixture(org, "good", "https://idp.good.example", 1)
		bad := realmFixture(org, "bad", "https://idp.bad.example", 1)
		for _, r := range []TrustRealm{good, bad} {
			if _, err := store.Upsert(ctx, r, "admin"); err != nil {
				t.Fatalf("upsert %s: %v", r.RealmID, err)
			}
		}
		// Corrupt ONE row's config in a way only the decoder can see: an
		// enumeration value that does not exist.
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(ctx, `
				UPDATE identity_trust_realms
				   SET config = jsonb_set(config, '{directory}', '"external-graph-ish"')
				 WHERE org_id = $1 AND realm_id = 'bad'`, org)
			return execErr
		}); err != nil {
			t.Fatalf("corrupt the row: %v", err)
		}

		realms, _, err := store.Load(ctx, org)
		if err == nil {
			t.Fatalf("the load returned %d realm(s) despite an undecodable row; a registry silently missing a realm denies every credential from its issuer with no cause attached", len(realms))
		}
		if !strings.Contains(err.Error(), `"bad"`) {
			t.Errorf("the failure does not name the offending realm: %v", err)
		}
		// The control: the same load succeeds once the row is repaired, so the
		// failure above is the corruption and not something ambient.
		if err := rls.WithOrgScope(ctx, appDB, org, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(ctx, `
				UPDATE identity_trust_realms
				   SET config = jsonb_set(config, '{directory}', '"scim"')
				 WHERE org_id = $1 AND realm_id = 'bad'`, org)
			return execErr
		}); err != nil {
			t.Fatalf("repair the row: %v", err)
		}
		if realms, _, err := store.Load(ctx, org); err != nil || len(realms) != 2 {
			t.Fatalf("after repair: %d realm(s), err = %v; the earlier failure is therefore not evidence about the corrupt row", len(realms), err)
		}
	})

	t.Run("RLS isolates organizations from the app role", func(t *testing.T) {
		org := "org_isolated"
		if _, err := store.Upsert(ctx, realmFixture(org, "primary", "https://idp.isolated.example", 1), "admin"); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		other := "org_intruder"

		// The store itself, asked for another organization's realm, finds
		// nothing - which is UNKNOWN_REALM, which denies.
		if _, err := store.Get(ctx, other, "primary"); !errors.Is(err, ErrRealmNotFound) {
			t.Fatalf("err = %v, want a not-found for another organization's realm", err)
		}
		realms, _, err := store.Load(ctx, other)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(realms) != 0 {
			t.Fatalf("loading %s returned %d realm(s) belonging to %s", other, len(realms), org)
		}

		// And underneath, the policy is what does it: a direct read naming the
		// other organization returns nothing.
		var n int
		for _, table := range []string{"identity_trust_realms", "identity_realm_epochs"} {
			if err := rls.WithOrgScope(ctx, appDB, other, func(tx *sql.Tx) error {
				return tx.QueryRowContext(ctx,
					fmt.Sprintf(`SELECT count(*) FROM %s WHERE org_id = $1`, table), org).Scan(&n)
			}); err != nil {
				t.Fatalf("scoped read of %s: %v", table, err)
			}
			if n != 0 {
				t.Fatalf("the app role scoped to %s read %d row(s) of %s from %s", other, n, org, table)
			}
			// Unscoped, nothing is visible at all: current_setting(..., true)
			// is NULL when unset and `org_id = NULL` is NULL, so a query that
			// forgets its organization matches NOTHING rather than everything.
			if err := appDB.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
				t.Fatalf("unscoped read of %s: %v", table, err)
			}
			if n != 0 {
				t.Fatalf("an UNSCOPED app-role read of %s returned %d row(s)", table, n)
			}
		}

		// Writing into another organization is refused by the policy's WITH
		// CHECK rather than silently stored where nobody will look for it.
		err = rls.WithOrgScope(ctx, appDB, other, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(ctx, `
				INSERT INTO identity_trust_realms (org_id, realm_id, kind, canonical_issuer, enabled, version, config)
				VALUES ($1, 'smuggled', 'oidc', 'https://idp.smuggled.example', true, 1, '{}'::jsonb)`, org)
			return execErr
		})
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("the app role scoped to %s wrote a realm for %s: err = %v", other, org, err)
		}
	})
}

// realmsEqual compares two realms VALUE BY VALUE.
//
// AN EARLIER VERSION COMPARED THEIR ENCODINGS, with a comment claiming that
// made it immune to a field the codec drops. It is the opposite: comparing
// encodings is precisely HOW a dropped field hides, because both sides omit it
// and compare equal. With a mutant that dropped `Enabled` from the record,
// `want.Enabled` was true, `got.Enabled` was false, and the encoding compare
// returned true - so the subtest named "every field intact" was verifying only
// that the BLOB survived the database, not that the realm did.
//
// reflect.DeepEqual over the loaded value is what the subtest's name claims.
// The codec's own field-by-field guard is
// TestEveryTrustRealmFieldSurvivesTheRoundTrip, which walks the struct by
// reflection and recurses into nested ones.
func realmsEqual(a, b TrustRealm) bool {
	return reflect.DeepEqual(a, b)
}

// TestMigration169_TrustRealms_RealPostgres exercises the migration file
// itself: its self-verification, its FORCE'd RLS posture from a NON-SUPERUSER
// OWNER, its CHECK constraints, and its down migration.
//
// Own container: it changes table ownership and then drops the tables, neither
// of which the store suite above could survive.
func TestMigration169_TrustRealms_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pc.DB
	ctx := context.Background()

	applyRealmMigration(t, db, "migrations/core/169_identity_trust_realms.sql")
	applyRealmMigration(t, db, "migrations/core/169_identity_trust_realms.sql")

	t.Run("RLS is ENABLEd and FORCEd on both tables", func(t *testing.T) {
		for _, table := range []string{"identity_trust_realms", "identity_realm_epochs"} {
			var enabled, forced bool
			if err := db.QueryRowContext(ctx,
				`SELECT relrowsecurity, relforcerowsecurity FROM pg_catalog.pg_class WHERE oid = $1::regclass`,
				table).Scan(&enabled, &forced); err != nil {
				t.Fatalf("%s: %v", table, err)
			}
			if !enabled || !forced {
				t.Errorf("%s: RLS enabled=%t forced=%t, want both. Without FORCE the table OWNER bypasses every policy.", table, enabled, forced)
			}
		}
	})

	t.Run("the issuer constraint is scoped to the organization", func(t *testing.T) {
		// THE COLUMN NAMES ARE RESOLVED, not counted. An arity check under a
		// message that asserts the columns is the pattern the migration's own
		// probe was fixed for: `UNIQUE (org_id, kind)` is two columns and
		// catastrophically wrong, and it satisfies a count.
		var cols string
		if err := db.QueryRowContext(ctx, `
			SELECT string_agg(a.attname, ',' ORDER BY a.attname)
			  FROM pg_catalog.pg_constraint c
			  JOIN pg_catalog.pg_attribute a
			    ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
			 WHERE c.conrelid = 'identity_trust_realms'::regclass
			   AND c.conname = 'identity_trust_realms_issuer_uniq'`).Scan(&cols); err != nil {
			t.Fatal(err)
		}
		if cols != "canonical_issuer,org_id" {
			t.Fatalf("the issuer uniqueness constraint covers (%s), want (org_id, canonical_issuer). A global one lets one customer's registration lock another out of a shared public IdP.", cols)
		}
	})

	t.Run("a realm id carrying a colon is refused", func(t *testing.T) {
		// A realm id is colon-free BY CONSTRUCTION, and that is not cosmetic:
		// it is what makes the canonical principal wire form parseable when a
		// subject id contains colons. A colon here produces principals nothing
		// can parse back.
		insert := func(realmID string) error {
			return rls.WithOrgScope(ctx, db, "org-a", func(tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, `
					INSERT INTO identity_trust_realms (org_id, realm_id, kind, canonical_issuer, enabled, version, config)
					VALUES ('org-a', $1, 'oidc', $2, true, 1, '{}'::jsonb)`,
					realmID, "https://idp."+realmID+".example")
				return err
			})
		}
		if err := insert("has:colon"); err == nil {
			t.Fatal("a realm id containing a colon was stored")
		} else if !strings.Contains(err.Error(), "colon_free") {
			t.Errorf("the refusal did not come from the colon-free CHECK: %v", err)
		}
		// The control: the same insert with a colon-free id succeeds, so the
		// refusal above is the CHECK and not the policy or a typo.
		if err := insert("no-colon"); err != nil {
			t.Fatalf("a colon-free realm id was refused, so the refusal above is not evidence about the CHECK: %v", err)
		}
	})

	t.Run("a non-superuser OWNER is bound by the policy", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `CREATE ROLE rls_owner_169 LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'ownerpw'`); err != nil {
			t.Fatalf("create owner role: %v", err)
		}
		// The CONTROL: the same shape with ENABLE but no FORCE. If the probe
		// below cannot distinguish the two it is not testing FORCE.
		if _, err := db.ExecContext(ctx, `
			CREATE TABLE rls_control_169 (org_id TEXT NOT NULL, note TEXT);
			ALTER TABLE rls_control_169 ENABLE ROW LEVEL SECURITY;
			CREATE POLICY rls_control_169_org_isolation ON rls_control_169
				USING (org_id = current_setting('app.current_org_id', true))
				WITH CHECK (org_id = current_setting('app.current_org_id', true));
			INSERT INTO rls_control_169 (org_id, note) VALUES ('org-a', 'control');
			ALTER TABLE rls_control_169 OWNER TO rls_owner_169;
			ALTER TABLE identity_trust_realms OWNER TO rls_owner_169;
			ALTER TABLE identity_realm_epochs OWNER TO rls_owner_169`); err != nil {
			t.Fatalf("set up the owner and the control table: %v", err)
		}

		ownerDB, err := sql.Open("postgres", replaceCredsForRealmStore(t, pc.URL, "rls_owner_169", "ownerpw"))
		if err != nil {
			t.Fatalf("open owner connection: %v", err)
		}
		defer func() { _ = ownerDB.Close() }()
		var who string
		if err := ownerDB.QueryRowContext(ctx, `SELECT current_user`).Scan(&who); err != nil {
			t.Fatal(err)
		}
		if who != "rls_owner_169" {
			t.Fatalf("the probe is connected as %q, not the table owner", who)
		}

		// THERE MUST BE A ROW TO HIDE. `count(*) == 0` is equally true of an
		// EMPTY table, so without this the probe below would pass against a
		// table with no policy at all - and it was non-vacuous only by
		// accident, because an earlier subtest happened to leave a row behind.
		var seeded int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM identity_trust_realms`).Scan(&seeded); err != nil {
			t.Fatalf("count rows on the superuser handle: %v", err)
		}
		if seeded == 0 {
			t.Fatal("identity_trust_realms is empty, so an owner reading 0 rows proves nothing about FORCE")
		}

		var n int
		if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM identity_trust_realms`).Scan(&n); err != nil {
			t.Fatalf("owner read: %v", err)
		}
		if n != 0 {
			t.Fatalf("the table OWNER read %d of the %d realm(s) present, with no organization scope; RLS is not FORCEd and every isolation assertion made on an owner connection is vacuous", n, seeded)
		}
		if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM rls_control_169`).Scan(&n); err != nil {
			t.Fatalf("owner read of the control table: %v", err)
		}
		if n != 1 {
			t.Fatalf("the ENABLE-but-not-FORCE control returned %d row(s) to its owner, want 1. The probe above cannot tell FORCE from its absence, so it is not evidence.", n)
		}
	})

	t.Run("the down migration removes both tables and is idempotent", func(t *testing.T) {
		applyRealmMigration(t, db, "migrations/core/169_identity_trust_realms_down.sql")
		for _, table := range []string{"identity_trust_realms", "identity_realm_epochs"} {
			var reg sql.NullString
			if err := db.QueryRowContext(ctx, `SELECT to_regclass($1)::text`, table).Scan(&reg); err != nil {
				t.Fatal(err)
			}
			if reg.Valid {
				t.Errorf("%s still exists after the down migration", table)
			}
		}
		applyRealmMigration(t, db, "migrations/core/169_identity_trust_realms_down.sql")
		applyRealmMigration(t, db, "migrations/core/169_identity_trust_realms.sql")
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM identity_trust_realms`).Scan(&n); err != nil {
			t.Fatalf("re-applied migration did not produce a usable table: %v", err)
		}
	})
}

// replaceCredsForRealmStore swaps the user:password in a postgres URL.
//
// The package already has replaceCreds in provisioning_realpg_test.go, which
// carries //go:build enterprise - so it is not compiled into the community
// test binary this file also runs in.
func replaceCredsForRealmStore(t *testing.T, url, user, pass string) string {
	t.Helper()
	rest, ok := strings.CutPrefix(url, "postgres://")
	if !ok {
		t.Fatalf("unexpected postgres URL shape: %q", url)
	}
	_, hostPart, found := strings.Cut(rest, "@")
	if !found {
		t.Fatalf("unexpected postgres URL shape (no creds): %q", url)
	}
	return "postgres://" + user + ":" + pass + "@" + hostPart
}
