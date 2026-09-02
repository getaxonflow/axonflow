// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Trust-realm persistence (#3550 PR 2, migration core/169).
//
// RealmRegistry has held an organization's trust realms in memory since
// #3556, with its own doc comment saying "ADR-065 Phase 1 persists realms, and
// that migration is deliberately not in this change: the registry's contract
// is what the rest of the plane compiles against, and it does not change when
// the backing store does." This is that store, and the sentence holds - the
// registry's API is untouched.
//
// # What the store is FOR, and what it is not
//
// It is the durable record of an organization's realm declarations, so that a
// replica which has just booted, or one that has never been told anything by
// any other channel, resolves the same issuers as its peers. It is NOT a
// second lookup path: nothing on a decision path reads this store. Realms are
// LOADED into a RealmRegistry, and every hot-path lookup goes through the
// registry exactly as before. That is deliberate - an issuer lookup that could
// take a database round trip would put the identity plane's availability on
// the database's, and EX-47's answer to a lookup that cannot complete is a
// denial.
//
// # Write-through, and why the epoch moves in the same transaction
//
// Upsert and Remove each bump the organization's identity epoch, and they do
// it in the SAME transaction as the realm write. A decision proof binds the
// epoch; if the two could be observed apart, a replica could read the new
// realm set with the old epoch and mint proofs that look current while
// describing a configuration that has changed.

package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"axonflow/platform/agent/rls"
)

// ErrRealmNotFound is returned when no realm is stored for (org, realm id).
//
// It is distinct from an empty LOAD for the reason RealmRegistry.Lookup's
// second return value exists: absence of a realm is UNKNOWN_REALM, which
// denies, and a caller must be able to tell it from a store that failed to
// answer - which is a different failure with a different remedy.
var ErrRealmNotFound = errors.New("identity: no trust realm stored for this organization and realm id")

// DBRealmStore persists trust realms in the tables of migration core/169.
type DBRealmStore struct {
	db *sql.DB
}

// NewDBRealmStore builds the store.
func NewDBRealmStore(db *sql.DB) (*DBRealmStore, error) {
	if db == nil {
		return nil, fmt.Errorf("identity: NewDBRealmStore requires a database handle; organization isolation on identity_trust_realms is RLS, and there is nothing to scope without one")
	}
	return &DBRealmStore{db: db}, nil
}

const upsertRealmSQL = `
	INSERT INTO identity_trust_realms (
		org_id, realm_id, kind, canonical_issuer, enabled, version, config, updated_by, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	ON CONFLICT (org_id, realm_id) DO UPDATE SET
		kind             = EXCLUDED.kind,
		canonical_issuer = EXCLUDED.canonical_issuer,
		enabled          = EXCLUDED.enabled,
		version          = EXCLUDED.version,
		config           = EXCLUDED.config,
		updated_by       = EXCLUDED.updated_by,
		updated_at       = NOW()
	WHERE EXCLUDED.version > identity_trust_realms.version
	RETURNING version`

// bumpEpochSQL advances an organization's identity epoch, creating the row on
// first use.
//
// THE INCREMENT READS THE STORED VALUE INSIDE THE STATEMENT
// (`identity_realm_epochs.epoch + 1`), never a value the caller carried in.
// Two replicas writing concurrently would both read nothing beforehand and
// both try to insert 1; the ON CONFLICT arm makes the loser increment whatever
// actually landed.
//
// THAT MAKES THE EPOCH MONOTONIC ONLY WHILE THE ROW EXISTS, and an earlier
// version of this comment claimed it "can therefore only ever go UP" full
// stop. It cannot: the INSERT arm fires whenever the row is ABSENT and starts
// again at 1. Callers must therefore run requireEpochRowUnlessOrgIsEmpty
// first, which is what makes the unqualified claim true - the row can only be
// absent for an organization that has no realms either.
// epochStateSQL reports, for one organization, whether an identity-epoch row
// exists and how many realms are stored.
//
// It is read BEFORE any write on every path that advances the epoch. See
// requireEpochRowUnlessOrgIsEmpty for what it is for.
const epochStateSQL = `
	SELECT (SELECT count(*) FROM identity_realm_epochs WHERE org_id = $1),
	       (SELECT count(*) FROM identity_trust_realms WHERE org_id = $1)`

// requireEpochRowUnlessOrgIsEmpty refuses an epoch mutation for an
// organization whose epoch row is MISSING while realms remain.
//
// # Why the read path's refusal was not enough, which is the defect this closes
//
// Load refuses that state, on the argument that epochs 2..N have already been
// bound into cached closures and decision proofs and re-issuing from 1 makes
// an invalidated closure compare equal to a current one. Every WRITE path
// walked straight into it: bumpEpochSQL's INSERT arm fires whenever the row is
// absent and sets the epoch to 1, so the very first Upsert or Remove after a
// partial restore RE-ISSUED epoch 1 for an organization that had already
// issued 1..N - and Load, seeing a row again, was satisfied for ever after.
//
// The realistic sequence is not exotic. A restore repopulates
// identity_trust_realms and not identity_realm_epochs (there is no foreign key
// between them - the migration says so). Replicas refuse to boot: loud, and
// correct. An operator reacts by re-registering a realm through the admin
// path. THAT WRITE SETS THE EPOCH TO 1, every replica loads happily, and every
// closure and proof bound to a higher epoch now compares equal to a current
// one. The guard removed itself in response to somebody reacting to it.
//
// So the refusal lives on both sides, worded the same way, and the invariant
// is a property of the organization rather than of which entry point was
// called. An organization with NO realms and no epoch row is untouched: that
// is a genuinely fresh organization, and its first write legitimately starts
// at 1.
func requireEpochRowUnlessOrgIsEmpty(ctx context.Context, tx *sql.Tx, orgID string) error {
	var epochRows, realms int
	if err := tx.QueryRowContext(ctx, epochStateSQL, orgID).Scan(&epochRows, &realms); err != nil {
		return fmt.Errorf("identity: read the identity-epoch state of organization %s: %w", orgID, err)
	}
	if epochRows == 0 && realms > 0 {
		return fmt.Errorf("identity: organization %s has %d stored trust realm(s) but NO identity-epoch row, so its epoch cannot be advanced.\n"+
			"Refusing rather than restarting at 1: epochs have already been issued for this organization and bound into cached closures and decision proofs, and re-issuing from 1 makes an invalidated closure compare equal to a current one. Writing a realm here would have SILENTLY REPAIRED the symptom and destroyed the invariant. Restore identity_realm_epochs, or set it above the highest epoch this organization has ever issued",
			orgID, realms)
	}
	return nil
}

const bumpEpochSQL = `
	INSERT INTO identity_realm_epochs (org_id, epoch, updated_at)
	VALUES ($1, 1, NOW())
	ON CONFLICT (org_id) DO UPDATE SET
		epoch = identity_realm_epochs.epoch + 1,
		updated_at = NOW()
	RETURNING epoch`

// Upsert stores a realm and advances the organization's identity epoch.
//
// A RE-REGISTRATION MUST ADVANCE THE VERSION, and the `WHERE EXCLUDED.version
// > ...` clause is what enforces it across processes. RealmRegistry.Register
// applies the same rule in memory and explains why: a no-graph closure derives
// its recorded source version from the realm's, so two materially different
// declarations sharing a version produce closures that are indistinguishable
// in a decision proof and in replay. In-process that check is per-replica;
// here it is the database's, so two replicas cannot each accept a different
// declaration at the same version.
//
// A refused re-registration is reported, not swallowed. Returning success for
// a write that did not happen would let an operator believe a configuration
// change had taken effect on a fleet where it had not.
func (s *DBRealmStore) Upsert(ctx context.Context, realm TrustRealm, updatedBy string) (epoch int64, err error) {
	if realm.OrgID == "" {
		return 0, fmt.Errorf("identity: a trust realm must name its organization; org_id is the RLS boundary and a realm never spans organizations")
	}
	config, err := encodeRealm(realm)
	if err != nil {
		return 0, err
	}

	err = rls.WithOrgScope(ctx, s.db, realm.OrgID, func(tx *sql.Tx) error {
		// BEFORE the realm is written, not after: this Upsert is about to
		// create a realm, so afterwards "the organization has realms" is
		// trivially true and the precondition could never distinguish a fresh
		// organization from one whose epoch row was lost.
		if err := requireEpochRowUnlessOrgIsEmpty(ctx, tx, realm.OrgID); err != nil {
			return err
		}

		var stored int64
		scanErr := tx.QueryRowContext(ctx, upsertRealmSQL,
			realm.OrgID, string(realm.RealmID), string(realm.Kind), realm.CanonicalIssuer,
			realm.Enabled, realm.Version, config, nullIfEmpty(updatedBy),
		).Scan(&stored)
		if errors.Is(scanErr, sql.ErrNoRows) {
			// The conflict arm matched but its WHERE refused the update: the
			// stored realm is at this version or a later one.
			var current int64
			if err := tx.QueryRowContext(ctx,
				`SELECT version FROM identity_trust_realms WHERE org_id = $1 AND realm_id = $2`,
				realm.OrgID, string(realm.RealmID)).Scan(&current); err != nil {
				// The write was refused by the version rule; this read was
				// only going to say WHICH version it lost to. Name both, so a
				// reader is not handed a diagnostic about a SELECT when the
				// caller's actual problem is that its registration did not
				// advance the version.
				return fmt.Errorf("identity: realm %q was NOT written - a re-registration must advance the version - and the stored version could not be read to say which one it lost to: %w", realm.RealmID, err)
			}
			return fmt.Errorf("identity: realm %q is already stored at version %d and this registration carries version %d; a re-registration must ADVANCE the version, because a closure derives its recorded source version from it and two different declarations sharing one are indistinguishable in a decision proof and in replay",
				realm.RealmID, current, realm.Version)
		}
		if scanErr != nil {
			if strings.Contains(scanErr.Error(), "identity_trust_realms_issuer_uniq") {
				// The cross-process half of RealmRegistry.Register's
				// issuer-collision refusal. In-process that check is
				// per-replica, so two replicas can pass it concurrently and
				// store two realms claiming one issuer; the constraint is what
				// makes that unconstructible. Named here because the raw
				// constraint violation says nothing about why it matters.
				return fmt.Errorf("identity: issuer %q in organization %s is already declared by a DIFFERENT realm, so realm %q was not stored; an issuer resolving to two realms has no determinate answer and picking one would be arbitrary: %w",
					realm.CanonicalIssuer, realm.OrgID, realm.RealmID, scanErr)
			}
			return fmt.Errorf("identity: store trust realm %q: %w", realm.RealmID, scanErr)
		}
		// The epoch moves in the SAME transaction as the realm write: if the
		// two could be observed apart, a replica could read the new realm set
		// with the old epoch and mint proofs that look current.
		return tx.QueryRowContext(ctx, bumpEpochSQL, realm.OrgID).Scan(&epoch)
	})
	if err != nil {
		return 0, err
	}
	return epoch, nil
}

// Remove deletes a realm and advances the organization's identity epoch.
//
// A removed realm is UNKNOWN_REALM again, not a realm with default settings -
// the same contract RealmRegistry.Remove has, and the reason the epoch must
// advance on a DELETE as well as on a write. That is also why the epoch is a
// stored counter rather than max(version) over the surviving rows: a maximum
// goes DOWN when the highest-versioned realm is removed, and an epoch that
// goes backwards makes a stale cached closure look current again.
//
// Removing a realm that is not there is not an error - the end state is the
// one the caller asked for - but it does NOT advance the epoch, because
// nothing changed and a bump would invalidate every cached closure in the
// organization for no reason.
func (s *DBRealmStore) Remove(ctx context.Context, orgID string, id RealmID) (removed bool, epoch int64, err error) {
	if orgID == "" {
		return false, 0, fmt.Errorf("identity: Remove requires an organization; identity_trust_realms is organization-scoped RLS")
	}
	err = rls.WithOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		// Before the DELETE, for the reason Upsert checks before its INSERT:
		// afterwards the organization may have no realms left, and a lost
		// epoch row would then look like a fresh organization.
		if err := requireEpochRowUnlessOrgIsEmpty(ctx, tx, orgID); err != nil {
			return err
		}

		res, execErr := tx.ExecContext(ctx,
			`DELETE FROM identity_trust_realms WHERE org_id = $1 AND realm_id = $2`, orgID, string(id))
		if execErr != nil {
			return fmt.Errorf("identity: remove trust realm %q: %w", id, execErr)
		}
		n, execErr := res.RowsAffected()
		if execErr != nil {
			return fmt.Errorf("identity: remove trust realm %q: %w", id, execErr)
		}
		if n == 0 {
			// Nothing changed, so the epoch must NOT advance - a no-op bump
			// would invalidate every cached closure in the organization for
			// nothing. But the CURRENT epoch is still what a caller wants
			// back: returning 0 handed out the one value Load's own comment
			// calls unusable ("a value no registry ever reports, and which a
			// comparison against a bound epoch would read as older than
			// everything"), and `removed` was the only thing distinguishing
			// that sentinel from a real answer - which nothing forces a caller
			// to read.
			var current sql.NullInt64
			if scanErr := tx.QueryRowContext(ctx,
				`SELECT epoch FROM identity_realm_epochs WHERE org_id = $1`, orgID).Scan(&current); scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
				return fmt.Errorf("identity: read the current identity epoch: %w", scanErr)
			}
			if current.Valid {
				epoch = current.Int64
				return nil
			}
			// NO EPOCH ROW. Reporting 1 here is right for a genuinely fresh
			// organization and WRONG for one whose epoch row was lost while
			// its realms survived - and the code establishes only "there is no
			// epoch row", which Load's own refusal exists because is reachable.
			//
			// An earlier version returned 1 unconditionally, with a comment
			// asserting "nothing has ever been written for this organization".
			// In the lost-row state that is a plausible-looking real epoch
			// handed back with err == nil, which is worse than the bare 0 it
			// replaced: 0 is at least obviously a sentinel.
			//
			// So the same precondition decides it. It refuses the lost-row
			// state and passes for a genuinely empty organization, which is
			// the only case where 1 is the right answer.
			if err := requireEpochRowUnlessOrgIsEmpty(ctx, tx, orgID); err != nil {
				return err
			}
			epoch = 1
			return nil
		}
		removed = true
		return tx.QueryRowContext(ctx, bumpEpochSQL, orgID).Scan(&epoch)
	})
	if err != nil {
		return false, 0, err
	}
	return removed, epoch, nil
}

// Get reads one stored realm.
func (s *DBRealmStore) Get(ctx context.Context, orgID string, id RealmID) (TrustRealm, error) {
	if orgID == "" {
		return TrustRealm{}, fmt.Errorf("identity: Get requires an organization; identity_trust_realms is organization-scoped RLS")
	}
	var out TrustRealm
	err := rls.WithOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		var config []byte
		scanErr := tx.QueryRowContext(ctx,
			`SELECT config FROM identity_trust_realms WHERE org_id = $1 AND realm_id = $2`,
			orgID, string(id)).Scan(&config)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return ErrRealmNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("identity: read trust realm %q: %w", id, scanErr)
		}
		realm, decErr := decodeRealm(config)
		if decErr != nil {
			// Framed with the organization and the realm, as Load frames its
			// own. A bare codec error names a field and a value and leaves the
			// reader to work out whose realm it was.
			return fmt.Errorf("identity: organization %s realm %q is stored but could not be loaded: %w", orgID, id, decErr)
		}
		out = realm
		return nil
	})
	if err != nil {
		return TrustRealm{}, err
	}
	return out, nil
}

// loadSQL reads an organization's realms AND its identity epoch in ONE
// statement.
//
// ONE STATEMENT, NOT TWO IN ONE TRANSACTION, and the difference is the whole
// point. rls.WithOrgScope opens a READ COMMITTED transaction, where each
// STATEMENT takes a fresh snapshot - so two statements inside it do NOT see a
// consistent view, and a write committing between them is visible to the
// second and not the first. An earlier version read realms and then the epoch
// and claimed the transaction made them agree; measured under a concurrent
// writer, it did not - loads came back holding five realms while reporting the
// epoch that described six.
//
// That is not a cosmetic inconsistency. A replica hydrating that answer holds
// a realm set missing a peer's realm while reporting an epoch that says it is
// current, so every proof it mints binds a current-looking epoch to a stale
// configuration and the staleness the epoch exists to expose is invisible.
//
// The FULL OUTER JOIN ON true is what lets one statement carry all three
// shapes: an organization with realms and an epoch yields one row per realm;
// one with realms and no epoch row yields those rows with a NULL epoch (which
// Load REFUSES - see there); one with neither yields ZERO rows, which Load
// reads as the unconfigured baseline. (An earlier version of this comment said
// "a single all-NULL row"; a FULL OUTER JOIN of two empty sides produces
// nothing. The behaviour was always right - the default arm handles it - only
// the description was wrong.)
const loadSQL = `
	SELECT e.epoch, r.realm_id, r.config
	  FROM (SELECT epoch FROM identity_realm_epochs WHERE org_id = $1) e
	  FULL OUTER JOIN (
	       SELECT realm_id, config FROM identity_trust_realms WHERE org_id = $1
	  ) r ON true
	 ORDER BY r.realm_id`

// ORDERING NOTE: the ORDER BY above gives a stable, readable result set; it is
// NOT the caller's ordering guarantee. sortedRealms re-sorts in Go, and that is
// what wins - deliberately, because the database's ordering depends on its
// collation (en_US.UTF-8 orders differently from Go's byte comparison) and two
// replicas on differently-configured databases must register realms in the SAME
// order, or their per-process epochs and their issuer-collision diagnostics
// would depend on the deployment.

// Load reads every stored realm for one organization, and the organization's
// identity epoch, in ONE statement.
//
// A DECODE FAILURE FAILS THE WHOLE LOAD. Skipping the bad row and returning
// the rest would produce a registry that is quietly missing one realm, and a
// missing realm is UNKNOWN_REALM for every credential from its issuer -
// visible only as a wave of denials with no cause attached to any of them.
// Failing loudly means the replica does not come up believing it has a
// complete configuration.
//
// A MISSING EPOCH ROW BESIDE STORED REALMS IS ALSO A FAILURE, and an earlier
// version defaulted it to 1. That default was justified for an organization
// with NO stored configuration and was applied to one WITH realms too, where
// it is the cardinal sin this design is built around: epochs 2..N have already
// been handed out and bound into cached closures and decision proofs, and
// re-issuing from 1 makes an old epoch compare equal to a new one, so an
// invalidated closure looks current again. It is reachable by an ordinary
// restore that repopulates identity_trust_realms and not identity_realm_epochs
// - two tables with no foreign key between them. The refusal costs a boot; the
// default costs silently reusable stale authorization.
func (s *DBRealmStore) Load(ctx context.Context, orgID string) (realms []TrustRealm, epoch int64, err error) {
	if orgID == "" {
		return nil, 0, fmt.Errorf("identity: Load requires an organization; identity_trust_realms is organization-scoped RLS")
	}
	err = rls.WithOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		rows, queryErr := tx.QueryContext(ctx, loadSQL, orgID)
		if queryErr != nil {
			return fmt.Errorf("identity: load trust realms: %w", queryErr)
		}
		defer func() { _ = rows.Close() }()

		var (
			loaded      []TrustRealm
			storedEpoch sql.NullInt64
		)
		for rows.Next() {
			var (
				rowEpoch sql.NullInt64
				realmID  sql.NullString
				config   []byte
			)
			if scanErr := rows.Scan(&rowEpoch, &realmID, &config); scanErr != nil {
				return fmt.Errorf("identity: load trust realms: %w", scanErr)
			}
			// Every row carries the same epoch - the join is against a single
			// epochs row - so any row's copy is the organization's epoch.
			storedEpoch = rowEpoch
			if !realmID.Valid {
				// The epoch-only row of an organization with no realms.
				continue
			}
			realm, decErr := decodeRealm(config)
			if decErr != nil {
				return fmt.Errorf("identity: organization %s realm %q could not be loaded, so the whole load fails rather than returning a registry silently missing it (a missing realm is UNKNOWN_REALM for every credential from its issuer): %w", orgID, realmID.String, decErr)
			}
			loaded = append(loaded, realm)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return fmt.Errorf("identity: load trust realms: %w", rowsErr)
		}
		realms = sortedRealms(loaded)

		switch {
		case storedEpoch.Valid:
			epoch = storedEpoch.Int64
		case len(realms) > 0:
			return fmt.Errorf("identity: organization %s has %d stored trust realm(s) but NO identity-epoch row.\n"+
				"Refusing rather than restarting the epoch at 1: epochs have already been issued for this organization and bound into cached closures and decision proofs, and re-issuing from 1 makes an invalidated closure compare equal to a current one - the single thing the epoch exists to prevent. Restore identity_realm_epochs, or set it above the highest epoch this organization has ever issued",
				orgID, len(realms))
		default:
			// No realms and no epoch row: nothing has ever been written for
			// this organization. 1 is what a fresh RealmRegistry reports, so
			// an unconfigured organization and an empty in-memory registry
			// agree - rather than 0, a value no registry ever reports and
			// which a comparison against a bound epoch would read as "older
			// than everything".
			epoch = 1
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return realms, epoch, nil
}

// LoadRegistry builds a FRESH RealmRegistry from one organization's stored
// realms, and returns the STORE's identity epoch alongside it.
//
// # Why it returns a new registry rather than filling one in
//
// An earlier version took an existing registry and registered into it. That
// cannot be called twice, and the reason is structural rather than
// incidental: RealmRegistry.Register REFUSES a re-registration whose version
// does not ADVANCE, so hydrating the same unchanged store into the same
// registry a second time always fails. A store whose whole purpose is "a
// replica resolves the same issuers as its peers" therefore had NO REFRESH
// PATH - the only call that worked was the first, on a virgin registry.
//
// Building a fresh registry IS the refresh path: load, then swap the pointer.
// It is idempotent by construction, and it removes the partially-hydrated
// failure mode entirely - a load that fails leaves the caller's live registry
// untouched rather than half-replaced.
//
// # What the caller still has to decide, and this deliberately does not
//
// A deployment's registry also carries BUILT-IN realms (the AxonFlow-minted,
// API-credential, internal-service, community and trusted-header realms), all
// registered at version 1. If a STORED realm shares a builtin's realm id or
// canonical issuer, whichever is registered second is refused - and in the
// builtin path that refusal is memoized per organization, so it is permanent.
// Composing the two sets is the wiring lane's decision (#3564); this function
// returns only what is stored.
//
// It registers through Register rather than writing the registry's maps, so
// every rule Register enforces - the underspecified-realm refusal, the
// issuer-collision refusal, the version-advance rule - applies to stored
// configuration exactly as to configuration supplied any other way.
//
// The epoch returned is the STORE's, not the registry's. The registry's
// counter is per process and counts the registrations this call just made;
// reporting it would make two replicas that loaded identical configuration
// disagree because one had registered something else earlier in its life.
func (s *DBRealmStore) LoadRegistry(ctx context.Context, orgID string) (*RealmRegistry, int64, error) {
	realms, epoch, err := s.Load(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}
	reg := NewRealmRegistry()
	for _, realm := range realms {
		if regErr := reg.Register(realm); regErr != nil {
			return nil, 0, fmt.Errorf("identity: organization %s realm %q was loaded from storage but the registry refused it, so no registry is returned rather than a partially populated one: %w", orgID, realm.RealmID, regErr)
		}
	}
	return reg, epoch, nil
}

// nullIfEmpty maps "" to SQL NULL.
func nullIfEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
