// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"axonflow/platform/agent/rls"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// The signing chain, and the exact claim it makes.
//
// #3762 signed with a per-process ephemeral ed25519 key authorized in that
// process's own trust store. That was deliberate: a durable signing IDENTITY
// for policy bundles is #3605's KMS custody chain, and building a second
// key-custody surface beside it would be the vocabulary fork this program
// exists to avoid.
//
// What it left broken is verification, not signing. A persisted artifact whose
// authorizing key died with the process that made it is a durable row nothing
// can check - worse than not persisting it, because it looks like policy
// history. So this file persists the PUBLIC half of every authorization and
// nothing else:
//
//   - each process still mints its own key and can only sign AS ITSELF;
//   - every process can VERIFY everything any process ever published;
//   - the private key never reaches the database, so this adds no key-custody
//     surface for #3605 to have to reconcile with.
//
// The strength of the chain is therefore bounded by who may INSERT a row into
// typed_policy_signing_keys, which is the organization's own application role
// under FORCE ROW LEVEL SECURITY. That is a real bound and it is stated rather
// than claimed away; narrowing it to an explicit authorizing act is #3605's,
// and migrations/core/176 carries the REVISIT WHEN (it was enterprise/155
// until #3975 moved these tables to core; 155's copy is unchanged but is no
// longer the owner).

// KeyIDFor derives a signing key's identifier FROM THE KEY ITSELF.
//
// # Why this is not left to the caller, having been left to the caller twice
//
// Every caller mints an ephemeral key per workspace and records its public
// half. An identifier that does not depend on the key material is therefore
// STABLE ACROSS PROCESSES WHILE THE MATERIAL IS NOT, so the second process to
// authorize under it presents a new key under an existing id - which
// AuthorizeKey refuses, correctly, because that read-back is the only thing
// stopping one process from silently taking over another's identity.
//
// The consequence is not a visible error. Both known callers treat a failed
// authorization as "no durable store" and fall back to an in-process one, so
// the symptom is that DURABLE STORAGE WORKS EXACTLY ONCE PER ORGANIZATION,
// EVER, and every publication made before a restart is unreachable after it.
//
// That defect has now been written twice by two different callers a week
// apart: the customer portal (#3962, found by its own restart leg) and the
// orchestrator (#3975, found by the community restart leg). Both were fixed by
// deriving the id from the public key. Fixing it a third time is not a plan, so
// the derivation lives here and AuthorizeKey REFUSES an identifier that does
// not carry the fingerprint of the material presented with it.
//
// The format is unchanged from what both callers already emit:
// "<prefix>-<org>-<first 8 bytes of SHA-256(pub), hex>".
func KeyIDFor(prefix, orgID string, pub ed25519.PublicKey) string {
	return fmt.Sprintf("%s-%s-%s", prefix, orgID, keyFingerprint(pub))
}

// Fingerprint is the material-derived suffix every identifier must carry.
//
// EXPORTED so a caller that needs its own prefix shape can derive the suffix
// rather than reproduce the encoding. The legacy importer built
// `"import-" + hex.EncodeToString(sha256(pub)[:8])`, which is byte-identical to
// this today - and identical only while both sides agree on the slice width and
// on lowercase hex. One function removes that coincidence.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return fmt.Sprintf("%x", sum[:8])
}

// keyFingerprint is the internal spelling, kept so the refusal below reads as
// the rule rather than as a call into the exported surface.
func keyFingerprint(pub ed25519.PublicKey) string { return Fingerprint(pub) }

// ErrKeyIDNotDerivedFromKey is returned when an identifier does not carry the
// fingerprint of the key it is presented with.
//
// It is a distinct error because the remedy is specific and mechanical: call
// KeyIDFor. A caller that invents its own identifier is not making a naming
// choice, it is choosing whether durable storage survives a restart.
var ErrKeyIDNotDerivedFromKey = errors.New("authoringstore: a signing key identifier must be derived from the key material (use KeyIDFor); an identifier that is stable while the key is not makes durable storage work exactly once per organization")

// ErrKeyAlreadyAuthorized is returned when a key identifier is already
// authorized under a root with DIFFERENT key material.
//
// It is a distinct error because the two ways this can happen have opposite
// meanings: re-authorizing the SAME public key is a harmless retry and
// succeeds, while re-using an identifier for different material would let one
// process silently take over another's identity and is refused.
var ErrKeyAlreadyAuthorized = errors.New("authoringstore: that key identifier is already authorized under this root with different key material")

// ErrKeyRevoked is returned when the material presented matches a row that has
// been revoked. Distinct from ErrKeyAlreadyAuthorized because the remedy is
// different: a collision needs a new identifier, a revocation needs a new KEY.
var ErrKeyRevoked = errors.New("authoringstore: that key has been revoked")

// AuthorizeKey records the public half of a signing key.
//
// It is idempotent on identical material: an INSERT ... ON CONFLICT DO NOTHING
// followed by a read-back that compares the stored bytes. The read-back is not
// belt-and-braces - without it, DO NOTHING would silently swallow the case
// this function most needs to refuse, which is a second process claiming an
// existing key identifier with a key of its own.
func (s *Store) AuthorizeKey(ctx context.Context, root pdp.Root, keyID string, pub ed25519.PublicKey, authorizedBy string) error {
	if err := requireOrganizationRoot(root); err != nil {
		return err
	}
	if strings.TrimSpace(keyID) == "" {
		return fmt.Errorf("authoringstore: a signing key authorization names no key identifier")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("authoringstore: a signing key authorization carries %d bytes, and an ed25519 public key is %d", len(pub), ed25519.PublicKeySize)
	}
	// THE IDENTIFIER MUST BE DERIVED FROM THE MATERIAL. Checked here rather
	// than trusted, because this is the single door both callers pass through
	// and the alternative has been re-derived incorrectly twice. See KeyIDFor.
	if !strings.HasSuffix(keyID, "-"+keyFingerprint(pub)) {
		return fmt.Errorf("%w: %q does not end in the fingerprint of the key presented with it", ErrKeyIDNotDerivedFromKey, keyID)
	}
	return rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO typed_policy_signing_keys (org_id, root, key_id, public_key, authorized_by)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (org_id, root, key_id) DO NOTHING
		`, s.orgID, string(root), keyID, []byte(pub), authorizedBy); err != nil {
			return fmt.Errorf("authoringstore: authorizing key %q under root %q: %w", keyID, root, err)
		}
		var stored []byte
		var revoked sql.NullTime
		if err := tx.QueryRowContext(ctx, `
			SELECT public_key, revoked_at FROM typed_policy_signing_keys
			WHERE org_id = $1 AND root = $2 AND key_id = $3
		`, s.orgID, string(root), keyID).Scan(&stored, &revoked); err != nil {
			return fmt.Errorf("authoringstore: reading back key %q under root %q: %w", keyID, root, err)
		}
		if !ed25519.PublicKey(stored).Equal(pub) {
			return fmt.Errorf("%w: %q under root %q", ErrKeyAlreadyAuthorized, keyID, root)
		}
		if revoked.Valid {
			// SUCCESS HERE WOULD BE THE WORST ANSWER. LoadTrust reads only
			// unrevoked rows, so a caller told its key was authorized would
			// build a trust store that cannot verify its own signatures, and
			// every publication would fail at admission with "key is not
			// authorized" - naming a key this call had just confirmed.
			return fmt.Errorf(
				"%w: %q under root %q was revoked at %s, and re-presenting the same material does not un-revoke it",
				ErrKeyRevoked, keyID, root, revoked.Time.UTC().Format(time.RFC3339))
		}
		return nil
	})
}

// RevokeKey de-authorizes a signing key.
//
// Artifacts it signed stop verifying from the next process that loads its
// trust store, and immediately for any store rebuilt through LoadTrust. It is
// the read side of the revocation that does the work: nothing deletes the key
// row, because "this key was authorized between these two times" is itself a
// fact the audit trail needs.
func (s *Store) RevokeKey(ctx context.Context, root pdp.Root, keyID, reason string) error {
	if err := requireOrganizationRoot(root); err != nil {
		return err
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("authoringstore: revoking a signing key records a reason; an unexplained withdrawal of trust is the thing the audit trail exists to prevent")
	}
	return rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE typed_policy_signing_keys
			SET revoked_at = $4, revoked_reason = $5
			WHERE org_id = $1 AND root = $2 AND key_id = $3 AND revoked_at IS NULL
		`, s.orgID, string(root), keyID, time.Now().UTC(), reason)
		if err != nil {
			return fmt.Errorf("authoringstore: revoking key %q under root %q: %w", keyID, root, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("authoringstore: revoking key %q under root %q: %w", keyID, root, err)
		}
		if n == 0 {
			return fmt.Errorf("authoringstore: key %q is not authorized under root %q, or is already revoked", keyID, root)
		}
		return nil
	})
}

// LoadTrust builds a trust store from every key this organization has
// authorized under a root and NOT revoked.
//
// This is what makes a persisted artifact verifiable after the process that
// signed it is gone, and it is also where revocation takes effect: a revoked
// row is simply not loaded, so an artifact signed by it fails
// authoring.LoadArtifact with "key is not authorized to publish under this
// root" - the same refusal an unknown key gets, which is correct, because
// after a revocation that is exactly what it is.
func (s *Store) LoadTrust(ctx context.Context, root pdp.Root) (*pdp.TrustStore, error) {
	if err := requireOrganizationRoot(root); err != nil {
		return nil, err
	}
	trust := pdp.NewTrustStore()
	err := rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT key_id, public_key FROM typed_policy_signing_keys
			WHERE org_id = $1 AND root = $2 AND revoked_at IS NULL
			ORDER BY authorized_at ASC, key_id ASC
		`, s.orgID, string(root))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				keyID string
				pub   []byte
			)
			if err := rows.Scan(&keyID, &pub); err != nil {
				return err
			}
			if len(pub) != ed25519.PublicKeySize {
				// The column carries a CHECK for this, so reaching it means
				// the row predates the constraint or the constraint was
				// dropped. Refuse rather than authorize a key that cannot
				// verify anything: a trust store that silently holds a broken
				// key reports "signature does not verify" for artifacts that
				// are in fact fine.
				return fmt.Errorf("stored key %q under root %q is %d bytes, not %d", keyID, root, len(pub), ed25519.PublicKeySize)
			}
			trust.Authorize(root, keyID, ed25519.PublicKey(pub))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("authoringstore: loading the trust store for root %q: %w", root, err)
	}
	return trust, nil
}

// OpenForSigning builds a durable store this process can sign AND verify with.
//
// # Why this exists, in one sentence
//
// The sequence New -> AuthorizeKey -> LoadTrust -> New existed in THREE copies
// (the customer portal, the orchestrator's community route, and the legacy
// importer), and copying that sequence without its key naming is precisely what
// produced #3975 - the durable store working exactly once per organization. A
// sequence that must be written identically in three places is a sequence that
// belongs in one.
//
// # The order is the contract, not a preference
//
// AUTHORIZE BEFORE LOADING. Loading first would hand this process a trust store
// that cannot verify its OWN signatures. Then REBUILD over the loaded trust,
// because the store captures the trust store it was given: the first one holds
// only this process's key, and an artifact signed by an earlier process - or by
// another replica - would not verify through it.
//
// EVERY STEP MUST SUCCEED BEFORE THE CALLER MAY CLAIM DURABILITY. New alone
// validates its arguments and never touches the database, so a caller that
// treated New's success as "durable" would write artifacts whose signing key is
// recorded NOWHERE: rows that outlive the process and cannot be loaded by it,
// which reads as data loss rather than as a stated limit. This returns an error
// if any step fails and the caller must not fall back silently.
//
// # What it returns, and why all of it
//
// The store, the trust store, and the key identifier. The trust is returned
// rather than kept private because a caller rebuilding its authoring plane
// needs it, and because trust REFRESH (#3962: trust is loaded once and baked
// into three separate structs) is being built on top of this - a helper that
// returned only the store would force that work to re-implement the chain,
// which is the defect this function exists to prevent.
// THE ROOT IS A PARAMETER, AND ONE VALUE OF IT IS ACCEPTED (#4047). This
// comment used to say every caller passing pdp.RootOrganization was "a
// coincidence rather than a rule". It is a rule: the system root's authority is
// the shipped corpus, which is never stored, so a durable signing key under it
// is authority granted by whoever could insert the row. The parameter stays so
// the refusal names the root a caller asked for, instead of a caller's constant
// silently disagreeing with this package's.
func OpenForSigning(
	ctx context.Context,
	db *sql.DB,
	root pdp.Root,
	orgID, prefix string,
	pub ed25519.PublicKey,
	authorizedBy string,
) (store *Store, trust authoring.TrustSource, keyID string, err error) {
	if db == nil {
		return nil, nil, "", fmt.Errorf("authoringstore: OpenForSigning requires a database handle; a caller with none has no durable store and should say so rather than pass nil")
	}
	if err := requireOrganizationRoot(root); err != nil {
		return nil, nil, "", err
	}
	keyID = KeyIDFor(prefix, orgID, pub)

	seed := pdp.NewTrustStore()
	seed.Authorize(root, keyID, pub)
	signer, err := New(db, orgID, authoring.StaticTrust(seed))
	if err != nil {
		return nil, nil, "", err
	}
	if err = signer.AuthorizeKey(ctx, root, keyID, pub, authorizedBy); err != nil {
		return nil, nil, "", fmt.Errorf("authorizing this process's signing key: %w", err)
	}
	// AUTHORIZE BEFORE LOADING, then the verifying half - which is the whole of
	// OpenForVerifying and is not restated here.
	store, trust, err = openOverAuthorizedKeys(ctx, signer, db, root, orgID)
	if err != nil {
		return nil, nil, "", err
	}
	return store, trust, keyID, nil
}

// OpenForVerifying builds a durable store a process can READ AND VERIFY with,
// and never sign with (#3895).
//
// # Who needs this and why it is not OpenForSigning
//
// An ENFORCING plane - the agent's decide seam - reads an organization's active
// document and verifies it, and authors nothing. OpenForSigning would make it
// mint a key and record its public half in typed_policy_signing_keys: a row
// claiming a process may publish under the organization root when it never
// will, which is authority granted by a side effect. So this is OpenForSigning
// with the authorization removed and nothing else changed, and OpenForSigning is
// now written as "authorize, then this" so the sequence exists once.
//
// # What it returns
//
// A store over EVERY key the organization has authorized and not revoked, and
// the REFRESHING trust source it verifies through, so an artifact another
// replica signed after this call still verifies (trust_source.go).
func OpenForVerifying(ctx context.Context, db *sql.DB, root pdp.Root, orgID string) (*Store, authoring.TrustSource, error) {
	if db == nil {
		return nil, nil, fmt.Errorf("authoringstore: OpenForVerifying requires a database handle; a caller with none has no durable store and should say so rather than pass nil")
	}
	if err := requireOrganizationRoot(root); err != nil {
		return nil, nil, err
	}
	// An EMPTY seed, and that is correct rather than a placeholder: this store
	// is used for exactly one call, LoadTrust, which reads key rows and verifies
	// no artifact. New refuses a nil trust source, and handing it any key here
	// would be trusting something nobody authorized.
	loader, err := New(db, orgID, authoring.StaticTrust(pdp.NewTrustStore()))
	if err != nil {
		return nil, nil, err
	}
	return openOverAuthorizedKeys(ctx, loader, db, root, orgID)
}

// openOverAuthorizedKeys is the shared tail of both openers: load every
// authorized key through an already-constructed store, then rebuild the store
// over a REFRESHING source of those keys.
func openOverAuthorizedKeys(ctx context.Context, loader *Store, db *sql.DB, root pdp.Root, orgID string) (*Store, authoring.TrustSource, error) {
	loaded, lerr := loader.LoadTrust(ctx, root)
	if lerr != nil {
		return nil, nil, fmt.Errorf("loading the authorized keys: %w", lerr)
	}
	if loaded == nil {
		return nil, nil, fmt.Errorf("authoringstore: LoadTrust returned no trust store for org %q", orgID)
	}
	// THE SAME SOURCE goes to the store and back to the caller, so the API,
	// authoring.Store and this backend all read one object rather than three
	// copies of it. It REFRESHES: see trust_source.go for why a reload publishes
	// a fresh store's pointer rather than authorizing into a live one.
	// REFRESHING, not static. A source captured here is captured for the life
	// of the caller's plane, and the set it captures moves: another replica
	// authorizing its signing key a moment later is invisible to it, and every
	// artifact that replica publishes then fails to verify here. The source
	// re-reads on exactly that condition; see trust_source.go.
	refreshing := newRefreshingTrust(loaded)
	// REBUILT over every authorized key, not just this process's.
	store, err := New(db, orgID, refreshing)
	if err != nil {
		return nil, nil, err
	}
	// BOUND AFTER THE REBUILD, because the loader reads through the store and
	// the store is built over the source. Binding here rather than at
	// construction is what breaks that cycle without giving Store a second
	// constructor - and an unbound source is still correct, it simply never
	// refreshes, which is the behaviour every caller had before this.
	refreshing.bind(func(ctx context.Context) (*pdp.TrustStore, error) {
		return store.LoadTrust(ctx, root)
	})
	return store, refreshing, nil
}
