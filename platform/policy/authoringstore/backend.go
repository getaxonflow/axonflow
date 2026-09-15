// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package authoringstore is the durable, organization-scoped storage under
// ADR-065 typed authoring (#3776).
//
// # What it is, and what it deliberately is not
//
// It implements authoring.Backend and NOTHING ELSE. Every rule that governs a
// publication or an activation - the gauntlet, the signature, separation of
// author and approver duties, the version advance, the parent chain - lives in
// platform/decision/authoring and has already run before any method here is
// called. There is no branch in this package that decides whether an
// activation is permitted, because a second opinion on that question is a
// second control plane, and ADR-065's retirement phase exists to end exactly
// that shape.
//
// The one thing it does decide is a compare-and-set: AppendActivation refuses
// unless the root's tip is still the parent the caller checked against. That is
// not a duplicated rule, it is the durable half of a rule the in-memory store
// could only enforce within one process.
//
// # Edition
//
// NONE. This package ships on every edition (#3975).
//
// It lived under ee/ until #3975, on the reasoning that organization-root
// typed authoring is Enterprise-only (v11 decision D4) so its storage should be
// too. That inference does not hold, and the measurement is #3975: #3943 gave
// the ORCHESTRATOR a typed-authoring write route on every edition, and on a
// booted Community stack publish and activate both returned 200 while
// `GET /active` returned 404 after a restart - because migrations/enterprise/155
// never ran there. DURABILITY IS NOT THE PAID FEATURE; ORGANIZATION-ROOT
// AUTHORING IS. A store that empties on restart is not a lesser tier of
// storage, and the edition boundary is carried per document by
// authoring.Profile at publication - which constructs an author may spend - not
// by which rows a deployment is allowed to keep. D4 itself is untouched.
//
// Nothing in this package branches on an edition, a tier or a licence, and
// nothing should: it implements authoring.Backend and the rules that decide
// what may be published all ran before any method here was called.
//
// # Why it is HERE and not beside the seam in platform/decision/authoring
//
// Because that would be a module cycle. platform/decision is its OWN Go module,
// reached from platform/ by a `replace` directive, and this package imports
// platform/agent/rls for WithOrgScope. Moving it into platform/decision would
// make the platform module a dependency of a module the platform module already
// depends on.
//
// So the seam and its durable implementation live in different modules on
// purpose: the Backend INTERFACE stays in platform/decision/authoring, where
// the model is, and the postgres implementation sits in the module that owns
// the database access it needs. Stated here because a placement without a
// written reason gets tidied into the cycle by the next reader who notices the
// two halves are apart.
//
// # Scope
//
// One instance is bound to one organization at construction. Every statement
// runs inside rls.WithOrgScope, so app.current_org_id is set for the
// transaction and the FORCE ROW LEVEL SECURITY policies on every table it
// touches bind: core/176's three and core/181's audit table. Nothing here takes an organization identifier per call, which is
// deliberate: a per-call scope is a per-call opportunity to pass the wrong one.
package authoringstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"axonflow/platform/agent/rls"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// Store is the postgres-backed authoring.Backend for one organization.
//
// CONSTRUCT IT AND HAND IT STRAIGHT TO authoring.NewAPIWithBackend. Its methods
// are exported because an interface's methods must be, not because they are an
// API: PutArtifact and AppendActivation apply no rule beyond the compare-and-set,
// so a caller holding a *Store directly can write an activation row that skips
// separation of author and approver duties, the version advance and the parent
// chain entirely. That is the correct division - the rules live in one place -
// and it is only safe while nothing calls these methods except authoring.Store.
type Store struct {
	db    *sql.DB
	orgID string
	// trust is the SOURCE, read at use time, not a snapshot taken at
	// construction. See authoring.TrustSource for why the three copies were the
	// defect rather than the refresh being missing.
	trust authoring.TrustSource
}

// compile-time proof that this package implements the seam rather than
// something shaped like it.
var _ authoring.Backend = (*Store)(nil)

// ErrSystemRootNotStored is returned when any write, or any trust load, names a
// root other than the organization's (#4047).
//
// The system root's one authority is the corpus this binary shipped: a digest
// compiled into the binary, signed per process for the engine that enforces it
// and never persisted (SYSTEM_ROOT_SIGNING_AUTHORITY.md). A durable system-root
// artifact, activation or signing key therefore has no legitimate writer, and a
// system-root trust store loaded from rows would be authority granted by
// whoever could insert one. migrations/core/178 holds the same line in the
// schema, so a writer that never passes through this package is bound too.
var ErrSystemRootNotStored = errors.New("authoringstore: the durable typed-authoring store holds organization-root policy only; the system root's authority is the shipped corpus, which is signed per process and never stored")

// requireOrganizationRoot is the one check every write path and every trust
// load makes.
func requireOrganizationRoot(root pdp.Root) error {
	if root != pdp.RootOrganization {
		return fmt.Errorf("%w (asked for root %q)", ErrSystemRootNotStored, root)
	}
	return nil
}

// New builds a Store for one organization.
//
// The trust store is required and is used on the READ path: every artifact
// coming back out of the database is re-loaded through authoring.LoadArtifact,
// which re-verifies the signature, recomputes the digest, re-lints the module
// and recompiles the carried source. A row that was written by a process whose
// key has since been revoked therefore fails to load rather than being handed
// back as though nothing had changed.
func New(db *sql.DB, orgID string, trust authoring.TrustSource) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("authoringstore: a durable store requires a database handle")
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("authoringstore: a durable store is bound to one organization and none was named")
	}
	if trust == nil {
		return nil, fmt.Errorf("authoringstore: a durable store requires a trust store; an artifact nothing can verify is not an artifact")
	}
	return &Store{db: db, orgID: orgID, trust: trust}, nil
}

// PutArtifact records a verified artifact.
//
// ON CONFLICT DO NOTHING is the idempotence: the primary key is
// (org_id, root, digest) and the digest is computed over the artifact's own
// content, so a row arriving under an existing digest carries the same bytes.
// It is not an "ignore errors" clause - every OTHER failure still surfaces.
//
// A NEW artifact's publish audit row is written in the same transaction, so an
// artifact whose row cannot be recorded is not stored. An artifact that was
// already stored records nothing: its publish is already on the trail.
func (s *Store) PutArtifact(ctx context.Context, root pdp.Root, a *authoring.Artifact) error {
	if err := requireOrganizationRoot(root); err != nil {
		return err
	}
	if a == nil {
		return fmt.Errorf("authoringstore: cannot store a nil artifact")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("authoringstore: marshalling artifact %s: %w", a.Digest(), err)
	}
	prov := a.Provenance()
	return rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO typed_policy_artifacts
			    (org_id, root, digest, source_digest, document_id, document_version, key_id, artifact)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (org_id, root, digest) DO NOTHING
		`, s.orgID, string(root), a.Digest(), prov.SourceDigest, prov.DocumentID, prov.DocumentVersion, a.KeyID(), raw)
		if err != nil {
			return fmt.Errorf("authoringstore: storing artifact %s under root %q: %w", a.Digest(), root, err)
		}
		stored, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("authoringstore: storing artifact %s under root %q: %w", a.Digest(), root, err)
		}
		if stored == 0 {
			return nil
		}
		return s.recordAudit(ctx, tx, root, authoring.PublishAuditEntry(a), 0)
	})
}

// GetArtifact returns an admitted artifact by digest.
func (s *Store) GetArtifact(ctx context.Context, root pdp.Root, digest string) (*authoring.Artifact, bool, error) {
	return s.loadOne(ctx, `
		SELECT artifact FROM typed_policy_artifacts
		WHERE org_id = $1 AND root = $2 AND digest = $3
	`, root, digest)
}

// ArtifactBySourceDigest returns an admitted artifact by the digest of the
// authoring document it carries.
//
// ORDER BY admitted_at, digest and LIMIT 1 make the answer STABLE rather than
// arbitrary: publishing one document twice produces two artifacts that differ
// only in their timestamp, and an importer asking "is this document already
// here" must get the same answer on every run or its idempotence is a
// coincidence. The oldest wins, and `digest` breaks a same-instant tie.
func (s *Store) ArtifactBySourceDigest(ctx context.Context, root pdp.Root, sourceDigest string) (*authoring.Artifact, bool, error) {
	if sourceDigest == "" {
		return nil, false, nil
	}
	return s.loadOne(ctx, `
		SELECT artifact FROM typed_policy_artifacts
		WHERE org_id = $1 AND root = $2 AND source_digest = $3
		ORDER BY admitted_at ASC, digest ASC
		LIMIT 1
	`, root, sourceDigest)
}

func (s *Store) loadOne(ctx context.Context, query string, root pdp.Root, key string) (*authoring.Artifact, bool, error) {
	var raw []byte
	err := rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, s.orgID, string(root), key).Scan(&raw)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("authoringstore: reading artifact under root %q: %w", root, err)
	}
	art, err := s.loadVerified(ctx, raw)
	if err != nil {
		return nil, false, loadFailure(root, err)
	}
	return art, true, nil
}

// ErrArtifactUnverifiable reports that a stored artifact was read and did not
// verify on load: its signing key is no longer authorized, or its signature,
// digest, module or carried source no longer holds - precisely the condition
// the durable store exists to be able to detect. It is not a storage failure
// and must not read like one (#4255): the typed-authoring route answers it 500
// active_unverifiable, never 503 storage_unavailable.
var ErrArtifactUnverifiable = errors.New("authoringstore: a stored artifact did not verify on load")

// ErrSigningKeyNotLoaded reports that a stored artifact's signing key is not in
// this process's trust, and the reload that could admit it was deferred:
// another reload was in flight, or the last ran inside the reload floor. The
// key may be one another replica authorized moments ago, or one that is not
// authorized at all, and only a reload can tell which (#4255). The
// typed-authoring route answers it 503 key_not_loaded, and a retry after the
// floor usually settles it.
var ErrSigningKeyNotLoaded = errors.New("authoringstore: the artifact's signing key is not loaded on this replica")

// loadFailure names why a stored artifact that was read did not load. The one
// storage failure loadVerified can meet, a failed re-read of the authorized
// keys, is marked there and stays a storage failure. A key that a deferred
// reload has not loaded is ErrSigningKeyNotLoaded. Every other refusal is
// the artifact's own and carries ErrArtifactUnverifiable.
func loadFailure(root pdp.Root, err error) error {
	if errors.Is(err, errKeyReloadFailed) {
		return fmt.Errorf("authoringstore: a stored artifact under root %q could not be verified: %w", root, err)
	}
	if errors.Is(err, ErrSigningKeyNotLoaded) {
		return fmt.Errorf("authoringstore: a stored artifact under root %q: %w", root, err)
	}
	return fmt.Errorf("%w: under root %q: %w", ErrArtifactUnverifiable, root, err)
}

// CountArtifacts returns how many artifacts are stored under a root.
func (s *Store) CountArtifacts(ctx context.Context, root pdp.Root) (int, error) {
	var n int
	err := rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM typed_policy_artifacts
			WHERE org_id = $1 AND root = $2
		`, s.orgID, string(root)).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("authoringstore: counting artifacts under root %q: %w", root, err)
	}
	return n, nil
}

// ListArtifacts returns up to limit artifacts under a root, newest document
// version first.
//
// Every row is re-loaded through authoring.LoadArtifact, so a listing is a
// list of artifacts that STILL verify rather than a list of rows. That costs a
// recompile per artifact and it is the right trade on an authoring surface:
// the alternative is showing an operator a version whose signature, module or
// carried source no longer holds, labelled as though it did.
func (s *Store) ListArtifacts(ctx context.Context, root pdp.Root, limit int) ([]*authoring.Artifact, error) {
	query := `
		SELECT artifact FROM typed_policy_artifacts
		WHERE org_id = $1 AND root = $2
		ORDER BY document_version DESC, digest ASC
	`
	args := []any{s.orgID, string(root)}
	if limit > 0 {
		query += " LIMIT $3"
		args = append(args, limit)
	}
	var raws [][]byte
	err := rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			raws = append(raws, raw)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("authoringstore: listing artifacts under root %q: %w", root, err)
	}
	// Loading happens OUTSIDE the transaction. Each load runs a compile and a
	// lint, and holding a pooled connection open across that work for a page
	// of artifacts is how an authoring listing starves the request path.
	out := make([]*authoring.Artifact, 0, len(raws))
	for _, raw := range raws {
		art, err := s.loadVerified(ctx, raw)
		if err != nil {
			return nil, loadFailure(root, err)
		}
		out = append(out, art)
	}
	return out, nil
}

// ActiveDigest returns the digest the most recent activation named.
func (s *Store) ActiveDigest(ctx context.Context, root pdp.Root) (string, error) {
	digest, _, err := s.ActiveTip(ctx, root)
	return digest, err
}

// ActiveTip returns the digest of the ACTIVE document AND the most recent
// activation's sequence number, from one read. An empty digest with a nil error
// means nothing is active: with a zero sequence nothing was ever activated, and
// with the latest entry's sequence the organization withdrew its document (PRD
// v11 §1.15). A withdrawal still advances the epoch, because it must invalidate
// an outstanding proof like any other change of what is in force.
//
// # WHY THE SEQUENCE AND NOT ONLY THE DIGEST (#3895)
//
// The sequence is the organization root's POLICY EPOCH: it advances on every
// promote AND every rollback, which is exactly the event that must invalidate an
// outstanding challenge or decision proof (contract.Snapshot.PolicyEpoch). The
// digest cannot stand in for it - a rollback to an earlier version reinstates an
// earlier digest, so a digest comparison would read "nothing changed" across the
// one transition the epoch exists to mark. An enforcing plane stamps both onto
// every decision it makes.
//
// It is ONE statement for ActiveDigest's reason: two reads would be two
// instants, and an activation landing between them would pair one version's
// digest with another's sequence.
func (s *Store) ActiveTip(ctx context.Context, root pdp.Root) (string, int64, error) {
	var (
		kind, digest string
		seq          int64
	)
	err := rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT kind, digest, seq FROM typed_policy_activations
			WHERE org_id = $1 AND root = $2
			ORDER BY seq DESC
			LIMIT 1
		`, s.orgID, string(root)).Scan(&kind, &digest, &seq)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("authoringstore: reading the active digest under root %q: %w", root, err)
	}
	if authoring.ActivationKind(kind) == authoring.ActivationWithdraw {
		return "", seq, nil
	}
	return digest, seq, nil
}

// Activations returns the activation history for a root, oldest first.
func (s *Store) Activations(ctx context.Context, root pdp.Root) ([]authoring.Activation, error) {
	var out []authoring.Activation
	err := rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT kind, digest, previous_digest, document_id, document_version, actor, activated_at, reason
			FROM typed_policy_activations
			WHERE org_id = $1 AND root = $2
			ORDER BY seq ASC
		`, s.orgID, string(root))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				act      authoring.Activation
				kind     string
				actorStr string
			)
			if err := rows.Scan(&kind, &act.Digest, &act.PreviousDigest, &act.DocumentID,
				&act.DocumentVersion, &actorStr, &act.At, &act.Reason); err != nil {
				return err
			}
			actor, err := contract.ParseID(contract.KindPrincipal, actorStr)
			if err != nil {
				// An activation record whose actor will not parse is a
				// CORRUPT audit row, not a row to hand back with an empty
				// actor. Silently zeroing it would turn "who activated this"
				// into "nobody", which is the one answer an audit trail must
				// never invent.
				return fmt.Errorf("activation actor %q under root %q does not parse: %w", actorStr, root, err)
			}
			act.Kind = authoring.ActivationKind(kind)
			act.Root = root
			act.Actor = actor
			act.At = act.At.UTC()
			out = append(out, act)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("authoringstore: reading the activation history under root %q: %w", root, err)
	}
	return out, nil
}

// AppendActivation appends one activation record under a compare-and-set on
// the root's current tip.
//
// It is ONE statement, not a read followed by a write, and that is the whole
// design. `tip` computes the current sequence number and the current active
// digest; the INSERT ... SELECT produces a row only when that digest is still
// expectPrev. Two portal replicas racing therefore fail in one of two ways,
// both of which land here as ErrActivationRaced:
//
//   - the loser's WHERE no longer matches, so zero rows are affected;
//   - both compute the same next sequence number and the loser violates
//     UNIQUE (org_id, root, seq).
//
// A read-then-write across two round trips would have a window between them
// that neither mechanism covers.
//
// The activation's audit row is a second statement in the SAME transaction,
// keyed by the sequence number the append returns, so a lost race writes
// neither row and an activation whose audit row cannot be recorded is not
// appended.
func (s *Store) AppendActivation(ctx context.Context, root pdp.Root, act authoring.Activation, expectPrev string) error {
	if act.Actor.IsZero() {
		return fmt.Errorf("authoringstore: refusing to record an activation with no actor")
	}
	if err := requireOrganizationRoot(root); err != nil {
		return err
	}
	return rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		var seq int
		err := tx.QueryRowContext(ctx, `
			-- $3 is BOTH the compare-and-set parameter and the value written
			-- into previous_digest. Both sites carry an explicit ::text cast
			-- because without one postgres deduces varchar(128) from the
			-- INSERT column and text from the comparison, and refuses the
			-- statement with "inconsistent types deduced for parameter $3".
			WITH tip AS (
			    SELECT
			        COALESCE(MAX(seq), 0) AS last_seq,
			        COALESCE((SELECT a.digest FROM typed_policy_activations a
			                   WHERE a.org_id = $1 AND a.root = $2
			                   ORDER BY a.seq DESC LIMIT 1), '')::text AS last_digest
			    FROM typed_policy_activations
			    WHERE org_id = $1 AND root = $2
			)
			INSERT INTO typed_policy_activations
			    (org_id, root, seq, kind, digest, previous_digest,
			     document_id, document_version, actor, activated_at, reason)
			SELECT $1, $2, tip.last_seq + 1, $4, $5, $3::text, $6, $7, $8, $9, $10
			FROM tip
			WHERE tip.last_digest = $3::text
			RETURNING seq
		`, s.orgID, string(root), expectPrev, string(act.Kind), act.Digest,
			act.DocumentID, act.DocumentVersion, act.Actor.String(), act.At.UTC(), act.Reason).Scan(&seq)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: root %q is no longer at %s", authoring.ErrActivationRaced, root, orNone(expectPrev))
		}
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: another replica activated under root %q first", authoring.ErrActivationRaced, root)
			}
			return fmt.Errorf("authoringstore: recording an activation under root %q: %w", root, err)
		}
		return s.recordAudit(ctx, tx, root, authoring.ActivationAuditEntry(act), seq)
	})
}

// recordAudit writes one typed_policy_audit row inside the caller's
// transaction.
//
// It takes the transaction rather than opening its own because being inside
// the write's transaction is the whole point: PRD v11 §1.12 puts the audit row
// in the same transaction as the artifact insert or the activation append, so
// a write whose row cannot be recorded rolls back with it. activationSeq is 0
// for a publish and the appended sequence number for an activation, which is
// what makes the row's primary key name one event (migrations/core/181).
//
// A PUBLISH ROW IS IDEMPOTENT AND AN ACTIVATION ROW IS NOT, and the difference
// is what each key names. A publish row is keyed by the artifact digest, which
// covers every fact the row records, so a second one for the same digest can
// only restate the first: it arises when typed_policy_artifacts lost the row
// and it is stored again, as after core/176's down and re-apply, and the row
// already there stands. An activation's sequence number restarts only when the
// activation history itself was lost, and a row already holding that number
// describes a different event, so the insert is refused and the activation
// with it.
func (s *Store) recordAudit(ctx context.Context, tx *sql.Tx, root pdp.Root, e authoring.AuditEntry, activationSeq int) error {
	approvers := make([]string, 0, len(e.Approvers))
	for _, approver := range e.Approvers {
		approvers = append(approvers, approver.String())
	}
	rawApprovers, err := json.Marshal(approvers)
	if err != nil {
		return fmt.Errorf("authoringstore: marshalling the approvers of %s: %w", e.Digest, err)
	}
	onConflict := ""
	if e.Action == authoring.AuditPublish {
		onConflict = "ON CONFLICT (org_id, root, action, digest, activation_seq) DO NOTHING"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO typed_policy_audit
		    (org_id, root, action, digest, activation_seq, previous_digest,
		     document_id, document_version, actor, approvers, self_approved, reason, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13)
	`+onConflict, s.orgID, string(root), string(e.Action), e.Digest, activationSeq, e.PreviousDigest,
		e.DocumentID, e.DocumentVersion, e.Actor.String(), string(rawApprovers), e.SelfApproved, e.Reason, e.At.UTC()); err != nil {
		return fmt.Errorf("authoringstore: recording the %s audit row for %s under root %q: %w", e.Action, e.Digest, root, err)
	}
	return nil
}

// AuditTrail returns the audit entries recorded under a root, oldest first.
//
// recorded_at is the database's clock at the insert, so the order is the order
// the writes committed in, whichever replica made them; the remaining columns
// only break a tie.
func (s *Store) AuditTrail(ctx context.Context, root pdp.Root) ([]authoring.AuditEntry, error) {
	var out []authoring.AuditEntry
	err := rls.WithOrgScope(ctx, s.db, s.orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT action, digest, previous_digest, document_id, document_version,
			       actor, approvers, self_approved, reason, occurred_at
			FROM typed_policy_audit
			WHERE org_id = $1 AND root = $2
			ORDER BY recorded_at ASC, activation_seq ASC, action ASC, digest ASC
		`, s.orgID, string(root))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				e            authoring.AuditEntry
				action       string
				actorStr     string
				rawApprovers []byte
			)
			if err := rows.Scan(&action, &e.Digest, &e.PreviousDigest, &e.DocumentID, &e.DocumentVersion,
				&actorStr, &rawApprovers, &e.SelfApproved, &e.Reason, &e.At); err != nil {
				return err
			}
			// A row whose actor or approver will not parse is a CORRUPT audit
			// row, refused for the reason Activations refuses one: an audit
			// trail must never answer "who" with nobody.
			if e.Actor, err = contract.ParseID(contract.KindPrincipal, actorStr); err != nil {
				return fmt.Errorf("audit actor %q under root %q does not parse: %w", actorStr, root, err)
			}
			var approvers []string
			if err := json.Unmarshal(rawApprovers, &approvers); err != nil {
				return fmt.Errorf("audit approvers of %s under root %q do not parse: %w", e.Digest, root, err)
			}
			for _, a := range approvers {
				id, err := contract.ParseID(contract.KindPrincipal, a)
				if err != nil {
					return fmt.Errorf("audit approver %q of %s under root %q does not parse: %w", a, e.Digest, root, err)
				}
				e.Approvers = append(e.Approvers, id)
			}
			e.Action = authoring.AuditAction(action)
			e.Root = root
			e.At = e.At.UTC()
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("authoringstore: reading the audit trail under root %q: %w", root, err)
	}
	return out, nil
}

// isUniqueViolation recognises postgres SQLSTATE 23505 WITHOUT importing a
// driver-specific error type.
//
// The driver is lib/pq here and pgx elsewhere in this tree, and pinning either
// one would make this package refuse to compile against the other for a reason
// that has nothing to do with authoring. The code is in the message on both.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") ||
		strings.Contains(strings.ToLower(msg), "duplicate key value violates unique constraint")
}

func orNone(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}
