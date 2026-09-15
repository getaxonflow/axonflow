// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// ActivationKind separates the two ways a digest becomes active. They are
// different operations with different rules, which is why they are not one
// function with a flag: promotion must advance the document version and must
// follow the parent chain, and rollback must do neither, because the state it
// restores is by definition an earlier one.
type ActivationKind string

const (
	// ActivationPromote makes a newly published version active.
	ActivationPromote ActivationKind = "promote"
	// ActivationRollback re-activates a previously activated digest.
	ActivationRollback ActivationKind = "rollback"
	// ActivationWithdraw returns the root to the implicit bundle (PRD v11
	// §1.15): after it nothing is active, and a later promote starts from
	// nothing active. The entry names the shipped organization template's
	// digest and chains onto the document it withdrew; its kind, not its
	// digest, carries the meaning.
	ActivationWithdraw ActivationKind = "withdraw"
)

// Activation is one audited entry in a root's activation history.
type Activation struct {
	Kind ActivationKind `json:"kind"`
	Root pdp.Root       `json:"root"`
	// Digest is the artifact digest activated. Activation names a digest and
	// never a version, so "which policy produced this decision" survives the
	// next edit.
	Digest string `json:"digest"`
	// PreviousDigest is what was active before, empty for the first
	// activation. It is what makes the history a chain rather than a list.
	PreviousDigest  string      `json:"previous_digest,omitempty"`
	DocumentID      string      `json:"document_id"`
	DocumentVersion int         `json:"document_version"`
	Actor           contract.ID `json:"actor"`
	At              time.Time   `json:"at"`
	Reason          string      `json:"reason,omitempty"`
}

// TrustSource is where a store reads the authorized keys AT USE TIME.
//
// # Why this is an interface and not a *pdp.TrustStore
//
// A trust store used to be captured once, at construction, into three separate
// fields - API.trust, Store.trust and the durable backend's own. They were
// three SNAPSHOTS of one fact, and the fact moves: a replica built before a
// peer authorized its signing key holds a trust store that cannot verify
// anything that peer publishes. Driven on real Postgres (#3962): listing
// returns 500s and Promote fails with "key ... is not authorized to publish
// under the organization authority root".
//
// Handing the same SOURCE to all three, and reading Current() at the moment of
// use, removes the class rather than refreshing one copy of it. The reload
// itself is not implemented here - a source that never changes is exactly the
// behaviour that shipped - but nothing now has to be re-plumbed to add it.
type TrustSource interface {
	// Current returns the trust store to verify against right now. It must
	// never return nil: a nil trust store verifies nothing, and a caller that
	// received one would report every artifact as unsigned rather than fail.
	Current() *pdp.TrustStore
}

// staticTrust is a TrustSource that never changes.
//
// It is what every caller had before, made explicit. A deployment with no
// durable store, and every test that builds a plane around a handful of keys,
// wants exactly this - so the static case stays a first-class one rather than
// being expressed as a refreshable source that happens not to refresh.
type staticTrust struct{ t *pdp.TrustStore }

func (s staticTrust) Current() *pdp.TrustStore { return s.t }

// StaticTrust wraps a fixed trust store as a TrustSource.
func StaticTrust(t *pdp.TrustStore) TrustSource {
	if t == nil {
		return nil
	}
	return staticTrust{t: t}
}

// Store holds admitted artifacts and the activation history per authority root.
//
// It is the ONLY place the activation rules live. Storage is a Backend
// underneath it - in memory by default, and durable where an edition supplies
// one - so making a deployment durable never means writing a second
// implementation of who may activate what. See backend.go for why that
// separation is load bearing rather than tidy.
type Store struct {
	// mu serialises this process's read-then-write sequences. It is NOT what
	// makes an activation safe across replicas; the Backend's compare-and-set
	// on expectPrev is. It is kept because it makes the single-replica case -
	// which is every in-memory deployment - free of races without a round trip
	// to storage, and because holding it across a Backend call costs nothing on
	// an authoring surface.
	mu      sync.Mutex
	trust   TrustSource
	profile Profile
	backend Backend
	// organizationOnly binds the store to the ORGANIZATION authority: Admit,
	// Promote and Rollback refuse every other root (#4047). NewAPIWithBackend
	// sets it, and that constructor is how every transport builds its store.
	// NewStore and NewStoreWithBackend leave it unset because they are the
	// root-agnostic primitives the fixture world is built on, and
	// TestNoProductionCodeReachesTheRootAgnosticPrimitives holds that no
	// production code constructs one.
	organizationOnly bool
}

// refuseOutsideAuthority refuses a root the store's authority does not own.
//
// An EMPTY root passes through to the operation's own refusal, which says what
// is missing; naming an authority for a root nobody declared would send the
// reader to the wrong fix.
func (s *Store) refuseOutsideAuthority(operation string, root pdp.Root) error {
	if !s.organizationOnly || root == "" || root == pdp.RootOrganization {
		return nil
	}
	return &ErrSystemRootOutsideAuthority{Operation: operation, Root: root}
}

// NewStore builds a store bound to a trust store and an edition profile,
// keeping its artifacts in memory.
//
// THE PROFILE IS TAKEN HERE AND NOT PER CALL. Promote and Rollback are the
// activation half of separation of duties, and a profile passed per
// activation would be a per-activation opportunity to pass the weaker one -
// the same argument the enterprise backend makes for binding an organization
// at construction. A store belongs to a deployment, and so does its licence.
func NewStore(trust TrustSource, profile Profile) (*Store, error) {
	return NewStoreWithBackend(trust, profile, nil)
}

// NewStoreWithBackend builds a store over a supplied Backend. A nil backend
// means the in-process one, so this is the single constructor and NewStore is
// its common case rather than a second path.
//
// THE PROFILE AND THE BACKEND ARE DIFFERENT AXES. The profile is a rule about
// what may be written and is bound here for the reason above; the backend is
// where what was written is kept. Neither implies the other, and a Community
// deployment with a durable store is as coherent as an Enterprise one running
// in memory - which is what every test in this package does.
func NewStoreWithBackend(trust TrustSource, profile Profile, b Backend) (*Store, error) {
	if trust == nil {
		return nil, fmt.Errorf("authoring: a store requires a trust store; an artifact that nothing verified is not an artifact")
	}
	if err := profile.validate(); err != nil {
		return nil, fmt.Errorf("authoring: a store is bound to an edition: %w", err)
	}
	if b == nil {
		b = NewMemoryBackend()
	}
	return &Store{trust: trust, profile: profile, backend: b}, nil
}

// Admit verifies an artifact and records it as available for activation.
//
// Verification happens HERE rather than at activation, and also happens again
// at activation, because the two answer different questions at different times
// and an artifact that was verifiable when it was stored is not evidence that
// it is verifiable now: a key can be de-authorized between the two.
func (s *Store) Admit(ctx context.Context, a *Artifact) error {
	if a == nil {
		return fmt.Errorf("authoring: cannot admit a nil artifact")
	}
	if err := s.refuseOutsideAuthority("admit", a.provenance.Root); err != nil {
		return err
	}
	if err := a.verify(s.trust.Current()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.PutArtifact(ctx, a.provenance.Root, a)
}

// Get returns an admitted artifact by root and digest.
func (s *Store) Get(ctx context.Context, root pdp.Root, digest string) (*Artifact, bool, error) {
	return s.backend.GetArtifact(ctx, root, digest)
}

// BySourceDigest returns an admitted artifact by the digest of the authoring
// document it carries.
//
// This is the question an importer asks and Get cannot answer: an artifact
// digest covers the publication timestamp, so re-publishing an unchanged
// document produces a digest that has never been seen before, while its source
// digest is unchanged. Anything that must be idempotent across runs keys on
// this.
func (s *Store) BySourceDigest(ctx context.Context, root pdp.Root, sourceDigest string) (*Artifact, bool, error) {
	return s.backend.ArtifactBySourceDigest(ctx, root, sourceDigest)
}

// Count returns how many artifacts are admitted under a root.
func (s *Store) Count(ctx context.Context, root pdp.Root) (int, error) {
	return s.backend.CountArtifacts(ctx, root)
}

// List returns up to limit admitted artifacts under a root, newest document
// version first. A limit of zero or less returns them all.
//
// This is the enumeration a durable deployment needs and an in-process one did
// not: a portal listing what one process happens to remember is a list of that
// process's history, not the organization's.
func (s *Store) List(ctx context.Context, root pdp.Root, limit int) ([]*Artifact, error) {
	return s.backend.ListArtifacts(ctx, root, limit)
}

// Active returns the currently active artifact for a root.
//
// It re-loads the artifact through the backend, so a backend that re-derives
// an artifact's claims on read - the durable one does, on every load - reports
// an ERROR here for an artifact whose signing key has since been
// de-authorized, rather than handing it back as though nothing had changed.
//
// THE IN-PROCESS BACKEND DOES NOT DO THAT, and the difference is worth naming
// rather than glossing: it returns the same *Artifact it was given, with no
// re-verification, because nothing between Admit and Get could have changed it
// - the artifact never left the process. Promote and Rollback re-verify
// explicitly for both backends, which is where the guarantee actually lives.
func (s *Store) Active(ctx context.Context, root pdp.Root) (*Artifact, bool, error) {
	digest, err := s.backend.ActiveDigest(ctx, root)
	if err != nil {
		return nil, false, err
	}
	if digest == "" {
		return nil, false, nil
	}
	return s.backend.GetArtifact(ctx, root, digest)
}

// History returns the activation history for a root, oldest first.
func (s *Store) History(ctx context.Context, root pdp.Root) ([]Activation, error) {
	return s.backend.Activations(ctx, root)
}

// AuditTrail returns the audit entries for a root, oldest first: one per
// publish, promote and rollback (PRD v11 §1.12).
func (s *Store) AuditTrail(ctx context.Context, root pdp.Root) ([]AuditEntry, error) {
	return s.backend.AuditTrail(ctx, root)
}

// Promote activates a newly published digest.
//
// Four rules, each of which exists because of a way policy deployment goes
// wrong in practice:
//
//   - the artifact must still verify, because a key can be de-authorized
//     between admission and activation;
//   - the activator must not be the author, which is ADR-065's "bundle
//     activation requires the configured separation of author and approver
//     duties". Emergency changes are not exempt: the ADR says an emergency
//     change still creates a signed version and an audited activation;
//   - the version must advance the active one, so a stale editor tab cannot
//     silently reinstate old policy while looking like a promotion;
//   - the artifact's parent must be the currently active digest. Two authors
//     who both start from version 4 and both save version 5 agree on the
//     number and disagree on the parent, and only the parent check sees it.
//
// The fourth rule is re-asserted by the Backend at write time against the same
// expected parent, so two replicas that both pass it in memory cannot both
// commit. See Backend.AppendActivation.
func (s *Store) Promote(ctx context.Context, root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	return s.promote(ctx, root, digest, actor, at, reason, nil)
}

// promote is Promote with the deployment's self-approval answer (PRD v11
// §1.12). Only API.Promote passes one, from the transport's SelfApproval;
// the exported Promote passes none, so a caller holding a *Store cannot grant
// an author the exception by calling it directly.
func (s *Store) promote(ctx context.Context, root pdp.Root, digest string, actor contract.ID, at time.Time, reason string, selfApproval func() (bool, error)) (*Activation, error) {
	if err := s.refuseOutsideAuthority("promote", root); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok, err := s.backend.GetArtifact(ctx, root, digest)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("authoring: digest %s is not admitted under root %q; a digest is activated only after it has been verified", digest, root)
	}
	if err := a.verify(s.trust.Current()); err != nil {
		return nil, fmt.Errorf("authoring: refusing to activate %s: %w", digest, err)
	}
	if err := checkActivationAuthority(a, actor, s.profile, selfApproval); err != nil {
		return nil, err
	}
	// The ACTIVE digest decides the promotion's rules and the ledger's TIP is
	// its parent. They differ only after a withdrawal, whose entry names the
	// template rather than a document: the promotion then starts from nothing
	// active (PRD v11 §1.15) and still chains onto the withdrawal.
	prev, err := s.backend.ActiveDigest(ctx, root)
	if err != nil {
		return nil, err
	}
	tip, err := s.tipDigest(ctx, root)
	if err != nil {
		return nil, err
	}
	if prev != "" {
		current, ok, err := s.backend.GetArtifact(ctx, root, prev)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("authoring: the active digest %s for root %q is not in the store", prev, root)
		}
		if a.provenance.DocumentID != current.provenance.DocumentID {
			return nil, fmt.Errorf(
				"authoring: refusing to promote document %q over active document %q under one authority root; a root carries one document",
				a.provenance.DocumentID, current.provenance.DocumentID)
		}
		if a.provenance.DocumentVersion <= current.provenance.DocumentVersion {
			return nil, fmt.Errorf(
				"authoring: refusing to promote version %d over active version %d; promotion advances a version and rollback is the operation that does not",
				a.provenance.DocumentVersion, current.provenance.DocumentVersion)
		}
		if a.provenance.Supersedes != prev {
			return nil, fmt.Errorf(
				"authoring: version %d was edited from %s and the active version is %s; rebase the edit onto the active version rather than overwriting it",
				a.provenance.DocumentVersion, orNone(a.provenance.Supersedes), prev)
		}
	} else if a.provenance.Supersedes != "" {
		return nil, fmt.Errorf(
			"authoring: version %d declares parent %s and root %q has nothing active; the parent is not in this store",
			a.provenance.DocumentVersion, a.provenance.Supersedes, root)
	}

	act := Activation{
		Kind: ActivationPromote, Root: root, Digest: digest, PreviousDigest: tip,
		DocumentID: a.provenance.DocumentID, DocumentVersion: a.provenance.DocumentVersion,
		Actor: actor, At: at.UTC(), Reason: reason,
	}
	if err := s.backend.AppendActivation(ctx, root, act, tip); err != nil {
		return nil, err
	}
	return &act, nil
}

// tipDigest is the digest the root's most recent activation names, whatever its
// kind: the parent the next entry chains onto and the value the backend's
// compare-and-set holds it to. It is the active digest except after a
// withdrawal, whose entry names the template (Backend.ActiveDigest).
func (s *Store) tipDigest(ctx context.Context, root pdp.Root) (string, error) {
	history, err := s.backend.Activations(ctx, root)
	if err != nil {
		return "", err
	}
	if len(history) == 0 {
		return "", nil
	}
	return history[len(history)-1].Digest, nil
}

// Rollback re-activates a previously activated digest.
//
// It requires the target to have been activated before, which is what makes
// "roll back to a verified digest" true rather than aspirational: the target
// has already passed the gauntlet, been signed, been verified and been through
// separation of duties once. Rollback does not re-run that approval, and it
// deliberately does not require the version to advance, because restoring an
// earlier version is the entire operation. It still re-verifies, and it is
// still audited.
//
// What rollback does NOT relax is who may perform it. The actor must be a
// named, non-zero principal, because an unattributed activation record defeats
// the audited history that is the stated reason emergency changes are
// tolerable at all. And the AUTHOR of the target version may not roll back to
// it: separation of author and approver duties is deliberately the same as
// Promote's, since a rollback the author can perform alone is a route to
// activating their own policy that Promote just refused. Rollback skips only
// re-approval of the target, never actor validation.
func (s *Store) Rollback(ctx context.Context, root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	return s.rollback(ctx, root, digest, actor, at, reason, nil)
}

// rollback is Rollback with the deployment's self-approval answer, passed
// only by API.Rollback, for the reason promote gives.
func (s *Store) rollback(ctx context.Context, root pdp.Root, digest string, actor contract.ID, at time.Time, reason string, selfApproval func() (bool, error)) (*Activation, error) {
	if err := s.refuseOutsideAuthority("rollback", root); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok, err := s.backend.GetArtifact(ctx, root, digest)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("authoring: digest %s is not admitted under root %q", digest, root)
	}
	if err := a.verify(s.trust.Current()); err != nil {
		return nil, fmt.Errorf("authoring: refusing to roll back to %s: %w", digest, err)
	}
	if err := checkActivationActor(a, actor, s.profile, selfApproval); err != nil {
		return nil, err
	}
	history, err := s.backend.Activations(ctx, root)
	if err != nil {
		return nil, err
	}
	activated := false
	for _, h := range history {
		if h.Digest == digest {
			activated = true
			break
		}
	}
	if !activated {
		return nil, fmt.Errorf(
			"authoring: digest %s has never been activated under root %q, so it is not a verified digest to roll back to; promote it instead", digest, root)
	}
	if reason == "" {
		return nil, fmt.Errorf("authoring: a rollback records a reason; an unexplained reversal of policy is the thing the audit trail exists to prevent")
	}
	var prev string
	if len(history) > 0 {
		prev = history[len(history)-1].Digest
	}
	if prev == digest {
		return nil, fmt.Errorf("authoring: digest %s is already active under root %q", digest, root)
	}
	act := Activation{
		Kind: ActivationRollback, Root: root, Digest: digest, PreviousDigest: prev,
		DocumentID: a.provenance.DocumentID, DocumentVersion: a.provenance.DocumentVersion,
		Actor: actor, At: at.UTC(), Reason: reason,
	}
	if err := s.backend.AppendActivation(ctx, root, act, prev); err != nil {
		return nil, err
	}
	return &act, nil
}

// Withdraw returns root to the implicit bundle (PRD v11 §1.15): the
// organization is decided exactly as one that never published anything is, and
// nothing is deleted - the entry is appended, naming the shipped organization
// template, with the document it withdrew as its parent.
//
// It requires a document to be active, a named actor and a reason: an
// unexplained return to the shipped set wants explaining as much as a rollback
// does. The actor answers to rollback's rule against the ACTIVE document's author
// (#4299), read from its admission record - the artifact is loaded only when no
// record exists, and the withdrawal is refused if it will not load - so a
// document whose signing key has since been revoked can still be withdrawn. This
// exported method grants no self-approval; API.Withdraw passes the deployment's
// answer.
func (s *Store) Withdraw(ctx context.Context, root pdp.Root, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	return s.withdraw(ctx, root, actor, at, reason, nil)
}

// withdraw is Withdraw with the deployment's self-approval answer. Only
// API.Withdraw supplies one: the exported method grants none, as the exported
// Promote and Rollback do not, so a caller holding a *Store cannot withdraw
// their own self-approved document through it (#4299).
func (s *Store) withdraw(ctx context.Context, root pdp.Root, actor contract.ID, at time.Time, reason string, selfApproval func() (bool, error)) (*Activation, error) {
	if err := s.refuseOutsideAuthority("withdraw", root); err != nil {
		return nil, err
	}
	if err := checkActor(actor); err != nil {
		return nil, err
	}
	if reason == "" {
		return nil, fmt.Errorf("authoring: a withdrawal records a reason; an unexplained return to the shipped set is the thing the audit trail exists to prevent")
	}
	digest, err := pdp.SystemCorpusOrganizationTemplateDigest()
	if err != nil {
		return nil, err
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active, err := s.backend.ActiveDigest(ctx, root)
	if err != nil {
		return nil, err
	}
	if active == "" {
		return nil, fmt.Errorf("authoring: nothing is active under root %q, so there is no document to withdraw", root)
	}
	// THE SAME AUTHORITY AS ROLLBACK (PRD v11 §1.15, #4299). A withdrawal
	// removes every constraint the organization authored in one call, so it
	// answers to rollback's rule: where separation of duties applies, the actor
	// is not the author of the document it removes, and need not be one of its
	// approvers; a self-approval grant applies as for rollback. A withdrawal
	// names no target version, so the ACTIVE document is the one that answers.
	//
	// ITS AUTHOR IS READ FROM THE ADMISSION RECORD, NOT BY LOADING THE
	// ARTIFACT: the artifact is loaded only when no record exists (below), and
	// the withdrawal is then refused if it will not load. The durable backend
	// re-verifies an artifact on every load (see
	// Active above: the in-process backend never does), so a document whose
	// signing key has since been revoked does not load - and the anchored
	// enforcer then fails closed on every decision of that organization, promote
	// reads that same document, and rollback may have nothing to return to. A
	// withdrawal that depended on the load would leave that organization no exit
	// but a database edit. The publish audit entry carries the author and the
	// approvers the verified artifact declared when it was admitted.
	author, approvers, version, found, err := s.admittedAuthorship(ctx, root, active)
	if err != nil {
		return nil, err
	}
	if !found {
		// No admission record: only an artifact admitted before
		// migrations/core/181 created the audit table, which no release carries.
		// Fall back to the artifact and REFUSE if it does not load - a withdrawal
		// is never admitted without the actor rule.
		current, ok, err := s.backend.GetArtifact(ctx, root, active)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("authoring: the active digest %s for root %q is not in the store", active, root)
		}
		author, approvers, version = current.provenance.Author, current.provenance.Approvers, current.provenance.DocumentVersion
	}
	if err := checkActorOfVersion(author, approvers, version, actor, s.profile, selfApproval); err != nil {
		return nil, fmt.Errorf("authoring: refusing to withdraw %s: %w", active, err)
	}
	act := Activation{
		Kind: ActivationWithdraw, Root: root, Digest: digest, PreviousDigest: active,
		DocumentID: pdp.SystemCorpusOrganizationTemplateID, DocumentVersion: template.Version,
		Actor: actor, At: at.UTC(), Reason: reason,
	}
	if err := s.backend.AppendActivation(ctx, root, act, active); err != nil {
		return nil, err
	}
	return &act, nil
}

// admittedAuthorship returns the author, approvers and version of the artifact
// admitted under digest, from its publish audit entry (#4299). It reads the
// ADMISSION RECORD rather than the artifact: PublishAuditEntry derives the entry
// from the verified artifact and every backend records it in the artifact's own
// write, so the answer does not depend on the artifact still verifying now.
// found is false when no publish entry names the digest.
func (s *Store) admittedAuthorship(ctx context.Context, root pdp.Root, digest string) (contract.ID, []contract.ID, int, bool, error) {
	trail, err := s.backend.AuditTrail(ctx, root)
	if err != nil {
		return contract.ID{}, nil, 0, false, err
	}
	for _, e := range trail {
		if e.Action == AuditPublish && e.Digest == digest {
			return e.Actor, e.Approvers, e.DocumentVersion, true, nil
		}
	}
	return contract.ID{}, nil, 0, false, nil
}

// checkActivationActor is the actor validation EVERY activation performs,
// promotion and rollback alike: a named principal, who on an edition carrying
// separation of duties is not the author of the version being activated.
//
// THE SPLIT BETWEEN WHAT IS AND IS NOT EDITION-CONDITIONAL IS THE WHOLE POINT
// OF THIS FUNCTION, so it is stated rather than left to be read off the code.
//
// The first two checks are NOT conditional and must never become so. An
// activation with no actor, or with an actor of a kind that is not a
// principal, is an unattributed change of enforced policy - the audit trail is
// the stated reason emergency changes are tolerable at all, and it is the same
// audit trail on a single-admin Community deployment as on a fleet. Losing it
// would be a real regression, and it is not what PRD 5.3 rules None/None/Full.
//
// The third IS conditional, because it is the capability that PRD row names:
// "Compound approvals and separation of duties - None / None / Full". Below
// the floor, the author may activate their own version, which is the only way
// a deployment with one administrator can put a policy into force at all.
func checkActivationActor(a *Artifact, actor contract.ID, p Profile, selfApproval func() (bool, error)) error {
	return checkActorOfVersion(a.provenance.Author, a.provenance.Approvers, a.provenance.DocumentVersion, actor, p, selfApproval)
}

// checkActorOfVersion is checkActivationActor's rule over the three facts it
// reads - the version's author, its approvers and its number - so an artifact
// and a version's admission record (#4299) feed ONE rule rather than two.
func checkActorOfVersion(author contract.ID, approvers []contract.ID, version int, actor contract.ID, p Profile, selfApproval func() (bool, error)) error {
	if err := checkActor(actor); err != nil {
		return err
	}
	if !p.RequiresSeparationOfDuties() {
		return nil
	}
	// samePerson, NOT String() (#3876). The rendered form carries the principal
	// TYPE, which classifies an identity rather than identifying one, so an
	// author presenting a different type compared as a different person and
	// activated their own version. Publication had the identical defect, which
	// meant the two-person rule was defeatable at BOTH ENDS of the lifecycle:
	// approve your own publication, then activate your own version.
	if samePerson(actor, author) {
		// PRD v11 §1.12: the author of a SELF-APPROVED version may activate it
		// while the deployment still grants self-approval. The grant is asked
		// now rather than trusted from publication, so an organization that has
		// since reached two eligible approvers no longer can; and it covers only
		// a version whose every approver is its author, never one a second
		// person approved.
		if selfApproval != nil && everyApproverIsTheAuthor(author, approvers) {
			granted, err := selfApproval()
			if err != nil {
				return fmt.Errorf("authoring: deciding whether %q may activate their own self-approved version %d: %w",
					actor, version, err)
			}
			if granted {
				return nil
			}
		}
		return fmt.Errorf(
			"authoring: %q authored version %d and cannot also activate it; activation requires separation of author and approver duties",
			actor, version)
	}
	return nil
}

// checkActivationAuthority enforces separation of author and activator duties
// plus promotion's stronger requirement that the activator approved the
// version being activated.
func checkActivationAuthority(a *Artifact, actor contract.ID, p Profile, selfApproval func() (bool, error)) error {
	if err := checkActivationActor(a, actor, p, selfApproval); err != nil {
		return err
	}
	// Below the separation-of-duties floor there are no recorded approvers to
	// be one of - the publication was permitted to name none - so requiring
	// membership of an empty list would refuse every promotion on the editions
	// this whole change exists to unblock. The actor validation above still
	// ran: the activation is attributed, and it is audited.
	if !p.RequiresSeparationOfDuties() {
		return nil
	}
	// THE SAME FIX POINTING THE OTHER WAY, and the direction is worth stating
	// because it is a behaviour change on a path that works today. This
	// comparison asks "is the activator one of the recorded approvers", and
	// comparing rendered forms made it too STRICT rather than too lax: a
	// genuine approver presenting a different principal type - or a different
	// casing of the same address - was refused activation of a version they
	// really had approved. So an activator may now present a type that differs
	// from the one recorded against them in the provenance and still count as
	// that approver. That is the intended consequence of samePerson and the
	// mirror image of the bypass above, not a second hole: the identity is the
	// same person either way, and the type was never what made them an
	// approver.
	for _, ap := range a.provenance.Approvers {
		if samePerson(ap, actor) {
			return nil
		}
	}
	names := make([]string, 0, len(a.provenance.Approvers))
	for _, ap := range a.provenance.Approvers {
		names = append(names, ap.String())
	}
	sort.Strings(names)
	return fmt.Errorf(
		"authoring: %q is not among the approvers of version %d (%v); activation is performed by an approver of the version being activated",
		actor, a.provenance.DocumentVersion, names)
}

func orNone(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}

// checkActor is what every activation asks of who performs it: a named
// principal. An unattributed entry defeats the audited history that is the
// stated reason emergency changes are tolerable at all.
func checkActor(actor contract.ID) error {
	if actor.IsZero() {
		return fmt.Errorf("authoring: activation names no actor")
	}
	if actor.Kind != contract.KindPrincipal {
		return fmt.Errorf("authoring: activation actor %q is a %q, and an activator is a principal", actor, actor.Kind)
	}
	return nil
}
