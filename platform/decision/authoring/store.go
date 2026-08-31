package authoring

import (
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

// Store holds admitted artifacts and the activation history per authority root.
//
// It is an in-process store. ADR-065 phase 0 has no persistence: a document is
// a content-addressed artifact, not a row, and the migration that gives it a
// table needs a schema number that only the release owner allocates. Nothing
// here assumes a database, and nothing here writes one.
type Store struct {
	mu      sync.RWMutex
	trust   *pdp.TrustStore
	byRoot  map[pdp.Root]map[string]*Artifact
	active  map[pdp.Root]string
	history map[pdp.Root][]Activation
}

// NewStore builds an empty store bound to a trust store.
func NewStore(trust *pdp.TrustStore) (*Store, error) {
	if trust == nil {
		return nil, fmt.Errorf("authoring: a store requires a trust store; an artifact that nothing verified is not an artifact")
	}
	return &Store{
		trust:   trust,
		byRoot:  map[pdp.Root]map[string]*Artifact{},
		active:  map[pdp.Root]string{},
		history: map[pdp.Root][]Activation{},
	}, nil
}

// Admit verifies an artifact and records it as available for activation.
//
// Verification happens HERE rather than at activation, and also happens again
// at activation, because the two answer different questions at different times
// and an artifact that was verifiable when it was stored is not evidence that
// it is verifiable now: a key can be de-authorized between the two.
func (s *Store) Admit(a *Artifact) error {
	if a == nil {
		return fmt.Errorf("authoring: cannot admit a nil artifact")
	}
	if err := a.verify(s.trust); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	root := a.provenance.Root
	if s.byRoot[root] == nil {
		s.byRoot[root] = map[string]*Artifact{}
	}
	if _, ok := s.byRoot[root][a.digest]; ok {
		// Already admitted. The digest is content-addressed over the verified
		// view, so an artifact arriving under an existing digest carries the
		// same content; the original is kept and re-admission is idempotent.
		return nil
	}
	s.byRoot[root][a.digest] = a
	return nil
}

// Get returns an admitted artifact by root and digest.
func (s *Store) Get(root pdp.Root, digest string) (*Artifact, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.byRoot[root][digest]
	return a, ok
}

// Active returns the currently active artifact for a root.
func (s *Store) Active(root pdp.Root) (*Artifact, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	digest, ok := s.active[root]
	if !ok {
		return nil, false
	}
	a, ok := s.byRoot[root][digest]
	return a, ok
}

// History returns the activation history for a root, oldest first.
func (s *Store) History(root pdp.Root) []Activation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Activation(nil), s.history[root]...)
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
func (s *Store) Promote(root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byRoot[root][digest]
	if !ok {
		return nil, fmt.Errorf("authoring: digest %s is not admitted under root %q; a digest is activated only after it has been verified", digest, root)
	}
	if err := a.verify(s.trust); err != nil {
		return nil, fmt.Errorf("authoring: refusing to activate %s: %w", digest, err)
	}
	if err := checkActivationAuthority(a, actor); err != nil {
		return nil, err
	}
	prev := s.active[root]
	if prev != "" {
		current, ok := s.byRoot[root][prev]
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
		Kind: ActivationPromote, Root: root, Digest: digest, PreviousDigest: prev,
		DocumentID: a.provenance.DocumentID, DocumentVersion: a.provenance.DocumentVersion,
		Actor: actor, At: at.UTC(), Reason: reason,
	}
	s.active[root] = digest
	s.history[root] = append(s.history[root], act)
	return &act, nil
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
func (s *Store) Rollback(root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byRoot[root][digest]
	if !ok {
		return nil, fmt.Errorf("authoring: digest %s is not admitted under root %q", digest, root)
	}
	if err := a.verify(s.trust); err != nil {
		return nil, fmt.Errorf("authoring: refusing to roll back to %s: %w", digest, err)
	}
	if err := checkActivationActor(a, actor); err != nil {
		return nil, err
	}
	activated := false
	for _, h := range s.history[root] {
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
	prev := s.active[root]
	if prev == digest {
		return nil, fmt.Errorf("authoring: digest %s is already active under root %q", digest, root)
	}
	act := Activation{
		Kind: ActivationRollback, Root: root, Digest: digest, PreviousDigest: prev,
		DocumentID: a.provenance.DocumentID, DocumentVersion: a.provenance.DocumentVersion,
		Actor: actor, At: at.UTC(), Reason: reason,
	}
	s.active[root] = digest
	s.history[root] = append(s.history[root], act)
	return &act, nil
}

// checkActivationActor is the actor validation EVERY activation performs,
// promotion and rollback alike: a named principal who is not the author of the
// version being activated.
func checkActivationActor(a *Artifact, actor contract.ID) error {
	if actor.IsZero() {
		return fmt.Errorf("authoring: activation names no actor")
	}
	if actor.Kind != contract.KindPrincipal {
		return fmt.Errorf("authoring: activation actor %q is a %q, and an activator is a principal", actor, actor.Kind)
	}
	if actor.String() == a.provenance.Author.String() {
		return fmt.Errorf(
			"authoring: %q authored version %d and cannot also activate it; activation requires separation of author and approver duties",
			actor, a.provenance.DocumentVersion)
	}
	return nil
}

// checkActivationAuthority enforces separation of author and activator duties
// plus promotion's stronger requirement that the activator approved the
// version being activated.
func checkActivationAuthority(a *Artifact, actor contract.ID) error {
	if err := checkActivationActor(a, actor); err != nil {
		return err
	}
	for _, ap := range a.provenance.Approvers {
		if ap.String() == actor.String() {
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
