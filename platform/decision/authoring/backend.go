// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// Backend is where a Store keeps admitted artifacts and the activation history
// for one authority scope.
//
// It is DUMB STORAGE ON PURPOSE, and that is the whole reason this seam
// exists. Every rule that governs an activation - re-verification against the
// trust store, separation of author and approver duties, the version advance,
// the parent chain - lives in Store and has already run by the time any method
// here is called. A Backend that re-implemented one of them would be a second
// write path with its own opinion about who may activate what, which is
// precisely what ADR-065's retirement phase exists to end. There is one set of
// rules, in one file, and a durable backend is storage underneath it rather
// than a second control plane beside it.
//
// # The one thing a Backend must decide
//
// AppendActivation takes expectPrev and MUST refuse when the scope's active
// digest is not that value. Store's rules are a read-then-write: it reads the
// active digest, checks the candidate's parent against it, and then writes. In
// one process a mutex makes that atomic. Across two portal replicas it does
// not, and without the compare-and-set two authors who both start from
// version 4 could both promote a version 5 over the same parent and each
// believe they won - the exact failure the parent check was written to catch,
// reintroduced by the move to durable storage.
//
// # Scope
//
// A Backend instance is bound to ONE authority scope (in the enterprise
// implementation, one organization) at construction. Nothing in this package
// carries an organization identifier, which is deliberate: the isolation
// boundary is enforced by the backend and by row-level security beneath it,
// and a scope identifier threaded through this package would be a second place
// that could get it wrong.
type Backend interface {
	// PutArtifact records a verified artifact as available for activation.
	// It is idempotent on (root, artifact digest): an artifact arriving under
	// a digest already stored carries the same content by construction, so
	// re-admission is a no-op rather than an error.
	PutArtifact(ctx context.Context, root pdp.Root, a *Artifact) error

	// GetArtifact returns an admitted artifact by digest.
	GetArtifact(ctx context.Context, root pdp.Root, digest string) (*Artifact, bool, error)

	// ArtifactBySourceDigest returns an admitted artifact by the digest of the
	// AUTHORING DOCUMENT it carries, which is the identity that survives a
	// re-publication.
	//
	// It exists for idempotent importers. An artifact digest covers the
	// publication timestamp, so publishing the same document twice produces
	// two different artifact digests; the source digest does not move, so it
	// is the only key on which "this document is already published here" is a
	// question with a stable answer.
	ArtifactBySourceDigest(ctx context.Context, root pdp.Root, sourceDigest string) (*Artifact, bool, error)

	// CountArtifacts returns how many artifacts are stored under a root.
	//
	// It is a separate method rather than len(ListArtifacts(...)) because
	// loading an artifact RE-DERIVES every claim it makes - signature, digest,
	// module lint and a recompile of the carried source - so answering "how
	// many" by loading them all would make a bound check cost more than the
	// thing it bounds.
	CountArtifacts(ctx context.Context, root pdp.Root) (int, error)

	// ListArtifacts returns up to limit artifacts under a root, newest
	// document version first. A limit of zero or less returns them all.
	//
	// It exists because a DURABLE store must be able to say what it holds. The
	// in-process store never needed it: what one process had published was
	// what that process could remember, so a portal could list from its own
	// admission set. The moment a second replica can publish, that set is a
	// list of what THIS process did, and presenting it as the organization's
	// artifacts is wrong in the exact way #3776 exists to fix.
	ListArtifacts(ctx context.Context, root pdp.Root, limit int) ([]*Artifact, error)

	// ActiveDigest returns the digest of the document that is ACTIVE: the one
	// the most recent activation named, or "" when the root has never been
	// activated or its most recent activation withdrew it (PRD v11 §1.15).
	//
	// It is DERIVED from the activation history rather than stored beside it.
	// A separate "active" column would be a second record of the same fact,
	// and the two would disagree the first time an append succeeded and an
	// update did not.
	ActiveDigest(ctx context.Context, root pdp.Root) (string, error)

	// Activations returns the activation history for a root, oldest first.
	Activations(ctx context.Context, root pdp.Root) ([]Activation, error)

	// AppendActivation appends one activation record, and MUST refuse with an
	// error satisfying errors.Is(err, ErrActivationRaced) when the digest the
	// root's most recent activation named - its TIP, which after a withdrawal
	// is the template's and not an active document's - is not expectPrev.
	// expectPrev is "" for the first activation under a root.
	//
	// The record is append-only: there is no update and no delete, here or in
	// any storage beneath it. An activation history that can be edited is not
	// an audit trail.
	AppendActivation(ctx context.Context, root pdp.Root, act Activation, expectPrev string) error

	// AuditTrail returns the audit entries recorded under a root, oldest first.
	//
	// PutArtifact and AppendActivation MUST each record their entry in the
	// SAME atomic step as their write (PRD v11 §1.12). PutArtifact records
	// PublishAuditEntry when it stores a NEW artifact and nothing when the
	// digest was already stored; AppendActivation records ActivationAuditEntry
	// only when the append commits. A backend that could store either without
	// its entry would reopen the gap the audit row closes.
	AuditTrail(ctx context.Context, root pdp.Root) ([]AuditEntry, error)
}

// ErrActivationRaced is what a Backend returns when the active digest moved
// between Store's check and Store's write.
//
// It is a distinct error rather than a generic failure because the caller's
// correct response is specific: reload the active version and rebase the edit
// onto it. "The database rejected your write" and "somebody else promoted
// while you were deciding" want different words in front of an operator.
var ErrActivationRaced = errors.New("authoring: the active digest changed while this activation was being decided")

// memBackend is the in-process Backend, and it is the DEFAULT.
//
// ADR-065 phase 0 needs no database and the decision module deliberately
// carries no driver, so a Store built without a backend is fully functional
// and entirely in memory. What it is not is durable: a restart loses every
// published artifact and every activation record, which is what #3776 exists
// to fix and what the enterprise postgres backend supplies.
type memBackend struct {
	mu        sync.RWMutex
	byDigest  map[pdp.Root]map[string]*Artifact
	bySource  map[pdp.Root]map[string]*Artifact
	histories map[pdp.Root][]Activation
	audits    map[pdp.Root][]AuditEntry
}

// NewMemoryBackend builds an empty in-process Backend.
func NewMemoryBackend() Backend {
	return &memBackend{
		byDigest:  map[pdp.Root]map[string]*Artifact{},
		bySource:  map[pdp.Root]map[string]*Artifact{},
		histories: map[pdp.Root][]Activation{},
		audits:    map[pdp.Root][]AuditEntry{},
	}
}

func (m *memBackend) PutArtifact(_ context.Context, root pdp.Root, a *Artifact) error {
	if a == nil {
		return fmt.Errorf("authoring: cannot store a nil artifact")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byDigest[root] == nil {
		m.byDigest[root] = map[string]*Artifact{}
		m.bySource[root] = map[string]*Artifact{}
	}
	if _, ok := m.byDigest[root][a.digest]; ok {
		return nil
	}
	m.byDigest[root][a.digest] = a
	// The source-digest index keeps the FIRST artifact published from a given
	// document, not the last. Two publications of one document differ only in
	// their timestamp, so either answers "is this document already here"; the
	// first is chosen so a repeated import is stable rather than walking
	// forward through equivalent artifacts.
	if _, ok := m.bySource[root][a.provenance.SourceDigest]; !ok {
		m.bySource[root][a.provenance.SourceDigest] = a
	}
	m.audits[root] = append(m.audits[root], PublishAuditEntry(a))
	return nil
}

func (m *memBackend) GetArtifact(_ context.Context, root pdp.Root, digest string) (*Artifact, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.byDigest[root][digest]
	return a, ok, nil
}

func (m *memBackend) ArtifactBySourceDigest(_ context.Context, root pdp.Root, sourceDigest string) (*Artifact, bool, error) {
	if sourceDigest == "" {
		return nil, false, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.bySource[root][sourceDigest]
	return a, ok, nil
}

func (m *memBackend) CountArtifacts(_ context.Context, root pdp.Root) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byDigest[root]), nil
}

func (m *memBackend) ListArtifacts(_ context.Context, root pdp.Root, limit int) ([]*Artifact, error) {
	m.mu.RLock()
	out := make([]*Artifact, 0, len(m.byDigest[root]))
	for _, a := range m.byDigest[root] {
		out = append(out, a)
	}
	m.mu.RUnlock()
	// Map iteration is randomised, so an unsorted result would present the
	// same artifacts in a different order on every request. Sorted by document
	// version descending, then digest, which is total: two artifacts can share
	// a version (two authors, same number, different parents) and only the
	// digest separates them.
	sort.Slice(out, func(i, j int) bool {
		if out[i].provenance.DocumentVersion != out[j].provenance.DocumentVersion {
			return out[i].provenance.DocumentVersion > out[j].provenance.DocumentVersion
		}
		return out[i].digest < out[j].digest
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memBackend) ActiveDigest(_ context.Context, root pdp.Root) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h := m.histories[root]
	if len(h) == 0 || h[len(h)-1].Kind == ActivationWithdraw {
		return "", nil
	}
	return h[len(h)-1].Digest, nil
}

func (m *memBackend) Activations(_ context.Context, root pdp.Root) ([]Activation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Activation(nil), m.histories[root]...), nil
}

func (m *memBackend) AppendActivation(_ context.Context, root pdp.Root, act Activation, expectPrev string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var current string
	if h := m.histories[root]; len(h) > 0 {
		current = h[len(h)-1].Digest
	}
	if current != expectPrev {
		return fmt.Errorf("%w: expected %s, found %s", ErrActivationRaced, orNone(expectPrev), orNone(current))
	}
	m.histories[root] = append(m.histories[root], act)
	m.audits[root] = append(m.audits[root], ActivationAuditEntry(act))
	return nil
}

func (m *memBackend) AuditTrail(_ context.Context, root pdp.Root) ([]AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]AuditEntry, 0, len(m.audits[root]))
	for _, e := range m.audits[root] {
		e.Approvers = append([]contract.ID(nil), e.Approvers...)
		out = append(out, e)
	}
	return out, nil
}
