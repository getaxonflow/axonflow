package authoring

import (
	"context"
	"fmt"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// API is the in-process typed authoring surface: create, validate, publish,
// render, diff, promote and roll back.
//
// It is in-process for now on purpose. ADR-065 phase 0 proves the semantics
// before any production plane is switched, and an HTTP or portal surface is a
// transport over these calls rather than a second implementation of them. What
// matters here is that the transport CANNOT reach a weaker path: every method
// below delegates to the package-level function that carries the guard, so an
// HTTP handler that forgets to validate is not a thing anyone can write.
type API struct {
	catalog *Catalog
	store   *Store
	trust   *pdp.TrustStore
}

// NewAPI builds the authoring surface over a catalog and a trust store.
func NewAPI(cat *Catalog, trust *pdp.TrustStore) (*API, error) {
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	store, err := NewStore(trust)
	if err != nil {
		return nil, err
	}
	return &API{catalog: cat, store: store, trust: trust}, nil
}

// Store exposes the publication store for activation queries.
func (a *API) Store() *Store { return a.store }

// Catalog exposes the registry a document is validated against.
func (a *API) Catalog() *Catalog { return a.catalog }

// Create builds and validates a new document version.
func (a *API) Create(meta Metadata, policy pdp.Document) (*Document, Findings, error) {
	return NewDocument(meta, policy, a.catalog)
}

// Validate re-checks an existing document, for example one a portal is editing
// or one that arrived over the wire.
func (a *API) Validate(d *Document) Findings { return Validate(d, a.catalog) }

// Publish runs the full pipeline and admits the resulting artifact.
//
// Admission is part of publishing rather than a separate call the caller might
// skip. An artifact that was produced and never verified is an artifact whose
// signature nobody has checked, and the only way to notice would be at
// activation, which is the worst moment.
func (a *API) Publish(ctx context.Context, d *Document, opts PublishOptions) (*Artifact, Findings, error) {
	art, findings, err := Publish(ctx, d, a.catalog, opts)
	if err != nil {
		return nil, findings, err
	}
	if err := a.store.Admit(art); err != nil {
		return nil, findings, err
	}
	return art, findings, nil
}

// Render returns the exact source of the document currently active on a root.
//
// This is the operator-facing half of "rendered back without loss": what comes
// back is the byte sequence that was signed, that parses, that re-renders
// identically, and that recompiles to the module being enforced. Every one of
// those was proven before the signature and is re-proven on every load.
func (a *API) Render(root pdp.Root) ([]byte, error) {
	art, ok := a.store.Active(root)
	if !ok {
		return nil, fmt.Errorf("authoring: no document is active on the %q authority root", root)
	}
	return art.Source(), nil
}

// RenderDigest returns the exact source of one admitted artifact.
func (a *API) RenderDigest(root pdp.Root, digest string) ([]byte, error) {
	art, ok := a.store.Get(root, digest)
	if !ok {
		return nil, fmt.Errorf("authoring: digest %s is not admitted under the %q authority root", digest, root)
	}
	return art.Source(), nil
}

// Diff compares a candidate document against what is active on its root.
//
// It is what the portal's dry-run consumes before anything is published, which
// is why it takes an unpublished document: an operator has to be able to see
// the direction of a change before committing to it, and a diff that only
// worked between two published versions would be available exactly one step too
// late.
func (a *API) Diff(candidate *Document) (Diff, error) {
	if candidate == nil {
		return Diff{}, fmt.Errorf("authoring: cannot diff a nil candidate")
	}
	active, ok := a.store.Active(candidate.Policy.Root)
	if !ok {
		return DiffDocuments(nil, candidate)
	}
	from, err := active.Document()
	if err != nil {
		return Diff{}, err
	}
	return DiffDocuments(from, candidate)
}

// Promote activates a published digest.
func (a *API) Promote(root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	return a.store.Promote(root, digest, actor, at, reason)
}

// Rollback re-activates a previously activated digest.
func (a *API) Rollback(root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	return a.store.Rollback(root, digest, actor, at, reason)
}
