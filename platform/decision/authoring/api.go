// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
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
	catalog   *Catalog
	store     *Store
	trust     TrustSource
	profile   Profile
	activator Activator
	// selfApproval is the transport's answer to PRD v11 §1.12's question, and
	// nil where the transport installs none: every transport but the portal.
	selfApproval SelfApproval
}

// NewAPI builds the authoring surface over a catalog, a trust store and an
// edition PROFILE, keeping published artifacts in memory.
//
// THE PROFILE IS A POSITIONAL ARGUMENT RATHER THAN AN OPTION, and that costs
// every caller one word deliberately. An option, or a second constructor with
// a default, would make "which edition is this?" a question a transport could
// forget to answer - and the answer it would get by forgetting is whichever
// one the default names, silently, on the deployment least able to notice. A
// required argument makes the omission a compile error.
//
// IT IS A PROFILE AND NOT AN EDITION, since #3956. The boundary a surface
// enforces is two facts, not one - which edition, and whether the process
// could establish that it is that edition - and the second is what decides the
// DUTY rule. While the argument was an Edition, that second fact had nowhere
// to travel: NewAPI, NewStore and Publish each re-derived a profile from the
// edition alone, so three derivations existed and all three lost it. One
// profile, built once by the resolver, is what removes both the loss and the
// redundancy.
func NewAPI(cat *Catalog, trust TrustSource, profile Profile) (*API, error) {
	return NewAPIWithBackend(cat, trust, profile, nil)
}

// NewAPIWithBackend builds the authoring surface over a supplied storage
// Backend. A nil backend means the in-process one.
//
// This is the ONLY thing an edition has to supply to make typed authoring
// durable. The rules - validation, the gauntlet, signing, separation of
// duties, the parent chain - are the same code either way, because a second
// implementation of them is the failure mode this seam exists to prevent.
//
// THE PROFILE AND THE BACKEND ARE INDEPENDENT, and it is worth saying so
// because they look like the same axis. The profile decides WHICH CONSTRUCTS
// an author may write and under WHICH DUTY RULE; the backend decides WHERE
// what they wrote is kept. A Community deployment with a durable backend is a
// coherent thing, and so is an Enterprise one running in memory - which is
// what every test in this package does.
func NewAPIWithBackend(cat *Catalog, trust TrustSource, profile Profile, b Backend) (*API, error) {
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	if err := profile.validate(); err != nil {
		return nil, err
	}
	store, err := NewStoreWithBackend(trust, profile, b)
	if err != nil {
		return nil, err
	}
	// THE ORGANIZATION AUTHORITY, bound here (#4047). Every transport builds its
	// authoring plane through this constructor, so every transport's store
	// refuses the system root by AUTHORITY - not by the route's own constant,
	// and not by which keys its trust store happens to hold. See
	// system_authority.go for the other half.
	store.organizationOnly = true
	return &API{catalog: cat, store: store, trust: trust, profile: profile}, nil
}

// Profile returns the edition boundary this surface enforces. A transport
// serves Profile().Constructs() so an author can see the boundary before
// meeting it as a refusal.
func (a *API) Profile() Profile { return a.profile }

// Store exposes the publication store for activation queries.
func (a *API) Store() *Store { return a.store }

// Catalog exposes the registry a document is validated against.
func (a *API) Catalog() *Catalog { return a.catalog }

// Create builds and validates a new document version.
func (a *API) Create(meta Metadata, policy pdp.Document) (*Document, Findings, error) {
	return NewDocument(Document{Metadata: meta, Policy: policy}, a.catalog)
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
	return a.PublishAdmitting(ctx, d, opts, nil)
}

// PublishAdmitting is Publish with a hook that runs BETWEEN the two halves of
// publication: after the document has been fully judged, before the artifact is
// stored.
//
// # Why the seam is here and not in the caller
//
// Publish is already two steps - a PURE half that validates, applies the
// edition boundary, runs the gauntlet and signs, and a DURABLE half that writes
// the artifact. Every refusal a caller can cause lives in the first half.
// A transport that needs to record something only when a publication is going
// to succeed therefore needs exactly this point, and it must not get there by
// calling the two halves itself: the package-level Publish takes a Profile, and
// a transport supplying its own would publish under a boundary it chose rather
// than the one the deployment holds. That is the failure this type exists to
// prevent (see the note on API and on Publish's profile overwrite), so the hook
// is offered here instead.
//
// # What a hook is for, and the one rule it must obey
//
// It is for a side effect that must not happen for a publication that is
// refused, and must have happened before one that is stored - the tier
// admission ledger being the case it was built for (#3973: an append-only
// ledger that recorded what was ATTEMPTED left organizations at their ceiling
// with nothing published).
//
// AN ERROR FROM THE HOOK REFUSES THE PUBLICATION AND NOTHING IS STORED. The
// artifact is discarded, so a hook that refuses leaves no trace of the
// publication anywhere - which is the property that makes "a refused request
// consumes nothing" true for the hook's own resource as well as ours.
//
// The findings are returned either way: a refusal explained by findings the
// caller cannot see is a refusal the author cannot act on.
//
// # The residual, stated rather than left to be discovered
//
// A hook that SUCCEEDS and is then followed by a failing store write has
// recorded something for a document that was never stored. The hook's resource
// and the artifact are not written in one transaction: both this store and the
// admission ledger open their own through rls.WithOrgScope, which takes a
// *sql.DB and owns the transaction it creates, and neither exposes a form that
// accepts an external one. Closing it would mean a tx-taking variant on both
// interfaces, and neither the in-process backend nor the in-memory ledger can
// join a Postgres transaction at all.
//
// REVISIT WHEN: rls gains a tx-taking scope form AND both the Backend and the
// admission Ledger expose one. Until then the window is one statement wide, on
// a path where storage has already been probed, and it is strictly smaller than
// the alternative it replaces - recording for every refusal, including every
// edition and approver refusal, which is what shipped before #3973.
func (a *API) PublishAdmitting(ctx context.Context, d *Document, opts PublishOptions, admit func(context.Context, *Artifact) error) (*Artifact, Findings, error) {
	// THE PROFILE IS OVERWRITTEN, NOT DEFAULTED. A transport that supplied its
	// own would otherwise be able to publish under a wider boundary than the
	// deployment holds simply by naming one - which is the entire boundary,
	// decided by the request. The surface's own profile wins, always, and a
	// caller of the package-level Publish that wants a different one has to
	// build a different API.
	opts.Profile = a.profile
	// THE AUTHORITY, BEFORE ANYTHING IS SIGNED. Store.Admit refuses the same
	// root below; asking here as well means a refused system-root publication
	// never produces a signature at all.
	if d != nil {
		if err := a.store.refuseOutsideAuthority("publish", d.Policy.Root); err != nil {
			return nil, nil, err
		}
	}
	if err := a.store.refuseOutsideAuthority("publish", opts.Root); err != nil {
		return nil, nil, err
	}
	// SELF-APPROVAL IS ASKED, NEVER CLAIMED (PRD v11 §1.12). This is the only
	// place the grant is set, and the question is asked only for a publication
	// in the self-approved shape, so the transport's answer - which reads the
	// approver directory - is not paid for on every publish.
	opts.selfApprovalGranted = false
	if d != nil && everyApproverIsTheAuthor(d.Metadata.Author, opts.Approvers) {
		if ask := a.selfApprovalFor(ctx); ask != nil {
			granted, err := ask()
			if err != nil {
				return nil, nil, fmt.Errorf("authoring: deciding whether this organization may self-approve: %w", err)
			}
			opts.selfApprovalGranted = granted
		}
	}
	art, findings, err := Publish(ctx, d, a.catalog, opts)
	if err != nil {
		return nil, findings, err
	}
	if admit != nil {
		if err := admit(ctx, art); err != nil {
			return nil, findings, err
		}
	}
	if err := a.store.Admit(ctx, art); err != nil {
		return nil, findings, err
	}
	return art, findings, nil
}

// ErrNothingActive is what Render returns for a root on which no document is
// active: a store that answered and holds nothing there. A store that could not
// be read is a different outcome, and Render wraps its error instead, so a
// caller tells the two apart with errors.Is (#4255). The typed-authoring route
// answers the first 404 nothing_active and the second 503 storage_unavailable;
// reading a database failure as "nothing active" told an operator their
// organization had no active document when the store was merely unreachable.
var ErrNothingActive = errors.New("authoring: no document is active")

// ErrNotAdmitted is what RenderDigest returns for a digest the store answered
// for and does not hold under the root. A store that could not be read is a
// different outcome, and RenderDigest wraps its error instead, so a caller
// tells the two apart with errors.Is (#4271): the portal's artifact-source
// route answers the first 404 not_admitted and the second as the store refusal
// it is, where it had answered a database failure "that digest was never
// admitted".
var ErrNotAdmitted = errors.New("authoring: the digest is not admitted")

// ErrActiveUnavailable marks a Diff that could not read what is active on the
// candidate's root: the store's read, or the active artifact's own document.
// Neither is the candidate's fault, and the portal's diff route answers it as
// the store refusal it is rather than 422 diff_failed, which told an operator
// during an outage that their document could not be diffed (#4271). The cause is
// wrapped beside it.
var ErrActiveUnavailable = errors.New("authoring: the document active on the root could not be read")

// Render returns the exact source of the document currently active on a root.
//
// This is the operator-facing half of "rendered back without loss": what comes
// back is the byte sequence that was signed, that parses, that re-renders
// identically, and that recompiles to the module being enforced. Every one of
// those was proven before the signature and is re-proven on every load.
func (a *API) Render(ctx context.Context, root pdp.Root) ([]byte, error) {
	art, ok, err := a.store.Active(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("authoring: reading the document active on the %q authority root: %w", root, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w on the %q authority root", ErrNothingActive, root)
	}
	return art.Source(), nil
}

// RenderDigest returns the exact source of one admitted artifact.
func (a *API) RenderDigest(ctx context.Context, root pdp.Root, digest string) ([]byte, error) {
	art, ok, err := a.store.Get(ctx, root, digest)
	if err != nil {
		return nil, fmt.Errorf("authoring: reading digest %s under the %q authority root: %w", digest, root, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: digest %s under the %q authority root", ErrNotAdmitted, digest, root)
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
func (a *API) Diff(ctx context.Context, candidate *Document) (Diff, error) {
	if candidate == nil {
		return Diff{}, fmt.Errorf("authoring: cannot diff a nil candidate")
	}
	active, ok, err := a.store.Active(ctx, candidate.Policy.Root)
	if err != nil {
		return Diff{}, fmt.Errorf("%w (the %q authority root): %w", ErrActiveUnavailable, candidate.Policy.Root, err)
	}
	if !ok {
		return DiffDocuments(nil, candidate)
	}
	// A loaded artifact's document was re-proven on load, so this is not
	// expected; if it happens it is still the active side, not the candidate.
	// It carries no store sentinel, so the portal answers it storage_unavailable:
	// a refusal on the safe side, never a leak.
	from, err := active.Document()
	if err != nil {
		return Diff{}, fmt.Errorf("%w (the %q authority root): %w", ErrActiveUnavailable, candidate.Policy.Root, err)
	}
	return DiffDocuments(from, candidate)
}

// Activator is the production activation check an API runs BEFORE it flips
// the active digest: given the artifact about to become active, it builds the
// engine that would enforce it and refuses if that engine cannot be built.
//
// It is a hook rather than a hard dependency because the package that knows
// how to build a production engine (platform/decision/activation) imports
// this one. A nil activator means "flip the pointer and nothing else", which
// is what every in-package test and the offline importer's dry run want.
//
// A TRANSPORT THAT ACTIVATES SHOULD INSTALL ONE, and that is a rule with a
// check behind it rather than a sentence here: an earlier version of this
// comment claimed "platform/shared/authoringedition hands every transport an
// activator, and a census in that package holds them to it", and neither the
// hand-out nor the census existed. R3 caught it, and the one transport the
// imaginary census would have caught was the Enterprise portal - the surface
// with DURABLE storage, activating without the production dry run while the
// in-memory one had it.
//
// The real check is authoring.TestEveryActivatingTransportInstallsAnActivator,
// which walks the tree for calls to API.Promote, API.Rollback and API.Withdraw
// and requires each calling package to also call WithActivator.
//
// candidate is nil for a withdrawal: what it would put in force is the implicit
// bundle, which no artifact carries (PRD v11 §1.15).
type Activator func(ctx context.Context, kind ActivationKind, candidate *Artifact) error

// WithActivator installs the production activation check. Returns the receiver
// so it can be chained onto the constructor.
func (a *API) WithActivator(act Activator) *API {
	a.activator = act
	return a
}

// SelfApproval answers, when it is asked, whether this deployment grants the
// organization it serves self-approval (PRD v11 §1.12): the organization
// enabled it and has fewer than two eligible approvers. It is asked at a
// self-approved publication and again at every activation by the author of a
// self-approved version, so an organization that gains a second eligible
// approver loses the exception without anything being revoked.
//
// A transport installs one only where it can answer: the portal, which holds
// the organization's setting and its approver directory. The orchestrator
// installs none, so self-approval does not exist there (§1.12: portal-only in
// v11). An error refuses the publication or the activation: an exception that
// cannot be decided is not granted.
type SelfApproval func(ctx context.Context) (bool, error)

// WithSelfApproval installs the deployment's self-approval answer. Returns the
// receiver so it can be chained onto the constructor.
func (a *API) WithSelfApproval(fn SelfApproval) *API {
	a.selfApproval = fn
	return a
}

// selfApprovalFor returns the question this surface may ask, or nil when it
// may not ask at all: no answer is installed; the edition carries no
// separation of duties, so there is nothing to relax; or separation of
// duties applies only because the tier could not be established - an
// unestablished tier gets no self-approval (§1.12), fail-closed like the duty
// rule it would relax.
func (a *API) selfApprovalFor(ctx context.Context) func() (bool, error) {
	if a.selfApproval == nil || !a.profile.tierEstablished || !a.profile.RequiresSeparationOfDuties() {
		return nil
	}
	return func() (bool, error) { return a.selfApproval(ctx) }
}

// ErrCatalogIsFixture is returned by Promote and Rollback when the surface's
// catalog is a fixture. It carries CodeCatalogIsFixture so a transport can
// name the refusal without parsing the message.
type ErrCatalogIsFixture struct {
	Source string
}

func (e *ErrCatalogIsFixture) Error() string {
	return fmt.Sprintf("%s: this surface authors against the %q FIXTURE vocabulary, which no request can arrive in; "+
		"a fixture may be validated and published against and may never be activated. Resolve the deployment "+
		"vocabulary (AXONFLOW_TYPED_AUTHORING_CATALOG=deployment) to activate", CodeCatalogIsFixture, e.Source)
}

// Code is the machine-readable refusal.
func (e *ErrCatalogIsFixture) Code() string { return CodeCatalogIsFixture }

// refuseFixtureActivation is the check both activation verbs share. It runs
// BEFORE the store is consulted, so a fixture surface cannot even advance the
// activation sequence.
func (a *API) refuseFixtureActivation() error {
	if a.catalog != nil && a.catalog.Provenance.Fixture {
		return &ErrCatalogIsFixture{Source: a.catalog.Provenance.Source}
	}
	return nil
}

// runActivator builds the engine the candidate would be enforced by, if an
// activator is installed. It reads the candidate out of the store so that the
// artifact checked is the artifact the store will flip to, not one the caller
// handed over.
func (a *API) runActivator(ctx context.Context, kind ActivationKind, root pdp.Root, digest string) error {
	if a.activator == nil {
		return nil
	}
	art, ok, err := a.store.Get(ctx, root, digest)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("authoring: digest %s is not admitted under root %q; a digest is activated only after it has been verified", digest, root)
	}
	if err := a.activator(ctx, kind, art); err != nil {
		return fmt.Errorf("authoring: refusing to %s %s: %w", kind, digest, err)
	}
	return nil
}

// Promote activates a published digest.
//
// ORDER: the fixture refusal, then the activator, then the store. The store's
// own rules (verification, separation of duties, the parent chain) are
// unchanged and still run; what precedes them is the question they cannot
// ask, which is whether the thing about to become active can be ENFORCED by
// the engine this deployment would build from it.
func (a *API) Promote(ctx context.Context, root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	if err := a.store.refuseOutsideAuthority("promote", root); err != nil {
		return nil, err
	}
	if err := a.refuseFixtureActivation(); err != nil {
		return nil, err
	}
	if err := a.runActivator(ctx, ActivationPromote, root, digest); err != nil {
		return nil, err
	}
	return a.store.promote(ctx, root, digest, actor, at, reason, a.selfApprovalFor(ctx))
}

// Rollback re-activates a previously activated digest. It is held to the same
// two production checks as Promote: a rollback target that cannot be enforced
// is not a state to restore to.
func (a *API) Rollback(ctx context.Context, root pdp.Root, digest string, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	if err := a.store.refuseOutsideAuthority("rollback", root); err != nil {
		return nil, err
	}
	if err := a.refuseFixtureActivation(); err != nil {
		return nil, err
	}
	if err := a.runActivator(ctx, ActivationRollback, root, digest); err != nil {
		return nil, err
	}
	return a.store.rollback(ctx, root, digest, actor, at, reason, a.selfApprovalFor(ctx))
}

// Withdraw returns root to the implicit bundle (PRD v11 §1.15). It is held to
// the two production checks promote and rollback are: a fixture vocabulary
// activates nothing, and the activator dry-runs the implicit bundle it would
// restore, so a deployment that could not enforce its own shipped set cannot be
// withdrawn into it.
func (a *API) Withdraw(ctx context.Context, root pdp.Root, actor contract.ID, at time.Time, reason string) (*Activation, error) {
	if err := a.store.refuseOutsideAuthority("withdraw", root); err != nil {
		return nil, err
	}
	if err := a.refuseFixtureActivation(); err != nil {
		return nil, err
	}
	if a.activator != nil {
		if err := a.activator(ctx, ActivationWithdraw, nil); err != nil {
			return nil, fmt.Errorf("authoring: refusing to withdraw into the implicit bundle: %w", err)
		}
	}
	return a.store.withdraw(ctx, root, actor, at, reason, a.selfApprovalFor(ctx))
}
