// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package activationinputs builds activation.Inputs for one organization on any
// enforcement scope. It is the one builder of an organization's activation
// inputs outside the agent's enforcing seams: the typed-authoring workspaces
// (the orchestrator's and the customer portal's) take their dry run's inputs
// from it for the decide plane, and the orchestrator's own planes take theirs
// from it for the scope they enforce (#4254).
//
// IT LIVES IN platform/shared, and nowhere nearer the engine, for two module
// reasons. platform/decision is its own module and imports nothing from
// platform, so it cannot reach the stores an organization's inputs are read
// from. platform/orchestrator imports platform/agent, so a package there could
// never be imported by the agent. Here, the orchestrator, the agent and the
// portal can all import it. What only one of them can read - an organization's
// recorded detection posture, read through the agent's repository in the
// orchestrator and through the portal's own in the portal - is passed in as a
// function.
package activationinputs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
)

// RecordedPosture reads an organization's recorded detection posture in the
// anchored engine's key (#4045, detectionposture.AnchoredCategoryActions). It
// fails closed, as the agent's enforcing seam does, when the posture cannot be
// read, and states why in its own words: the caller knows which store it read.
type RecordedPosture func(ctx context.Context, orgID string) (legacycompile.CategoryActions, error)

// Builder is what every activation of one organization's inputs shares,
// whichever scope it is for.
type Builder struct {
	// Snapshot is the deployment vocabulary the engine admits against.
	Snapshot *authoringcatalog.Snapshot
	// Trust is READ PER ACTIVATION, through #3991's TrustSource, and never
	// captured. A durable open replaces the source's store with one carrying
	// every authorized key, so a store captured before the open would activate
	// against a trust store that cannot verify what another replica signed, and
	// would refuse an activation that is perfectly valid.
	Trust authoring.TrustSource
	// System and Composition sign the shipped corpus and the composed
	// organization root for this process (see NewAuthorities).
	System      *authoring.SystemAuthority
	Composition *authoring.CompositionAuthority
	// Profile is the edition boundary (ADR-066 chokepoint 2), from the caller's
	// licence-derived profile.
	Profile authoring.Profile
	// RefuseConstructsOutsideEdition is activation.Inputs'. An authoring door
	// asks unconditionally, because there a refusal is a sentence an author reads
	// while choosing what to write; an enforcing plane gates it as the agent's
	// seam does, because there the same refusal would refuse every request.
	RefuseConstructsOutsideEdition bool
	// OrganizationID is the organization the inputs are for.
	OrganizationID string
	// Posture reads the organization's recorded detection posture per
	// activation, uncached, so the engine is judged under the posture it will be
	// enforced under. Nil means none is recorded, as for a caller with no
	// database.
	Posture RecordedPosture
	// Packs are the deployment's installed policy packs, instantiated for its
	// realms (activation.InstallPacks), carried into every activation as the
	// agent's enforcer carries them (PRD v11 §1.9). Nil means none is installed.
	// A pack binds only on a plane that reads the static substrate (activation's
	// packForScope), so on wcp and map it binds nothing.
	Packs []activation.InstalledPack
}

// NewAuthorities mints the system-root and composition authorities an
// activation outside the agent signs with, each under a key of its own that is
// never persisted and never an organization's.
//
// THE SYSTEM KEY IS MINTED SEPARATELY (#4047): activation refuses a system key
// that signed the organization's document, by name, and writes nothing into the
// caller's trust store. THE COMPOSITION KEY IS MINTED BESIDE IT: every
// organization root composes the deployment's baseline permission pack (PRD v11
// §1.4), so the activation composes and signs one as the agent's enforcer does,
// and judges the document as it will be enforced.
func NewAuthorities() (*authoring.SystemAuthority, *authoring.CompositionAuthority, error) {
	_, sysPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("the system-root signing key could not be generated: %w", err)
	}
	system, err := authoring.NewSystemAuthority(sysPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("the system-root authority could not be built: %w", err)
	}
	_, compositionPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("the organization composition signing key could not be generated: %w", err)
	}
	composition, err := authoring.NewCompositionAuthority(compositionPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("the composition authority could not be built: %w", err)
	}
	return system, composition, nil
}

// For is the inputs for the scope plane and phase name. phase is empty on a
// plane that evaluates one phase, and names the phase on one that evaluates
// two. What the scope's wire delivers is the one statement of it
// (legacycompile.ScopeDeliveries, #4131), and nil on a scope whose seam
// discharges inline.
//
// The organization's document is not part of the inputs: the authoring API's
// activator sets the candidate artifact (activation.Activator), and an
// enforcing plane sets the active one.
func (b Builder) For(ctx context.Context, plane legacycompile.Plane, phase legacycompile.Phase) (activation.Inputs, error) {
	scope, err := legacycompile.ScopeFor(plane, phase)
	if err != nil {
		return activation.Inputs{}, fmt.Errorf("activationinputs: %w", err)
	}
	if b.Trust == nil {
		return activation.Inputs{}, fmt.Errorf("activationinputs: a trust source is required; an unverified bundle cannot be activated")
	}
	var assigned legacycompile.CategoryActions
	if b.Posture != nil {
		if assigned, err = b.Posture(ctx, b.OrganizationID); err != nil {
			return activation.Inputs{}, err
		}
	}
	return activation.Inputs{
		Snapshot:                       b.Snapshot,
		Trust:                          b.Trust.Current(),
		System:                         b.System,
		Composition:                    b.Composition,
		Plane:                          string(scope.Plane),
		Phase:                          scope.Phase,
		Delivers:                       legacycompile.ScopeDeliveries(scope),
		Profile:                        b.Profile,
		RefuseConstructsOutsideEdition: b.RefuseConstructsOutsideEdition,
		OrganizationID:                 b.OrganizationID,
		Overrides:                      assigned,
		Packs:                          b.Packs,
	}, nil
}

// Source is For bound to one scope, in the shape activation.Activator takes.
func (b Builder) Source(plane legacycompile.Plane, phase legacycompile.Phase) func(context.Context) (activation.Inputs, error) {
	return func(ctx context.Context) (activation.Inputs, error) { return b.For(ctx, plane, phase) }
}
