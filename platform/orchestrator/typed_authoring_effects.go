// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/activationinputs"
	"axonflow/platform/shared/authoringedition"
)

// ErrActiveEffectsUnavailable is ActiveEffects' refusal when what is in force
// on an organization cannot be read. A report states it as the section's
// error, never as zero policies (#4249).
var ErrActiveEffectsUnavailable = errors.New("what is in force on this organization could not be read")

// ActiveEffects is what the organization's activation enforces on one scope:
// the activationinputs.EffectsFunc the compliance readers are handed (OJK,
// SEBI, US securities, #4249). It reads exactly what GET
// /api/v1/typed-policies/active/summary counts (handleActiveSummary): the same
// workspace, the same active document, the edition boundary gated as the
// agent's enforcing seam gates it, and activationinputs.ActiveEffects, which
// ActiveSummary counts. Only the scope is the caller's.
//
// It refuses wherever the summary route refuses: an unresolvable vocabulary, a
// degraded workspace, or an active document that could not be read. Nothing
// active is NOT a refusal: the organization root is then the implicit
// baseline, which is enforced.
func (h *TypedAuthoringRouteHandler) ActiveEffects(ctx context.Context, orgID string, plane legacycompile.Plane, phase legacycompile.Phase) ([]activation.PolicyEffect, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: no typed-authoring handler is wired", ErrActiveEffectsUnavailable)
	}
	if snap, err := h.vocabulary(); err != nil || snap == nil {
		return nil, fmt.Errorf("%w: this deployment's typed-authoring vocabulary could not be resolved: %v", ErrActiveEffectsUnavailable, err)
	}
	ws, err := h.workspaceFor(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrActiveEffectsUnavailable, err)
	}
	if ws.degraded {
		return nil, fmt.Errorf("%w: this organization's durable store could not be opened", ErrActiveEffectsUnavailable)
	}
	art, found, err := ws.api.Store().Active(ctx, typedAuthoringRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: the active document could not be read: %v", ErrActiveEffectsUnavailable, err)
	}
	if !found {
		art = nil
	}
	_, effects, err := activationinputs.ActiveEffects(ctx, ws.inputs.Source(plane, phase), art,
		authoringedition.Resolve(ctx).EnforcesConstructBoundary())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrActiveEffectsUnavailable, err)
	}
	return effects, nil
}

// compile-time: the handler's method is the readers' injected func.
var _ activationinputs.EffectsFunc = (*TypedAuthoringRouteHandler)(nil).ActiveEffects

// complianceTypedAuthoring is the typed-authoring handler whose ActiveEffects
// the compliance readers count, through complianceActiveEffects. Run sets it
// when it builds the handler, before the server accepts a request; nil until
// then, which ActiveEffects reports as unavailable, never as zero policies.
var complianceTypedAuthoring *TypedAuthoringRouteHandler

// complianceActiveEffects is the activationinputs.EffectsFunc the compliance
// modules are built with (run.go). The modules are built in
// initializeComponents, before Run builds the typed-authoring handler, so it
// reads complianceTypedAuthoring per call rather than capturing it.
func complianceActiveEffects(ctx context.Context, orgID string, plane legacycompile.Plane, phase legacycompile.Phase) ([]activation.PolicyEffect, error) {
	return complianceTypedAuthoring.ActiveEffects(ctx, orgID, plane, phase)
}
