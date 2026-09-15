// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
)

// INSTALLED POLICY PACKS (PRD v11 §1.9, #4126)
//
// A policy pack is deployment-authored, like the baseline permission pack: a
// deployment installs it, and it composes on the organization root beside the
// baseline pack whatever the organization has published. An organization's own
// document does not remove it. A pack policy the document already carries is
// the document's own and stands, exactly as for the baseline pack (notCarried).
//
// # THE PACK RESTRICTION
//
// A pack's controls read detectors the shipped census does not carry, so the
// corpus restriction cannot judge them: restrictToScope refuses a non-corpus
// id, and its census arms would KEEP an unjudged control on every scope, where
// its detector never runs and the control reads UNKNOWN on every request. The
// pack arm is derived from the same declarations the corpus arms read, for the
// pack's own detectors. A pack control binds on a scope when, for some phase
// the scope evaluates:
//
//   - the scope's plane reads the static substrate, the one the detector
//     layer's rows belong to;
//   - the control binds on that phase: its detector's declared phase (or
//     `both`), or, for a detector compiled to one control per phase because
//     its phases take different actions, that control's own phase;
//   - one of the plane's call sites in that phase runs the shared engine
//     (EvaluateRequest or EvaluateResponse), which is where an installed pack's
//     detectors are loaded - the tier engine's EvaluatePolicy, retired by
//     #4253, never loaded them;
//   - and the phase's category admission (legacycompile.AdmissionFor) admits
//     the detector's category, as it does for a corpus control.
//
// Nothing here is a list of planes: a call site whose category filter changes
// moves the set, which TestAPackBindsWhereItsDetectorsRun pins.

// RefusalPackApproverRealm is the code InstallPacks refuses with when a pack
// names an approver pool and the deployment declares no realm a person can
// answer in, so the pool would name nobody.
const RefusalPackApproverRealm = "POLICY_PACK_NO_APPROVER_REALM"

// InstalledPack is a policy pack a deployment installed, instantiated for the
// realms its identity plane mints principals in.
type InstalledPack struct {
	Pack *policypack.Pack
	// Document is the instantiated document: the committed form with its
	// approver pool qualified by the deployment's realms.
	Document *pdp.Document
	// Digest is the instantiated document's digest, the one the wire and the
	// audit row name the pack by.
	Digest string
}

// Ref is the pack as the wire and the audit row name it: <id>@<digest>.
func (p InstalledPack) Ref() string { return p.Pack.Source.ID + "@" + p.Digest }

// InstallPacks instantiates each pack for the deployment whose vocabulary snap
// is. The approver pool names the pack's group in every realm a person can
// answer in (authoring.RealmEntry.Interactive). A group graph is NOT required:
// the scopes a pack binds on today hold no approval (PRD v11 §1.13 - a
// challenge there is refused as approval_required), so the pool is named and
// never resolved.
//
// It refuses two packs with one id and two packs that ship one detector id,
// because one detector id is one signal path and two detectors writing it would
// decide each other's controls.
func InstallPacks(snap *authoringcatalog.Snapshot, packs []*policypack.Pack) ([]InstalledPack, error) {
	if len(packs) == 0 {
		return nil, nil
	}
	if snap == nil || snap.Catalog == nil {
		return nil, fmt.Errorf("activation: installing a policy pack needs the deployment vocabulary, whose realms qualify its approver pool")
	}
	var interactive []string
	for realm, entry := range snap.Catalog.Realms {
		if entry.Interactive {
			interactive = append(interactive, realm)
		}
	}
	sort.Strings(interactive)
	ids := map[string]bool{}
	detectors := map[string]string{}
	out := make([]InstalledPack, 0, len(packs))
	for _, p := range packs {
		if p == nil {
			return nil, fmt.Errorf("activation: a nil policy pack cannot be installed")
		}
		id := p.Source.ID
		if ids[id] {
			return nil, fmt.Errorf("activation: policy pack %q is installed twice", id)
		}
		ids[id] = true
		for _, d := range p.Source.Detectors {
			if other, taken := detectors[d.ID]; taken {
				return nil, fmt.Errorf("activation: policy packs %q and %q both ship detector %q; one detector id is one signal, and the two would decide each other's controls", other, id, d.ID)
			}
			detectors[d.ID] = id
		}
		if p.Source.Approval != nil && len(interactive) == 0 {
			return nil, &pdp.ActivationRefusal{
				Code: RefusalPackApproverRealm,
				Detail: fmt.Sprintf("policy pack %q's require_approval controls name an approver pool, and this deployment declares no realm a "+
					"person can answer in, so the pool would name nobody", id),
			}
		}
		doc, digest, err := p.Instantiate(interactive)
		if err != nil {
			return nil, fmt.Errorf("activation: %w", err)
		}
		out = append(out, InstalledPack{Pack: p, Document: doc, Digest: digest})
	}
	return out, nil
}

// PackActivation is what one installed pack did on one scope.
type PackActivation struct {
	ID      string
	Version int
	// Digest is the instantiated pack document's digest.
	Digest string
	// Policies is how many of the pack's controls bind on this scope, of how
	// many it ships.
	Policies, Of int
}

// Ref is the pack as the wire names it: <id>@<digest>.
func (p PackActivation) Ref() string { return p.ID + "@" + p.Digest }

// PackRefs names the packs that bind on this engine's scope as the wire and
// the audit row carry them (`policy_packs`), sorted; nil when none binds.
func (a *Activation) PackRefs() []string {
	if a == nil || len(a.Packs) == 0 {
		return nil
	}
	out := make([]string, 0, len(a.Packs))
	for _, p := range a.Packs {
		out = append(out, p.Ref())
	}
	return out
}

// packForScope is an installed pack's document restricted to the controls that
// bind on scope (see THE PACK RESTRICTION above).
func packForScope(scope legacycompile.EnforcementScope, ip InstalledPack) (*pdp.Document, error) {
	scope, err := legacycompile.ScopeFor(scope.Plane, scope.Phase)
	if err != nil {
		return nil, fmt.Errorf("activation: which of pack %q's controls bind on %s cannot be derived: %w", ip.Pack.Source.ID, scope, err)
	}
	out := &pdp.Document{Root: ip.Document.Root, Version: ip.Document.Version, InteractiveRealms: ip.Document.InteractiveRealms}
	if !readsStaticSubstrate(scope.Plane) {
		return out, nil
	}
	sites, err := legacycompile.CallSites()
	if err != nil {
		return nil, fmt.Errorf("activation: %w", err)
	}
	// Per phase this scope evaluates, what the sites that LOAD the pack's
	// detectors admit. It is their admission and not the phase's
	// (legacycompile.AdmissionFor), because that one unions every static site
	// in the phase: on a plane that also ran the tier engine's unfiltered
	// EvaluatePolicy (retired by #4253) it admitted every category, through a
	// site that never produced a pack detector's verdict.
	admits := map[legacycompile.Phase]legacycompile.CategoryAdmission{}
	for _, ph := range scope.Phases() {
		var a legacycompile.CategoryAdmission
		loads := false
		for _, s := range sites {
			if s.Plane != scope.Plane || s.Phase() != ph || !loadsInstalledPacks(s) {
				continue
			}
			site, declared := legacycompile.SiteAdmission(s)
			if !declared {
				return nil, fmt.Errorf("activation: call site %s loads pack %q's detectors and declares no category admission", s.Key(), ip.Pack.Source.ID)
			}
			a, loads = a.Union(site), true
		}
		if loads {
			admits[ph] = a
		}
	}
	bySignal := make(map[string]policypack.Detector, len(ip.Pack.Source.Detectors))
	for _, d := range ip.Pack.Source.Detectors {
		bySignal[legacycompile.DetectorSignalPath(d.ID)] = d
	}
	for _, p := range ip.Document.Policies {
		d, err := packDetectorOf(p, bySignal)
		if err != nil {
			return nil, fmt.Errorf("activation: pack %q: %w", ip.Pack.Source.ID, err)
		}
		// The control's own phase, not its detector's: a detector whose phases
		// take different actions compiles to one control per phase
		// (policypack.Controls), and each binds only where its phase is scanned.
		phase, ok := ip.Pack.ControlPhase(p.ID)
		if !ok {
			return nil, fmt.Errorf("activation: pack %q: control %q is not one its source compiles to", ip.Pack.Source.ID, p.ID)
		}
		for ph, a := range admits {
			if scansPhase(phase, ph) && a.Admits(d.Category) {
				out.Policies = append(out.Policies, p)
				break
			}
		}
	}
	out.Attributes = schemasRead(out.Policies, ip.Document.Attributes)
	return out, nil
}

// packDetectorOf is the one pack detector a pack control reads. A pack control
// that reads anything else, or two detectors, is a compile defect and refused:
// the restriction judges a control by its detector.
func packDetectorOf(p pdp.Policy, bySignal map[string]policypack.Detector) (policypack.Detector, error) {
	var found []policypack.Detector
	for _, path := range p.ReferencedPaths() {
		if contract.NamespaceOf(path) != contract.NsSignal {
			continue
		}
		if d, ok := bySignal[path]; ok {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		return policypack.Detector{}, fmt.Errorf("control %q reads %d of the pack's detectors; a pack control reads exactly its own", p.ID, len(found))
	}
	return found[0], nil
}

// loadsInstalledPacks reports whether a call site loads an installed pack's
// detectors: a shared-engine site (EvaluateRequest, EvaluateResponse) in the
// agent, whose engine the pack's detectors are appended to. The orchestrator's
// shared engine is not given the packs, so it produces no pack detector's
// verdict; nor did the tier engine's EvaluatePolicy, retired by #4253.
func loadsInstalledPacks(s legacycompile.CallSite) bool {
	if s.Evaluator != legacycompile.EvaluatorRequest && s.Evaluator != legacycompile.EvaluatorResponse {
		return false
	}
	return strings.HasPrefix(s.File, "platform/agent/")
}

// scansPhase reports whether a detector declared for phase declared scans ph.
func scansPhase(declared string, ph legacycompile.Phase) bool {
	return legacycompile.Phase(declared) == legacycompile.PhaseBoth || legacycompile.Phase(declared) == ph
}

// readsStaticSubstrate reports whether a plane's call sites read the static
// substrate.
func readsStaticSubstrate(p legacycompile.Plane) bool {
	for _, s := range legacycompile.MustSpecFor(p).Substrates {
		if s == legacycompile.SubstrateStatic {
			return true
		}
	}
	return false
}
