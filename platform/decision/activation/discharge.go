// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE DISCHARGE GUARD (#4046).
//
// A shipped control that binds on a scope and carries a MANDATORY obligation
// nothing on that scope can discharge is not a control that scope can enforce.
// pdp's composition refuses such a request with unsupported_obligation
// (contract/obligation.go, composeSet's capability check), which is ADR-065
// invariant 8 working as designed - and it means an enforcing engine DENIES
// every request the control matches, where the legacy engine allowed and
// redacted it. MEASURED on the decide seam as shipped in #4025:
// sys_pii_singapore_fin denied under enforce, allowed with a redact_pii
// obligation under off.
//
// So activation refuses such a scope, naming the controls, before an engine
// exists. The fact is (policy, scope, discharge surface): it is computed here,
// where the corpus meets a scope, and never written into the corpus artifact -
// a profile change must not force a corpus regeneration, and ADR-065 removed
// execution location from policy identity for exactly that reason.
//
// # WHAT CAN DISCHARGE, AND WHY THE PLANE'S ROW IS NOT THE WHOLE ANSWER
//
// A decision is judged against the RESOLVED per-request profile: the
// enforcement point's own capability handshake when it presented one, the
// plane's registered profile (registry/legacy_plane_peps.tsv) otherwise
// (pdp.DecideOptions). The registered row lists only what the plane discharges
// ITSELF, and under-advertising is its safe direction - declaring field_redact
// on decide's row would count every caller as able to discharge a redaction,
// including one that never redacts.
//
// A plane that RETURNS its decision can still carry an obligation to the caller
// that asked: the Decision API hands a field_redact to an enforcement point as
// redact_pii with a fulfillment route. For such a scope a control is
// enforceable for every caller that declares the capability, and a caller that
// does not is answered unsupported_obligation per request - invariant 8 applied
// to that caller rather than to the scope. So the surface this guard reads is
// the registered profile PLUS what the scope's wire delivers to a declaring
// caller (Inputs.Delivers), narrowed to what an enforcement point of this
// edition may declare at all (registry.SplitOverAdvertised): a capability the
// edition would drop from every declaration cannot make a control enforceable.
//
// # NO EXEMPTION
//
// decide shipped (#4025) with a per-control exemption for its sixteen static
// field_redact controls, held to a re-entry condition that reported an entry
// STALE once the scope could discharge it. Measuring decide against its wire
// reported all sixteen STALE in both editions, and the exemption was removed
// with the fix rather than left as a list nothing needs.

// DischargeSurface is everything that can discharge a mandatory obligation on
// one scope. It is registry.DischargeSurface (#4131): the corpus build's
// template split reads the same surface, so the guard and the split cannot
// disagree about what a scope can carry out.
type DischargeSurface = registry.DischargeSurface

// NewDischargeSurface builds a scope's surface from its registered profile and
// the capabilities its wire delivers (registry.NewDischargeSurface).
func NewDischargeSurface(profile *contract.PEPProfile, delivers []contract.Capability, edition registry.Edition) DischargeSurface {
	return registry.NewDischargeSurface(profile, delivers, edition)
}

// UndischargeableControls returns, for every control in a restricted system
// document, the mandatory obligations nothing on the surface can discharge,
// keyed by policy id. An empty surface discharges nothing, so every mandatory
// obligation is reported rather than silently passed.
func UndischargeableControls(system *pdp.Document, surface DischargeSurface) map[string][]string {
	out := map[string][]string{}
	if system == nil {
		return out
	}
	for _, p := range system.Policies {
		for _, o := range p.Obligations {
			if !o.Mandatory || surface.Discharges(o) {
				continue
			}
			out[p.ID] = append(out[p.ID], fmt.Sprintf("%s@%d", o.Type, o.SchemaVersion))
		}
	}
	return out
}

// refuseUndischargeable refuses a scope whose restriction carries a control
// its surface cannot discharge.
func refuseUndischargeable(scope legacycompile.EnforcementScope, system *pdp.Document, surface DischargeSurface) error {
	var refused []string
	for id, types := range UndischargeableControls(system, surface) {
		sort.Strings(types)
		refused = append(refused, id+" ("+strings.Join(types, ",")+")")
	}
	if len(refused) == 0 {
		return nil
	}
	sort.Strings(refused)
	profile := "no registered profile"
	if surface.Profile != nil {
		profile = fmt.Sprintf("registered profile %q", surface.Profile.ID)
	}
	delivers := "delivers nothing to its caller"
	if len(surface.Delivers) > 0 {
		names := make([]string, 0, len(surface.Delivers))
		for _, c := range surface.Delivers {
			names = append(names, c.String())
		}
		delivers = "delivers only " + strings.Join(names, ",") + " to a caller that declares it"
	}
	return fmt.Errorf("activation: %d shipped control(s) bind on %s and carry a mandatory obligation that neither its %s discharges nor its wire, which %s, can hand to a caller, "+
		"so an engine here would deny every request they match as unsupported_obligation - a verdict the legacy engine never gave: %s. "+
		"Declare the capability for the plane, deliver the obligation on the scope's wire, or leave the scope unenforced (#4046)",
		len(refused), scope, profile, delivers, strings.Join(refused, "; "))
}
