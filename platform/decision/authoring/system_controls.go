// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// SystemControlEntry is an organization's control of one shipped system control
// (PRD v11 §1.5).
//
// Control is the control's corpus identifier, the identifier the shipped posture
// table lists. It governs every corpus policy the control compiled to - a split
// control's per-scope variants and a dynamic row's "#n" parts included - because
// that is what legacycompile.CorpusControlOf reads each of them back to.
//
// An entry says exactly one thing. Enabled false leaves the control out on every
// plane; Action replaces its action with one an organization may assign
// (legacycompile.OverrideActions). Restoring a control is removing its entry.
type SystemControlEntry struct {
	Control string                     `json:"control"`
	Enabled *bool                      `json:"enabled,omitempty"`
	Action  legacycompile.LegacyAction `json:"action,omitempty"`
}

// Disabled reports whether the entry leaves its control out.
func (c SystemControlEntry) Disabled() bool { return c.Enabled != nil && !*c.Enabled }

// dynamicControlTable is the source table of the shipped dynamic controls, which
// v11 lets an organization disable but not re-action (PRD v11 §1.5).
const dynamicControlTable = "dynamic_policies"

// DynamicSystemControl reports whether a corpus control identifier names a
// shipped dynamic control. It reads the table segment of the identifier
// legacycompile.CorpusControlOf returns, "corpus:<table>:<row>".
func DynamicSystemControl(control string) bool {
	rest, isCorpus := strings.CutPrefix(control, "corpus:")
	table, _, _ := strings.Cut(rest, ":")
	return isCorpus && table == dynamicControlTable
}

// shippedSystemControls is the set of shipped system controls by corpus control
// identifier, read from the embedded corpus once.
var shippedSystemControls = sync.OnceValues(func() (map[string]bool, error) {
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, p := range corpus.Policies {
		if control, _, ok := legacycompile.CorpusControlOf(p.ID); ok {
			out[control] = true
		}
	}
	return out, nil
})

// CheckSystemControls runs the save-time checks of a document's system_controls
// section alone, with the codes an authored document's section is refused with.
// The upgrade import proposes each entry through it before it writes a draft
// (PRD v11 §1.5), so an entry an author could not save is never written for one.
func CheckSystemControls(d *Document) Findings { return validateSystemControls(d) }

// validateSystemControls checks the system_controls section.
//
// Whether a replacement action compiles for the control's category is not
// checked here: it needs the detector census, which is activation's. Publication
// dry-runs the activation, so an action that does not compile is refused before
// anything becomes active.
func validateSystemControls(d *Document) Findings {
	if len(d.SystemControls) == 0 {
		return nil
	}
	var out Findings
	if d.Policy.Root != pdp.RootOrganization {
		out = append(out, newFinding(CodeSystemControlsOutsideOrganization, "", fmt.Sprintf(
			"policy.root is %q and the document carries %d system control(s); only the organization root controls the shipped set",
			d.Policy.Root, len(d.SystemControls))))
	}
	shipped, err := shippedSystemControls()
	if err != nil {
		return append(out, newFinding(CodeEnvelopeInvalid, "", "the shipped corpus could not be read to check system_controls: "+err.Error()))
	}
	seen := map[string]bool{}
	for i, c := range d.SystemControls {
		at := fmt.Sprintf("system_controls[%d]", i)
		switch {
		case !shipped[c.Control]:
			out = append(out, newFinding(CodeSystemControlUnknown, "", fmt.Sprintf(
				"%s names %q, which is not a shipped system control", at, c.Control)))
		case seen[c.Control]:
			out = append(out, newFinding(CodeSystemControlDuplicate, "", fmt.Sprintf("%s names %s again", at, c.Control)))
		}
		seen[c.Control] = true
		switch {
		case (c.Enabled == nil) == (c.Action == ""):
			out = append(out, newFinding(CodeSystemControlMalformed, "", fmt.Sprintf(
				"%s (%s) carries both or neither of enabled and action; it must carry exactly one", at, c.Control)))
		case c.Enabled != nil && *c.Enabled:
			out = append(out, newFinding(CodeSystemControlMalformed, "", fmt.Sprintf(
				"%s (%s) says enabled true; a shipped control is enabled unless the document disables it, so remove the entry to restore it", at, c.Control)))
		case c.Action != "" && !slices.Contains(legacycompile.OverrideActions(), c.Action):
			out = append(out, newFinding(CodeSystemControlMalformed, "", fmt.Sprintf(
				"%s (%s) assigns action %q; an organization assigns one of %v", at, c.Control, c.Action, legacycompile.OverrideActions())))
		case c.Action != "" && DynamicSystemControl(c.Control):
			out = append(out, newFinding(CodeSystemControlNotReactionable, "", fmt.Sprintf(
				"%s assigns %q to the shipped dynamic control %s, which v11 lets an organization disable but not re-action", at, c.Action, c.Control)))
		}
	}
	return out
}

// SystemControlChange is what happened to one system_controls entry between two
// document versions. Before and After render the entry's instruction:
// "disabled", or "action=<action>".
type SystemControlChange struct {
	Control   string     `json:"control"`
	Kind      ChangeKind `json:"kind"`
	Effect    Effect     `json:"effect"`
	Rationale string     `json:"rationale"`
	Before    string     `json:"before,omitempty"`
	After     string     `json:"after,omitempty"`
}

func (c SystemControlEntry) instruction() string {
	if c.Disabled() {
		return "disabled"
	}
	return "action=" + string(c.Action)
}

// diffSystemControls computes the changes between two system_controls sections,
// ordered by control.
//
// Its directions follow from the model: a shipped system control only restricts,
// requires or inspects - the corpus permits nothing - so leaving one out can only
// let more requests through, and bringing it back can only let fewer. A
// replacement action compared with the shipped one is undetermined, because the
// shipped action of a split control differs by scope; two replacement actions
// compare by legacycompile.OverrideActions' order of restrictiveness.
func diffSystemControls(from, to []SystemControlEntry) []SystemControlChange {
	before := map[string]SystemControlEntry{}
	for _, c := range from {
		before[c.Control] = c
	}
	after := map[string]SystemControlEntry{}
	for _, c := range to {
		after[c.Control] = c
	}
	controls := make([]string, 0, len(before)+len(after))
	for id := range before {
		controls = append(controls, id)
	}
	for id := range after {
		if _, both := before[id]; !both {
			controls = append(controls, id)
		}
	}
	slices.Sort(controls)

	var out []SystemControlChange
	for _, id := range controls {
		b, had := before[id]
		a, has := after[id]
		change := SystemControlChange{Control: id}
		switch {
		case !had:
			change.Kind, change.After = ChangeAdded, a.instruction()
			if a.Disabled() {
				change.Effect, change.Rationale = EffectWidening, "leaving a shipped control out can only let more requests through"
			} else {
				change.Effect, change.Rationale = EffectUndetermined, "the replacement action is compared with the shipped one, which can differ by scope; read the shipped posture table"
			}
		case !has:
			change.Kind, change.Before = ChangeRemoved, b.instruction()
			if b.Disabled() {
				change.Effect, change.Rationale = EffectNarrowing, "the shipped control returns, which can only let fewer requests through"
			} else {
				change.Effect, change.Rationale = EffectUndetermined, "the shipped action returns, and it can differ by scope; read the shipped posture table"
			}
		case b.instruction() == a.instruction():
			continue
		default:
			change.Kind, change.Before, change.After = ChangeModified, b.instruction(), a.instruction()
			switch {
			case a.Disabled():
				change.Effect, change.Rationale = EffectWidening, "the control is left out instead of re-actioned, which can only let more requests through"
			case b.Disabled():
				change.Effect, change.Rationale = EffectNarrowing, "the control returns with a replacement action instead of being left out"
			case restrictiveness(a.Action) > restrictiveness(b.Action):
				change.Effect, change.Rationale = EffectNarrowing, "the replacement action is more restrictive than the one it replaces"
			default:
				change.Effect, change.Rationale = EffectWidening, "the replacement action is less restrictive than the one it replaces"
			}
		}
		out = append(out, change)
	}
	return out
}

// restrictiveness ranks an assignable action; higher is more restrictive.
func restrictiveness(a legacycompile.LegacyAction) int {
	actions := legacycompile.OverrideActions()
	return len(actions) - slices.Index(actions, a)
}
