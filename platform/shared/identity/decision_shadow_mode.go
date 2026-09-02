// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The per-plane PDP shadow mode's STORAGE vocabulary (#3564, session v10.3-A).
//
// # WHY THIS PARSER LIVES IN package identity AND NOT IN package planeshadow
//
// The decision shadow is not an identity concern, and planeshadow owns every
// decision it makes. What lives here is narrower: the vocabulary of ONE COLUMN
// on identity_org_settings, which this package reads. parseOrgSettingsRow has
// to decide whether a stored string is usable before it can hand anything to
// anybody, and it cannot import planeshadow - planeshadow imports this package
// for the composition rule. So the parser sits beside the reader that needs
// it, and planeshadow re-exports it under its own name rather than writing a
// second one.
//
// # WHY IT REUSES CompatMode INSTEAD OF DECLARING ITS OWN TYPE
//
// An operator reading "shadow" must not have to ask which shadow they are
// reading about. One vocabulary across both axes means one mental model, one
// spelling in configuration, one spelling in the database, and one set of
// tri-state rules already argued for in compat.go - membership validation
// rather than inequality against a zero value, and an unrecognized value
// failing towards OFF rather than towards evaluation.
//
// # WHY enforce IS REFUSED HERE RATHER THAN CLAMPED LATER
//
// CompatMode carries three values and this axis may only ever hold two: v11 is
// what turns the PDP into an authority, and until then a deployment that
// believes it has switched the decision plane on to enforce has been
// misinformed by its own configuration. Refusing at parse means the operator
// finds out at the moment they typed it - a refusal to boot for the flag, a
// rejected write for the column - rather than discovering weeks later that the
// value they set was silently downgraded. This is ParseCompatMode's own
// argument about "enfore" applied one value further along.
//
// The refusal is stated in BOTH directions, and deliberately: this parser
// refuses it, and the column's CHECK constraint refuses it. A CHECK added by
// migration 150 is evidence about writes migration 150 governs; it is not
// evidence about a row some later migration, backup restore, or direct
// operator UPDATE puts there. A guard that trusts a constraint it did not
// enforce is a guard that fails open on the day the constraint is dropped.
package identity

import (
	"fmt"
	"sort"
	"strings"
)

// EnvDecisionShadowMode names the environment variable selecting the
// deployment-wide per-plane PDP shadow mode. Absent or empty means off.
const EnvDecisionShadowMode = "AXONFLOW_DECISION_SHADOW_MODE"

// decisionShadowModes is the CLOSED set this axis may hold, and the order is
// the order an error message lists them in.
var decisionShadowModes = []CompatMode{CompatModeOff, CompatModeShadow}

// DecisionShadowModeIsStorable reports whether m is a value this axis may
// hold. It is positive membership over the closed set, never `m !=
// CompatModeEnforce`: the two differ on CompatMode(99) and on the Unspecified
// zero value, and both of those must be refused rather than admitted by an
// inequality that happens to be true for them.
func DecisionShadowModeIsStorable(m CompatMode) bool {
	for _, known := range decisionShadowModes {
		if m == known {
			return true
		}
	}
	return false
}

// DecisionShadowModeNames returns the storable spellings, sorted, for an error
// message.
func DecisionShadowModeNames() []string {
	out := make([]string, 0, len(decisionShadowModes))
	for _, m := range decisionShadowModes {
		out = append(out, m.String())
	}
	sort.Strings(out)
	return out
}

// ParseDecisionShadowMode maps a configured or stored string to a mode.
//
// Empty is off - the unconfigured deployment, and the only spelling of "off by
// omission" this accepts. "enforce" is a NAMED refusal rather than a generic
// one, because an operator who typed it has a specific wrong belief and
// telling them "not a recognized mode" would send them to check their spelling
// instead of their calendar. Everything else is refused for ParseCompatMode's
// reason: guessing "off" leaves an operator believing a plane is being
// measured when nothing is measuring it, and an unmeasured window is exactly
// what ADR-065 gate 18 cannot be satisfied from.
func ParseDecisionShadowMode(raw string) (CompatMode, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "":
		return CompatModeOff, nil
	case "off", "false", "0", "disabled":
		return CompatModeOff, nil
	case "shadow":
		return CompatModeShadow, nil
	case "enforce":
		// ONE PHRASE FOR ONE FACT, and it is the phrase every other refusal
		// on this axis already uses: Observer.effectiveMode clamps a stored
		// enforce with "the decision plane has no authority before v11", and
		// this parse-time refusal said the same thing in different words. Two
		// spellings of one contract is what an operator greps past and what a
		// runtime suite pins to only one of; the boot refusal is the one an
		// operator actually reads, so it carries the canonical wording.
		return CompatModeUnspecified, fmt.Errorf(
			"identity: %s=enforce is not available: the decision plane has no authority before v11, "+
				"and until then every plane's verdict is recorded and never applied; use shadow to measure it",
			EnvDecisionShadowMode)
	default:
		return CompatModeUnspecified, fmt.Errorf(
			"identity: %s=%q is not a recognized decision shadow mode (%v); refusing to guess, because guessing 'off' would leave an operator believing the planes are being measured when nothing is measuring them",
			EnvDecisionShadowMode, raw, DecisionShadowModeNames())
	}
}
