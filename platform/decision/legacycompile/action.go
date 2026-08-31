package legacycompile

import (
	"sort"
	"strings"
)

// LegacyAction is a stored static_policies action value.
type LegacyAction string

const (
	ActionBlock           LegacyAction = "block"
	ActionRequireApproval LegacyAction = "require_approval"
	ActionAllow           LegacyAction = "allow"
	ActionRedact          LegacyAction = "redact"
	ActionLog             LegacyAction = "log"
	ActionWarn            LegacyAction = "warn"
	// ActionDeny appears only in policy_overrides' widened CHECK constraint
	// (mig 070) and in dynamic policy action documents. It is recognised so
	// that a dynamic row carrying it is not classed unknown.
	ActionDeny LegacyAction = "deny"
	// ActionLogOnly is the other value mig 070 widened policy_overrides to.
	ActionLogOnly LegacyAction = "log_only"
	// ActionRoute and ActionAlert exist ONLY in the dynamic action vocabulary
	// (dynamic_policies.actions[].type). They are deliberately absent from
	// KnownActions, which is the static_policies.action column's CHECK-
	// constrained set: a static row storing "route" is an unknown action and
	// must be reported as one, not quietly accepted because the dynamic plane
	// happens to have a verb by that name.
	ActionRoute LegacyAction = "route"
	ActionAlert LegacyAction = "alert"
)

// KnownActions returns every legacy action value the engines understand, in a
// stable order. Anything outside it is ReasonUnknownLegacyAction rather than
// being coerced to a neighbour.
func KnownActions() []LegacyAction {
	return []LegacyAction{
		ActionAllow, ActionBlock, ActionDeny, ActionLog, ActionLogOnly,
		ActionRedact, ActionRequireApproval, ActionWarn,
	}
}

func isKnownAction(a LegacyAction) bool {
	for _, k := range KnownActions() {
		if k == a {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The legacy action-resolution model.
//
// This is a REIMPLEMENTATION of platform/shared/policy's
// CompiledPolicy.GetActionForPhase, and a reimplementation that is merely
// believed to match the original is worth nothing in a differential harness:
// the whole exercise assumes the legacy side of the diff IS the legacy side.
//
// It is therefore pinned by an executable, exhaustive table rather than by
// eyeballing. legacy_resolution.tsv holds the resolved action for every
// (category, severity, phase, stored-action) combination, including both
// spellings of "no stored action" - NULL and the empty string - which must
// resolve identically because the legacy engine cannot tell them apart.
// TestResolutionTableIsExhaustiveAndAgrees, in this package, proves this code
// reproduces the table; TestLegacyResolutionTableDescribesGetActionForPhase in
// the MAIN module proves the table describes the real GetActionForPhase. Two
// readers, one artifact, neither able to drift silently, and no cross-module
// import - which matters because the decision module is deliberately
// standalone and pins OPA on its own.
// ---------------------------------------------------------------------------

// isPIICategory mirrors sharedpolicy.IsPIIPolicyCategory: any "pii-*"
// category, by convention rather than an enumerated list, so a newly seeded
// pii-* category is covered without anything to remember. "media-pii" is
// deliberately excluded there and here - its detector is the orchestrator's
// OCR subsystem, not the text engine.
func isPIICategory(cat string) bool { return strings.HasPrefix(cat, "pii-") }

// isSecurityCategory mirrors sharedpolicy.isSecurityPolicyCategory, which is
// an enumerated pair, not a prefix.
func isSecurityCategory(cat string) bool {
	return cat == "security-sqli" || cat == "security-dangerous"
}

// ResolveActionForPhase reproduces GetActionForPhase.
//
// It takes the phase column's value and NOTHING ELSE, deliberately. The legacy
// function has no concept of presence: it tests `p.ActionRequest != ""` on a
// field that compilePolicy leaves as the empty string when the column is NULL,
// so NULL and a stored empty string resolve identically there. An earlier
// signature took a separate `storedPresent` flag, which admitted the state
// (present=false, stored="block") that the legacy engine cannot represent -
// and on that input the two disagreed. The state is now unrepresentable.
//
// Presence still matters for the migration REPORT - "the action column is NULL
// and the fallback ran" is the fact an operator needs - so the caller tracks it
// and records it as a reason. It just does not reach the resolution.
func ResolveActionForPhase(category, severity string, storedAction string) LegacyAction {
	if storedAction != "" {
		return LegacyAction(storedAction)
	}
	if isPIICategory(category) {
		return ActionRedact
	}
	if isSecurityCategory(category) && severity == "critical" {
		return ActionBlock
	}
	if category == "admin-access" {
		return ActionWarn
	}
	return ActionLog
}

// ---------------------------------------------------------------------------
// The detection-posture lever.
// ---------------------------------------------------------------------------

// postureLeverCategories maps a category to the environment lever that
// displaces its resolved action, mirroring
// ModeDetectionConfig.BuildActionOverrides. A category absent from this map is
// one no lever reaches, which is a per-category fact and is why the lever
// cannot be modelled as one global translation.
//
// The set is pinned by the same generated table as the resolution model, for
// the same reason: an override map that has silently gained or lost a category
// changes which rows the posture displaces, and that is a difference the
// shadow diff would otherwise attribute to the compiler.
var postureLeverCategories = map[string]string{
	"pii-global":         "PII_ACTION",
	"pii-us":             "PII_ACTION",
	"pii-india":          "PII_ACTION",
	"pii-eu":             "PII_ACTION",
	"pii-singapore":      "PII_ACTION",
	"pii-indonesia":      "PII_ACTION",
	"security-sqli":      "SQLI_ACTION",
	"sensitive-data":     "SENSITIVE_DATA_ACTION",
	"security-dangerous": "DANGEROUS_COMMAND_ACTION",
}

// PostureLeverFor returns the environment lever that displaces a category's
// resolved action, or "" when no lever reaches it.
func PostureLeverFor(category string) string { return postureLeverCategories[category] }

// PostureLeverCategories returns every category a lever reaches, sorted.
func PostureLeverCategories() []string {
	out := make([]string, 0, len(postureLeverCategories))
	for c := range postureLeverCategories {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Posture is a deployment detection posture: the resolved action each lever
// currently carries. An empty Posture means "no lever configured", which is
// not the same as a lever set to the stored action - the first leaves the
// stored action in place, the second replaces it with an identical value and
// is still a displacement the audit trail must show.
type Posture map[string]LegacyAction

// Apply returns the action a lever-bearing plane actually enforces for a
// category, and whether the posture displaced the resolved action.
func (p Posture) Apply(category string, resolved LegacyAction) (LegacyAction, bool) {
	lever := PostureLeverFor(category)
	if lever == "" {
		return resolved, false
	}
	act, ok := p[lever]
	if !ok || act == "" {
		return resolved, false
	}
	return act, true
}
