// Package shadow dual-evaluates the legacy policy substrate and the ADR-065
// PDP over the same replay case, and classifies every semantic difference.
//
// ADR-065 acceptance gate 18 is "shadow migration has no unexplained fail-open
// difference for the agreed window". That sentence has no operand until
// something computes the differences and decides which are explained, which is
// what this package is. Gate() is the executable form of it; UNEXPLAINED == 0
// over a non-vacuous corpus is its operand.
//
// # The two sides are genuinely two sides
//
// The legacy side is a MODEL of the legacy decision procedure - phase-column
// resolution, the category and severity fallback, the detection-posture lever,
// priority-ordered evaluation, the ADR-060 segment rule, and the orchestrator
// condition resolver's context fallthrough, under which a field outside the
// explicit cases reads caller-forwarded context (#3515). The ADR-065 side is the
// REAL PDP: typed documents compiled to Rego v1, signed into bundles,
// verified, and evaluated in-process by OPA with the combining semantics
// implemented in Go above it.
//
// The two sides also speak DIFFERENT vocabularies on purpose. The legacy side
// reports the legacy action each matched row resolved; the ADR-065 side
// reports typed obligations. They are compared through a correspondence table
// that lives in the classifier, which is a SECOND, independent statement of
// the mapping the compiler asserts. If the compiler's mapping and the
// classifier's expectation diverge, the run reports UNEXPLAINED - which is the
// property that makes this a differential harness rather than a description of
// the compiler comparing itself to itself.
//
// # What this package does not do
//
// It does not call the running legacy engines. Doing so would need the main
// platform module, and the decision module is deliberately standalone. The
// seam for that is LegacyEvaluator: a production-capture adapter implemented
// in the main module satisfies the same interface and drops into the same
// runner. See CAPTURE.md for the design.
package shadow

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// Verdict is one engine's outcome, normalized so the two are comparable.
//
// Normalization is where a differential harness usually goes wrong: normalize
// too hard and every difference disappears, too little and every run is noise.
// The rule here is that a field is normalized only where the two engines say
// the same thing in different words, and never where they might be DECIDING
// differently.
type Verdict struct {
	// Executable is the one field that decides fail-open versus fail-closed.
	// The legacy engines express it as PolicyEvaluationResult.Allowed or an
	// unblocked static result; ADR-065 expresses it as OperationalState ALLOW.
	Executable bool
	// State is the ADR-065 operational state. The legacy side reports the
	// state its behaviour is equivalent to, which the classifier checks rather
	// than trusts: legacy has no CHALLENGE, so a legacy require_approval
	// reports DENY, because that is what the running system does.
	State contract.OperationalState
	// Effects are the attributed non-authorization outcomes, each rendered as
	// "<source policy id>|<kind>". The KIND is deliberately vocabulary-
	// specific: "legacy_action:redact" on one side, "field_redact" on the
	// other. They are reconciled by the classifier's correspondence table, not
	// by pre-normalizing them into agreement here.
	Effects []string
	// ApprovalClauses is the number of outstanding approval clauses. It is
	// counted rather than attributed because contract.ApprovalRequirement
	// carries no source policy - composition merges clauses from every
	// requirement that demanded one - so per-row attribution is not available
	// from a decision and is not invented here.
	ApprovalClauses int
	// Determining names the policies that produced the outcome. The two sides
	// use different identifier spaces; SourceDetermining maps both back to
	// legacy policy ids for comparison.
	Determining []string
}

// There is deliberately no Error field. An evaluation failure on either side
// is returned from Execute as an error and stops the run; it is never folded
// into a verdict, because a verdict that can carry "we could not evaluate"
// invites a comparison in which both sides failed and were called equal.

// Canonical returns a copy with Determining sorted and duplicate-free and
// Effects sorted but NOT deduplicated.
//
// The asymmetry is deliberate. A determining set is a set: naming a policy
// twice says nothing extra. An effect set is a MULTISET: three redactions of
// three different fields are three instructions, and collapsing them let a
// compiler that dropped two of three targets correspond cleanly with a legacy
// side that demanded three. Multiplicity is part of what the enforcement point
// is told to do.
func (v Verdict) Canonical() Verdict {
	out := v
	out.Effects = sortedCopy(v.Effects)
	out.Determining = dedupeSorted(v.Determining)
	return out
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	cp := append([]string(nil), in...)
	sort.Strings(cp)
	return cp
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	cp := append([]string(nil), in...)
	sort.Strings(cp)
	out := cp[:0]
	var prev string
	for i, s := range cp {
		if i > 0 && s == prev {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return out
}

// effectSep separates an effect's source row key from its kind.
//
// Two characters, because the source is a ROW KEY that already contains a
// single "|" separating the table from the policy id. A one-character
// separator split the row key in half and every effect was attributed to a
// source called "static_policies".
const effectSep = "||"

// LegacyEffect renders one legacy action as an attributed effect.
// sourceRowKey is RowKey(table, policy_id); target is the field path a
// redaction names, empty for every other action.
func LegacyEffect(sourceRowKey string, action string, target string) string {
	if target == "" {
		return sourceRowKey + effectSep + "legacy_action:" + action
	}
	return sourceRowKey + effectSep + "legacy_action:" + action + ";target=" + target
}

// SplitKind separates an effect kind into its type token and its target, which
// is what the correspondence table compares. The type alone does not say what
// the enforcement point does: two field_redact instructions against two
// different fields are two different instructions.
func SplitKind(kind string) (typ, target string) {
	typ = kind
	if i := strings.Index(kind, ";"); i >= 0 {
		typ = kind[:i]
		for _, part := range strings.Split(kind[i+1:], ";") {
			if rest, ok := strings.CutPrefix(part, "target="); ok {
				target = rest
			}
		}
	}
	return strings.TrimPrefix(typ, "legacy_action:"), target
}

// NewEffect renders one ADR-065 obligation as an attributed effect.
//
// The TARGET and the PARAMETERS are part of the key, not decoration. An
// obligation type alone does not say what the enforcement point does: three
// field_redact obligations against three different fields are three different
// instructions, and rendering them identically let a compiler that redacted one
// field where the legacy row redacted three compare as equal.
func NewEffect(o contract.Obligation) string {
	return SourcePolicyOf(o.SourcePolicy) + effectSep + ObligationDetail(o)
}

// SplitEffect returns an effect's source row key and kind.
func SplitEffect(e string) (source, kind string) {
	i := strings.Index(e, effectSep)
	if i < 0 {
		return "", e
	}
	return e[:i], e[i+len(effectSep):]
}

// ObligationDetail renders an obligation's full parameter set, used in diff
// detail text where the type alone would not say what changed.
func ObligationDetail(o contract.Obligation) string {
	parts := []string{string(o.Type)}
	if o.Target != "" {
		parts = append(parts, "target="+o.Target)
	}
	keys := make([]string, 0, len(o.Params))
	for k := range o.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+o.Params[k])
	}
	if o.Mandatory {
		parts = append(parts, "mandatory")
	}
	return strings.Join(parts, ";")
}

// FromDecision normalizes an ADR-065 decision into a Verdict.
func FromDecision(d *contract.Decision) (Verdict, error) {
	if d == nil {
		return Verdict{}, fmt.Errorf("shadow: a nil decision cannot be normalized; an unevaluable request is an Indeterminate decision, not the absence of one")
	}
	v := Verdict{Executable: d.State.Executable(), State: d.State}
	for _, o := range d.Obligations {
		// Composition merges identical instructions: N policies demanding the
		// same transform with the same parameters compose to ONE applied
		// obligation whose SourcePolicy is the comma-joined, sorted source
		// list (contract's dedupeObligations and chooseLeastDisclosing both
		// join this way, and a compiled policy identifier cannot contain a
		// comma - sanitizePathSegment emits none). The comparison keys effects
		// per SOURCE ROW, so a composed obligation is expanded back to one
		// attributed effect per source: each of those rows demanded the
		// instruction and the instruction is applied, which is what the
		// correspondence asserts row by row. Splitting nothing loses nothing -
		// a single source round-trips - while NOT splitting attributed a
		// merged obligation to whichever source sorted first and reported
		// every other demanding row's control as missing.
		for _, src := range strings.Split(o.SourcePolicy, ",") {
			oo := o
			oo.SourcePolicy = src
			v.Effects = append(v.Effects, NewEffect(oo))
		}
	}
	if d.Approval != nil {
		v.ApprovalClauses = len(d.Approval.AllOf)
	}
	v.Determining = append(v.Determining, d.Determining.MatchedConstraints...)
	v.Determining = append(v.Determining, d.Determining.MatchedRequirement...)
	v.Determining = append(v.Determining, d.Determining.MatchedInspections...)
	// Permissions are deliberately NOT part of the determining comparison. The
	// only permission in a compiled document is the migration's own baseline,
	// which has no legacy counterpart by construction, so including it would
	// make every case differ for a reason that is not about the migration.
	return v.Canonical(), nil
}

// SourcePolicyOf recovers the legacy ROW KEY from a compiled policy identifier
// of the form legacy:<table>:<sanitised policy_id>:<plane>[:<phase>][#n].
//
// The key is (table, sanitised policy_id), and both halves matter.
//
// The TABLE, because policy_id is unique within each table and the two tables
// are independent, so a static_policies row and a dynamic_policies row can
// share one; keying on the id alone collapsed them, and exercising either
// marked both.
//
// The SANITISED id, because policy_id is VARCHAR(100) with no character
// constraint and can contain the ':' this format splits on. RowKeyFor is what
// the legacy side of the diff must use, so the two spaces agree.
func SourcePolicyOf(compiledID string) string {
	if !strings.HasPrefix(compiledID, "legacy:") {
		return compiledID
	}
	parts := strings.Split(compiledID, ":")
	if len(parts) < 3 {
		return compiledID
	}
	raw, ok := legacycompile.UnsanitizePolicyID(parts[2])
	if !ok {
		// A segment the encoding cannot have produced. Returning the encoded
		// form keeps the key distinct rather than inventing a policy id, and
		// the mismatch then surfaces as an unexercised row rather than as a
		// silent collision.
		return RowKey(parts[1], parts[2])
	}
	return RowKey(parts[1], raw)
}

// RowKeyFor renders the row key for a captured row, matching what
// SourcePolicyOf recovers from a compiled policy identifier. The key carries
// the ORIGINAL policy_id, so a diff record names the row an operator can find
// in the database.
func RowKeyFor(table, policyID string) string { return RowKey(table, policyID) }

// SourceDetermining maps a verdict's determining set back to legacy policy
// ids, sorted and duplicate-free, so the two identifier spaces compare.
func SourceDetermining(v Verdict) []string {
	out := make([]string, 0, len(v.Determining))
	for _, id := range v.Determining {
		// The migration's own baseline permission is filtered on its FULL
		// compiled identifier, before SourcePolicyOf strips it down. An
		// earlier version filtered the stripped form and a "migration" prefix,
		// which was wrong in both directions: it never matched the baseline
		// (SourcePolicyOf yields "baseline_permission"), and it would have
		// silently dropped any customer row whose policy_id happened to begin
		// with "migration" - making two different determining sets compare
		// equal.
		if id == BaselinePermissionID {
			continue
		}
		out = append(out, SourcePolicyOf(id))
	}
	return dedupeSorted(out)
}
