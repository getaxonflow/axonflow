// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE TWO CORPUS GUARDS THAT MUST HOLD ON EVERY TIER (#3884, #3323)
//
// The corpus artifact is regenerated against a migrated database, and every
// check that compares it with that database runs on a tier that does not fire
// on a pull_request. Two properties must not wait for that tier, because the
// failure they describe is silent in the artifact's own terms:
//
//  1. A SUPERSESSION DECISION WHOSE PRECONDITION IS FALSE. The ledger records
//     what the platform decided to do with each pre-canonical row; this checks
//     the decision against the actions the census holds to the database, using
//     the ranking the corpus collapse already declares. It lives here, not in
//     the registry, because this is where that ranking lives.
//
//  2. A CENSUS ROW WHOSE ENABLED STATE THE CORPUS DOES NOT REFLECT. An enabled
//     row with no policy is a shipped control that stopped existing - which is
//     what deleting one of the five stronger superseded rows looks like from
//     here. A disabled row WITH a policy is a control switched on by the
//     migration, which none of the nine disabled integration seeds may be.
//
// Both are called by BuildCorpus, so a regeneration cannot produce an artifact
// that violates them, and by tests over the checked-in artifact, so a hand edit
// or a stale artifact cannot either.

// CheckSupersessionDecisions holds every ledger decision to its precondition.
//
// keep_both claims the pre-canonical row enforces MORE than at least one of its
// superseders; drop_superseded claims it enforces more than none of them. Each
// is checked over the census's stored actions with corpusRestrictiveness, the
// ranking the corpus collapse declares. An action that ranking cannot place is
// a refusal, not a default.
//
// A drop that passes here has passed its STRENGTH ground only. Whether the
// pre-canonical pattern matches inputs no superseder matches is not derivable
// (see registry/supersession.go), so it is not what this function certifies.
func CheckSupersessionDecisions(ledger []registry.SupersessionRow, census []registry.CensusRow) error {
	if len(ledger) == 0 || len(census) == 0 {
		return fmt.Errorf("legacycompile: the supersession decision check was handed %d ledger row(s) and %d census row(s); a comparison with an empty side proves nothing",
			len(ledger), len(census))
	}
	action := map[string]string{}
	for _, c := range census {
		action[c.PolicyID] = c.LegacyAction
	}
	var problems []string
	for _, l := range ledger {
		if len(l.SupersededBy) == 0 {
			continue
		}
		rank, _, ok := corpusRestrictiveness(action[l.PolicyID])
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: stored action %q cannot be ranked, so decision %s cannot be checked", l.PolicyID, action[l.PolicyID], l.Decision))
			continue
		}
		var outranked []string
		unranked := false
		for _, s := range l.SupersededBy {
			sRank, _, ok := corpusRestrictiveness(action[s])
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: superseder %s's stored action %q cannot be ranked, so decision %s cannot be checked", l.PolicyID, s, action[s], l.Decision))
				unranked = true
				continue
			}
			if rank > sRank {
				outranked = append(outranked, fmt.Sprintf("%s (%s)", s, action[s]))
			}
		}
		if unranked {
			continue
		}
		switch l.Decision {
		case registry.SupersessionKeepBoth:
			if len(outranked) == 0 {
				problems = append(problems, fmt.Sprintf("%s is decided keep_both on the ground that it enforces more than a superseder, and its action %q outranks none of %v. The ground is gone: restate the decision",
					l.PolicyID, action[l.PolicyID], l.SupersededBy))
			}
		case registry.SupersessionDropSuperseded:
			if len(outranked) > 0 {
				problems = append(problems, fmt.Sprintf("%s is decided drop_superseded and its action %q outranks %s; removing it LOWERS enforcement on every input the two share",
					l.PolicyID, action[l.PolicyID], strings.Join(outranked, ", ")))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("legacycompile: %d supersession decision(s) do not hold:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// CheckCorpusRepresentsTheCensus holds the corpus to every census row's
// enabled state, in both directions and on both documents.
//
//   - An ENABLED row carries at least one policy, in the document its tier
//     selects - system tier on the system root, everything else in the
//     organization template - and none in the other.
//   - A DISABLED row carries no policy in either document, and a
//     row_not_represented divergence whose compiler reasons name the legacy
//     readers' own predicate, so the absence is declared as the switch-off it
//     is rather than as a gap.
func CheckCorpusRepresentsTheCensus(c *Corpus, census []registry.CensusRow) error {
	if c == nil || c.System == nil || c.OrganizationTemplate == nil {
		return fmt.Errorf("legacycompile: the corpus representation check was handed an incomplete corpus")
	}
	if len(census) == 0 {
		return fmt.Errorf("legacycompile: the corpus representation check was handed no census; it would compare nothing")
	}
	count := func(doc *pdp.Document) map[string]int {
		out := map[string]int{}
		for _, p := range doc.Policies {
			// Keyed on the CONTROL, so a split control's per-scope variants and a
			// multi-policy row's "#n" siblings count for the row they came from.
			control, _, ok := CorpusControlOf(p.ID)
			if !ok {
				control = p.ID
			}
			out[control]++
		}
		return out
	}
	inSystem, inTemplate := count(c.System), count(c.OrganizationTemplate)
	declaredOff := map[string]bool{}
	excluded := string(ReasonExcludedByLegacyPredicate) + ":"
	for _, d := range c.Divergences {
		if d.Kind != DivergenceRowNotRepresented || d.Table != "static_policies" {
			continue
		}
		for _, r := range d.CompilerReasons {
			if strings.HasPrefix(r, excluded) {
				declaredOff[d.PolicyID] = true
			}
		}
	}

	var problems []string
	for _, r := range census {
		key := CorpusPolicyIDFor("static_policies", r.PolicyID)
		own, other, ownName, otherName := inTemplate[key], inSystem[key], "organization template", "system document"
		if r.SystemTier() {
			own, other, ownName, otherName = inSystem[key], inTemplate[key], "system document", "organization template"
		}
		switch {
		case r.Enabled && own == 0:
			problems = append(problems, fmt.Sprintf("%s is enabled in the census (tier %s) and the %s carries no policy for it: a shipped control that stopped existing", r.PolicyID, r.Tier, ownName))
		case r.Enabled && other > 0:
			problems = append(problems, fmt.Sprintf("%s is enabled in the census (tier %s) and the %s carries %d policy(ies) for it; its tier puts it in the %s only", r.PolicyID, r.Tier, otherName, other, ownName))
		case !r.Enabled && own+other > 0:
			problems = append(problems, fmt.Sprintf("%s is DISABLED in the census and the corpus carries %d policy(ies) for it: the migration would switch on a control the legacy readers' own predicate excludes", r.PolicyID, own+other))
		case !r.Enabled && !declaredOff[r.PolicyID]:
			problems = append(problems, fmt.Sprintf("%s is disabled in the census and the corpus declares no row_not_represented divergence naming %s; its absence would read as a gap rather than as a switch-off", r.PolicyID, ReasonExcludedByLegacyPredicate))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("legacycompile: the corpus does not represent the census in %d way(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}
