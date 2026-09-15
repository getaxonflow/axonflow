// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

// THE CONTENT-REDACTION HELPERS: how a pass that masks the content it evaluated
// names what a permit's field_redact requires it to mask, and which targets name
// that content.

import (
	"errors"
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	sharedpolicy "axonflow/platform/shared/policy"
)

// DischargesAsResponseContent reports whether a field_redact target names the
// content this pass evaluated, which it discharges by masking. That is the
// evaluated-content target every scope's compilation uses, and response.content:
// on the response pass the response IS the evaluated content, and it was the
// compiled target before #4046, so a document published against that template
// keeps being masked rather than turning into a withheld response.
func DischargesAsResponseContent(target string) bool {
	return target == legacycompile.DefaultContentTarget || target == ResponseContentTarget
}

// ResponseContentTarget is the response content's attribute path.
const ResponseContentTarget = "response.content"

// ContentRedactionPolicies names the shared engine's detectors whose matches a
// permit's redactions require masking, on a pass that masks the content it
// evaluated itself: the response pass masks what it releases, and the MCP
// request pass the statement it hands back. discharges says which field_redact
// targets name that content; pass names the pass in a refusal.
//
// immutable_audit is discharged by the pass's own audit row. A field_redact on
// the evaluated content is discharged by masking - through the detectors behind
// the requirements that attached it, read off the decision's determining
// requirements and the policies the engine activated. Any other mandatory
// obligation, or a field_redact on a target this pass does not hold, is
// UNSUPPORTED and refuses: releasing the content without anyone discharging
// what the policy required is the fail-open ADR-065 invariant 8 forbids. An
// ADVISORY obligation - the disclosure an inspection policy attaches - demands
// nothing: an advisory control cannot deny, so it is neither discharged nor
// refused. An error is a redaction the pass cannot name a detector for.
func ContentRedactionPolicies(dec *contract.Decision, activated func(id string) (pdp.Policy, bool), observation *sharedpolicy.Observation,
	pass string, discharges func(target string) bool) ([]string, string, error) {
	redacts := false
	for _, o := range dec.Obligations {
		switch {
		case !o.Mandatory:
		case o.Type == contract.ObImmutableAudit:
		case o.Type == contract.ObFieldRedact && discharges(o.Target):
			redacts = true
		default:
			return nil, fmt.Sprintf("%s: the mandatory %s obligation on %q attached by %s cannot be discharged on %s",
				contract.ReasonUnsupportedObligation, o.Type, o.Target, o.SourcePolicy, pass), nil
		}
	}
	if !redacts {
		return nil, "", nil
	}
	matched := map[string]string{}
	if observation != nil {
		for _, row := range observation.Rows {
			if row.Ran && row.Matched {
				matched[registry.DetectorID(row.PolicyID).SignalPath()] = row.PolicyID
			}
		}
	}
	seen := map[string]bool{}
	var ids []string
	for _, id := range dec.Determining.MatchedRequirement {
		if activated == nil {
			return nil, "", fmt.Errorf("the decision names requirement %s and no activated engine was supplied to read it from", id)
		}
		p, ok := activated(id)
		if !ok {
			return nil, "", fmt.Errorf("the decision names requirement %s, which the activated engine does not hold", id)
		}
		if !RedactsContent(p, discharges) {
			continue
		}
		named := false
		for _, path := range p.ReferencedPaths() {
			if policyID, ok := matched[path]; ok {
				named = true
				if !seen[policyID] {
					seen[policyID] = true
					ids = append(ids, policyID)
				}
			}
		}
		if !named {
			return nil, "", fmt.Errorf("requirement %s demands a redaction of the response content and names no detector this pass ran and matched, so nothing can be masked for it", id)
		}
	}
	if len(ids) == 0 {
		return nil, "", errors.New("the decision composed a redaction of the response content and none of its determining requirements attaches one")
	}
	sort.Strings(ids)
	return ids, "", nil
}

// RedactsContent reports whether a requirement attaches a field_redact a pass
// discharges by masking, on the same targets the obligation check in
// ContentRedactionPolicies accepts: a redaction counted as discharged there and
// skipped here would be released unmasked.
func RedactsContent(p pdp.Policy, discharges func(target string) bool) bool {
	for _, o := range p.Obligations {
		if o.Type == contract.ObFieldRedact && discharges(o.Target) {
			return true
		}
	}
	return false
}
