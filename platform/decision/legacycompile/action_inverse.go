// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// LegacyActionOf reads a compiled control back to the legacy action it
// enforces. It is the inverse of ActionPolicy and ApprovalPolicy, the one
// mapping of every action, and it lives beside them so the two cannot drift:
// TestLegacyActionOfInvertsEveryActionMapping holds every known action to a
// round trip through the mapping, and TestLegacyActionOfAgreesWithEveryShippedVariant
// holds it to the action each per-scope variant of the shipped corpus names in
// its identifier.
//
// A compiled policy carries its action only as its shape (its authority, its
// obligations and whether it is mandatory), so nothing else can answer "what
// does this control do": the corpus stores no action beside the policy.
//
// Two pairs of actions compile to one shape, and the inverse answers the first
// of each: deny reads as block, and log_only as log. category and severity are
// read from the obligation that records them (warn and log record both, allow
// records its category), and are empty for a shape that records neither
// (block, redact and require_approval).
//
// ok is false for a policy neither mapping produces: a permission, or an
// authored constraint or requirement of any other shape. Such a policy has no
// legacy action, and is named by its authority alone.
func LegacyActionOf(p pdp.Policy) (act LegacyAction, category, severity string, ok bool) {
	switch p.Authority {
	case contract.AuthorityConstraint:
		if len(p.Obligations) == 0 {
			return ActionBlock, "", "", true
		}
	case contract.AuthorityInspection:
		if len(p.Obligations) == 1 {
			ob := p.Obligations[0]
			if ob.Type == contract.ObImmutableAudit && ob.Params["observed"] == string(ActionAllow) {
				return ActionAllow, ob.Params["category"], "", true
			}
		}
	case contract.AuthorityRequirement:
		if len(p.Obligations) != 1 {
			break
		}
		ob := p.Obligations[0]
		switch ob.Type {
		case contract.ObFieldRedact:
			if p.Mandatory && ob.Mandatory {
				return ActionRedact, "", "", true
			}
		case contract.ObApprovalChallenge:
			if p.Mandatory && ob.Mandatory {
				return ActionRequireApproval, "", "", true
			}
		case contract.ObNotification:
			return ActionWarn, ob.Params["category"], ob.Params["severity"], true
		case contract.ObImmutableAudit:
			if _, observed := ob.Params["observed"]; !observed {
				return ActionLog, ob.Params["category"], ob.Params["severity"], true
			}
		}
	}
	return "", "", "", false
}
