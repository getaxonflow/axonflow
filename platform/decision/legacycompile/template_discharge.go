// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// A TEMPLATE REDACTION IS BOUND WHERE A SCOPE CAN CARRY IT OUT (#4131).
//
// #4046 splits a SYSTEM row by what each plane's legacy engine resolves. The
// organization template's redact rows resolve redact on every phase - their
// phase columns are NULL, and legacy_resolution.tsv resolves NULL to redact for
// the PII and compliance categories they carry - so that rule finds nothing to
// split, and each would bind a mandatory field_redact on every scope that admits
// it. That includes scopes that can neither discharge the obligation themselves
// nor hand it to a caller: /api/request and the OpenAI-compatible route forward
// the request or refuse it and tell their caller no obligation, so there the
// engine refuses every request the control matches (unsupported_obligation,
// ADR-065 invariant 8). The system corpus never meets the case, because its PII
// rows store warn on the request phase.
//
// So a template row whose compiled policy carries a mandatory field_redact is
// split by DISCHARGE, in #4046's shape (CorpusVariantIDFor and scope bindings):
// the redact policy is bound to every scope that can carry a redaction out, and
// a warn policy - ActionPolicy's own warn, the action the system corpus's PII
// controls take on the request scopes - to every scope that cannot.
//
// A scope carries it out when registry.DischargeSurface says so: its plane's
// registered profile supports the capability (registry/legacy_plane_peps.tsv),
// or its wire hands the obligation to an enforcement point that declares it
// (scopeDeliveries). That is the same surface activation's discharge guard
// reads, so the split and the guard ask one question of one model. It is read
// per edition and the corpus is one artifact for both, so a scope whose
// editions would answer differently is refused rather than resolved one way.

// scopeDeliveries is, per enforcement scope, the capabilities the scope's wire
// hands to an enforcement point that declares them, and it is the one statement
// of that. platform/agent's enforcingSeams (decision_enforcing_seam.go) and both
// authoring dry runs read it through ScopeDeliveries; the agent's
// TestEverySeamDeliversWhatScopeDeliveriesStates holds every seam to it by
// value, and TestNoSecondStatementOfWhatAScopesWireDelivers refuses a dry run
// or seam that spells the Decision API's vocabulary out again.
var scopeDeliveries = map[string][]contract.Capability{
	"decide":          contract.DecisionWireCapabilities(),
	"gateway_request": contract.DecisionWireCapabilities(),
}

// ScopeDeliveries is what scope's wire hands to an enforcement point that
// declares it, as a copy.
func ScopeDeliveries(scope EnforcementScope) []contract.Capability {
	return append([]contract.Capability(nil), scopeDeliveries[scope.String()]...)
}

// fieldRedactCapability is the capability a template redaction needs.
var fieldRedactCapability = contract.Capability{Type: contract.ObFieldRedact, Version: 1}

// ScopeDischarges reports whether scope can carry out an obligation needing
// capability c, on every edition its plane exists in.
func ScopeDischarges(scope EnforcementScope, c contract.Capability) (bool, error) {
	rows, err := registry.ParseLegacyPlanes(registry.LegacyPlaneFile)
	if err != nil {
		return false, err
	}
	return scopeDischarges(rows, ScopeDeliveries(scope), scope, c)
}

func scopeDischarges(rows []registry.LegacyPlaneRow, delivers []contract.Capability, scope EnforcementScope, c contract.Capability) (bool, error) {
	answers := map[registry.Edition]bool{}
	for _, r := range rows {
		if r.Plane != string(scope.Plane) {
			continue
		}
		surface := registry.NewDischargeSurface(&contract.PEPProfile{ID: r.PEPID(), Capabilities: r.Capabilities}, delivers, r.Edition)
		answers[r.Edition] = surface.Discharges(contract.Obligation{Type: c.Type, SchemaVersion: c.Version})
	}
	if len(answers) == 0 {
		return false, fmt.Errorf("legacycompile: plane %q has no row in the legacy plane profiles, so whether %s can discharge %s cannot be derived", scope.Plane, scope, c)
	}
	editions := make([]string, 0, len(answers))
	for e := range answers {
		editions = append(editions, e.String())
	}
	sort.Strings(editions)
	var got []bool
	for _, e := range editions {
		for ed, ok := range answers {
			if ed.String() == e {
				got = append(got, ok)
			}
		}
	}
	for _, ok := range got[1:] {
		if ok != got[0] {
			return false, fmt.Errorf("legacycompile: %s discharges %s on some editions (%v) and not others; the corpus is one artifact for every edition, so it cannot bind a template redaction there", scope, c, answers)
		}
	}
	return got[0], nil
}

// splitTemplateRedactionByDischarge is corpusPolicyFor's last step for a
// template row: see the comment at the top of this file. policies is the row's
// collapsed compilation; a row none of whose policies carries a mandatory
// field_redact, or whose every scope can discharge one, is returned unchanged.
func splitTemplateRedactionByDischarge(table, id string, rec Record, winner *PlaneResult, policies []pdp.Policy, bindings map[string][]string, divs []Divergence, opts CorpusOptions) ([]pdp.Policy, map[string][]string, []Divergence, error) {
	redacting := 0
	for _, p := range policies {
		if carriesMandatoryFieldRedact(p) {
			redacting++
		}
	}
	if redacting == 0 {
		return policies, bindings, divs, nil
	}
	if redacting != len(policies) {
		return nil, nil, nil, fmt.Errorf("legacycompile: template row %s %s compiled to %d policies and %d carry a mandatory field_redact; a discharge split of some parts and not others would bind one row two ways", table, id, len(policies), redacting)
	}
	var redactScopes, warnScopes []string
	for _, s := range AllScopes() {
		ok, err := ScopeDischarges(s, fieldRedactCapability)
		if err != nil {
			return nil, nil, nil, err
		}
		if ok {
			redactScopes = append(redactScopes, s.String())
		} else {
			warnScopes = append(warnScopes, s.String())
		}
	}
	if len(warnScopes) == 0 {
		return policies, bindings, divs, nil
	}
	sort.Strings(redactScopes)
	sort.Strings(warnScopes)
	category, severity, ok := capturedCategoryAndSeverity(opts.Rows, table, rec.Source.OrgScope, id)
	if !ok {
		return nil, nil, nil, fmt.Errorf("legacycompile: template row %s %s is split by discharge and its warn half is compiled from its category and severity, which no captured row carries", table, id)
	}
	out := make([]pdp.Policy, 0, 2*len(policies))
	for i, p := range policies {
		suffix := ""
		if len(policies) > 1 {
			suffix = fmt.Sprintf("#%d", i+1)
		}
		redact := p
		redact.ID = CorpusVariantIDFor(table, id, string(ActionRedact)) + suffix
		redact.Obligations = append([]contract.Obligation(nil), p.Obligations...)
		for j := range redact.Obligations {
			redact.Obligations[j].SourcePolicy = redact.ID
		}
		redact.Description = fmt.Sprintf("the redaction, bound to the scopes that can carry one out (%s) (#4131). %s", strings.Join(redactScopes, ", "), p.Description)
		base := pdp.Policy{
			ID: CorpusVariantIDFor(table, id, string(ActionWarn)) + suffix, Name: p.Name, Root: p.Root,
			Scope: p.Scope, Actions: p.Actions, ResourceScope: p.ResourceScope, Where: p.Where, Unless: p.Unless,
			Description: fmt.Sprintf("the warn half of %s %s, bound to the scopes that can neither discharge a field_redact nor hand one to a caller (%s): "+
				"there a mandatory redaction would refuse every request the control matches (#4131). %s", table, id, strings.Join(warnScopes, ", "), p.Description),
		}
		warn, reasons := ActionPolicy(base, ActionWarn, category, severity, opts.ContentTarget, winner.Plane)
		if warn == nil {
			return nil, nil, nil, fmt.Errorf("legacycompile: the warn half of template row %s %s does not compile: %v", table, id, reasons)
		}
		for _, v := range []*pdp.Policy{&redact, warn} {
			if class, control := pdp.DeriveAssurance(*v); control {
				v.Assurance = class
			}
		}
		out = append(out, redact, *warn)
		bindings[redact.ID] = append([]string(nil), redactScopes...)
		bindings[warn.ID] = append([]string(nil), warnScopes...)
	}
	divs = append(divs, Divergence{
		PolicyID: id, Table: table, Kind: DivergenceRedactionBoundByDischarge,
		Detail: fmt.Sprintf("the template row compiles to a mandatory redaction on every scope; it is bound as redact on the scopes that can carry "+
			"one out (%s) and as warn on the scopes that cannot (%s), where a mandatory redaction would refuse every request it matches",
			strings.Join(redactScopes, ", "), strings.Join(warnScopes, ", ")),
	})
	return out, bindings, divs, nil
}

// carriesMandatoryFieldRedact reports whether p carries a mandatory field_redact.
func carriesMandatoryFieldRedact(p pdp.Policy) bool {
	for _, o := range p.Obligations {
		if o.Type == contract.ObFieldRedact && o.Mandatory {
			return true
		}
	}
	return false
}

// capturedCategoryAndSeverity reads a captured row's category and severity.
func capturedCategoryAndSeverity(rows []RawRow, table, orgScope, policyID string) (string, string, bool) {
	for _, r := range rows {
		if r.Table == table && r.OrgScope == orgScope && r.stringOr("policy_id", "") == policyID {
			return r.stringOr("category", ""), r.stringOr("severity", ""), true
		}
	}
	return "", "", false
}
