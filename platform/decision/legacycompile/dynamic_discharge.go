// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// A DYNAMIC REDACTION SHIPS AS A WARN WHERE NO SCOPE CAN CARRY IT OUT (#4254).
//
// A dynamic_policies row's redact action compiles to a mandatory field_redact
// (dynamicPolicyFor), and the corpus policy binds by substrate on every plane
// that reads dynamic_policies: wcp, map, policy_simulation and policy_test. None
// of them can carry a redaction out. No plane profile among them registers
// field_redact@1 (registry/legacy_plane_peps.tsv), and no wire among them hands
// one to a caller (scopeDeliveries). So activation's discharge guard refuses the
// whole scope rather than build an engine that would deny every request the
// control matches as unsupported_obligation, a verdict the legacy engine never
// gave, and neither orchestrator plane could be decided by the engine at all.
//
// #4131's template split does not fit. It binds a template row's redaction where
// a scope CAN carry it out and a warn where it cannot, under new variant ids. A
// dynamic redaction has no scope of the first kind, so that split would bind
// nothing as redact and rename every control. So the policy keeps its id and
// ships as the dynamic substrate's own warn, the requirement carrying one
// notification a dynamic `warn` action compiles to, on every scope it binds on.
// The row declares DivergenceDynamicRedactionShipsAsWarn, naming the fields it
// no longer masks and the scopes it binds on.
//
// The question is asked of the surface activation's guard reads
// (ScopeDischarges), so the rule and the guard cannot disagree. A dynamic
// redaction that some scope could carry out is refused rather than split:
// nothing in the model produces one, and binding it one way would be a decision
// this rule has no measurement for.

// dynamicNotificationSeverity is the severity a dynamic alert or warn records
// when its action names none.
const dynamicNotificationSeverity = "medium"

// dynamicNotificationPolicy is the dynamic substrate's alert and warn arm: base
// as a requirement carrying one notification of kind, at severity, on channel,
// sourced from base itself. dynamicPolicyFor compiles a dynamic alert or warn
// action through it, and a dynamic redaction that ships as a warn is compiled
// through it too, so there is one shape of a dynamic warn and not two.
func dynamicNotificationPolicy(base pdp.Policy, kind, severity, channel string) *pdp.Policy {
	base.Authority = contract.AuthorityRequirement
	base.Obligations = []contract.Obligation{{
		Type: contract.ObNotification,
		Params: map[string]string{
			"kind":     kind,
			"severity": severity,
			"channel":  channel,
		},
		SourcePolicy: base.ID, SchemaVersion: 1,
	}}
	return &base
}

// shipDynamicRedactionAsWarn is corpusPolicyFor's last step for a dynamic row:
// see the comment at the top of this file. policies is the row's collapsed
// compilation and bindings its scope bindings; a policy carrying no mandatory
// field_redact is returned unchanged.
func shipDynamicRedactionAsWarn(table, id string, policies []pdp.Policy, bindings map[string][]string, divs []Divergence) ([]pdp.Policy, map[string][]string, []Divergence, error) {
	out := make([]pdp.Policy, 0, len(policies))
	for _, p := range policies {
		if !carriesMandatoryFieldRedact(p) {
			out = append(out, p)
			continue
		}
		var fields []string
		for _, o := range p.Obligations {
			if o.Type != contract.ObFieldRedact {
				return nil, nil, nil, fmt.Errorf("legacycompile: dynamic row %s %s compiles %s to a mandatory field_redact beside an obligation of type %s; "+
					"shipping the redaction as a warn would drop that obligation too, so the build refuses", table, id, p.ID, o.Type)
			}
			fields = append(fields, o.Target)
		}
		sort.Strings(fields)
		scopes, err := dynamicPolicyScopes(p.ID, bindings)
		if err != nil {
			return nil, nil, nil, err
		}
		names := make([]string, 0, len(scopes))
		var discharging []string
		for _, s := range scopes {
			ok, err := ScopeDischarges(s, fieldRedactCapability)
			if err != nil {
				return nil, nil, nil, err
			}
			names = append(names, s.String())
			if ok {
				discharging = append(discharging, s.String())
			}
		}
		if len(discharging) > 0 {
			return nil, nil, nil, fmt.Errorf("legacycompile: dynamic row %s %s compiles %s to a mandatory field_redact and %s can carry it out; "+
				"a dynamic redaction ships as a warn only where no scope it binds on can, so the build refuses rather than bind it one way",
				table, id, p.ID, strings.Join(discharging, ", "))
		}
		base := p
		base.Mandatory = false
		base.Assurance = ""
		base.Description = fmt.Sprintf("the warn this dynamic redaction ships as, on scopes none of which can carry a redaction out (%s): "+
			"there a mandatory field_redact would refuse every request the control matches (#4254). %s", strings.Join(names, ", "), p.Description)
		warn := dynamicNotificationPolicy(base, "warn", dynamicNotificationSeverity, "")
		if class, control := pdp.DeriveAssurance(*warn); control {
			warn.Assurance = class
		}
		out = append(out, *warn)
		divs = append(divs, Divergence{
			PolicyID: id, Table: table, Kind: DivergenceDynamicRedactionShipsAsWarn, Fields: fields,
			Detail: fmt.Sprintf("%s compiles to a mandatory redaction of %s, and no scope it binds on (%s) can carry one out, "+
				"so it ships as a warn under the same id and masks nothing", p.ID, strings.Join(fields, ", "), strings.Join(names, ", ")),
		})
	}
	return out, bindings, divs, nil
}

// dynamicPolicyScopes is every scope a dynamic row's corpus policy binds on: its
// explicit bindings where a split gave it some, and otherwise every scope of
// every plane that reads dynamic_policies, which is where activation's
// substrate arm keeps an unbound one.
func dynamicPolicyScopes(policyID string, bindings map[string][]string) ([]EnforcementScope, error) {
	all := AllScopes()
	if bound, ok := bindings[policyID]; ok {
		out := make([]EnforcementScope, 0, len(bound))
		for _, name := range bound {
			found := false
			for _, s := range all {
				if s.String() == name {
					out = append(out, s)
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("legacycompile: %s is bound to %q, which is not a declared enforcement scope", policyID, name)
			}
		}
		return out, nil
	}
	dynamic := map[Plane]bool{}
	for _, p := range PlanesFor(SubstrateDynamic) {
		dynamic[p] = true
	}
	var out []EnforcementScope
	for _, s := range all {
		if dynamic[s.Plane] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("legacycompile: no declared scope reads dynamic_policies, so %s binds nowhere", policyID)
	}
	return out, nil
}
