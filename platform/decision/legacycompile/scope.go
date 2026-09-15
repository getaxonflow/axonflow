// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"sort"
)

// EnforcementScope is the unit an enforcing seam cuts over: a plane and, on a
// plane that evaluates two legacy phases, ONE of them (#3564).
//
// # WHY A PLANE IS NOT ALWAYS THE UNIT
//
// A plane enforces a restriction of the shipped corpus, and the restriction is
// derived from what the plane's call sites load and evaluate. On a plane with
// two phases those are two different things. MEASURED on `mcp`: its request
// pass binds 66 of the 118 shipped policies and its response pass binds 27. The
// response pass never loads `sys_pii_indonesia_ktp` (seeded phase='request')
// and its call sites never pass `security-sqli`, so an engine activated from
// the plane-wide restriction would read those controls UNKNOWN on every
// response and answer ERROR. Two phases are two restrictions wearing one plane
// name, so a seam cuts over a scope and a registration names one.
//
// A plane that evaluates one phase, or the dynamic substrate (which has no
// phase), is named by the plane alone: its Phase is empty, so `decide` stays
// `decide` in every place a scope is rendered.
type EnforcementScope struct {
	Plane Plane
	// Phase is empty unless the plane evaluates more than one phase.
	Phase Phase
}

// ScopeFor validates a scope and returns it in canonical form.
//
// A phase named on a single-phase plane is accepted when it is that phase and
// canonicalised away; a two-phase plane refuses an empty phase, because either
// answer would be a restriction the other pass cannot enforce.
func ScopeFor(p Plane, ph Phase) (EnforcementScope, error) {
	spec, err := SpecFor(p)
	if err != nil {
		return EnforcementScope{}, err
	}
	if len(spec.Phases) < 2 {
		if ph != "" && (len(spec.Phases) == 0 || spec.Phases[0] != ph) {
			return EnforcementScope{}, fmt.Errorf("legacycompile: plane %q evaluates phases %v, so it has no %q scope", p, spec.Phases, ph)
		}
		return EnforcementScope{Plane: p}, nil
	}
	if ph == "" {
		return EnforcementScope{}, fmt.Errorf("legacycompile: plane %q evaluates phases %v, and each is its own restriction; name one", p, spec.Phases)
	}
	if !spec.EvaluatesPhase(ph) {
		return EnforcementScope{}, fmt.Errorf("legacycompile: plane %q evaluates phases %v, so it has no %q scope", p, spec.Phases, ph)
	}
	return EnforcementScope{Plane: p, Phase: ph}, nil
}

// MustScopeFor is ScopeFor for a scope the caller states as a constant.
func MustScopeFor(p Plane, ph Phase) EnforcementScope {
	s, err := ScopeFor(p, ph)
	if err != nil {
		panic(err)
	}
	return s
}

// String renders the scope as `plane` or `plane:phase`.
func (s EnforcementScope) String() string {
	if s.Phase == "" {
		return string(s.Plane)
	}
	return string(s.Plane) + ":" + string(s.Phase)
}

// Phases are the legacy phases this scope evaluates: the named one, or every
// phase of a plane named alone.
func (s EnforcementScope) Phases() []Phase {
	if s.Phase != "" {
		return []Phase{s.Phase}
	}
	return append([]Phase(nil), MustSpecFor(s.Plane).Phases...)
}

// ContentPhase is the phase whose content DefaultContentTarget names on this
// scope (#4046): the content the scope evaluated, so a redaction of it is
// fulfilled on that phase. It is the named phase, or the single phase of a
// plane named alone, and empty for a plane that evaluates no legacy phase.
//
// This is the per-(plane, phase) half of the content target. The shipped
// corpus targets the evaluated content once for every scope, and the scope
// decides where that content lives - so `decide` asks its caller to mask the
// request, and the MCP response pass masks what it releases.
func (s EnforcementScope) ContentPhase() Phase {
	if s.Phase != "" {
		return s.Phase
	}
	if phases := MustSpecFor(s.Plane).Phases; len(phases) == 1 {
		return phases[0]
	}
	return ""
}

// AllScopes returns every declared scope in a stable order.
func AllScopes() []EnforcementScope {
	var out []EnforcementScope
	for _, p := range AllPlanes() {
		spec := MustSpecFor(p)
		if len(spec.Phases) < 2 {
			out = append(out, EnforcementScope{Plane: p})
			continue
		}
		for _, ph := range spec.Phases {
			out = append(out, EnforcementScope{Plane: p, Phase: ph})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
