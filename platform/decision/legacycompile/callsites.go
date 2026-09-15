// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	_ "embed"
	"fmt"
	"strings"
)

// legacyCallSitesTSV is the call-site census, embedded so that a guard in
// another module reads the SAME bytes this package's own census tests read.
//
//go:embed legacy_call_sites.tsv
var legacyCallSitesTSV string

// callSiteColumns is the census header, in order. A reordered column would
// silently key a guard on the wrong field, so the reader refuses anything else.
var callSiteColumns = []string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition", "default_posture", "gate"}

// Legacy evaluators named by the census. The set is CLOSED: a new evaluator is
// a new way of reaching policy, and classifying it as static or dynamic is a
// decision somebody has to make rather than a default.
const (
	EvaluatorRequest         = "EvaluateRequest"
	EvaluatorResponse        = "EvaluateResponse"
	EvaluatorDynamicPolicies = "EvaluateDynamicPolicies"
	// EvaluatorDynamicFacts is the dynamic condition matcher running as a fact
	// producer (PRD v11 §1.2 ruling R2, #4254): the entry point a plane that
	// decides on the anchored engine calls for the facts its dynamic rows read.
	// Its substrate is dynamic; it has no phase and is not static.
	EvaluatorDynamicFacts = "Produce"
)

// CallSite is one row of legacy_call_sites.tsv: a function that reaches a
// legacy evaluator on behalf of a plane.
type CallSite struct {
	Plane     Plane
	Evaluator string
	// File is the repository-relative source file, as the census writes it.
	File     string
	Function string
}

// StaticEvaluator reports whether the site evaluates the STATIC substrate - the
// only one a category filter narrows. (EvaluatePolicy, the tier engine's
// static and unfiltered evaluator, was deleted by #4253.)
func (c CallSite) StaticEvaluator() bool {
	switch c.Evaluator {
	case EvaluatorRequest, EvaluatorResponse:
		return true
	}
	return false
}

// Key is the site's identity as the census names it: plane|evaluator|function.
func (c CallSite) Key() string {
	return string(c.Plane) + "|" + c.Evaluator + "|" + c.Function
}

// Phase is the legacy phase the site's evaluator loads (#3564). EvaluateRequest
// runs on the request; EvaluateResponse
// loads PhaseResponse rows whatever it is handed. The dynamic evaluator has no
// phase.
func (c CallSite) Phase() Phase {
	switch c.Evaluator {
	case EvaluatorRequest:
		return PhaseRequest
	case EvaluatorResponse:
		return PhaseResponse
	}
	return ""
}

// CallSites parses the embedded census (#3895 PR-A2).
//
// It exists for the category-admission welds in platform/agent and
// platform/orchestrator, which must key on the SAME census the plane model is
// pinned to rather than on a second list of call sites. It refuses a header,
// a row width, a plane or an evaluator it does not recognise, because a
// guard reading a census it misparsed reports a clean sweep over nothing.
func CallSites() ([]CallSite, error) {
	return parseCallSites(legacyCallSitesTSV)
}

// parseCallSites is CallSites over any source.
//
// It is separate because the refusals are the reader's whole value and none of
// them is reachable against the embedded census, which is well formed. A
// refusal no caller can hand a malformed source is a branch nobody knows still
// works, and a reader whose refusals quietly stopped firing reports a clean
// sweep over whatever it misparsed.
func parseCallSites(src string) ([]CallSite, error) {
	lines := strings.Split(strings.TrimRight(src, "\n"), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("legacycompile: legacy_call_sites.tsv holds no call site; an empty census supports any model at all")
	}
	if got := strings.Split(lines[0], "\t"); strings.Join(got, "\t") != strings.Join(callSiteColumns, "\t") {
		return nil, fmt.Errorf("legacycompile: legacy_call_sites.tsv header is %v, want %v", got, callSiteColumns)
	}
	out := make([]CallSite, 0, len(lines)-1)
	for i, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != len(callSiteColumns) {
			return nil, fmt.Errorf("legacycompile: legacy_call_sites.tsv line %d has %d fields, want %d", i+2, len(f), len(callSiteColumns))
		}
		site := CallSite{Plane: Plane(f[0]), Evaluator: f[1], File: f[2], Function: f[3]}
		if _, err := SpecFor(site.Plane); err != nil {
			return nil, fmt.Errorf("legacycompile: legacy_call_sites.tsv line %d names plane %q, which the model does not declare: %w", i+2, f[0], err)
		}
		switch site.Evaluator {
		case EvaluatorRequest, EvaluatorResponse, EvaluatorDynamicPolicies, EvaluatorDynamicFacts:
		default:
			return nil, fmt.Errorf("legacycompile: legacy_call_sites.tsv line %d names evaluator %q, which is not a declared legacy evaluator", i+2, f[1])
		}
		out = append(out, site)
	}
	return out, nil
}
