package legacycompile

import (
	"fmt"
	"sort"
)

// Plane is one enforcement plane. ADR-065 Phase 4 cuts these over
// independently, so compilation, diffing and the gate are all per-plane: a
// plane whose diffs are clean can move while another is still red.
type Plane string

const (
	// PlaneDecide is the agent's /api/v1/decide surface. It reaches
	// evaluateInputPolicies with runDynamicPolicy=false, so it evaluates the
	// STATIC substrate only - an earlier version of this model gave it the
	// dynamic substrate too, which was simply wrong.
	PlaneDecide Plane = "decide"
	// PlaneGatewayRequest is the gateway pre-check.
	PlaneGatewayRequest Plane = "gateway_request"
	// PlaneMCP is the MCP tool plane: an input pass, an input-redaction pass
	// and an output pass.
	PlaneMCP Plane = "mcp"
	// PlaneOpenAICompatible is the OpenAI-compatible surface.
	PlaneOpenAICompatible Plane = "openai_compatible"
	// PlaneProxyRequest is the proxy plane's PHASE 1: the shared static engine
	// over the request, in clientRequestHandler.
	PlaneProxyRequest Plane = "proxy_request"
	// PlaneProxyTier is the proxy plane's PHASE 2 tier engine, in the same
	// handler. It is the ONLY plane that reads static_policies.action, through
	// StaticPolicyRepository.GetEffective, and the only static plane that does
	// not pass EvalOptions.ActionOverrides.
	PlaneProxyTier Plane = "proxy_tier"
	// PlaneOrchestratorResponse is the orchestrator's response plane: the
	// response processor and the PII detector, both over the shared static
	// engine. It is reached from processRequestHandler, the /api/v1/process
	// handler - NOT, as a stale doc comment in the response processor claims,
	// from the gateway or MAP.
	PlaneOrchestratorResponse Plane = "orchestrator_response"
	// PlaneCoworkIngest is the cowork OTEL ingest storage plane. It evaluates
	// static_policies in the response phase like the others, but builds its own
	// override map coercing every enabled PII category to redact, so a
	// warn/log/block deployment still masks before store.
	PlaneCoworkIngest Plane = "cowork_ingest"
	// PlaneWCP is the workflow control plane: the step gate, the plan executor
	// and the orchestrator's own request handler, all over the dynamic engine.
	PlaneWCP Plane = "wcp"
	// PlaneMAP is the multi-agent plane, reached through map_hitl_adapter. It
	// evaluates the DYNAMIC substrate only.
	PlaneMAP Plane = "map"
	// PlanePolicySimulation is the orchestrator's policy-simulation surface.
	// It is an operator tool rather than an enforcement point, and it is
	// modelled because it reads the same substrate: a simulation that disagrees
	// with enforcement is its own defect.
	PlanePolicySimulation Plane = "policy_simulation"
	// PlanePolicyTest is the agent's and the orchestrator's policy-test
	// surfaces, for the same reason.
	PlanePolicyTest Plane = "policy_test"
)

// Substrate names a legacy policy table.
type Substrate string

const (
	// SubstrateStatic is static_policies.
	SubstrateStatic Substrate = "static"
	// SubstrateDynamic is dynamic_policies.
	SubstrateDynamic Substrate = "dynamic"
)

// ReadPath names one of the disjoint ways the legacy substrate is queried.
//
// The distinction is not academic. The two static_policies column sets do not
// overlap on the columns that decide the action, so "what does this row do"
// has two answers and which one is correct depends on which plane is asking.
type ReadPath string

const (
	// ReadPathRuntimePhase selects phase, action_request and action_response
	// and never selects action. Used by every shared-engine plane.
	ReadPathRuntimePhase ReadPath = "runtime_phase_columns"
	// ReadPathEffectiveAction selects action and none of the phase columns.
	// Used by the proxy tier engine.
	ReadPathEffectiveAction ReadPath = "effective_action_column"
	// ReadPathDynamicRows is the dynamic_policies read.
	ReadPathDynamicRows ReadPath = "dynamic_rows"
)

// Phase is the legacy evaluation phase.
type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
	// PhaseBoth is the stored default for static_policies.phase (mig 039).
	PhaseBoth Phase = "both"
)

// PlaneSpec describes how one plane reads the legacy substrate.
type PlaneSpec struct {
	Plane Plane
	// Substrates are the legacy tables this plane evaluates.
	Substrates []Substrate
	// StaticReadPath is which static_policies column set this plane sees. It
	// is empty when the plane does not evaluate static policies.
	StaticReadPath ReadPath
	// Phases are the legacy phases this plane evaluates. A request-only plane
	// never resolves action_response, so a row storing only action_response is
	// inert there and that is a per-plane fact, not a per-row one.
	Phases []Phase
	// PostureLever reports whether EvalOptions.ActionOverrides - the
	// deployment/org detection posture - displaces the stored action on this
	// plane. It is true everywhere the shared engine is reached with
	// BuildActionOverrides(), and false on the proxy tier engine, which
	// resolves through StaticPolicyRepository.GetEffective and never sees the
	// override map. Compiling one global translation would be wrong for
	// exactly one plane, which is the plane an operator is least likely to
	// check.
	PostureLever bool
	// ForcedAction is an action this plane COERCES, regardless of the
	// deployment posture and regardless of what the row stores. It is empty on
	// every plane but the cowork ingest storage plane, which forces redact so
	// that content is masked before it is persisted.
	//
	// It is separate from PostureLever because the two are different
	// mechanisms with different authorities: the lever is deployment or
	// organization configuration an operator sets, and this is a hard-coded
	// property of the plane. Modelling one as the other would let a posture
	// change appear to alter a plane it cannot reach.
	ForcedAction LegacyAction
	// ForcedActionCategories restricts ForcedAction to a category family. The
	// cowork plane scopes its override to the tenant's enabled PII categories,
	// so a non-PII row on that plane keeps its resolved action. Nil means the
	// forced action applies to every category.
	ForcedActionCategories func(category string) bool
}

// Forces reports the action this plane coerces for a category, and whether it
// coerces one at all.
func (s PlaneSpec) Forces(category string) (LegacyAction, bool) {
	if s.ForcedAction == "" {
		return "", false
	}
	if s.ForcedActionCategories != nil && !s.ForcedActionCategories(category) {
		return "", false
	}
	return s.ForcedAction, true
}

// planeSpecs is the per-plane read model.
//
// EVERY ENTRY IS PINNED. platform/decision/legacycompile/legacy_call_sites.tsv
// names the call sites behind each plane and whether each passes
// EvalOptions.ActionOverrides;
// platform/shared/policy/legacy_call_site_census_test.go proves that census
// describes the tree, in both directions; and TestPlaneModelMatchesTheCensus
// in this package proves this map describes the census.
//
// It is pinned because the first version was not, and independent review found
// it wrong in both directions: it carried a connector_execution plane with no
// evaluation call site anywhere, gave MAP a static substrate on the strength of
// a stale doc comment, gave /decide a dynamic substrate although its one call
// site passes runDynamicPolicy=false, and omitted the proxy request pass, the
// tier engine's second call site, the orchestrator's PII detector and both
// policy-test surfaces. AllPlanes is the gate's DENOMINATOR: an invented plane
// measures nothing while reading as coverage, and a missing one is an
// enforcement surface nobody diffs.
var planeSpecs = map[Plane]PlaneSpec{
	PlaneDecide: {
		Plane: PlaneDecide, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PostureLever: true,
	},
	PlaneGatewayRequest: {
		Plane: PlaneGatewayRequest, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PostureLever: true,
	},
	PlaneMCP: {
		Plane: PlaneMCP, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest, PhaseResponse}, PostureLever: true,
	},
	PlaneOpenAICompatible: {
		Plane: PlaneOpenAICompatible, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PostureLever: true,
	},
	PlaneProxyRequest: {
		Plane: PlaneProxyRequest, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PostureLever: true,
	},
	PlaneProxyTier: {
		Plane: PlaneProxyTier, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathEffectiveAction, Phases: []Phase{PhaseRequest}, PostureLever: false,
	},
	PlaneOrchestratorResponse: {
		Plane: PlaneOrchestratorResponse, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseResponse}, PostureLever: true,
	},
	PlaneCoworkIngest: {
		Plane: PlaneCoworkIngest, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseResponse},
		// The census records this call site as passing ActionOverrides, and it
		// does - but it passes its OWN map, built in the handler, not the
		// deployment posture. PostureLever is therefore false and ForcedAction
		// carries the coercion, because the two are different authorities and
		// modelling one as the other would let a posture change appear to alter
		// a plane it cannot reach.
		PostureLever: false,
		ForcedAction: ActionRedact,
		ForcedActionCategories: func(category string) bool {
			return isPIICategory(category)
		},
	},
	PlaneWCP: {
		Plane: PlaneWCP, Substrates: []Substrate{SubstrateDynamic},
	},
	PlaneMAP: {
		Plane: PlaneMAP, Substrates: []Substrate{SubstrateDynamic},
	},
	PlanePolicySimulation: {
		Plane: PlanePolicySimulation, Substrates: []Substrate{SubstrateDynamic},
	},
	PlanePolicyTest: {
		Plane: PlanePolicyTest, Substrates: []Substrate{SubstrateStatic, SubstrateDynamic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PostureLever: true,
	},
}

// UnimplementedPlanes are enforcement planes ADR-065 Phase 4 names that have NO
// legacy policy evaluation call site in this tree.
//
// They are recorded rather than modelled. A plane in planeSpecs with no call
// site behind it would be compiled for, diffed and counted - reading as
// coverage of something that does not exist. A plane simply omitted would be
// invisible. Naming them here is the third option: the gate reports them as
// unmeasurable, and if one acquires a call site the census test fails on the PR
// that adds it.
var UnimplementedPlanes = map[Plane]string{
	"connector_execution": "ADR-065 Phase 4 names connector execution as an independently cut-over plane. " +
		"No call to EvaluateRequest, EvaluateResponse, EvaluateDynamicPolicies or EvaluatePolicy exists on any " +
		"connector execution path in platform/ or ee/, so there is nothing to compile, diff or count. " +
		"Either the plane enforces policy somewhere this census does not reach, or it does not enforce policy at all - " +
		"and which of those is true is a question for #3564, not something this model may assume.",
}

// AllPlanes returns every plane in a stable order.
func AllPlanes() []Plane {
	out := make([]Plane, 0, len(planeSpecs))
	for p := range planeSpecs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SpecFor returns the read model for a plane.
func SpecFor(p Plane) (PlaneSpec, error) {
	s, ok := planeSpecs[p]
	if !ok {
		return PlaneSpec{}, fmt.Errorf("legacycompile: %q is not a declared enforcement plane", p)
	}
	return s, nil
}

// MustSpecFor is SpecFor for a plane the caller has already validated.
//
// It panics rather than returning a zero PlaneSpec because a zero spec reads
// as "no substrates, no phases, no posture lever", which is a plane that
// enforces nothing - the silent fail-open shape this whole package exists to
// find. An undeclared plane is a programming error and must be loud.
func MustSpecFor(p Plane) PlaneSpec {
	s, err := SpecFor(p)
	if err != nil {
		panic(err)
	}
	return s
}

// PlanesFor returns the planes that evaluate a substrate, in a stable order.
func PlanesFor(s Substrate) []Plane {
	var out []Plane
	for _, p := range AllPlanes() {
		for _, have := range planeSpecs[p].Substrates {
			if have == s {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// EvaluatesPhase reports whether a plane evaluates a legacy phase.
func (s PlaneSpec) EvaluatesPhase(ph Phase) bool {
	for _, have := range s.Phases {
		if have == ph {
			return true
		}
	}
	return false
}
