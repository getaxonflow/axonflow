// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

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
	// evaluateInputPolicies, which has no dynamic hop, so it evaluates the
	// STATIC substrate only - an earlier version of this model gave it the
	// dynamic substrate too, which was simply wrong.
	PlaneDecide Plane = "decide"
	// PlaneGatewayRequest is the gateway pre-check.
	PlaneGatewayRequest Plane = "gateway_request"
	// PlaneMCP is the MCP tool plane: an input pass and an output pass.
	PlaneMCP Plane = "mcp"
	// PlaneOpenAICompatible is the OpenAI-compatible surface.
	PlaneOpenAICompatible Plane = "openai_compatible"
	// PlaneProxyRequest is /api/request's one pass: the shared static engine
	// over the request (proxyDetectorPass, which the route's preview shares) as
	// the anchored engine's detector input. Its second pass, the tier engine,
	// retired with the proxy_tier plane (#4253, PRD v11 §1 item 1).
	PlaneProxyRequest Plane = "proxy_request"
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
	// and the orchestrator's own request handler. Since #4254 each decides on the
	// anchored engine and reads the dynamic rows as facts, through the dynamic
	// fact producer.
	PlaneWCP Plane = "wcp"
	// PlaneMAP is the multi-agent plane, reached through map_hitl_adapter. It
	// reads the DYNAMIC substrate only, as facts through the dynamic fact producer,
	// and decides on the anchored engine (#4254).
	PlaneMAP Plane = "map"
	// PlanePolicySimulation is the orchestrator's policy-simulation surface.
	// It is an operator tool rather than an enforcement point, and it is
	// modelled because it reads the same substrate: a simulation that disagrees
	// with enforcement is its own defect.
	PlanePolicySimulation Plane = "policy_simulation"
	// PlanePolicyTest is the orchestrator's policy-test surface, for the same
	// reason. The agent's previews /api/request's anchored pass since #4253 and
	// is recorded as that pass's call site, not as this plane's.
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
// Until #4253 there were two static read paths whose column sets did not
// overlap on the columns that decide the action - the runtime phase columns
// every shared-engine plane reads, and the stored action column the retired
// proxy_tier plane read - so "what does this row do" had two answers. One
// static path is left; the stored action column's one remaining effect on a
// verdict is PlaneSpec.EnforcesRetiredTierPassRead.
type ReadPath string

const (
	// ReadPathRuntimePhase selects phase, action_request and action_response
	// and never selects action. Used by every shared-engine plane.
	ReadPathRuntimePhase ReadPath = "runtime_phase_columns"
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
	// PassesOrgOverrides reports whether the plane passes
	// EvalOptions.ActionOverrides - an organization's recorded detection
	// overrides (#3961) - so that an override displaces the stored action on
	// this plane. It is true everywhere the shared engine is reached with
	// BuildActionOverrides(), and false where a plane builds its own map (the
	// cowork ingest plane, ForcedAction below).
	PassesOrgOverrides bool
	// EnforcesRetiredTierPassRead reports that this plane keeps what
	// /api/request's retired second pass read from a row's STORED action column
	// (#4253). It is /api/request's alone. Until #4253 a second pass ran there
	// after the first allowed - the tier engine, reading the stored column
	// verbatim (StaticPolicyRepository.GetEffective) - and PRD v11 §1 item 1
	// retires that pass and evaluates every control that named it on
	// proxy_request. Two arms keep its read, each where the phase column resolves
	// something weaker (retiredTierPassArm):
	//
	//   - a SYSTEM row's stored block. The pass refused on it. A system row
	//     compiles to one policy per scope (#4046), so the pass's lesser reads of
	//     a system row were proxy_tier-only variants, and they leave the corpus
	//     with the plane.
	//   - a TEMPLATE row's stored action, wherever it outranks the phase
	//     resolution. A non-system row compiles to ONE policy, its most
	//     restrictive plane compilation, and the pass's read of the stored column
	//     was that compilation: the organization template's DROP TABLE, TRUNCATE
	//     and SQL-injection refusals and its five redactions. A stored hold
	//     (require_approval) is not kept: the route's hold exit retired with the
	//     pass, and holds return with the orchestrator's typed approval
	//     challenge (#4254), never as a refusal here.
	//
	// Two limits the retired pass did not have. Both arms sit behind the phase
	// gate, as every static read does, so a row whose phase column names only
	// the response never reaches them on this request-phase plane, though the
	// pass read the stored column whatever the phase; no shipped row is
	// response-only (the capture's 101 static rows are both or request), and
	// only an organization's own imported rows could be. And an organization's
	// category action (PassesOrgOverrides) displaces the kept action as it
	// displaces any other, where the pass applied none.
	EnforcesRetiredTierPassRead bool
	// ForcedAction is an action this plane COERCES, regardless of the
	// deployment posture and regardless of what the row stores. It is empty on
	// every plane but the cowork ingest storage plane, which forces redact so
	// that content is masked before it is persisted.
	//
	// It is separate from PassesOrgOverrides because the two are different
	// mechanisms with different authorities: the override is organization
	// configuration an operator records, and this is a hard-coded
	// property of the plane. Modelling one as the other would let a posture
	// change appear to alter a plane it cannot reach.
	ForcedAction LegacyAction
	// ForcedActionCategories restricts ForcedAction to a category family. The
	// cowork plane scopes its override to the tenant's enabled PII categories,
	// so a non-PII row on that plane keeps its resolved action. Nil means the
	// forced action applies to every category.
	ForcedActionCategories func(category string) bool
	// Admission is which static_policies categories this plane's call sites
	// pass to the evaluator (#3895 PR-A2): the union of the per-site
	// declarations (siteAdmissions) over its static call sites in
	// legacy_call_sites.tsv, DERIVED at package init and never written here. A
	// static site with no declaration leaves it zero, which activation refuses
	// by name. What a plane EVALUATES is the row's load planes intersected with
	// this; see CategoryAdmission for why it is a second fact rather than a
	// correction of Record.Planes. Zero on a plane with no static substrate.
	// The compiler does not read it; activation's restriction reads the
	// per-phase form, AdmissionFor.
	Admission CategoryAdmission
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
// site never reached the dynamic substrate, and omitted the proxy request pass, the
// tier engine's second call site, the orchestrator's PII detector and both
// policy-test surfaces. AllPlanes is the gate's DENOMINATOR: an invented plane
// measures nothing while reading as coverage, and a missing one is an
// enforcement surface nobody diffs.
var planeSpecs = map[Plane]PlaneSpec{
	PlaneDecide: {
		Plane: PlaneDecide, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PassesOrgOverrides: true,
	},
	PlaneGatewayRequest: {
		Plane: PlaneGatewayRequest, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PassesOrgOverrides: true,
	},
	PlaneMCP: {
		Plane: PlaneMCP, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest, PhaseResponse}, PassesOrgOverrides: true,
	},
	PlaneOpenAICompatible: {
		Plane: PlaneOpenAICompatible, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PassesOrgOverrides: true,
	},
	PlaneProxyRequest: {
		Plane: PlaneProxyRequest, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseRequest}, PassesOrgOverrides: true,
		EnforcesRetiredTierPassRead: true,
	},
	PlaneOrchestratorResponse: {
		Plane: PlaneOrchestratorResponse, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseResponse}, PassesOrgOverrides: true,
	},
	PlaneCoworkIngest: {
		Plane: PlaneCoworkIngest, Substrates: []Substrate{SubstrateStatic},
		StaticReadPath: ReadPathRuntimePhase, Phases: []Phase{PhaseResponse},
		// The census records this call site as passing ActionOverrides, and it
		// does - but it passes its OWN map, built in the handler, not the
		// organization's overrides. PassesOrgOverrides is therefore false and
		// ForcedAction carries the coercion, because the two are different
		// authorities and modelling one as the other would let an override appear to alter
		// a plane it cannot reach.
		PassesOrgOverrides: false,
		ForcedAction:       ActionRedact,
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
		Plane: PlanePolicyTest, Substrates: []Substrate{SubstrateDynamic},
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
		"No call to EvaluateRequest, EvaluateResponse or EvaluateDynamicPolicies exists on any " +
		"connector execution path in platform/ or ee/, so there is nothing to compile, diff or count. " +
		"Either the plane enforces policy somewhere this census does not reach, or it does not enforce policy at all - " +
		"and which of those is true is a question for #3564, not something this model may assume.",
}

// PlanesGatedUnderDefaultPosture names every plane whose call sites are ALL
// gated, so no deployment running the default configuration can produce a
// single observation for it.
//
// # WHY THIS IS A THIRD STATE AND NOT A VARIANT OF THE OTHER TWO
//
// UnimplementedPlanes above is "there is no call site". planeSpecs is "there is
// a call site". This is the gap between them that nothing named: there IS a
// call site, the model is right about it, and the code that CONSTRUCTS the
// object holding it is behind a switch that no shipped deployment sets. The
// plane is therefore modelled, watched, compiled for, and permanently empty.
//
// It mattered because ADR-065 gate 18 was stated per plane and read off a
// denominator the decision shadow pre-created at zero: a gated plane read
// mode=shadow, compared=0 - byte-identical to a watched plane that had merely
// seen no traffic yet, with opposite remedies. The map plane spent the whole
// v11 observation window in this state while the decision-shadow canary
// reported it covered, which is the pair of defects #3555 and this map exist to
// make impossible to repeat. v11 retired that observer; the model's statement
// of which planes are reachable outlives it.
//
// EVERY ENTRY CARRIES A REVISIT CONDITION THAT CAN BE CHECKED - a code fact or
// a shipped configuration - not a date and not a judgement: an entry whose
// condition cannot be checked is an exemption that outlives its reason.
//
// The keys are pinned against legacy_call_sites.tsv by
// TestGatedPlanesMatchTheCallSiteCensus, so a plane cannot be listed here
// without every one of its rows saying default_posture=gated, and a plane whose
// rows all say gated cannot be left out.
var PlanesGatedUnderDefaultPosture = map[Plane]string{
	PlaneMAP: "map's only call site is MAPHITLPolicyChecker.CheckPolicy, which reaches the dynamic rows through " +
		"mapStepPolicyCheck and its decision mapStepDecide (the census row since #4254), and MAPHITLPolicyChecker is " +
		"constructed in exactly one place - the orchestrator's HITL block. TWO conditions gate it and " +
		"both must hold: AXONFLOW_HITL_ENABLED=\"true\", and the DEPLOYMENT POSTURE is not community " +
		"(isCommunityMode, which reads deploymode.CurrentIsCommunityPosture - a DEPLOYMENT_MODE env " +
		"read, NOT a build tag; the edition column means the build and these are different axes). " +
		"Clearing only the first still leaves the site unreachable, which is why naming one gate would " +
		"be a claim a reader could check and still be wrong about. " +
		"The variable is absent from every deploy surface in this repository, defaults to false in " +
		"docker-compose.yml, and was absent from the running task definitions of BOTH fleet stacks when " +
		"this was measured (2026-09-08). The live orchestrator says so itself at boot: " +
		"\"HITL mode disabled (set AXONFLOW_HITL_ENABLED=true to enable)\". So hitlWorkflowEngine is nil, " +
		"both ExecuteWithHITL call sites are guarded on it being non-nil, so the plane has no reachable " +
		"observation site on either stack. The claim is the MECHANISM, deliberately: a Prometheus " +
		"counter is per-process and bounded by retention, so \"the counter has never left zero\" - which " +
		"an earlier revision of this entry asserted - is not something any instrument here can support. " +
		"REVISIT WHEN a SHIPPED deploy surface turns AXONFLOW_HITL_ENABLED on - a CloudFormation " +
		"template under infrastructure/ or ee/ that sets it to \"true\", or docker-compose.yml's default " +
		"for it, which is \"false\" today - or when MAPHITLPolicyChecker gains a construction site outside " +
		"the orchestrator's HITL block. Either one makes the site reachable on some deployment, and this " +
		"entry is then stale. The condition was an observation counter until v11 retired the decision " +
		"shadow that emitted it; the agent's enforce counter cannot stand in for it, because map is an " +
		"orchestrator plane. The runtime-e2e harnesses are deliberately excluded: three of them set the " +
		"variable to true and DO construct the checker (runtime-e2e/3297_map_segment_policy, " +
		"3135_map_hitl_approver_identity, cross-system-hitl), and a retirement condition that is already " +
		"met on the day it is written retires nothing.",
}

// ComponentAgent and ComponentOrchestrator are the two binaries that hold
// legacy policy call sites. They are the same strings Bootstrap is called with,
// because they are the same fact.
const (
	ComponentAgent        = "agent"
	ComponentOrchestrator = "orchestrator"
)

// planeComponents records WHICH BINARY holds each plane's call sites.
//
// # WHY IT IS RECORDED IN THE MODEL
//
// It was added for the per-plane decision shadow, retired in v11, which
// published a mode gauge for every plane on every component and so reported the
// agent as watching `map` - a plane whose only call site is in
// platform/orchestrator. A plane is unreachable on the OTHER component for a
// reason that component's boot code knows nothing about, so the fact is a
// property of the model and lives here. ComponentHoldsPlane and
// ComponentsForPlane answer it.
//
// A plane could have both; none has since #4253, when the agent's policy-test
// surface retired. Such a plane would be declared unreachable by neither.
//
// Held to legacy_call_sites.tsv's `file` column, in both directions, by
// TestPlaneComponentsMatchTheCallSiteCensus - so this cannot drift from where
// the code actually is.
var planeComponents = map[Plane][]string{
	PlaneCoworkIngest:         {ComponentAgent},
	PlaneDecide:               {ComponentAgent},
	PlaneGatewayRequest:       {ComponentAgent},
	PlaneMCP:                  {ComponentAgent},
	PlaneOpenAICompatible:     {ComponentAgent},
	PlaneProxyRequest:         {ComponentAgent},
	PlaneMAP:                  {ComponentOrchestrator},
	PlaneWCP:                  {ComponentOrchestrator},
	PlanePolicySimulation:     {ComponentOrchestrator},
	PlaneOrchestratorResponse: {ComponentOrchestrator},
	PlanePolicyTest:           {ComponentOrchestrator},
}

// ComponentHoldsPlane reports whether this binary holds any call site for the
// plane.
//
// A component that holds none cannot ever observe it, on any configuration and
// in any edition - which is a stronger statement than either gap map above and
// is why it is derived rather than declared per plane.
func ComponentHoldsPlane(component string, p Plane) bool {
	for _, c := range planeComponents[p] {
		if c == component {
			return true
		}
	}
	return false
}

// ComponentsForPlane returns the binaries holding a plane's call sites.
func ComponentsForPlane(p Plane) []string {
	out := append([]string(nil), planeComponents[p]...)
	sort.Strings(out)
	return out
}

// PlanesGatedByEdition names every plane whose call sites all live in
// enterprise-tagged files, so a COMMUNITY build models, watches and pre-creates
// a denominator for a plane whose code is not in the binary.
//
// # WHY IT IS A SECOND MAP AND NOT A ROW IN THE ONE ABOVE
//
// PlanesGatedUnderDefaultPosture is "no deployment of ANY edition reaches this
// under default configuration; an operator can change that by setting
// something". This is "one edition reaches it and the other cannot, ever" - the
// remedy is an edition change or nothing at all, never a configuration one.
// Folding them together would tell an operator to go looking for a switch that
// does not exist for half the entries, which is the same collapse
// ReasonRealmDisabled refuses against ReasonUnknownRealm.
//
// The consequence is why this is modelled at all: planeSpecs is not
// build-tagged, so the model carries cowork_ingest on a community binary whose
// code for it does not exist. The decision shadow, retired in v11, read that as
// a watched plane awaiting traffic on the community-SaaS stack that carried the
// whole v11 observation window.
//
// Bound to the census by TestEditionGatedPlanesMatchTheCallSiteCensus, in both
// directions, so a plane cannot become enterprise-only without a declaration
// and a declaration cannot outlive the tag.
var PlanesGatedByEdition = map[Plane]string{
	PlaneCoworkIngest: "cowork_ingest's only call site is coworkRedactDefault in " +
		"platform/agent/cowork_otel_ingest.go, whose first line is //go:build enterprise. The " +
		"community twin (cowork_otel_ingest_community.go, //go:build !enterprise) mounts a 501 stub " +
		"and evaluates no policy, so on a community binary the function does not exist and the plane " +
		"has no observation site at all - while planeSpecs, which is not build-tagged, still models " +
		"it. " +
		"REVISIT WHEN platform/agent/cowork_otel_ingest.go loses its //go:build enterprise " +
		"constraint, or when coworkRedactDefault gains a caller in a file without it. Either one " +
		"means the plane is reachable outside the enterprise edition and this entry is stale. The " +
		"condition also named an observation counter until v11 retired the decision shadow that " +
		"emitted it; the code condition is the whole of it now.",
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
// as "no substrates, no phases, no override map", which is a plane that
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
