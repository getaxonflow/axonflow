// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"sync/atomic"

	"axonflow/platform/orchestrator/llm"
)

// THE PLATFORM STATES WHAT A STEP WILL COST (#4249 row 5664825929).
//
// `signal.cost_estimate` is read by the shipped advisory controls
// corpus:dynamic_policies:sys__dyn__expensive__query#1 (warn) and #2 (log),
// compiled from the seeded row sys_dyn_expensive_query (cost_estimate > 100).
// Until now the orchestrator's planes stated the fact NOWHERE, so both were
// skipped with a warning on every step: its only source was the caller's own
// `context.cost_estimate`, which the legacy condition evaluator reads
// (db_dynamic_policies.go), and the decision contract admits the `signal`
// namespace only with detector provenance (contract/provenance.go). A caller's
// claim does not become a detector finding by relabelling.
//
// So the PLATFORM computes it, from the step it is about to run, through the
// estimator the planner already uses (estimateStepTokens) and the deployment's
// own pricing (cost.PricingConfig.EstimateCostPriced).
//
// # WHAT THE NUMBER IS: THE PRICE OF THE DECLARED PAIR, ELSE A CEILING
//
// A step that names its provider and model, AND whose provider this deployment
// has registered, is priced at that pair. Every other step - which is EVERY
// step the planner generates, because the generation schema, the synthesis step
// and the template step all write name, type and prompt and no provider or
// model, and also a stored step naming a provider this deployment does not have
// - is priced at the dearest pair among the providers it is registered with
// (routableCeiling). Stated as a ceiling in the release note and the PR body,
// because that is what a reader must not mistake for the price of the call that
// ran.
//
// THE DECLARED PROVIDER IS NOT NECESSARILY THE ONE THAT RUNS (R3 round 1,
// LOW-4): applyLLMCallRoutes may redirect an llm.completion to another provider,
// and the router may fail over. Those rows are the ORGANIZATION's, held in its
// policy and not movable by the caller. They do NOT merely narrow where a call
// can go (master R3 round 2, MEDIUM-B): a preferred provider is resolved
// through Registry.Get, which ignores health and the Enabled flag, so a row can
// send a step to a provider the selector's own set excludes. That is why the
// ceiling is taken over every REGISTERED provider, which covers both.
//
// A ZERO PRICE IS A PRICE (R3 round 1, LOW-5). The shipped table prices some
// pairs at 0 - `ollama`, `local`, `gemini-2.0-flash-exp` - and those state 0
// with priced=true, which is correct: a deployment that runs a local model
// genuinely spends nothing on tokens. It is not the "unpriced" case, and it is
// not reachable by a caller: on the multi-agent plane the pair is the planner's
// under the customer's own credential, and the step gate states nothing at all.
//
// AN EMPTY PROMPT WITH NO CEILING IS ESTIMATED AT 1000/500 TOKENS (R3 round 1,
// LOW-6), estimateStepTokens' defaults: a positive estimate for a step nobody
// sized. Every planner-generated step carries a prompt, so this is the shape of
// a hand-written plan, and the direction is the conservative one.
//
// # THE MULTI-AGENT PLANE ONLY, AND WHY NOT THE STEP GATE
//
// The estimate is a measurement, so its inputs must be the PLATFORM's. On the
// multi-agent plane they are: the step comes from the plan this deployment
// stored and is executing, so its provider, model, prompt and max_tokens are
// the plan author's, fixed before the request that runs it.
//
// THE WORKFLOW STEP GATE STATES NOTHING, and that is deliberate (#4249 row
// 5664825929, ruled after this lane's own hostile round). There the step is
// declared by the CALLER in the gate request - StepGateRequest.Provider, .Model
// and .StepInput are ordinary JSON fields, copied into the step context and
// never checked against anything the platform holds, because the platform does
// not run that step. An estimate computed from them would be the caller's claim
// wearing detector provenance: naming a provider this deployment prices at zero
// (the shipped table prices `ollama` so) would state cost_estimate = 0, and an
// organization's CONSTRAINT over that path - which is unknown_constraint and
// REFUSES today - would start admitting requests the caller had priced for it.
// So the step gate keeps today's answer, unstated, and a constraint there stays
// fail-closed. Stating a cost on it needs a platform-held step definition, which
// is its own #4249 row.
//
// # THE INPUTS ARE TYPED AND UNEXPORTED
//
// stepCostInputs reaches the producer on OrchestratorRequest as an unexported
// field, for the reason mediaAnalysis is unexported: a caller must not be able
// to name it. There is no JSON tag to set, no context key to write, and no
// exported setter. The multi-agent adapter fills it from the stored step, in
// this package.
//
// # NO PRICE MEANS UNSTATED, NEVER ZERO
//
// A deployment that cannot price the provider and model states NOTHING, so the
// advisory is skipped with its warning exactly as before. Stating 0 there would
// be a fabricated "cheap" finding about a step nobody priced - the failure this
// whole file exists to avoid - and a policy that refuses over a threshold would
// read it as a pass.

// stepCostInputs is what the platform needs to price the step a request will
// run: the provider and model it will call, the prompt it will send, the
// output ceiling it set, and the step's own output schema, which the estimator
// counts as input tokens.
type stepCostInputs struct {
	provider  string
	model     string
	prompt    string
	maxTokens int
	output    map[string]interface{}
}

// stepCostCandidate is one provider/model pair the router may route a step to:
// a provider this deployment has REGISTERED, at the model that provider is
// CONFIGURED with. The model is read from the registry's own ProviderConfig,
// never from a provider package's default constant, because the fact must
// follow this deployment's configuration and not the build's.
type stepCostCandidate struct {
	provider string
	model    string
}

// stepCostPricing is the deployment's pricing, wired at boot beside the cost
// service (run.go). Nil on a deployment that wires none, where the fact is
// unstated.
var stepCostPricing atomic.Pointer[stepCostPricer]

// stepCostRoutable is the deployment's routable set, wired at boot from the LLM
// router (run.go). Nil on a deployment that wires no router, where a step that
// names no pair is unstated.
var stepCostRoutable atomic.Pointer[stepCostRouter]

// stepCostRouter holds the routable-set reader. A function rather than the
// router type, so this file keeps no dependency on how the router is built.
type stepCostRouter struct {
	candidates func() []stepCostCandidate
}

// setStepCostRoutable installs the deployment's routable set for the fact
// producer.
func setStepCostRoutable(candidates func() []stepCostCandidate) {
	stepCostRoutable.Store(&stepCostRouter{candidates: candidates})
}

// deploymentRoutableCandidates reports what the process wired, and nothing on a
// deployment that wired no router: a step with no named pair is then unstated,
// exactly as an unpriced one is.
func deploymentRoutableCandidates() []stepCostCandidate {
	r := stepCostRoutable.Load()
	if r == nil || r.candidates == nil {
		return nil
	}
	return r.candidates()
}

// routerRoutableCandidates reads EVERY REGISTERED PROVIDER, each paired with
// its configured model. A provider configured with none is returned with an
// empty model, which makes the whole estimate unstated rather than dropping
// that candidate out of the ceiling.
//
// THE REGISTERED SET, NOT THE HEALTHY ONE (master R3 round 2, MEDIUM-B). The
// selector's own set is the healthy providers falling back to every enabled one
// - but that is not the whole of where a call can go, and reading it here
// UNDERSTATED the ceiling. `Router.selectProvider` resolves a preferred
// provider through `Registry.Get` BEFORE consulting that set, and `Get` returns
// a registered provider whatever its health and whatever its `Enabled` flag
// (`Disable` only flips the flag). So an organization's
// `policy_preferred_provider` row naming a registered-but-unhealthy or disabled
// provider routes a step OUTSIDE the healthy set; if that provider is dearer,
// a "ceiling" taken over the healthy set is below what runs, and a constraint
// admits it.
//
// The registered set is a superset of the healthy set AND of anything `Get` can
// resolve, so its maximum is a ceiling over both. Over-stating is the direction
// this whole file accepts; it also keeps no copy of the selector's fallback
// rule here, which was a second statement of two lines that can drift.
func routerRoutableCandidates(router *llm.UnifiedRouter) func() []stepCostCandidate {
	return func() []stepCostCandidate {
		if router == nil {
			return nil
		}
		registry := router.Registry()
		if registry == nil {
			return nil
		}
		names := registry.List(llm.GlobalTenant)
		candidates := make([]stepCostCandidate, 0, len(names))
		for _, name := range names {
			candidate := stepCostCandidate{provider: name}
			if cfg, err := registry.GetConfig(llm.GlobalTenant, name); err == nil && cfg != nil {
				candidate.model = cfg.Model
			}
			candidates = append(candidates, candidate)
		}
		return candidates
	}
}

// stepCostPricer holds the deployment's priced lookup, as cost.PricingConfig
// implements it. A function rather than the concrete type, so this package
// keeps no dependency on the cost package's construction.
type stepCostPricer struct {
	price func(provider, model string, tokensIn, tokensOut int) (float64, bool)
}

// setStepCostPricing installs the deployment's pricing for the fact producer.
func setStepCostPricing(price func(provider, model string, tokensIn, tokensOut int) (float64, bool)) {
	stepCostPricing.Store(&stepCostPricer{price: price})
}

// deploymentStepCost prices a step through whatever the process wired, and
// reports UNPRICED when nothing is wired: a deployment with no pricing states
// no estimate rather than a zero.
func deploymentStepCost(provider, model string, tokensIn, tokensOut int) (float64, bool) {
	p := stepCostPricing.Load()
	if p == nil || p.price == nil {
		return 0, false
	}
	return p.price(provider, model, tokensIn, tokensOut)
}

// costEstimate is the platform's estimate for the step this request will run,
// and whether it could be computed at all: a request that carries no step cost
// inputs (every plane but the multi-agent one) and a deployment that can price
// nothing the step could run on both answer false.
//
// The token estimate is estimateStepTokens', the planner's own, read from a
// WorkflowStep built out of the inputs, so the token counts here and in a plan
// cost report come from one function. The two are not the same ANSWER: a plan
// cost report substitutes ONE pair for a step that names none - a constant
// "openai"/"gpt-4o" unless a healthy provider replaces the provider half
// (planning_engine.go) - and prices every step but a connector call. That is a
// report a person reads. This is a fact a policy may REFUSE on, so it
// substitutes a CEILING instead (routableCeiling), never a representative
// price.
func (p *dynamicFactProducer) costEstimate(req OrchestratorRequest) (float64, bool) {
	in := req.stepCost
	if in == nil || p.estimateCost == nil {
		// A producer built without an estimator states nothing rather than
		// panicking: the fact is an advisory input, and no request may fail on
		// a wiring gap.
		return 0, false
	}
	tokensIn, tokensOut := estimateStepTokens(WorkflowStep{
		Prompt:    in.prompt,
		MaxTokens: in.maxTokens,
		Output:    in.output,
	})
	candidates := p.candidates()
	if in.provider != "" && in.model != "" && registeredProvider(candidates, in.provider) {
		// The plan names the pair AND this deployment has that provider, so
		// there is nothing to substitute: this is the price of the call the
		// plan declares. A route row may still redirect it (see the header),
		// which is the organization's own change.
		return p.estimateCost(in.provider, in.model, tokensIn, tokensOut)
	}
	// A PAIR THIS DEPLOYMENT DOES NOT HAVE IS NOT WHAT WILL RUN (master R3
	// round 2, LOW-D): `selectProvider` logs "Requested provider not available"
	// and falls through to its own set, so pricing the declared pair would
	// price a call that cannot happen - and an unregistered name can be priced
	// at anything, or at nothing. Such a step takes the ceiling too.
	return p.routableCeiling(in, candidates, tokensIn, tokensOut)
}

// routableCeiling prices a step that does not name a registered pair at the
// DEAREST the deployment could actually run it for: the maximum over every
// REGISTERED provider, each at the model that step would send it - the step's
// own declared model where it names one, and otherwise that provider's
// configured model. It is a ceiling, not a price, and is stated as one
// everywhere it is described.
//
// WHY A CEILING AND NOT THE DEFAULT PROVIDER. The planner writes no provider or
// model on any step it generates, so every platform-generated plan takes this
// path. Substituting the configured default would be wrong in the PERMISSIVE
// direction: only the failover strategy routes to the default at all
// (ProviderSelector.selectFailover), while the shipped default strategy is
// weighted - a weighted random draw over the healthy set that never reads the
// default - so a step priced at a cheap default can run on a dear provider, and
// a policy refusing above a threshold would have admitted it on a number no
// call could have produced. The maximum over the set can only over-state, and
// over-stating an advisory warns where nothing was due; under-stating a
// constraint admits a step that was.
//
// THE SET IS EVERY REGISTERED PROVIDER, at its configured model
// (routerRoutableCandidates). It is deliberately WIDER than the set the
// selector draws from: a preferred provider is resolved through Registry.Get
// before that set is consulted, and Get ignores both health and the Enabled
// flag, so an organization's route row can send a step to a registered provider
// the healthy set does not contain. A ceiling over the registered set covers
// that arm as well as every narrowing one, which is why a route row that points
// at the cheaper provider must NOT lower what is stated here. The set is read
// at DECISION time; registering a provider widens it, and that is the
// operator's change to the deployment, never the caller's to this request.
//
// ANY CANDIDATE THIS DEPLOYMENT CANNOT PRICE MAKES THE FACT UNSTATED - a
// candidate with no configured model, or a pair the price table misses. Pricing
// the rest and stating the maximum of those would turn the ceiling back into a
// floor with a gap above it, which is the permissive direction again.
func (p *dynamicFactProducer) routableCeiling(in *stepCostInputs, candidates []stepCostCandidate, tokensIn, tokensOut int) (float64, bool) {
	// A step naming a REGISTERED provider narrows the set to it: only that one
	// can run the step. A step naming one this deployment does not have narrows
	// nothing - the router will fall through to its own set - so the ceiling is
	// taken over all of them (master R3 round 2, LOW-D).
	narrow := in.provider != "" && registeredProvider(candidates, in.provider)
	ceiling, any := 0.0, false
	for _, candidate := range candidates {
		if narrow && candidate.provider != in.provider {
			continue
		}
		model := candidate.model
		if in.model != "" {
			// A DECLARED MODEL IS WHAT THE CALL SENDS, whoever runs it (master
			// R3 round 3, MEDIUM-C). The step's model travels in the request
			// context (workflow_engine.go) and the adapter passes it to
			// whichever provider is selected, which falls back to its own
			// configured model only when the request names none. So a step
			// naming a model is priced at THAT model on every candidate - not
			// at each candidate's configured one, which understated the
			// ceiling wherever the declared model is dearer. It does not
			// matter whether the declared provider is registered: the pairing
			// that runs carries the declared model either way.
			model = in.model
		}
		if candidate.provider == "" || model == "" {
			return 0, false
		}
		cost, priced := p.estimateCost(candidate.provider, model, tokensIn, tokensOut)
		if !priced {
			return 0, false
		}
		if cost > ceiling {
			ceiling = cost
		}
		any = true
	}
	if !any {
		// Nothing registered at all: a step this deployment cannot place is one
		// it cannot price.
		return 0, false
	}
	return ceiling, true
}

// registeredProvider reports whether this deployment has that provider at all.
func registeredProvider(candidates []stepCostCandidate, provider string) bool {
	for _, c := range candidates {
		if c.provider == provider {
			return true
		}
	}
	return false
}

// candidates is the registered set, or nothing on a producer with no reader.
func (p *dynamicFactProducer) candidates() []stepCostCandidate {
	if p.routable == nil {
		return nil
	}
	return p.routable()
}
