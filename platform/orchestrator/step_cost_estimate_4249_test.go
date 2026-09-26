// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/llm"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// THE PLATFORM'S COST ESTIMATE IS A DETECTOR SIGNAL (#4249 row 5664825929).
//
// The shipped advisories corpus:dynamic_policies:sys__dyn__expensive__query#1
// (a notification) and #2 (an audit) read signal.cost_estimate > 100. The
// orchestrator stated the fact nowhere, so both were skipped with a warning on
// every step. These cells drive the production producer.

const expensiveQueryControl = "corpus:dynamic_policies:sys__dyn__expensive__query"

// pricedAt installs a deployment that prices every step at usd, and one that
// prices nothing when priced is false. It also REGISTERS the pair the step
// helpers name: since master R3 round 2 a step whose provider this deployment
// has not registered is priced at the ceiling instead of at its declared pair
// (LOW-D), so a cell about the declared pair has to register it.
func pricedAt(p *dynamicFactProducer, usd float64, priced bool) *dynamicFactProducer {
	p.estimateCost = func(string, string, int, int) (float64, bool) { return usd, priced }
	return registering(p, stepCostCandidate{provider: "openai", model: "gpt-4o"})
}

// registering installs the deployment's registered provider set.
func registering(p *dynamicFactProducer, candidates ...stepCostCandidate) *dynamicFactProducer {
	p.routable = func() []stepCostCandidate { return candidates }
	return p
}

// llmStepRequest is a step-plane request for an llm-call step, as the two
// adapters build one: the cost inputs come from the step's own definition.
func llmStepRequest(t *testing.T, callerClaim interface{}) OrchestratorRequest {
	t.Helper()
	req := stepFactRequest("summarise the quarter", nil)
	req.stepCost = mapStepCostInputs(WorkflowStep{
		Type: "llm-call", Provider: "openai", Model: "gpt-4o", Prompt: "summarise the quarter", MaxTokens: 4096,
	}, "summarise the quarter")
	if callerClaim != nil {
		if req.Context == nil {
			req.Context = map[string]interface{}{}
		}
		req.Context["cost_estimate"] = callerClaim
	}
	return req
}

func TestTheStepPlanesStateThePlatformsCostEstimate(t *testing.T) {
	rows := seedDynamicRows(t)
	path := "signal.cost_estimate"

	t.Run("a priced step is stated known, with detector provenance", func(t *testing.T) {
		facts := produceFacts(t, pricedAt(testFactProducer(t, rows), 150.25, true), llmStepRequest(t, nil))
		got, stated := facts[path]
		if !stated {
			t.Fatalf("%s is not stated on a priced step; the advisory would be skipped as before", path)
		}
		if got.Value != 150.25 {
			t.Errorf("%s = %v, want the platform's estimate 150.25", path, got.Value)
		}
		if got.Source != contract.ProvDetector {
			t.Errorf("%s carries provenance %q; the signal namespace admits only %q, and a caller claim is not a detector finding", path, got.Source, contract.ProvDetector)
		}
	})

	t.Run("a deployment that prices nothing states nothing, never zero", func(t *testing.T) {
		// THE CLAIM IS PRESENT AND THE STEP IS PRESENT, which is the one
		// combination that would let a fallback to the caller's context survive
		// (R3 self-round, HIGH): with no step the code returns before reading
		// the context at all, so that case proves nothing about a fallback.
		facts := produceFacts(t, pricedAt(testFactProducer(t, rows), 0, false), llmStepRequest(t, 999.0))
		if got, stated := facts[path]; stated {
			t.Fatalf("%s = %v on a deployment with no pricing; an unpriced step must leave the fact UNSTATED, because 0 reads as cheap", path, got.Value)
		}
	})

	t.Run("a request with no step to price states nothing", func(t *testing.T) {
		// Every plane but the two step planes, and a tool step on them: the
		// adapters hand over no inputs, so there is nothing to price.
		facts := produceFacts(t, pricedAt(testFactProducer(t, rows), 150, true), stepFactRequest("summarise the quarter", nil))
		if _, stated := facts[path]; stated {
			t.Fatalf("%s is stated for a request that carries no step cost inputs", path)
		}
	})

	t.Run("the caller's context.cost_estimate is never the fact", func(t *testing.T) {
		// With no step to price, a caller's claim states nothing...
		facts := produceFacts(t, pricedAt(testFactProducer(t, rows), 150, true), stepFactRequest("summarise the quarter", map[string]interface{}{"cost_estimate": 999.0}))
		if got, stated := facts[path]; stated {
			t.Fatalf("%s = %v from the caller's context; the signal namespace admits a detector finding only", path, got.Value)
		}
		// ...and where there IS a step, the platform's estimate is the fact.
		facts = produceFacts(t, pricedAt(testFactProducer(t, rows), 150, true), llmStepRequest(t, 999.0))
		if got := facts[path]; got.Value != 150.0 {
			t.Fatalf("%s = %v with a caller claiming 999; want the platform's 150", path, got.Value)
		}
	})
}

// THE TWO ADAPTERS HAND OVER THE STEP'S OWN DEFINITION, and only for a step
// that spends tokens.
func TestTheStepAdaptersHandOverWhatPricesTheStep(t *testing.T) {
	t.Run("the multi-agent plane", func(t *testing.T) {
		// THE PROMPT HANDED OVER IS THE RENDERED QUERY, not the step's template
		// (master R3 round 1, MEDIUM-3): the template is a prefix of what the
		// step will send, so pricing it understates every interpolating step.
		in := mapStepCostInputs(WorkflowStep{Type: "llm-call", Provider: "anthropic", Model: "claude", Prompt: "p", MaxTokens: 77}, "p, rendered with the caller's input")
		if in == nil || in.provider != "anthropic" || in.model != "claude" || in.maxTokens != 77 {
			t.Fatalf("an llm-call hands over %+v", in)
		}
		if in.prompt != "p, rendered with the caller's input" {
			t.Fatalf("an llm-call is priced on %q; the plane decides the RENDERED query, and the template understates it", in.prompt)
		}
		for _, other := range []string{"connector-call", "function-call", "api-call"} {
			if got := mapStepCostInputs(WorkflowStep{Type: other, Provider: "anthropic", Model: "claude"}, "rendered"); got != nil {
				t.Errorf("%s hands over %+v; only an LLM call spends tokens", other, got)
			}
		}
	})
	t.Run("the workflow step gate hands over nothing, whatever the caller declares", func(t *testing.T) {
		// THE STEP GATE'S STEP IS THE CALLER'S DECLARATION (#4249 row
		// 5664825929, ruled): provider, model and step_input are ordinary JSON
		// fields of the gate request. An estimate from them would be the
		// caller's claim with detector provenance, and a caller naming a
		// provider priced at zero would satisfy an organization's constraint
		// over the cost that REFUSES today. The adapter therefore states
		// nothing, and this is the case that must not start being stated.
		free := &workflow_control.StepGateContext{
			StepType: workflow_control.StepTypeLLMCall, Provider: "ollama", Model: "llama3",
			StepInput: map[string]interface{}{"prompt": "summarise", "max_tokens": float64(2000000)},
		}
		req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(free)
		if req.stepCost != nil {
			t.Fatalf("the step gate handed over %+v; its step is the caller's declaration, so the platform measures nothing from it", req.stepCost)
		}
		p := pricedAt(testFactProducer(t, seedDynamicRows(t)), 0, true) // a provider priced at zero, as ollama is
		if got, stated := produceFacts(t, p, req)["signal.cost_estimate"]; stated {
			t.Fatalf("the step gate states signal.cost_estimate = %v for a caller-declared free provider; a constraint over it must stay unknown_constraint, which refuses", got.Value)
		}
	})
}

// THE SHIPPED ADVISORY FIRES AGAIN, on the real engine over the seeded rows:
// an expensive step attaches the notification the control carries, a cheap one
// attaches none, and an unpriced step is decided exactly as before this change
// - the advisory skipped, the step decided.
func TestTheExpensiveQueryAdvisoryFiresOverAPricedStep(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	act := wcpActivation(t)
	rows := seedDynamicRows(t)
	const query = "summarise the quarter"

	notified := func(dec *contract.Decision) bool {
		return slices.ContainsFunc(dec.Obligations, func(o contract.Obligation) bool {
			return strings.HasPrefix(o.SourcePolicy, expensiveQueryControl)
		})
	}

	// decideStep presents tool.call; an llm-call step is presented as
	// llm.completion in production (step_action_admission.go), and the shipped
	// advisories select any action, so both reach them. The completion is what
	// this cell drives, so the cell is about the step the fact describes.
	expensive := decideOnCompletion(t, act, query, produceFacts(t, pricedAt(testFactProducer(t, rows), 150.25, true), llmStepRequest(t, nil)))
	if !notified(expensive) {
		t.Fatalf("an estimate of 150.25 attached %+v; want the %s advisory, which reads signal.cost_estimate > 100", expensive.Obligations, expensiveQueryControl)
	}
	// IT IS NAMED AS A MATCHED REQUIREMENT, which is what the step gate's
	// answer carries in policy_ids on an allow (EvaluatedPolicies reads
	// Determining.MatchedRequirement), and what runtime-e2e/3564's leg asserts
	// on a booted stack.
	if !slices.ContainsFunc(expensive.Determining.MatchedRequirement, func(id string) bool {
		return strings.HasPrefix(id, expensiveQueryControl)
	}) {
		t.Fatalf("the advisory is not named among the matched requirements %v, so the gate's policy_ids would not carry it", expensive.Determining.MatchedRequirement)
	}
	// AND IT IS THE FIRST DECIDING POLICY (master R3 round 1, LOW-9). E6d does
	// not read the whole list: it reads the leading entry, as the multi-agent
	// seam does when it names the deciding policy on an allow
	// (anchoredenforcer.DecidingPolicies(dec)[0], map_enforcing_seam.go). A
	// reordering that left the advisory in the list but not first would leave
	// this cell green and red the suite leg, so the ordering the leg reads is
	// pinned here, beside the membership it rests on.
	deciding := anchoredenforcer.DecidingPolicies(expensive)
	if len(deciding) == 0 || !strings.HasPrefix(deciding[0], expensiveQueryControl) {
		t.Fatalf("the deciding policies are %v; runtime-e2e/3564's E6d reads the first one and expects %s", deciding, expensiveQueryControl)
	}
	if expensive.State != contract.StateAllow {
		t.Fatalf("an advisory answered %s %s; a warn requirement never refuses", expensive.State, expensive.Reason)
	}
	cheap := decideOnCompletion(t, act, query, produceFacts(t, pricedAt(testFactProducer(t, rows), 0.25, true), llmStepRequest(t, nil)))
	if notified(cheap) {
		t.Fatalf("an estimate of 0.25 attached the advisory: %+v", cheap.Obligations)
	}
	unpriced := decideOnCompletion(t, act, query, produceFacts(t, pricedAt(testFactProducer(t, rows), 0, false), llmStepRequest(t, nil)))
	if notified(unpriced) {
		t.Fatalf("a deployment with no pricing attached the advisory: %+v", unpriced.Obligations)
	}
	if unpriced.State == contract.StateError {
		t.Fatalf("a deployment with no pricing answered %s %s; an unstated advisory input is skipped, never a refusal", unpriced.State, unpriced.Reason)
	}
}

// THE PRODUCTION PATH, not an installed fake: newDynamicFactProducer wires the
// DEPLOYMENT's pricing (deploymentStepCost), so what a deployment that wires
// none states is what this cell measures. The cells above install their own
// estimator and would pass whatever the wiring did.
func TestADeploymentWithNoPricingWiredStatesNoEstimate(t *testing.T) {
	previous := stepCostPricing.Load()
	previousSet := stepCostRoutable.Load()
	t.Cleanup(func() { stepCostPricing.Store(previous); stepCostRoutable.Store(previousSet) })

	// THE SECOND PRODUCTION WIRING, through its own setter: the registered set
	// the ceiling is taken over, and what says a declared pair is this
	// deployment's (master R3 round 2, LOW-D). deploymentRoutableCandidates is
	// what newDynamicFactProducer wires, so this drives that reader too.
	setStepCostRoutable(func() []stepCostCandidate {
		return []stepCostCandidate{{provider: "openai", model: "gpt-4o"}}
	})

	// THE PRODUCTION CONSTRUCTOR'S OWN WIRING: testFactProducer builds through
	// newDynamicFactProducer, so estimateCost is whatever production wires.
	// Assigning it here - which this cell used to do - would have made it pass
	// with that wiring deleted, and production would then have stated nothing
	// for ever.
	p := testFactProducer(t, seedDynamicRows(t))
	const path = "signal.cost_estimate"

	stepCostPricing.Store(nil)
	if got, stated := produceFacts(t, p, llmStepRequest(t, nil))[path]; stated {
		t.Fatalf("%s = %v with no pricing wired; a deployment that prices nothing states nothing, and 0 would read as cheap", path, got.Value)
	}

	// The same producer, once the process wires pricing at boot.
	setStepCostPricing(func(provider, model string, in, out int) (float64, bool) {
		if provider != "openai" || model != "gpt-4o" {
			return 0, false
		}
		return 175.5, true
	})
	got, stated := produceFacts(t, p, llmStepRequest(t, nil))[path]
	if !stated || got.Value != 175.5 {
		t.Fatalf("%s stated=%v value=%v with pricing wired; want 175.5", path, stated, got.Value)
	}
	// A provider this deployment has not registered falls to the ceiling over
	// the registered set (LOW-D): the router would not call that provider
	// either. With NO model declared, each candidate is priced at its own
	// configured model, so the one registered candidate's price is the ceiling.
	unregisteredProvider := llmStepRequest(t, nil)
	unregisteredProvider.stepCost = mapStepCostInputs(WorkflowStep{Type: "llm-call", Provider: "mistral", Prompt: "p"}, "p")
	if got, stated := produceFacts(t, p, unregisteredProvider)[path]; !stated || got.Value != 175.5 {
		t.Fatalf("%s stated=%v value=%v for a step naming an unregistered provider and no model; want the ceiling over the registered set, 175.5", path, stated, got.Value)
	}
	// But a DECLARED MODEL is what the call sends, whoever runs it (master R3
	// round 3, MEDIUM-C), so the same step declaring `small` is priced at
	// `small` on every candidate - and this deployment's pricer knows only
	// gpt-4o, so the fact goes rather than being stated at gpt-4o's price.
	// Stating 175.5 here would be a number no call could produce.
	unpriceableModel := llmStepRequest(t, nil)
	unpriceableModel.stepCost = mapStepCostInputs(WorkflowStep{Type: "llm-call", Provider: "mistral", Model: "small", Prompt: "p"}, "p")
	if got, stated := produceFacts(t, p, unpriceableModel)[path]; stated {
		t.Fatalf("%s = %v for a step declaring a model this deployment cannot price; want unstated", path, got.Value)
	}
	// And with NOTHING registered there is no ceiling to take, so the fact goes
	// whatever the step declares.
	setStepCostRoutable(func() []stepCostCandidate { return nil })
	if got, stated := produceFacts(t, p, llmStepRequest(t, nil))[path]; stated {
		t.Fatalf("%s = %v on a deployment with no provider registered; want unstated", path, got.Value)
	}
}

// THE TOKEN ESTIMATE IS THE PLANNER'S, AND IT IS THE STEP'S (R3 self-round,
// HIGH): a pricer that ignores its token arguments makes every cell above pass
// with the counts zeroed, swapped or taken from another step. This one records
// what it was priced with.
func TestTheEstimateIsPricedOnTheStepsOwnTokens(t *testing.T) {
	rows := seedDynamicRows(t)
	var gotIn, gotOut int
	record := func(step WorkflowStep) {
		p := testFactProducer(t, rows)
		p.estimateCost = func(_, _ string, in, out int) (float64, bool) {
			gotIn, gotOut = in, out
			return 1, true
		}
		registering(p, stepCostCandidate{provider: "openai", model: "gpt-4o"})
		req := stepFactRequest("summarise the quarter", nil)
		req.stepCost = mapStepCostInputs(step, step.Prompt)
		if _, stated := produceFacts(t, p, req)["signal.cost_estimate"]; !stated {
			t.Fatal("PREMISE: the fact is not stated, so nothing was priced")
		}
	}
	base := WorkflowStep{Type: "llm-call", Provider: "openai", Model: "gpt-4o", Prompt: "one", MaxTokens: 512}

	record(base)
	shortIn, shortOut := gotIn, gotOut
	if shortIn <= 0 {
		t.Fatalf("a step was priced on %d input tokens; the estimate is not the step's", shortIn)
	}
	// THE OUTPUT CEILING IS THE OUTPUT ESTIMATE, which is estimateStepTokens'
	// own rule, and it is what tells the two counts apart: swapping them fails
	// here.
	if shortOut != base.MaxTokens {
		t.Errorf("a step with max_tokens %d was priced on %d output tokens", base.MaxTokens, shortOut)
	}

	longer := base
	longer.Prompt = strings.Repeat("a longer prompt ", 64)
	record(longer)
	if gotIn <= shortIn {
		t.Errorf("a prompt %d times longer was priced on %d input tokens against %d; the prompt is not counted", len(longer.Prompt)/len(base.Prompt), gotIn, shortIn)
	}

	withSchema := base
	withSchema.Output = map[string]interface{}{"summary": "string", "rows": "number"}
	record(withSchema)
	if gotIn <= shortIn {
		t.Errorf("a step declaring an output schema was priced on %d input tokens against %d; the schema is not counted", gotIn, shortIn)
	}
}

// decideOnCompletion is decideStep presenting llm.completion, the action a step
// that spends tokens is presented as.
func decideOnCompletion(t *testing.T, act *activation.Activation, query string, facts contract.AttributeSet) *contract.Decision {
	t.Helper()
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	v := stepDecisionEnforcer(t).Evaluate(context.Background(), anchoredenforcer.Call{
		Scope:     mapSeamScope,
		OrgID:     "org-a",
		RequestID: "map_step_1",
		Action:    authoringcatalog.ActionLLMCompletion,
		Subject:   headerCredentialSubject(h),
		Query:     query,
		Facts:     facts,
	})
	if v.Unavailable != "" || v.Refusal != nil || v.Decision == nil {
		t.Fatalf("PREMISE: no decision for %q (unavailable %q, refusal %+v)", query, v.Unavailable, v.Refusal)
	}
	return v.Decision
}

// A STEP THAT NAMES NO PAIR IS PRICED AT A CEILING OVER WHAT COULD RUN IT
// (#4249 row 5664825929; master R3 round 1, HIGH-1, ruled to this shape).
//
// Every plan the planner generates is such a step - it writes name, type and
// prompt and no provider or model - so this is the production path, and the
// substituted number must be one no call could exceed. The alternative that was
// ruled OUT is the configured default: only the failover strategy routes to it,
// while the shipped default strategy is a weighted random draw, so a step
// priced at a cheap default can run on a dear provider and a constraint would
// have admitted it.
func TestAStepThatNamesNoPairIsPricedAtTheCeilingOverTheRoutableSet(t *testing.T) {
	const path = "signal.cost_estimate"
	rows := seedDynamicRows(t)
	prices := map[string]float64{"cheap/c-1": 1, "dear/d-1": 9}

	over := func(candidates ...stepCostCandidate) *dynamicFactProducer {
		p := testFactProducer(t, rows)
		p.estimateCost = func(provider, model string, _, _ int) (float64, bool) {
			usd, priced := prices[provider+"/"+model]
			return usd, priced
		}
		p.routable = func() []stepCostCandidate { return candidates }
		return p
	}
	// The step the planner writes: a type and a prompt, no provider, no model.
	plannerStep := func() OrchestratorRequest {
		req := stepFactRequest("summarise the quarter", nil)
		req.stepCost = mapStepCostInputs(
			WorkflowStep{Type: "llm-call", Prompt: "summarise the quarter", MaxTokens: 512},
			"summarise the quarter")
		return req
	}
	cheap := stepCostCandidate{provider: "cheap", model: "c-1"}
	dear := stepCostCandidate{provider: "dear", model: "d-1"}

	t.Run("the dearest of the routable set is stated, not the configured default", func(t *testing.T) {
		// The deployment's default names the CHEAP provider. The ceiling must
		// not follow it: under the shipped weighted strategy the draw can land
		// on the dear one, and 1 would be a number no policy could rely on.
		t.Setenv("LLM_DEFAULT_PROVIDER", "cheap")
		got, stated := produceFacts(t, over(cheap, dear), plannerStep())[path]
		if !stated {
			t.Fatalf("%s is unstated for a planner-generated step over two priced providers; the advisory stays skipped, which is what the row is about", path)
		}
		if got.Value != 9.0 {
			t.Fatalf("%s = %v; want the ceiling 9 over {cheap 1, dear 9}. A number below the ceiling admits a step that can cost more", path, got.Value)
		}
	})

	t.Run("one candidate this deployment cannot price makes the fact unstated", func(t *testing.T) {
		// Pricing the rest and stating their maximum would be a ceiling with a
		// gap above it - the permissive direction - so the whole fact goes.
		for name, set := range map[string][]stepCostCandidate{
			"an unpriced pair":        {cheap, {provider: "exotic", model: "x-1"}},
			"no configured model":     {cheap, {provider: "dear"}},
			"nothing routable at all": nil,
		} {
			if got, stated := produceFacts(t, over(set...), plannerStep())[path]; stated {
				t.Errorf("%s: %s = %v; want unstated", name, path, got.Value)
			}
		}
	})

	t.Run("a single routable candidate is priced at exactly that pair", func(t *testing.T) {
		got, stated := produceFacts(t, over(dear), plannerStep())[path]
		if !stated || got.Value != 9.0 {
			t.Fatalf("%s stated=%v value=%v over one candidate; want the pair's own 9", path, stated, got.Value)
		}
	})

	t.Run("a route row narrowing the call does not lower what is stated", func(t *testing.T) {
		// The organization's route rows reach the call as these context keys
		// (llm_call_route_effects.go) and can only NARROW the set the router
		// draws from. A ceiling over the wider set therefore stays a ceiling
		// under any of them, and the plane must never admit on a number below
		// what could run: the stated value is unchanged.
		req := plannerStep()
		req.Context = map[string]interface{}{
			"policy_preferred_provider": "cheap",
			"policy_allowed_providers":  []string{"cheap"},
		}
		got, stated := produceFacts(t, over(cheap, dear), req)[path]
		if !stated || got.Value != 9.0 {
			t.Fatalf("%s stated=%v value=%v with the call narrowed to the cheap provider; want the unchanged ceiling 9", path, stated, got.Value)
		}
	})

	t.Run("a declared MODEL is priced on every candidate, registered provider or not", func(t *testing.T) {
		// master R3 round 3, MEDIUM-C. The step's model travels in the request
		// context and the adapter sends it to whichever provider is selected,
		// which falls back to its own configured model only when the request
		// names none. So a step naming a model this deployment configures
		// NOWHERE must still be priced at that model: pricing it at each
		// candidate's configured model understates the ceiling wherever the
		// declared one is dearer, which is the permissive direction.
		dearModel := stepCostCandidate{provider: "cheap", model: "c-1"}
		p := testFactProducer(t, rows)
		p.routable = func() []stepCostCandidate { return []stepCostCandidate{dearModel} }
		p.estimateCost = func(_, model string, _, _ int) (float64, bool) {
			if model == "d-9" {
				return 900, true
			}
			return 1, true
		}
		req := stepFactRequest("summarise the quarter", nil)
		// A model this deployment configures nowhere, and a provider it has
		// not registered either: the call still SENDS d-9.
		req.stepCost = mapStepCostInputs(
			WorkflowStep{Type: "llm-call", Provider: "unregistered", Model: "d-9", Prompt: "summarise the quarter", MaxTokens: 512},
			"summarise the quarter")
		got, stated := produceFacts(t, p, req)[path]
		if !stated || got.Value != 900.0 {
			t.Fatalf("%s stated=%v value=%v for a step declaring model d-9; want 900, the price of the model the call SENDS. Pricing the candidate's configured c-1 instead states 1 and admits a step that costs 900", path, stated, got.Value)
		}
		// The same with no provider named at all.
		req.stepCost = mapStepCostInputs(
			WorkflowStep{Type: "llm-call", Model: "d-9", Prompt: "summarise the quarter", MaxTokens: 512},
			"summarise the quarter")
		if got, stated := produceFacts(t, p, req)[path]; !stated || got.Value != 900.0 {
			t.Fatalf("%s stated=%v value=%v for a model-only step; want the declared model's 900", path, stated, got.Value)
		}
	})

	t.Run("a step that names only its provider is priced at that provider's configured model", func(t *testing.T) {
		req := stepFactRequest("summarise the quarter", nil)
		req.stepCost = mapStepCostInputs(
			WorkflowStep{Type: "llm-call", Provider: "cheap", Prompt: "summarise the quarter", MaxTokens: 512},
			"summarise the quarter")
		got, stated := produceFacts(t, over(cheap, dear), req)[path]
		if !stated || got.Value != 1.0 {
			t.Fatalf("%s stated=%v value=%v for a step naming the cheap provider; want that provider's own 1", path, stated, got.Value)
		}
	})
}

// THE ESTIMATE FOLLOWS THE CALLER'S INPUT UPWARDS, through the rendering the
// plane actually decides (master R3 round 1, MEDIUM-3).
//
// mapStepContent renders `{{input.*}}` from the execute request's context, so
// the text the step will send is longer than its template whenever it
// interpolates anything. Pricing the template would let `cost_estimate <= N`
// admit a step whose real prompt is far larger. The caller can raise the number
// and cannot lower it below the plan author's own text, so a constraint here is
// still not the caller's to choose.
func TestALongerCallerInputRaisesTheEstimate(t *testing.T) {
	step := WorkflowStep{Name: "s", Type: "llm-call", Provider: "openai", Model: "gpt-4o", Prompt: "summarise {{input.q}}", MaxTokens: 256}

	priceOf := func(t *testing.T, callerInput string) (float64, int) {
		t.Helper()
		content := StepContent{Input: map[string]interface{}{"q": callerInput}, Processor: NewLLMCallProcessor(nil)}
		query, err := mapStepContent(step, content, mapExecution())
		if err != nil {
			t.Fatalf("PREMISE: the step's content did not render: %v", err)
		}
		if !strings.Contains(query, callerInput) {
			t.Fatalf("PREMISE: the rendering %q does not carry the caller's input, so this cell measures nothing", query)
		}
		tokensIn := 0
		p := testFactProducer(t, seedDynamicRows(t))
		p.estimateCost = func(_, _ string, in, _ int) (float64, bool) {
			tokensIn = in
			return float64(in), true
		}
		registering(p, stepCostCandidate{provider: "openai", model: "gpt-4o"})
		req := stepFactRequest(query, nil)
		req.stepCost = mapStepCostInputs(step, query)
		got, stated := produceFacts(t, p, req)["signal.cost_estimate"]
		if !stated {
			t.Fatal("PREMISE: nothing was priced, so no estimate was compared")
		}
		usd, ok := got.Value.(float64)
		if !ok {
			t.Fatalf("PREMISE: the estimate is %T, not a number", got.Value)
		}
		return usd, tokensIn
	}

	short, shortTokens := priceOf(t, "the quarter")
	long, longTokens := priceOf(t, strings.Repeat("the quarter in detail ", 200))
	if longTokens <= shortTokens {
		t.Errorf("a caller input ~200 times longer was priced on %d input tokens against %d; the rendering is not counted", longTokens, shortTokens)
	}
	if long <= short {
		t.Errorf("the estimate did not rise with the caller's input: %v against %v", long, short)
	}
}

// A PLAN THE PLANNER GENERATED STATES THE FACT (master R3 round 1, HIGH-1).
//
// This is the production path the row is about: GeneratePlan, not a seeded
// plan. The planner writes name, type and prompt on every step it produces and
// NEVER a provider or a model - the generation schema, the synthesis step and
// the template step all omit them - which is why an unnamed step had to become
// priceable at all. The cell drives GeneratePlan on both of its arms (the LLM's
// own plan and the template fallback), asserts the premise that the steps name
// no pair, and then prices step one as the plane does.
func TestAPlannerGeneratedPlanStatesTheCostEstimate(t *testing.T) {
	const path = "signal.cost_estimate"
	withLLMCallRouteSource(t, &recordingRouteFacts{}, nil)

	plans := map[string]*recordingLLMRouter{}
	// The LLM's own plan: the schema the planner asks for, which carries no
	// provider or model on a step.
	fromLLM := newRecordingLLMRouter()
	fromLLM.routeRequestFn = func(_ context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
		return &LLMResponse{Content: `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"generated"},"spec":{"steps":[` +
				`{"name":"research","type":"llm-call","prompt":"research the quarter's filings in detail"}]}}`},
			&ProviderInfo{Provider: "stand-in"}, nil
	}
	plans["the LLM's own plan"] = fromLLM
	// The template fallback: the router fails, and the planner still produces
	// a plan, still with no pair on any step.
	fromTemplate := newRecordingLLMRouter()
	fromTemplate.routeRequestFn = func(_ context.Context, _ OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
		return nil, nil, errors.New("no provider answered")
	}
	plans["the template fallback"] = fromTemplate

	for name, router := range plans {
		t.Run(name, func(t *testing.T) {
			engine := NewPlanningEngine(router)
			workflow, err := engine.GeneratePlan(context.Background(), PlanGenerationRequest{
				Query: "summarise the quarter's filings", ClientID: "client-a", RequestID: "req-a",
			})
			if err != nil {
				t.Fatalf("PREMISE: the planner generated no plan: %v", err)
			}
			var step WorkflowStep
			for _, s := range workflow.Spec.Steps {
				if s.Type == "llm-call" {
					step = s
					break
				}
			}
			if step.Name == "" {
				t.Fatalf("PREMISE: the generated plan has no llm-call step: %+v", workflow.Spec.Steps)
			}
			// THE PREMISE HIGH-1 RESTS ON, asserted rather than assumed: no step
			// the planner generates names a provider or a model.
			for _, s := range workflow.Spec.Steps {
				if s.Provider != "" || s.Model != "" {
					t.Fatalf("PREMISE: the planner wrote provider %q model %q on step %q; this cell measures the unnamed path", s.Provider, s.Model, s.Name)
				}
			}

			p := testFactProducer(t, seedDynamicRows(t))
			p.estimateCost = func(provider, model string, _, _ int) (float64, bool) {
				if provider == "dear" && model == "d-1" {
					return 120, true
				}
				return 3, true
			}
			p.routable = func() []stepCostCandidate {
				return []stepCostCandidate{{provider: "cheap", model: "c-1"}, {provider: "dear", model: "d-1"}}
			}
			query, err := mapStepContent(step, StepContent{Input: map[string]interface{}{}, Processor: NewLLMCallProcessor(nil)}, mapExecution())
			if err != nil {
				t.Fatalf("PREMISE: the generated step did not render: %v", err)
			}
			req := stepFactRequest(query, nil)
			req.stepCost = mapStepCostInputs(step, query)
			got, stated := produceFacts(t, p, req)[path]
			if !stated {
				t.Fatalf("%s is unstated for a plan the planner generated; before this change every such plan skipped the advisory, which is the row", path)
			}
			if got.Value != 120.0 {
				t.Fatalf("%s = %v; want the ceiling 120 over the routable set", path, got.Value)
			}
		})
	}
}

// THE HAND-OVER AT THE SEAM IS DRIVEN, NOT ASSUMED (master R3 round 2,
// MEDIUM-A).
//
// Every cell above builds `req.stepCost` itself, so deleting the hand-over in
// mapStepDecide - or handing over the step's TEMPLATE instead of the presented
// content - left the whole package green and was caught only by a suite that
// has not run yet. This one goes through mapStepDecide, the production path, and
// asserts what the audit row carries: the allow's PolicyID, which is
// DecidingPolicies(dec)[0] and is exactly what E6d reads off a booted stack.
//
// THE STEP IS CHEAP AS WRITTEN AND EXPENSIVE AS SENT: its template is a few
// tokens, and the caller's input makes the presented content long. So a
// hand-over of `step.Prompt` reds it (the advisory does not fire), and so does
// no hand-over at all.
func TestTheSeamPricesThePresentedContentOfTheStepItDecides(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "development")
	withSeededMAPPlane(t)

	previousPricing, previousSet := stepCostPricing.Load(), stepCostRoutable.Load()
	t.Cleanup(func() { stepCostPricing.Store(previousPricing); stepCostRoutable.Store(previousSet) })
	// A deployment that prices its one registered provider per input token, so
	// the estimate is a function of the text length alone and the threshold
	// (100) sits between the template and the rendering.
	setStepCostRoutable(func() []stepCostCandidate {
		return []stepCostCandidate{{provider: "wt-registered", model: "m-1"}}
	})
	setStepCostPricing(func(_, _ string, tokensIn, _ int) (float64, bool) {
		return float64(tokensIn), true
	})

	step := WorkflowStep{Name: "draft", Type: "llm-call", Prompt: "summarise {{input.q}}"}
	long := strings.Repeat("the quarter in detail ", 200)
	content := StepContent{Input: map[string]interface{}{"q": long}, Processor: NewLLMCallProcessor(nil)}

	// PREMISE: the template alone is under the threshold and the presented
	// content is over it, or this cell cannot tell the two apart.
	template, _ := estimateStepTokens(WorkflowStep{Prompt: step.Prompt})
	presented, err := mapStepContent(step, content, mapExecution())
	if err != nil {
		t.Fatalf("PREMISE: the step did not render: %v", err)
	}
	rendered, _ := estimateStepTokens(WorkflowStep{Prompt: presented})
	if !(float64(template) <= 100 && float64(rendered) > 100) {
		t.Fatalf("PREMISE: template %d tokens, presented %d; the threshold 100 must separate them", template, rendered)
	}

	result := decideMAPStep(t, step, content)
	if result == nil || !result.Allowed {
		t.Fatalf("the step was not allowed: %+v; an advisory never refuses", result)
	}
	if !strings.HasPrefix(result.PolicyID, expensiveQueryControl) {
		t.Fatalf("the seam's allow names %q; want the %s advisory, which is what the step's audit row carries and what runtime-e2e/3564's E6d reads. A hand-over of the template, or none at all, answers exactly this way",
			result.PolicyID, expensiveQueryControl)
	}

	// THE CONTROL: the same step with a SHORT input is under the threshold, so
	// the advisory is silent - which is what makes the assertion above a
	// measurement of the estimate rather than of the seam's wiring in general.
	short := decideMAPStep(t, step, StepContent{Input: map[string]interface{}{"q": "it"}, Processor: NewLLMCallProcessor(nil)})
	if short == nil || !short.Allowed {
		t.Fatalf("the short step was not allowed: %+v", short)
	}
	if strings.HasPrefix(short.PolicyID, expensiveQueryControl) {
		t.Fatalf("a step whose presented content is %d tokens named the expensive-query advisory", template)
	}
}

// stepCostStubProvider is a registered provider with no behaviour: the reader
// under test reads the registry's CONFIG, never the provider itself.
type stepCostStubProvider struct{ name string }

func (p *stepCostStubProvider) Name() string            { return p.name }
func (p *stepCostStubProvider) Type() llm.ProviderType  { return llm.ProviderTypeOpenAI }
func (p *stepCostStubProvider) SupportsStreaming() bool { return false }
func (p *stepCostStubProvider) Capabilities() []llm.Capability {
	return nil
}
func (p *stepCostStubProvider) Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return nil, errors.New("the stub never completes")
}
func (p *stepCostStubProvider) HealthCheck(context.Context) (*llm.HealthCheckResult, error) {
	return &llm.HealthCheckResult{Status: llm.HealthStatusHealthy}, nil
}
func (p *stepCostStubProvider) EstimateCost(llm.CompletionRequest) *llm.CostEstimate { return nil }

// THE PRODUCTION READER, ON A REAL REGISTRY (master R3 round 2, MEDIUM-A).
//
// routerRoutableCandidates was pinned by nothing: no test named it, so the set
// it reads and the model it reads per candidate were whatever the last edit
// left. This drives it on an llm.Registry built here.
//
// THE SET IS EVERY REGISTERED PROVIDER, healthy or not, enabled or not
// (MEDIUM-B): a preferred-provider route row is resolved by Registry.Get, which
// ignores both, so a ceiling over the healthy set alone could be below what
// runs.
func TestTheRoutableSetIsEveryRegisteredProviderAtItsConfiguredModel(t *testing.T) {
	reg := llm.NewRegistry()
	register := func(name, model string, enabled bool) {
		t.Helper()
		if err := reg.RegisterProvider(name, &stepCostStubProvider{name: name}, &llm.ProviderConfig{
			Name: name, Type: llm.ProviderTypeOpenAI, APIKey: "k", Model: model, Enabled: enabled,
		}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	register("cheap", "c-1", true)
	// DISABLED AND NEVER HEALTH-CHECKED, so it is in neither the healthy set
	// nor the enabled one - and still reachable through a route row.
	register("dear", "d-1", false)

	router := llm.NewUnifiedRouter(llm.UnifiedRouterConfig{Registry: reg})
	got := routerRoutableCandidates(router)()
	want := map[string]string{"cheap": "c-1", "dear": "d-1"}
	if len(got) != len(want) {
		t.Fatalf("the routable set is %+v; want every registered provider %v", got, want)
	}
	for _, c := range got {
		model, registered := want[c.provider]
		if !registered {
			t.Errorf("the routable set carries %q, which is not registered", c.provider)
			continue
		}
		if c.model != model {
			t.Errorf("%s is paired with model %q; want its CONFIGURED %q, never a provider package's default", c.provider, c.model, model)
		}
	}

	// A PROVIDER WITH NO CONFIGURED MODEL IS KEPT, with an empty model, which is
	// what makes the whole estimate unstated: dropping it would leave a ceiling
	// with a gap above it.
	register("unmodelled", "", true)
	got = routerRoutableCandidates(router)()
	found := false
	for _, c := range got {
		if c.provider == "unmodelled" {
			found = true
			if c.model != "" {
				t.Errorf("unmodelled is paired with %q; want the empty model its config carries", c.model)
			}
		}
	}
	if !found {
		t.Fatalf("the routable set %+v drops a provider with no configured model; the estimate must go unstated instead", got)
	}
	p := testFactProducer(t, seedDynamicRows(t))
	p.estimateCost = func(string, string, int, int) (float64, bool) { return 500, true }
	p.routable = routerRoutableCandidates(router)
	req := stepFactRequest("summarise the quarter", nil)
	req.stepCost = mapStepCostInputs(WorkflowStep{Type: "llm-call", Prompt: "summarise the quarter"}, "summarise the quarter")
	if got, stated := produceFacts(t, p, req)["signal.cost_estimate"]; stated {
		t.Fatalf("signal.cost_estimate = %v with a registered provider that has no configured model; want unstated", got.Value)
	}

	// A router with no registry states nothing rather than panicking.
	if c := routerRoutableCandidates(nil)(); c != nil {
		t.Errorf("a nil router answers %+v; want no candidates", c)
	}
}
