// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE DYNAMIC CONDITION MATCHER IS A FACT PRODUCER (#4254, PRD v11 §1.2, ruling R2).
//
// The corpus compiles every dynamic_policies row into typed policies over
// attribute paths (legacycompile.Options.AttributePathFor), and a row's content
// conditions into one detector per row (legacycompile.DynamicContentDetectorPath).
// On the workflow control plane and the multi-agent plane nothing else produces
// those attributes, so the matcher stays and emits them: the value each field
// resolves to (dynamicFieldValue, the matcher's own resolver) at the path the
// corpus reads it at, and each row's content verdict at its detector path.
//
// IT DECIDES NOTHING. There is no allowed flag, no required action and no
// escalation of the risk score by a matched row. The anchored engine decides
// from these facts.
//
// EACH FACT IS STATED KNOWN, ABSENT OR UNKNOWN, OR NOT STATED AT ALL, and each is
// a claim:
//   - known: the field resolved to a value of the type the corpus declares;
//   - absent: principal.region, which the orchestrator has no authenticated
//     source for (applyAuthoritativePrincipal zeroes it), and a caller-context
//     field the request does not carry;
//   - unknown: a value of the wrong type (malformed_value), never a guess; and a
//     row's content detector when a content condition of the row could not be
//     evaluated (malformed_value, #4249 row 5674229132);
//   - not stated: a path no row governing this caller reads; env.environment on
//     a process that declares no ENVIRONMENT; and signal.cost_estimate on a
//     request with no step to price, on a deployment that does not price the
//     pair the step names, and on one that cannot price everything an unnamed
//     step could be routed to, whose ceiling would otherwise have a gap above
//     it (#4249 row 5664825929; the caller's own context.cost_estimate is never
//     its source). The engine reads a missing fact as
//     unknown, so a constraint over it answers unknown_constraint and an
//     advisory requirement over it is skipped with a warning; a fabricated
//     value would be a permit.
//
// EVERY STATED FACT CARRIES THE PROVENANCE ITS NAMESPACE PERMITS
// (contract.Namespace.ValidateProvenance); the engine refuses any other as
// invalid_input. A signal is a detector's finding, so a caller's claim is never
// stated as one: that is why the cost estimate is not stated at all (#4254).
//
// THE ENVIRONMENT IS THE DEPLOYMENT'S, NEVER THE CALLER'S. env.* names the
// deployment, so env.environment is read from the process's ENVIRONMENT alone.
// The matcher's own resolver reads the request context's environment first,
// and a caller that sent environment=development there exempted itself from a
// constraint such as sys__dyn__debug__restrict, which the shipped posture blocks
// on wcp and map (shipped_posture.json); the producer does not repeat that read
// (#4254).
//
// Media facts are the one family stated known on a request that carries no
// media: nothing was attached, so no media signal fired (ruling Q3). With media
// attached they are read from the analysis this process wrote for the request,
// and are UNKNOWN when none was written or it lacks the signal. The caller's
// context.media_analysis is never read (R3 A-H2).

// errDynamicFactsUnavailable is the producer's outage: the caller's governance
// segments could not be resolved, so which rows govern the caller cannot be
// established.
var errDynamicFactsUnavailable = errors.New("the dynamic facts could not be produced: the caller's governance segments could not be resolved")

// dynamicFactRows is where the producer selects the dynamic_policies rows that
// govern orgID, with their conditions parsed. The production source is the
// dynamic engine, whose two lists gate each cached row through the one predicate
// evaluation used (dbCachedPolicyAppliesToOrg):
//   - ListActivePoliciesForTenant: the rows for a caller in segmentIDs, when the
//     caller's segment membership is established;
//   - ListActivePoliciesForOrgInEverySegment: the rows for a caller whose
//     membership is NOT established, who is treated as possibly in every
//     segment (ADR-067 Decision 4 step 1b).
type dynamicFactRows interface {
	ListActivePoliciesForTenant(orgID string, segmentIDs []string) []DynamicPolicy
	ListActivePoliciesForOrgInEverySegment(orgID string) []DynamicPolicy
}

// dynamicFactProducer produces the facts. It holds no verdict method.
type dynamicFactProducer struct {
	rows     dynamicFactRows
	segments func(ctx context.Context, orgID, email string) ([]string, bool)
	// environment is the deployment's environment: the process's ENVIRONMENT.
	environment func() string
	// presentsNoContent marks a plane that hands policy NO CONTENT AT ALL, so
	// every content detector's answer is determined without running one: there
	// is nothing to run it over. The step gates were such planes until #4249 row
	// 5666236540 made them present the step's input; since then NO production
	// producer sets it, and it remains the subject of the fixtures that pin
	// what such a plane states. It is kept a field rather than deleted so a
	// plane that genuinely presents nothing states it rather than computing
	// detectors over an empty string.
	//
	// It is a STATEMENT ABOUT THE PLANE, not a computation over empty content.
	// Computing a detector over "" would answer the same way today and would be
	// a fabricated false the moment the plane starts presenting something: the
	// difference between "nothing was presented" and "we looked and found
	// nothing" is the one this codebase is built on (sharedpolicy.DetectorFact.Ran).
	presentsNoContent bool
	// statesStepContext marks a plane whose request is a STEP - the workflow
	// step gate and the multi-agent plane - and which therefore states the
	// step's name and its tool beside the legacy rows' facts (#4249 row
	// 5670275054). See stepContextFacts. Set only through asStepPlane, so a
	// seam test and production configure a step plane the same way.
	statesStepContext bool
	// estimateCost prices the step a request will run, and reports whether this
	// deployment prices it at all (#4249 row 5664825929). Replaceable so a test
	// can install a deployment with no pricing, and so a seam test states the
	// same way production does.
	estimateCost func(provider, model string, tokensIn, tokensOut int) (float64, bool)
	// routable is the set of provider/model pairs this deployment's router may
	// route an unnamed step to, at decision time, read from the router's own
	// registry (#4249 row 5664825929, R3 round 1 HIGH-1). It is what the
	// estimate's CEILING is taken over. Replaceable for the same two reasons
	// estimateCost is.
	routable func() []stepCostCandidate
	types    map[string]pdp.ValueType
	now      func() time.Time
}

// newDynamicFactProducer builds a producer over rows, typed by the shipped
// corpus's attribute schema.
func newDynamicFactProducer(rows dynamicFactRows) (*dynamicFactProducer, error) {
	if rows == nil {
		return nil, errors.New("the dynamic fact producer needs the dynamic rows it reads, and none were given")
	}
	types, err := shippedAttributeTypes()
	if err != nil {
		return nil, err
	}
	return &dynamicFactProducer{
		rows:         rows,
		segments:     resolveUserSegments,
		environment:  func() string { return os.Getenv("ENVIRONMENT") },
		estimateCost: deploymentStepCost,
		routable:     deploymentRoutableCandidates,
		types:        types,
		now:          func() time.Time { return time.Now().UTC() },
	}, nil
}

// shippedAttributeTypes is the type the shipped corpus declares for each
// attribute path, across the system document and the organization template.
func shippedAttributeTypes() (map[string]pdp.ValueType, error) {
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		return nil, err
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	out := map[string]pdp.ValueType{}
	for _, doc := range []*pdp.Document{corpus, template} {
		for _, a := range doc.Attributes {
			out[a.Path] = a.Type
		}
	}
	return out, nil
}

// Produce returns the facts the dynamic rows governing req's caller read, and
// beside them the route effects of the rows that
// apply to req (routeEffects). The effects are a second output and never an
// attribute: the engine decides from the facts alone.
//
// A ROW APPLIES ONLY WHEN EVERY ONE OF ITS CONDITIONS HOLDS over the request,
// the rule the dynamic engine's evaluation applies before it reads a row's
// actions. A content condition holds through the producer's own detector result,
// so on a plane that presents no content it never holds, and a route row
// conditioned on content never steers there. Only rows that carry a route action
// are evaluated as a whole: no other row's applicability is read.
//
// It is the producer's ONE entry point, and the call-site census's dynamic
// fact producer evaluator (legacy_call_sites.tsv): every call of it is a
// censused call site, so a plane that needs only the facts drops the effects.
func (p *dynamicFactProducer) Produce(ctx context.Context, req OrchestratorRequest) (contract.AttributeSet, routeEffects, error) {
	// The organization the rows are selected for is the one evaluation used:
	// the credential's copy first, then the user's (#3490).
	orgID := req.Client.OrgID
	if orgID == "" {
		orgID = req.User.OrgID
	}
	// SEGMENT MEMBERSHIP NOT ESTABLISHED MEANS EVERY SEGMENT, NEVER NONE
	// (ADR-067 Decision 4 step 1b, #4249 row 5697957634). An email the agent did
	// not vouch for came from a caller's header (or was synthesised), so the
	// segments it would resolve to are the caller's choice: naming someone else's
	// email used to select that person's segment rows and drop the caller's own
	// restrictions. Such a caller gets every segment-scoped row together with the
	// unsegmented ones. The email is not resolved at all: a resolution outage over
	// a caller-asserted email must not mask this outcome as
	// segment_resolution_failed.
	var rows []DynamicPolicy
	established := segmentMembershipEstablished(ctx, req)
	if established {
		segments, ok := p.segments(ctx, req.User.OrgID, req.User.Email)
		if !ok {
			return nil, routeEffects{}, errDynamicFactsUnavailable
		}
		rows = p.rows.ListActivePoliciesForTenant(orgID, segments)
	} else {
		rows = p.rows.ListActivePoliciesForOrgInEverySegment(orgID)
	}
	now := p.now()
	// The platform-computed risk score is the matcher's floor, and here it is
	// the whole figure: no matched row raises it.
	state := &PolicyEvaluationResult{RiskScore: dbRiskCalculator.CalculateRiskScore(req)}
	resolve := func(field string) (any, bool) { return dynamicFieldValue(field, req, state), true }

	facts := contract.AttributeSet{}
	detectors := map[string]bool{}
	// unevaluable names the detectors a content condition could not be
	// evaluated for (#4249 row 5674229132): stated UNKNOWN, never false.
	unevaluable := map[string]bool{}
	var routes routeEffects
	// unsegmented is the same merge over the unsegmented rows alone, read only to
	// name a not-established refusal (routeEffects.SegmentNotEstablished).
	var unsegmented routeEffects
	// The rows come in the order evaluation walks them, which the route merge
	// depends on (ListActivePoliciesForTenant).
	for _, row := range rows {
		detector := legacycompile.DynamicContentDetectorPath(row.ID)
		steers := rowCarriesRouteAction(row)
		applies := true
		// This row's own recorder, so the producer can read back what the
		// process-wide one only counts.
		recorder := &rowUnevaluableRecorder{next: dbUnevaluableRecorder}
		for _, c := range row.Conditions {
			mc := sharedpolicy.MatchCondition{Field: c.Field, Operator: c.Operator, Value: c.Value}
			if legacycompile.IsContentOperator(mc.Operator) {
				if p.presentsNoContent {
					// THE PLANE PRESENTS NO CONTENT, so this row's content
					// verdict is determined without running its detector:
					// there was nothing for it to look at. Stated about the
					// plane, never computed over an empty string - see
					// presentsNoContent for why those are different claims.
					detectors[detector] = false
					applies = false
					continue
				}
				// One detector per row: did every content condition of the row
				// hold (legacycompile.DynamicContentDetectorPath).
				recorder.fired = false
				matched := dbConditionEvaluator.Match(mc, resolve, recorder)
				if recorder.fired {
					unevaluable[detector] = true
				}
				prev, seen := detectors[detector]
				detectors[detector] = matched && (!seen || prev)
				if recorder.fired {
					// THE ROW'S OWN RESTRICTION IS APPLIED, NEVER DROPPED,
					// when its condition cannot be evaluated (master R3 round
					// 1 on #4395, MEDIUM-1). `matched` is false here for a
					// reason that is not "the content did not match", so
					// folding it into `applies` would take a route row out of
					// the merge and let applyLLMCallRoutes route UNRESTRICTED:
					// the organization's restriction, dropped by a malformed
					// condition. The fail-closed reading of a restriction is
					// to apply it, which is what the compiled requirement
					// already does (mandatory -> indeterminate).
					continue
				}
				applies = applies && matched
				continue
			}
			// A route row applies only when this condition holds too. Evaluated
			// only until the row is known not to apply, as evaluation does.
			//
			// An UNEVALUABLE condition is not a "does not hold" (master R3
			// round 1 on #4395, MEDIUM-1): the row keeps applying, so its
			// restriction is enforced rather than silently dropped. The
			// recorder is reset first because the content arm above reads the
			// same flag for its detector, and a route condition's firing is
			// never a detector's unknown.
			if steers && applies {
				recorder.fired = false
				if !dbConditionEvaluator.Match(mc, resolve, recorder) && !recorder.fired {
					applies = false
				}
			}
			path := legacycompile.Options{}.AttributePathFor(c.Field)
			if _, stated := facts[path]; stated {
				continue
			}
			if fact, ok := p.fact(path, c.Field, req, state, now); ok {
				facts[path] = fact
			}
		}
		if steers && applies {
			for _, action := range row.Actions {
				if action.Type == "route" {
					routes.apply(action.Config)
					if row.SegmentID == "" {
						unsegmented.apply(action.Config)
					}
				}
			}
		}
	}
	for path, matched := range detectors {
		if _, declared := p.types[path]; declared {
			if unevaluable[path] {
				// A content condition of this row could not be evaluated (a
				// non-string pattern or field value): whether it matched is not
				// known, so the detector is UNKNOWN and a constraint reading it
				// answers unknown_constraint. Stating it false read as "did not
				// match" and let the row not apply where it should refuse
				// (#4249 row 5674229132). Unknown wins over a false from another
				// condition of the same row: the withheld reading is the
				// fail-closed one.
				facts[path] = contract.Unknown(contract.ReasonMalformedValue, contract.ProvDetector, 1, now)
				continue
			}
			facts[path] = contract.Known(matched, contract.ProvDetector, 1, now)
		}
	}
	// THE SECOND SOURCE: the step's own context, stated because the DEPLOYMENT
	// declares it, not because a legacy row reads it. An organization's typed
	// document is what reads these paths, and the producer never sees that
	// document, so gating them on a row would leave every such constraint
	// unknown on every step.
	if p.statesStepContext {
		for _, path := range stepContextPaths() {
			if _, stated := facts[path]; stated {
				continue
			}
			if fact, ok := p.fact(path, stepContextFacts[path], req, state, now); ok {
				facts[path] = fact
			}
		}
	}
	routes.SegmentNotEstablished = !established && routes.NothingPermitted() && !unsegmented.NothingPermitted()
	return facts, routes, nil
}

// rowUnevaluableRecorder is one row's UnevaluableRecorder: it notes that a
// condition could not be evaluated, so the producer can state the row's
// detector unknown, and forwards the occurrence to the process-wide recorder,
// whose metric is unchanged (#4249 row 5674229132).
type rowUnevaluableRecorder struct {
	next  sharedpolicy.UnevaluableRecorder
	fired bool
}

func (r *rowUnevaluableRecorder) RecordUnevaluable(reason string) {
	r.fired = true
	if r.next != nil {
		r.next.RecordUnevaluable(reason)
	}
}

// stepContextFacts maps each deployment-declared step-context argument to the
// request context key the step planes put it under: wcp_policy_adapter.go
// convertToOrchestratorRequest and map_enforcing_seam.go mapStepDecide. The
// multi-agent plane carries no tool name, so tool__name is ABSENT there and is
// in practice the workflow step gate's attribute (tool_context.tool_name).
//
// EVERY VALUE IS BODY-SUPPLIED. The step gate's name and its tool context come
// from the HTTP body of the gate call, and a multi-agent step's name from the
// POSTed plan; nothing on either path verifies them. So they are stated with
// caller provenance (factProvenance: args.*), a permission may not read them
// (pdp.CallerTypedLabelPaths), and a document can only narrow on them.
//
// A step's TYPE is deliberately absent: it is the ACTION the step is presented
// as (step_action_admission.go), selected with the action selector.
var stepContextFacts = map[string]string{
	"args.context.step__name": "step_name",
	"args.context.tool__name": "tool_name",
}

// stepContextPaths is stepContextFacts' paths in a stable order.
func stepContextPaths() []string {
	out := make([]string, 0, len(stepContextFacts))
	for path := range stepContextFacts {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// asStepPlane configures p for a plane whose request is a step: it states the
// step's context. It sets no presentsNoContent: a step plane presents the step's
// input as content (#4249 row 5666236540). The production constructors and the
// seam tests both configure a step plane through this, so a test cannot pin a
// step plane the production wiring does not build.
func asStepPlane(p *dynamicFactProducer) *dynamicFactProducer {
	p.statesStepContext = true
	return p
}

// fact states one non-content field at path, or reports that nothing is stated
// for it: the corpus declares no such attribute (the engine refuses a request
// carrying an attribute its documents do not declare); it is the cost estimate,
// which only the caller supplies and the contract admits only as a detector's
// finding; or it is the environment and the process declares none.
func (p *dynamicFactProducer) fact(path, field string, req OrchestratorRequest, state *PolicyEvaluationResult, now time.Time) (contract.Attribute, bool) {
	typ, declared := p.types[path]
	if !declared {
		return contract.Attribute{}, false
	}
	prov := factProvenance(path)
	if key, isStepContext := stepContextFacts[path]; isStepContext {
		// STATED ONLY ON A STEP PLANE, whichever source asked. A legacy row that
		// reads `step_name` would otherwise state the label on /api/v1/process
		// from the caller's body, so whether an organization's constraint fired
		// there would depend on an unrelated legacy row; off a step plane the
		// enforcer's own ABSENT stands, and a caller's value changes nothing.
		if !p.statesStepContext {
			return contract.Attribute{}, false
		}
		// ONE TYPING on a step plane. An EMPTY name is no name - the step gate
		// forwards "" when the body omits step_name - and a label's absence is a
		// non-match to the only conditions that may read it (pdp
		// checkCallerTypedLabels: a positive eq with on_absent no_match). A
		// non-string value is UNKNOWN malformed_value, which withholds a step a
		// matching constraint selects (fail-closed); neither plane can reach it
		// over HTTP, since both carry the step's name as a Go string.
		switch v := req.Context[key].(type) {
		case nil:
			return contract.Absent(prov, 1, now), true
		case string:
			if v == "" {
				return contract.Absent(prov, 1, now), true
			}
			return contract.Known(v, prov, 1, now), true
		default:
			return contract.Unknown(contract.ReasonMalformedValue, prov, 1, now), true
		}
	}
	if path == "principal.region" {
		return contract.Absent(prov, 1, now), true
	}
	if path == "signal.cost_estimate" {
		// THE PLATFORM'S OWN ESTIMATE, never the caller's context value
		// (step_cost_estimate.go). Unstated where there is no step to price or
		// no price for it, which is what every plane but the two step planes
		// answers, and what a deployment with no pricing answers everywhere.
		cost, priced := p.costEstimate(req)
		if !priced {
			return contract.Attribute{}, false
		}
		return contract.Known(cost, contract.ProvDetector, 1, now), true
	}
	if path == "env.environment" {
		env := p.environment()
		if env == "" {
			return contract.Attribute{}, false
		}
		return contract.Known(env, prov, 1, now), true
	}
	var value interface{}
	if strings.HasPrefix(path, "signal.media.") {
		var stated bool
		if value, stated = mediaSignal(field, req); !stated {
			return contract.Unknown(contract.ReasonNotSupplied, prov, 1, now), true
		}
		if value == nil {
			// No media is attached, so no media signal fired.
			switch typ {
			case pdp.TypeBoolean:
				return contract.Known(false, prov, 1, now), true
			case pdp.TypeNumber:
				return contract.Known(float64(0), prov, 1, now), true
			}
			return contract.Absent(prov, 1, now), true
		}
	} else if value = dynamicFieldValue(field, req, state); value == nil {
		return contract.Absent(prov, 1, now), true
	}
	switch typ {
	case pdp.TypeBoolean:
		if b, ok := value.(bool); ok {
			return contract.Known(b, prov, 1, now), true
		}
	case pdp.TypeNumber:
		if n, ok := factNumber(value); ok {
			return contract.Known(n, prov, 1, now), true
		}
	case pdp.TypeString:
		if s, ok := value.(string); ok {
			return contract.Known(s, prov, 1, now), true
		}
	default:
		return contract.Known(value, prov, 1, now), true
	}
	return contract.Unknown(contract.ReasonMalformedValue, prov, 1, now), true
}

// mediaSignal reads one media signal for req (R3 A-H2).
//
// With no media attached it answers (nil, true): nothing was attached, so no
// signal fired, and the fact is KNOWN at its zero. With media attached it answers
// the value the analysis this process wrote for the request carries, and
// (nil, false) when no analysis was written or the analysis does not carry the
// signal - an analysis that failed under the fail-open strategy, media
// governance disabled for the tenant, or no results. That is UNKNOWN, never a
// zero. The caller's context.media_analysis is never read: a caller's claim is
// not a detector finding.
func mediaSignal(field string, req OrchestratorRequest) (interface{}, bool) {
	if len(req.Media) == 0 {
		return nil, true
	}
	value, ok := req.mediaAnalysis[strings.TrimPrefix(field, "media.")]
	if !ok || value == nil {
		return nil, false
	}
	return value, true
}

// factProvenance is the provenance class of the source a path is read from.
// The decision contract permits one class per namespace family
// (contract.Namespace.ValidateProvenance), and the engine refuses any other as
// invalid_input. signal.risk_score is the platform's computation over the
// request's content, which the contract states as a detector signal as the
// conformance world does.
func factProvenance(path string) contract.Provenance {
	switch {
	case strings.HasPrefix(path, "args."):
		return contract.ProvCaller
	case strings.HasPrefix(path, "signal."):
		return contract.ProvDetector
	case strings.HasPrefix(path, "principal."):
		return contract.ProvAuthentication
	default:
		return contract.ProvPlatform
	}
}

// factNumber reads a numeric field value as a float64.
func factNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
