// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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
//   - unknown: a value of the wrong type (malformed_value), never a guess;
//   - not stated: a path no row governing this caller reads; env.environment on
//     a process that declares no ENVIRONMENT; and signal.cost_estimate, whose
//     only source is the caller's context. The engine reads a missing fact as
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

// dynamicFactRows returns the dynamic_policies rows that govern orgID for a
// caller in segmentIDs, with their conditions parsed. The production source is
// the dynamic engine's organization-scoped list (ListActivePoliciesForTenant),
// which gates each cached row through the same predicate evaluation used.
type dynamicFactRows func(orgID string, segmentIDs []string) []DynamicPolicy

// dynamicFactProducer produces the facts. It holds no verdict method.
type dynamicFactProducer struct {
	rows     dynamicFactRows
	segments func(ctx context.Context, orgID, email string) ([]string, bool)
	// environment is the deployment's environment: the process's ENVIRONMENT.
	environment func() string
	// presentsNoContent marks a plane that hands policy NO CONTENT AT ALL, so
	// every content detector's answer is determined without running one: there
	// is nothing to run it over. The workflow step gate is such a plane - it
	// builds its policy request with no content field, and every content
	// condition there has evaluated over an empty string for as long as the
	// plane has existed (#4254, and the v11.1.0 row that would change it).
	//
	// It is a STATEMENT ABOUT THE PLANE, not a computation over empty content.
	// Computing a detector over "" would answer the same way today and would be
	// a fabricated false the moment the plane starts presenting something: the
	// difference between "nothing was presented" and "we looked and found
	// nothing" is the one this codebase is built on (sharedpolicy.DetectorFact.Ran).
	presentsNoContent bool
	types             map[string]pdp.ValueType
	now               func() time.Time
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
		rows:        rows,
		segments:    resolveUserSegments,
		environment: func() string { return os.Getenv("ENVIRONMENT") },
		types:       types,
		now:         func() time.Time { return time.Now().UTC() },
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
	segments, ok := p.segments(ctx, req.User.OrgID, req.User.Email)
	if !ok {
		return nil, routeEffects{}, errDynamicFactsUnavailable
	}
	now := p.now()
	// The platform-computed risk score is the matcher's floor, and here it is
	// the whole figure: no matched row raises it.
	state := &PolicyEvaluationResult{RiskScore: dbRiskCalculator.CalculateRiskScore(req)}
	resolve := func(field string) (any, bool) { return dynamicFieldValue(field, req, state), true }

	facts := contract.AttributeSet{}
	detectors := map[string]bool{}
	var routes routeEffects
	// The rows come in the order evaluation walks them, which the route merge
	// depends on (ListActivePoliciesForTenant).
	for _, row := range p.rows(orgID, segments) {
		detector := legacycompile.DynamicContentDetectorPath(row.ID)
		steers := rowCarriesRouteAction(row)
		applies := true
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
				matched := dbConditionEvaluator.Match(mc, resolve, dbUnevaluableRecorder)
				prev, seen := detectors[detector]
				detectors[detector] = matched && (!seen || prev)
				applies = applies && matched
				continue
			}
			// A route row applies only when this condition holds too. Evaluated
			// only until the row is known not to apply, as evaluation does.
			if steers && applies && !dbConditionEvaluator.Match(mc, resolve, dbUnevaluableRecorder) {
				applies = false
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
				}
			}
		}
	}
	for path, matched := range detectors {
		if _, declared := p.types[path]; declared {
			facts[path] = contract.Known(matched, contract.ProvDetector, 1, now)
		}
	}
	return facts, routes, nil
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
	if path == "principal.region" {
		return contract.Absent(prov, 1, now), true
	}
	if path == "signal.cost_estimate" {
		return contract.Attribute{}, false
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
