package agent

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"

	"axonflow/platform/shared/pep"
)

// The AuthZEN adapter: the total translation between the AuthZEN wire surface
// and the evaluation that already serves POST /api/v1/decide.
//
// # Why this is an adapter and not a second evaluator
//
// ADR-065's new Policy Decision Point does not answer this route before v11.
// It has no authored permission corpus yet, so answering from it would change
// customer decisions inside a minor release - the one thing a compatibility
// surface may not do. The route therefore maps onto the SAME evaluation the
// Decision API runs, and at v11 the engine behind it flips with no wire change,
// so an SDK user migrates once rather than twice.
//
// # The rule this file exists to enforce
//
// Every AuthZEN construct is either MAPPED or REFUSED. Nothing is ignored.
//
// That rule is the whole security argument for the surface. An adapter that
// accepted `context.department` and quietly evaluated without it would tell the
// caller a fact was weighed when it was not, and every audit of that decision
// inherits the claim. A caller who is told "I cannot evaluate department" can
// react; a caller silently given a decision that ignored it cannot. So an
// unrecognised member is an error naming its own JSON Pointer, never a default.
//
// The cost is that this mapping is deliberately NARROW. It covers what the
// legacy evaluator can actually read, and refuses the rest by name. Widening it
// is a matter of teaching the evaluator, not of loosening the adapter.

// authzenSubjectGateway is the only subject type this surface can evaluate
// today.
//
// The legacy evaluator derives the authenticated identity from the request's
// credentials, not from the body. A subject naming an END USER would therefore
// have to be either trusted from caller-supplied JSON - an impersonation surface
// - or dropped, and dropping it is the fail-open this adapter exists to prevent.
// So it is refused by name, with the reason, until the identity plane can
// resolve an end-user subject and bind it to the decision. That is a v11
// capability; see the migration notes.
const authzenSubjectGateway = "gateway"

// authzenAction maps an AuthZEN action name onto the evaluator's stage.
//
// The table is closed and explicit rather than derived from the string, because
// a derivation ("split on the dot") silently admits every action name anybody
// ever writes, and an action the evaluator does not recognise would then be
// evaluated as though it were one it does.
var authzenActionStage = map[string]string{
	"llm.completion": DecisionStageLLM,
	"tool.call":      DecisionStageTool,
	"agent.invoke":   DecisionStageAgent,
}

// authzenResourceStage maps an AuthZEN resource type onto the same stage, so
// the two halves of the request can be checked against each other.
var authzenResourceStage = map[string]string{
	"llm":   DecisionStageLLM,
	"tool":  DecisionStageTool,
	"agent": DecisionStageAgent,
}

// authzenContextMembers are the context members this adapter understands.
//
// `args` carries the content to evaluate. `correlation` carries the audit
// correlation keys. Everything else is refused: the evaluator has no way to
// read it, so accepting it would be the fail-open above.
const (
	authzenContextArgs        = "args"
	authzenContextCorrelation = "correlation"
	// authzenArgsQuery is the member carrying the content the policy engine
	// actually inspects. The evaluator requires it, so its absence is a
	// refusal rather than an empty evaluation.
	authzenArgsQuery = "query"
)

// mappedEvaluation is one projected AuthZEN entry translated into the legacy
// request, with the pointer it came from retained for error reporting.
type mappedEvaluation struct {
	request DecideRequest
	pointer string
}

// mapEnvelope translates a decoded envelope into one legacy request per entry.
//
// It returns a *contract.AuthZENError on any construct it cannot evaluate. The
// error names a JSON Pointer into the request the caller sent, because
// "unsupported_action" without the offending member is a puzzle rather than a
// diagnosis.
func mapEnvelope(env *contract.AuthZENEnvelope) ([]mappedEvaluation, *contract.AuthZENError) {
	if env == nil {
		return nil, &contract.AuthZENError{
			Code:    contract.ErrMalformedEnvelope,
			Message: "the request carried no envelope",
		}
	}
	entries, base, prefix := envelopeEntries(env)

	// EVERY MEMBER THE CALLER SENT IS EXAMINED AT ITS OWN POINTER, BEFORE ANY
	// MERGING.
	//
	// Merging alone is not enough, and the gap is not theoretical: mergeEntry
	// takes a base member only when the entry omits it, so an entry that
	// supplies its own subject DISCARDS the base's subject - and with it any
	// caller-supplied properties the base carried. Validating only the merged
	// result therefore never looks at the discarded half, and a plural envelope
	// could carry `subject.properties` in the base and receive a decision, while
	// the byte-identical singular request was refused. That is precisely the
	// fail-open this file exists to prevent, hiding in the one shape the
	// refusal tests did not cover.
	if base != nil {
		if err := refuseUnevaluableMembers(*base, prefix); err != nil {
			return nil, err
		}
	}
	out := make([]mappedEvaluation, 0, len(entries))
	for i, entry := range entries {
		pointer := prefix
		if env.Evaluations != nil {
			// The base is at /evaluations; the entries are inside its own
			// `evaluations` array. Pointing a base refusal at the array (the
			// earlier prefix) produced /evaluations/evaluations/subject -- an
			// array indexed by a member name, which resolves to nothing. The
			// pointer IS the diagnostic value of a refusal, so a pointer that
			// does not resolve is a refusal the caller cannot act on.
			pointer = fmt.Sprintf("%s/evaluations/%d", prefix, i)
		}
		if err := refuseUnevaluableMembers(entry, pointer); err != nil {
			return nil, err
		}
		merged := mergeEntry(entry, base)
		req, err := mapOne(merged, pointer)
		if err != nil {
			return nil, err
		}
		out = append(out, mappedEvaluation{request: req, pointer: pointer})
	}
	if len(out) == 0 {
		// Unreachable through DecodeAuthZENEnvelope, which refuses an empty
		// plural array. Stated anyway: a zero-entry mapping would meet to a
		// vacuous ALLOW below, and "the list was empty" is the worst possible
		// reason to permit an operation.
		return nil, &contract.AuthZENError{
			Code:    contract.ErrMalformedEnvelope,
			Message: "the envelope produced no evaluations",
		}
	}
	return out, nil
}

// envelopeEntries flattens the two envelope shapes into one iteration.
func envelopeEntries(env *contract.AuthZENEnvelope) (entries []contract.AuthZENRequest, base *contract.AuthZENRequest, pointer string) {
	if env.Evaluation != nil {
		return []contract.AuthZENRequest{*env.Evaluation}, nil, "/evaluation"
	}
	b := contract.AuthZENRequest{
		Subject:  env.Evaluations.Subject,
		Action:   env.Evaluations.Action,
		Resource: env.Evaluations.Resource,
		Context:  env.Evaluations.Context,
	}
	// The BASE is the bulk object itself, at /evaluations. Its entries live in
	// that object's own `evaluations` array, so an entry is
	// /evaluations/evaluations/<i>. Returning the array as the base's pointer
	// produced /evaluations/evaluations/subject - an array indexed by a member
	// name, which resolves to nothing, on the refusal whose entire diagnostic
	// value is the pointer.
	return env.Evaluations.Evaluations, &b, "/evaluations"
}

// mergeEntry applies the shared base to an entry, member by member.
//
// Inheritance is per MEMBER, matching contract.Project: an entry that names its
// own resource inherits the base's subject, action and context. Merging at any
// coarser granularity would silently drop the half of an entry that names one
// member and expects the rest.
//
// CONTEXT IS MERGED PER KEY, NOT ALL OR NOTHING, and that asymmetry is the
// point. The other three members are single objects: an entry naming its own
// resource is naming a different resource, and the base's is not describing the
// same thing. `context` is a BAG of independent members, so taking it whole
// meant an entry that supplied `args` discarded the base's `correlation` - a key
// the base had already been validated for and accepted, dropped with no refusal
// and no audit row. That is exactly the harm refuseUnrecordedCorrelation's own
// message names: the caller is told a key was captured when it was not. Mapped
// or refused, never silently ignored, so the base's keys survive an entry that
// writes beside them.
//
// A GENUINE collision - the same key written in both places - is resolved in the
// entry's favour, which is an override the caller can see in its own request
// rather than a member vanishing. The merged bag is re-validated by
// refuseUnevaluableMembers in mapOne, so a merge cannot assemble a context that
// neither half would have been allowed to send: the correlation cap is applied
// to the result, not only to the halves.
func mergeEntry(entry contract.AuthZENRequest, base *contract.AuthZENRequest) contract.AuthZENRequest {
	if base == nil {
		return entry
	}
	if entry.Subject == nil {
		entry.Subject = base.Subject
	}
	if entry.Action == nil {
		entry.Action = base.Action
	}
	if entry.Resource == nil {
		entry.Resource = base.Resource
	}
	entry.Context = mergeContext(entry.Context, base.Context)
	return entry
}

// mergeContext returns the base's context members overlaid with the entry's.
//
// A fresh map is built rather than either input mutated: the base is shared by
// every entry of a plural envelope, so writing into it would let entry 0's
// context leak into entry 1's evaluation.
func mergeContext(entry, base map[string]any) map[string]any {
	if len(base) == 0 {
		return entry
	}
	if len(entry) == 0 {
		return base
	}
	out := make(map[string]any, len(base)+len(entry))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range entry {
		out[k] = v
	}
	return out
}

// refuseUnevaluableMembers checks every member that is PRESENT on one request
// object, without requiring the object to be complete.
//
// IT MUST COVER EVERY MEMBER, NOT THE ONES SOMEONE LISTED. The first version
// checked seven things - the three properties bags, the subject type, the
// action name, the resource type, and top-level context keys - and that was a
// LIST, not the class. Everything it omitted stayed reachable through the
// shared base of a plural envelope: an argument beside the query, an unrecorded
// correlation key, a non-string query, a resource id naming a provider nothing
// reads, an action and resource describing different operations, an empty
// subject id. Each was refused for a singular request and accepted for the
// byte-identical plural one.
//
// So this is written as "validate the object", and mapOne now calls it too
// rather than repeating a subset. The only thing that differs between a base
// and an entry is COMPLETENESS - a base is allowed to be missing members that
// its entries supply - and that is the one parameter.
func refuseUnevaluableMembers(r contract.AuthZENRequest, at string) *contract.AuthZENError {
	if r.Subject != nil {
		if len(r.Subject.Properties) > 0 {
			return unevaluableProperties(at + "/subject/properties")
		}
		if r.Subject.Type != "" && r.Subject.Type != authzenSubjectGateway {
			return &contract.AuthZENError{
				Code:      contract.ErrUnsupportedSubject,
				Pointer:   at + "/subject/type",
				Message:   fmt.Sprintf("subject type %q cannot be evaluated by this surface; an end-user subject requires the identity plane, which activates at v11", r.Subject.Type),
				Supported: []string{authzenSubjectGateway},
			}
		}
		// An id present but blank names no caller. contract.Project refuses it,
		// and this adapter must not be looser than the projection it mirrors.
		if r.Subject.ID != "" && strings.TrimSpace(r.Subject.ID) == "" {
			return &contract.AuthZENError{
				Code:    contract.ErrIncompleteEvaluation,
				Pointer: at + "/subject/id",
				Message: "the subject id must not be blank; a decision has to name the caller it was made for",
			}
		}
	}
	if r.Action != nil {
		if len(r.Action.Properties) > 0 {
			return unevaluableProperties(at + "/action/properties")
		}
		if r.Action.Name != "" {
			if _, ok := authzenActionStage[r.Action.Name]; !ok {
				return &contract.AuthZENError{
					Code:      contract.ErrUnsupportedAction,
					Pointer:   at + "/action/name",
					Message:   fmt.Sprintf("action %q is not an evaluable action", r.Action.Name),
					Supported: sortedKeys(authzenActionStage),
				}
			}
		}
	}
	if r.Resource != nil {
		if len(r.Resource.Properties) > 0 {
			return unevaluableProperties(at + "/resource/properties")
		}
		if r.Resource.Type != "" {
			stage, ok := authzenResourceStage[r.Resource.Type]
			if !ok {
				return &contract.AuthZENError{
					Code:      contract.ErrUnsupportedResource,
					Pointer:   at + "/resource/type",
					Message:   fmt.Sprintf("resource type %q is not an evaluable target", r.Resource.Type),
					Supported: sortedKeys(authzenResourceStage),
				}
			}
			// The id's SHAPE is a property of the resource alone, so it is
			// checked wherever the resource was written - including in a base
			// whose entries override it.
			if r.Resource.ID != "" {
				if _, err := mapTarget(stage, r.Resource, at); err != nil {
					return err
				}
			}
		}
	}
	// An action and a resource that name different stages describe two
	// different operations. Checked whenever BOTH are present, which includes a
	// base that carries both.
	if r.Action != nil && r.Resource != nil && r.Action.Name != "" && r.Resource.Type != "" {
		actionStage, aok := authzenActionStage[r.Action.Name]
		resourceStage, rok := authzenResourceStage[r.Resource.Type]
		if aok && rok && actionStage != resourceStage {
			return &contract.AuthZENError{
				Code:    contract.ErrUnsupportedResource,
				Pointer: at + "/resource/type",
				Message: fmt.Sprintf("action %q evaluates stage %q but the resource names stage %q; the two must describe one operation",
					r.Action.Name, actionStage, resourceStage),
			}
		}
	}
	// Context, including the CONTENTS of args and correlation. Only the
	// "is there anything to evaluate" question is positional and stays in
	// mapContext; everything else is a property of the bytes written here.
	if r.Context != nil {
		if err := refuseUnevaluableContext(r.Context, at); err != nil {
			return err
		}
	}
	return nil
}

// refuseUnevaluableContext checks a context object's members and their
// contents, without asking whether a query is present.
func refuseUnevaluableContext(ctx map[string]any, at string) *contract.AuthZENError {
	for _, k := range sortedAnyKeys(ctx) {
		if k != authzenContextArgs && k != authzenContextCorrelation {
			return &contract.AuthZENError{
				Code:      contract.ErrUnevaluableAttribute,
				Pointer:   at + "/context/" + k,
				Message:   fmt.Sprintf("this surface cannot evaluate the context member %q; accepting it would report that it was considered when it was not", k),
				Supported: []string{authzenContextArgs, authzenContextCorrelation},
			}
		}
	}
	if args, ok := ctx[authzenContextArgs].(map[string]any); ok {
		for _, k := range sortedAnyKeys(args) {
			if k != authzenArgsQuery {
				return &contract.AuthZENError{
					Code:      contract.ErrUnevaluableAttribute,
					Pointer:   at + "/context/" + authzenContextArgs + "/" + k,
					Message:   fmt.Sprintf("this surface evaluates only %q under args; %q would not be read", authzenArgsQuery, k),
					Supported: []string{authzenArgsQuery},
				}
			}
		}
		if raw, present := args[authzenArgsQuery]; present {
			if q, ok := raw.(string); !ok || strings.TrimSpace(q) == "" {
				return &contract.AuthZENError{
					Code:    contract.ErrMissingEvaluableContent,
					Pointer: at + "/context/" + authzenContextArgs + "/" + authzenArgsQuery,
					Message: "the query must be a non-empty string",
				}
			}
		}
	}
	if raw, present := ctx[authzenContextCorrelation]; present {
		m, ok := raw.(map[string]any)
		if !ok {
			return &contract.AuthZENError{
				Code:    contract.ErrUnevaluableAttribute,
				Pointer: at + "/context/" + authzenContextCorrelation,
				Message: "correlation must be an object of string values",
			}
		}
		if err := refuseUnrecordedCorrelation(m, at); err != nil {
			return err
		}
	}
	return nil
}

// refuseUnrecordedCorrelation refuses correlation keys the evaluator would drop.
//
// It calls the evaluator's OWN matcher rather than reimplementing the rule. The
// reimplementation folded "." along with "-" and "_", which the real rule does
// not, so `x.ai.agent`, `xaiagent` and `x-ai.agent` were accepted here and
// dropped there - the exact "reported as captured when it was not" harm this
// refusal exists to prevent, reintroduced by the refusal itself.
//
// The COUNT cap is enforced for the same reason: the evaluator keeps at most
// maxContextKeys and truncates the rest, so an eleventh key is a key the caller
// is told was recorded and is not.
func refuseUnrecordedCorrelation(m map[string]any, at string) *contract.AuthZENError {
	allowed := decisionContextAllowlist()
	kept := 0
	for _, k := range sortedAnyKeys(m) {
		if _, ok := m[k].(string); !ok {
			return &contract.AuthZENError{
				Code:    contract.ErrUnevaluableAttribute,
				Pointer: at + "/context/" + authzenContextCorrelation + "/" + k,
				Message: "correlation values must be strings",
			}
		}
		if !matchContextAllowlist(k, allowed) {
			return &contract.AuthZENError{
				Code:    contract.ErrUnevaluableAttribute,
				Pointer: at + "/context/" + authzenContextCorrelation + "/" + k,
				Message: fmt.Sprintf(
					"the correlation key %q is not recorded by this deployment, so it would reach no audit row; "+
						"accepting it would report that it was captured when it was not", k),
				Supported: allowed,
			}
		}
		kept++
	}
	if kept > maxContextKeys {
		return &contract.AuthZENError{
			Code:    contract.ErrUnevaluableAttribute,
			Pointer: at + "/context/" + authzenContextCorrelation,
			Message: fmt.Sprintf(
				"%d correlation keys were supplied but this deployment records at most %d; the surplus would be "+
					"truncated, and which keys survive is not the caller's choice", kept, maxContextKeys),
		}
	}
	return nil
}

// unevaluableProperties is the one refusal every properties bag gets, so the
// three call sites cannot drift into three different explanations.
func unevaluableProperties(pointer string) *contract.AuthZENError {
	return &contract.AuthZENError{
		Code:    contract.ErrUnevaluableAttribute,
		Pointer: pointer,
		Message: "this surface cannot evaluate caller-supplied properties; " +
			"accepting them would report that they were considered when they were not. " +
			"Remove them, or send the content to evaluate under context.args.query",
	}
}

// mapOne translates one merged entry.
func mapOne(r contract.AuthZENRequest, at string) (DecideRequest, *contract.AuthZENError) {
	var out DecideRequest

	// COMPLETENESS is the one property that is positional: a base may omit what
	// its entries supply, a merged entry may not.
	if r.Subject == nil || r.Action == nil || r.Resource == nil {
		return out, &contract.AuthZENError{
			Code:    contract.ErrIncompleteEvaluation,
			Pointer: at,
			Message: "after inheriting from the shared base this evaluation still has no subject, action or resource",
		}
	}
	if strings.TrimSpace(r.Subject.ID) == "" {
		return out, &contract.AuthZENError{
			Code:    contract.ErrIncompleteEvaluation,
			Pointer: at + "/subject/id",
			Message: "the subject id must not be empty; a decision has to name the caller it was made for",
		}
	}
	// AN ABSENT `type` IS NOT THE SUPPORTED TYPE.
	//
	// The schema marks `type` REQUIRED on both the subject and the resource, and
	// nothing on the serving path enforced it: DecodeAuthZENEnvelope enforces
	// unknown-field strictness and no required set, and the checks in
	// refuseUnevaluableMembers are all written `if type != "" && ...`, which
	// makes ABSENT indistinguishable from the one value this surface accepts.
	// The result was a tri-state collapse with an impersonation surface on the
	// far side: {"subject":{"type":"user","id":"alice@corp"}} was correctly
	// refused, while the same request with `type` OMITTED was ACCEPTED and bound
	// alice@corp to CallerIdentity.GatewayID. An omitted resource type likewise
	// skipped the action/resource cross-check, so an action and a target
	// describing two different operations were evaluated as one.
	//
	// It is checked HERE, on the merged entry, because required-ness is
	// COMPLETENESS: a plural base may legitimately omit a type that each entry
	// supplies, and only the merged entry can be asked whether anything supplied
	// it. The refusal reuses the code the stated-but-unsupported value gets, so a
	// client branches on one code for "this surface cannot evaluate that
	// subject" rather than on two that mean the same thing.
	if r.Subject.Type == "" {
		return out, &contract.AuthZENError{
			Code:    contract.ErrUnsupportedSubject,
			Pointer: at + "/subject/type",
			Message: "the subject names no type, which the schema requires; an absent type is not the " +
				"gateway type this surface evaluates, and reading it as one would let a body name any caller",
			Supported: []string{authzenSubjectGateway},
		}
	}
	if r.Resource.Type == "" {
		return out, &contract.AuthZENError{
			Code:    contract.ErrUnsupportedResource,
			Pointer: at + "/resource/type",
			Message: "the resource names no type, which the schema requires; without it the target cannot be " +
				"checked against the action, so the two could describe different operations",
			Supported: sortedKeys(authzenResourceStage),
		}
	}
	if r.Action.Name == "" {
		return out, &contract.AuthZENError{
			Code:      contract.ErrUnsupportedAction,
			Pointer:   at + "/action/name",
			Message:   "the action names nothing, which the schema requires; there is no operation to evaluate",
			Supported: sortedKeys(authzenActionStage),
		}
	}

	// Everything else is a property of the members, and is checked by the SAME
	// function that checks the shared base - not by a second copy here. The
	// duplicate copy was how the two drifted: the base's copy covered seven
	// members and this one covered nine.
	if err := refuseUnevaluableMembers(r, at); err != nil {
		return out, err
	}

	out.CallerIdentity.GatewayID = r.Subject.ID
	stage, ok := authzenActionStage[r.Action.Name]
	if !ok {
		// Unreachable: refuseUnevaluableMembers refuses an unmappable action
		// name above. Stated rather than assumed, because a lookup that cannot
		// fail is one refactor away from one that can, and the zero value here
		// is the empty stage.
		return out, &contract.AuthZENError{
			Code:      contract.ErrUnsupportedAction,
			Pointer:   at + "/action/name",
			Message:   fmt.Sprintf("action %q is not an evaluable action", r.Action.Name),
			Supported: sortedKeys(authzenActionStage),
		}
	}
	out.Stage = stage

	target, err := mapTarget(stage, r.Resource, at)
	if err != nil {
		return out, err
	}
	out.Target = target

	query, correlation, err := mapContext(r.Context, at)
	if err != nil {
		return out, err
	}
	out.Query = query
	if len(correlation) > 0 {
		out.Context = correlation
	}
	return out, nil
}

// mapTarget builds the evaluator's target from the AuthZEN resource.
// mapTarget builds the evaluator's target from the AuthZEN resource.
//
// WHICH HALVES OF A RESOURCE ID ARE ACTUALLY EVALUATED, measured rather than
// assumed:
//
//	tool   server + tool  ARE read (decision_handler.go binds both to the
//	                      audit row and to the HITL queue descriptor). NOT to
//	                      capability-scoped evaluation since #3717: a target
//	                      that names a hosting SERVER — which every tool
//	                      resource id here does, by construction — supplies no
//	                      scoping key, because the caller is routing to a
//	                      backend it does not itself execute. Those requests
//	                      get FULL evaluation. Attribution is unchanged, which
//	                      is what the asymmetry below is about.
//	llm    provider/model are read by NOTHING. `grep -rn "Target.Provider|
//	                      Target.Model"` over the non-test tree returns zero
//	                      hits; the HITL descriptor for an llm target is the
//	                      bare string "llm".
//	agent  no sub-target at all
//
// So a tool resource names its server and tool, and an llm or agent resource
// names only its stage. Accepting "openai/gpt-4o" would tell the caller the
// provider and the model were weighed when neither reaches policy, audit, or a
// human approver - the fail-open this file exists to prevent, and the reason
// the agent stage was already written this way. The asymmetry is evidence, not
// taste: it tracks exactly which fields the evaluation reads.
//
// This is what a future release widens. When the evaluator learns to read a
// model, the refusal here becomes an acceptance, and callers who were told
// "not evaluated" start being told "evaluated" - which is the honest order.
func mapTarget(stage string, res *contract.AuthZENResource, at string) (DecisionTarget, *contract.AuthZENError) {
	var t DecisionTarget
	switch stage {
	case DecisionStageTool:
		server, tool, ok := splitPair(res.ID)
		if !ok {
			return t, &contract.AuthZENError{
				Code:    contract.ErrUnsupportedResource,
				Pointer: at + "/resource/id",
				Message: fmt.Sprintf("a tool resource id must be \"server/tool\", got %q", res.ID),
			}
		}
		t = DecisionTarget{Type: pep.TargetTypeTool, Server: server, Tool: tool}
	case DecisionStageLLM, DecisionStageAgent:
		// The id must name the stage itself, because nothing finer is read.
		if res.ID != stage {
			return t, &contract.AuthZENError{
				Code:    contract.ErrUnsupportedResource,
				Pointer: at + "/resource/id",
				Message: fmt.Sprintf(
					"the %s stage evaluates no sub-target, so its resource id must be %q; %q names a "+
						"provider or model that reaches neither policy, audit nor a human approver, and "+
						"accepting it would report that it was considered",
					stage, stage, res.ID),
				Supported: []string{stage},
			}
		}
		t = DecisionTarget{Type: stage}
	}
	return t, nil
}

// mapContext reads the two context members this adapter understands and refuses
// every other one by name.
func mapContext(ctx map[string]any, at string) (query string, correlation map[string]any, err *contract.AuthZENError) {
	// Only the POSITIONAL question lives here: is there anything to evaluate?
	// A base may legitimately carry no query because its entries supply one;
	// a merged entry may not. Every other context rule - unknown members,
	// arguments beside the query, a non-string query, unrecorded or surplus
	// correlation keys - is a property of the bytes the caller wrote and is
	// checked by refuseUnevaluableContext, wherever they were written.
	if len(ctx) == 0 {
		return "", nil, &contract.AuthZENError{
			Code:    contract.ErrMissingEvaluableContent,
			Pointer: at + "/context",
			Message: fmt.Sprintf("there is nothing to evaluate; the content belongs under context.%s.%s", authzenContextArgs, authzenArgsQuery),
		}
	}
	args, _ := ctx[authzenContextArgs].(map[string]any)
	if len(args) == 0 {
		return "", nil, &contract.AuthZENError{
			Code:    contract.ErrMissingEvaluableContent,
			Pointer: at + "/context/" + authzenContextArgs,
			Message: fmt.Sprintf("there is nothing to evaluate; the content belongs under context.%s.%s", authzenContextArgs, authzenArgsQuery),
		}
	}
	q, ok := args[authzenArgsQuery].(string)
	if !ok || strings.TrimSpace(q) == "" {
		return "", nil, &contract.AuthZENError{
			Code:    contract.ErrMissingEvaluableContent,
			Pointer: at + "/context/" + authzenContextArgs + "/" + authzenArgsQuery,
			Message: "the query must be a non-empty string",
		}
	}
	if m, present := ctx[authzenContextCorrelation].(map[string]any); present {
		correlation = map[string]any{}
		for _, k := range sortedAnyKeys(m) {
			correlation[k] = m[k].(string)
		}
	}
	return q, correlation, nil
}

// splitPair splits "a/b" and refuses anything else, including an empty half. A
// resource id of "openai/" names no model, and defaulting the empty half would
// evaluate a different target than the one asked about.
func splitPair(id string) (string, string, bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAnyKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// The response direction.
// ---------------------------------------------------------------------------

// authzenStateFor maps a legacy verdict onto the operational state.
//
// The mapping is total over the verdicts the Decision API emits and returns
// StateError for anything else. A verdict this build does not recognise is an
// evaluation whose meaning is unknown, and the safe reading of an unknown
// meaning is not ALLOW.
func authzenStateFor(verdict string) contract.OperationalState {
	switch verdict {
	case VerdictAllow:
		return contract.StateAllow
	case VerdictDeny:
		return contract.StateDeny
	case VerdictNeedsApproval:
		return contract.StateChallenge
	default:
		return contract.StateError
	}
}

// authzenReasonFor maps a state onto a safe machine reason.
func authzenReasonFor(state contract.OperationalState) contract.ReasonCode {
	switch state {
	case contract.StateAllow:
		return contract.ReasonPermitted
	case contract.StateDeny:
		return contract.ReasonExplicitConstraint
	case contract.StateChallenge:
		return contract.ReasonApprovalRequired
	default:
		return contract.ReasonEvaluationError
	}
}

// authzenMeetPrecedence orders the states from least to most permissive.
//
// This is the combining order of the plural envelope, and it is deliberately
// NOT contract.MeetDecisions. That function combines contract.Decision values
// and requires each to name the policy snapshot it was computed against; the
// legacy evaluator produces no such snapshot, so calling it would mean
// synthesising one. A decision that names a snapshot it was not computed
// against cannot be replayed, and an unreplayable decision cannot be audited -
// so the combination is done here, over the states the legacy evaluator
// actually produces, rather than by fabricating the inputs a stricter function
// expects.
var authzenMeetPrecedence = map[contract.OperationalState]int{
	contract.StateDeny:      0,
	contract.StateError:     1,
	contract.StateChallenge: 2,
	contract.StateAllow:     3,
}

// meetStates returns the effective state for a plural envelope.
//
// A mapping's entries are preconditions of ONE operation, never independent
// queries, so the combination is a meet: moving a ticket must be authorized
// against the destination project as well as against the ticket. One denied
// entry denies the operation.
func meetStates(states []contract.OperationalState) (contract.OperationalState, error) {
	if len(states) == 0 {
		return contract.StateError, fmt.Errorf("authzen: cannot meet an empty state set")
	}
	worst := states[0]
	for _, s := range states {
		// Read with the two-value idiom. An unranked state cannot arrive today
		// because authzenStateFor is total, but a bare read would make that
		// safety depend on a second function staying total, and the zero rank
		// here is the most restrictive - so an unranked value would silently
		// become a deny rather than loudly becoming a bug.
		got, gotOK := authzenMeetPrecedence[s]
		held, heldOK := authzenMeetPrecedence[worst]
		if !gotOK || !heldOK {
			return contract.StateError, fmt.Errorf("authzen: cannot order state %q against %q", s, worst)
		}
		if got < held {
			worst = s
		}
	}
	return worst, nil
}
