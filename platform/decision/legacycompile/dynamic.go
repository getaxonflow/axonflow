package legacycompile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// resolverFields is the orchestrator's condition-field resolver, as a set of
// EXPLICIT case labels.
//
// It transcribes the switch at platform/orchestrator/db_dynamic_policies.go's
// getFieldValue - every case label, including the aliases. The two prefix
// families (media.* and context.*) are handled separately because they are
// prefixes rather than labels.
//
// A field OUTSIDE this set is not dead: getFieldValue's default arm ends in a
// direct req.Context[field] lookup over the caller-forwarded context map, so
// such a field resolves to whatever the CALLER supplied under that key and to
// nil otherwise. The set exists so that #3515 is DETECTABLE rather than
// believed: the policy editor offers ten fields, this switch has cases for
// seven, and the other three are enforced from a caller-suppliable input -
// which is a defect worth reporting per row, not a reason to compile the
// condition as inert.
var resolverFields = map[string]bool{
	"query": true, "request_type": true, "request_id": true,
	"user.id": true, "user_id": true,
	"user.email": true, "user_email": true,
	"user.role": true, "user_role": true,
	"user.region": true, "user_region": true, "region": true,
	"user.tenant_id": true,
	"client.id":      true, "client_id": true, "agent_id": true,
	"client.org_id": true, "org_id": true,
	"client.tenant_id": true, "tenant_id": true,
	"environment": true, "env": true,
	"risk_score": true, "cost_estimate": true,
}

// uiOfferedFields is the field list the Edit Policy dialog offers
// (ee/platform/customer-portal-ui/lib/api.ts POLICY_FIELDS). It is recorded
// here so the three-field gap in #3515 is a computed difference rather than a
// number in a comment that goes stale.
//
// Transcribed VERBATIM and in source order. The first version of this list was
// wrong on six of the ten entries and the derived gap still returned the right
// three, because all six mistakes happened to have resolver cases - a
// derivation that produces the right answer from the wrong inputs, which is
// the failure mode a derived list was supposed to prevent. Check it against
// the constant, not against the answer.
var uiOfferedFields = []string{
	"query",
	"response",
	"user.email",
	"user.role",
	"user.department",
	"user.tenant_id",
	"risk_score",
	"request_type",
	"connector",
	"cost_estimate",
}

// ContextOnlyUIFields returns the fields the policy editor offers that the
// orchestrator resolver has no explicit case for, sorted. Each of them resolves
// ONLY through getFieldValue's default arm - a direct req.Context[field] lookup
// over caller-forwarded context - so a condition over one is enforced from an
// input the caller controls (#3515). It is derived from the two lists above
// rather than hard-coded, so adding a resolver case closes the gap here
// automatically.
func ContextOnlyUIFields() []string {
	var out []string
	for _, f := range uiOfferedFields {
		if !fieldHasResolverCase(f) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// fieldHasResolverCase reports whether getFieldValue resolves a field WITHOUT
// falling through to the caller-forwarded context map: an explicit case label,
// or one of the two prefix families it handles before the direct lookup.
//
// A field for which this is false still resolves in production - the default
// arm reads req.Context[field], the agent forwards client context verbatim
// (platform/agent/run.go forwardToOrchestrator), and real MCP traffic
// populates context keys (platform/orchestrator/mcp_query_router.go) - so the
// answer decides PROVENANCE, never liveness. The one asymmetry that matters:
// a media.* or context.* field is also context-sourced, but through a
// different key derivation, which AttributePathFor reproduces.
func fieldHasResolverCase(field string) bool {
	if resolverFields[field] {
		return true
	}
	return strings.HasPrefix(field, "media.") || strings.HasPrefix(field, "context.")
}

// legacyCondition is one entry of a dynamic_policies.conditions array.
type legacyCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

// DynamicContentDetectorPath is the attribute path the compiled form of a
// dynamic row's CONTENT conditions reads.
//
// The four content operators - contains, not_contains, contains_any, regex -
// are substring and pattern matching over payloads, and ADR-065 keeps content
// inspection in the detector plane rather than in the condition language, the
// same decision that turns a static row's pattern into a named detector. So a
// dynamic content condition does not become a typed string comparison over
// `args.query` (which would be an approximation with different semantics); it
// becomes a reference to a named detector whose verdict is an ordinary
// tri-state attribute, exactly like DetectorSignalPath.
//
// One detector per ROW, not per condition, because the legacy engine ANDs
// every condition: the detector's verdict is "did every content condition of
// this row hold", and the row's non-content conditions stay typed and are
// conjoined with it. The path carries a "dyn." segment so a static row and a
// dynamic row sharing one policy_id (the two tables have independent id
// spaces) can never share one signal - sanitizePathSegment escapes '.', so no
// sanitized id can collide with the literal segment separator used here.
func DynamicContentDetectorPath(policyID string) string {
	return "signal.detector.dyn." + sanitizePathSegment(policyID)
}

// contentOperators are the condition operators that inspect content and
// therefore compile to a detector reference rather than a typed condition.
var contentOperators = map[string]bool{
	"contains": true, "not_contains": true, "contains_any": true, "regex": true,
}

// IsContentOperator reports whether a legacy condition operator is content
// inspection, i.e. compiles to a detector reference. Exported because the
// shadow corpus builder must supply a verdict for exactly this set.
func IsContentOperator(op string) bool { return contentOperators[op] }

// compileDynamicRow compiles one dynamic_policies row into a Record.
func compileDynamicRow(raw RawRow, row DynamicRow, opts Options) Record {
	rec := Record{
		Source: SourceRef{
			Table: raw.Table, OrgScope: raw.OrgScope, ID: row.ID,
			// Version too. SourceRef's contract is that a compiled policy is
			// traceable to a source row AND VERSION, and leaving it zero on
			// every dynamic record made that half of the claim false for one
			// of the two substrates.
			PolicyID: row.PolicyID, Version: row.Version, RowDigest: digestRow(raw),
		},
	}

	if row.EnabledNull || !row.Enabled {
		rec.Status = StatusUncompilable
		rec.Reasons = append(rec.Reasons, Reason{
			Code: ReasonExcludedByLegacyPredicate,
			Detail: "RefreshDynamicPolicies filters `enabled = true`; this row is " +
				describeBool(row.Enabled, row.EnabledNull) + " and never reaches the cache",
		})
		return rec
	}

	// #3397 on the dynamic substrate. RefreshDynamicPolicies scans
	// positionally and logs-and-continues on a scan error, so a NULL in one of
	// its non-nullable destinations removes the row from the cache while the
	// refresh still reports success - the same silent unenforcement the static
	// readers have, on the other table.
	if drops := dynamicScanDropColumns(row); len(drops) > 0 {
		rec.Status = StatusPreservedDefect
		rec.Reasons = append(rec.Reasons, Reason{
			Code: ReasonLegacyScanDrop, Issue: "#3397",
			Detail: "NULL in non-nullable scan destination(s): " + strings.Join(drops, ", ") +
				" - RefreshDynamicPolicies' scan errors, the row never reaches the cache, and the refresh reports success",
		})
		for _, plane := range PlanesFor(SubstrateDynamic) {
			rec.Planes = append(rec.Planes, PlaneResult{
				Plane: plane, ReadPath: ReadPathDynamicRows,
				Reasons: []Reason{{
					Code: ReasonLegacyScanDrop, Issue: "#3397", Plane: plane,
					Detail: "the row is dropped by the dynamic refresh's scan and is enforced nowhere",
				}},
			})
		}
		return rec
	}

	conds, condReasons, condFatal := parseConditions(row)
	rec.Reasons = append(rec.Reasons, condReasons...)
	if condFatal {
		rec.Status = StatusUncompilable
		return rec
	}

	actions, actReasons, actFatal := parseActions(row)
	rec.Reasons = append(rec.Reasons, actReasons...)
	if actFatal {
		rec.Status = StatusUncompilable
		return rec
	}

	where, whereReasons, whereOutcome := conditionsToTyped(conds, row, opts)
	rec.Reasons = append(rec.Reasons, whereReasons...)

	// The actions the LEGACY engine applies are a property of the row, not of
	// whether this compiler could express its conditions. They are computed
	// once, before the per-plane loop, and recorded on every plane result -
	// including the ones that emit no policy. Recording them only where a
	// policy was emitted is what made an unmigrated row invisible: the legacy
	// side of the diff went quiet on it, both sides agreed by being silent,
	// and a cutover fail-open read as a match.
	var legacyApplied []string
	for _, act := range actions {
		if legacyAppliesActionType(act.Type) {
			legacyApplied = append(legacyApplied, act.Type)
		}
	}
	legacyActionList := strings.Join(legacyApplied, ",")

	// Every attribute path the row's conditions read, whether or not the
	// condition compiled. Every field reads SOMETHING in production - an
	// explicit resolver case, or the caller-forwarded context map - so every
	// condition contributes a path; a content condition contributes its
	// detector path, because the corpus carries the detector's verdict even
	// when the row compiled to no policy.
	var paths []string
	seenPath := map[string]bool{}
	addPath := func(path string) {
		if !seenPath[path] {
			seenPath[path] = true
			paths = append(paths, path)
		}
	}
	for _, c := range conds {
		if IsContentOperator(c.Operator) {
			// Both paths: the compiled policy reads the DETECTOR, and the row
			// still reads the raw field in production - which is also what the
			// corpus supplies as the legacy engine's input, so the request
			// must be allowed to carry it.
			addPath(DynamicContentDetectorPath(row.PolicyID))
		}
		addPath(opts.AttributePathFor(c.Field))
	}
	sort.Strings(paths)

	for _, plane := range PlanesFor(SubstrateDynamic) {
		spec := MustSpecFor(plane)
		pr := PlaneResult{Plane: spec.Plane, ReadPath: ReadPathDynamicRows,
			ResolvedAction: legacyActionList, AttributePaths: paths}
		switch whereOutcome {
		case conditionInexpressible:
			pr.Reasons = append(pr.Reasons, Reason{
				Code: ReasonUnsupportedConditionOperator, Plane: spec.Plane,
				Detail: "the condition set has no complete typed equivalent, so no policy is emitted for this plane; the reasons on the record name each operator. " +
					"This row may be enforcing in production RIGHT NOW - it is a migration gap, not an inert row",
			})
			rec.Planes = append(rec.Planes, pr)
			continue
		}
		for i, act := range actions {
			pol, reasons := dynamicPolicyFor(row, spec, where, act, i, opts)
			pr.Reasons = append(pr.Reasons, reasons...)
			if pol != nil {
				pr.Policies = append(pr.Policies, *pol)
			}
		}
		if len(actions) == 0 {
			pr.Reasons = append(pr.Reasons, Reason{
				Code: ReasonNoActionableOutcome, Plane: spec.Plane,
				Detail: "the actions array is empty, so a matching policy applies nothing",
			})
		}
		rec.Planes = append(rec.Planes, pr)
	}

	rec.Reasons = append(rec.Reasons, Reason{
		Code: ReasonPriorityHasNoEquivalent,
		Detail: fmt.Sprintf("legacy evaluation order is priority DESC then created_at, and this row's priority is %s; "+
			"ADR-065 combines by authority, so ordering cannot change a deny but can change which policy is reported as determining",
			describeInt(row.Priority, row.PriorityNull)),
	})

	rec.Status = statusFrom(rec)
	return rec
}

func describeInt(v int, isNull bool) string {
	if isNull {
		return "NULL"
	}
	return strconv.Itoa(v)
}

// parseConditions reproduces the engine's conditions handling, including the
// two states that look alike and are not: a NULL/absent array is vacuous truth
// and the policy applies to everything, while an explicitly empty array is
// EXCLUDED from enforcement entirely (#3384).
func parseConditions(row DynamicRow) ([]legacyCondition, []Reason, bool) {
	if len(row.Conditions) == 0 || string(row.Conditions) == "null" {
		return nil, []Reason{{
			Code:   ReasonVacuousConditionSet,
			Detail: "conditions is NULL or absent; the engine treats that as vacuous truth and the policy applies to every request",
		}}, false
	}
	var conds []legacyCondition
	if err := json.Unmarshal(row.Conditions, &conds); err != nil {
		return nil, []Reason{{
			Code:   ReasonMalformedJSON,
			Detail: fmt.Sprintf("conditions will not parse (%v); the engine logs and `continue`s, so this policy is loaded, counted and never enforced", err),
		}}, true
	}
	if len(conds) == 0 {
		return nil, []Reason{{
			Code:   ReasonExcludedByLegacyPredicate,
			Detail: "conditions is an explicitly empty array, which #3384 excludes from enforcement; it is recorded unevaluable and skipped",
		}}, true
	}
	return conds, nil, false
}

type legacyAction struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

func parseActions(row DynamicRow) ([]legacyAction, []Reason, bool) {
	if len(row.Actions) == 0 || string(row.Actions) == "null" {
		return nil, []Reason{{
			Code:   ReasonNoActionableOutcome,
			Detail: "actions is NULL or absent, so a matching policy applies nothing",
		}}, false
	}
	var raw []legacyAction
	if err := json.Unmarshal(row.Actions, &raw); err != nil {
		return nil, []Reason{{
			Code:   ReasonMalformedJSON,
			Detail: fmt.Sprintf("actions will not parse (%v); the engine logs and applies nothing while the policy still counts as applied", err),
		}}, true
	}
	return raw, nil, false
}

// conditionsToTyped turns the legacy condition array into one typed
// conjunction. The legacy engine ANDs every condition and short-circuits on
// the first non-match, so a conjunction is the faithful shape.
// conditionOutcome is the two-valued result of compiling a condition set.
type conditionOutcome int

const (
	// conditionCompiled means the whole set has a typed equivalent.
	conditionCompiled conditionOutcome = iota
	// conditionInexpressible means this compiler has no typed equivalent for
	// at least one condition. The row is a MIGRATION GAP: the legacy engine
	// may well be enforcing it right now.
	conditionInexpressible
)

func conditionsToTyped(conds []legacyCondition, row DynamicRow, opts Options) (pdp.Condition, []Reason, conditionOutcome) {
	var reasons []Reason
	if len(conds) == 0 {
		// Vacuous truth: applies to everything.
		return pdp.Condition{Kind: pdp.CondTrue}, reasons, conditionCompiled
	}
	var operands []pdp.Condition
	inexpressible := false
	contentConds := 0
	// Every condition is examined even once the outcome is decided. Returning
	// early made the recorded reason set depend on the ORDER the operator
	// happened to author the conditions in, so a census of "which operators
	// block compilation" undercounted whenever the blocking condition came
	// first.
	for _, c := range conds {
		if !fieldHasResolverCase(c.Field) {
			// The FALSE version of this reason said the field resolves to nil
			// no matter what the request carries. It does not: getFieldValue's
			// default arm is a direct req.Context[field] lookup, the agent
			// forwards client context verbatim, and real traffic populates
			// context keys - so the condition is LIVE for any caller that
			// supplies the key, which makes "compile it as inert" a silent
			// fail-open hole. The condition is compiled against the same
			// context-sourced path the spelling "context.<field>" maps to, and
			// the defect - enforcement keyed on a caller-suppliable input the
			// editor presents as a first-class field - is recorded, preserved,
			// and diffed rather than repaired or refused.
			reasons = append(reasons, Reason{
				Code: ReasonLegacyDeadConditionField, Issue: "#3515",
				Detail: fmt.Sprintf("field %q has no case in getFieldValue, so it falls through to the caller-forwarded req.Context[%q] lookup: "+
					"the condition is live for exactly the requests whose caller supplies that context key, and resolves to nil for the rest "+
					"(operator %q, literal %v). The policy editor presents it as a first-class field; enforcement reads an untrusted input",
					c.Field, c.Field, c.Operator, c.Value),
			})
		}
		if IsContentOperator(c.Operator) {
			// Content inspection compiles to a DETECTOR REFERENCE, the same
			// mechanism that carries a static row's pattern: ADR-065 keeps
			// substring and pattern matching in the detector plane, and a
			// typed string comparison over the raw field would be an
			// approximation with different semantics. One detector per row;
			// its verdict is "did every content condition of this row hold".
			reasons = append(reasons, Reason{
				Code: ReasonPatternNotTypedCondition,
				Detail: fmt.Sprintf("content operator %q on field %q (literal %v) is carried as detector %q rather than a typed condition; "+
					"an unrun detector is UNKNOWN, where the legacy engine had no match",
					c.Operator, c.Field, c.Value, DynamicContentDetectorPath(row.PolicyID)),
			})
			contentConds++
			continue
		}
		typed, tReasons, tOK := conditionToTyped(c, opts)
		reasons = append(reasons, tReasons...)
		if !tOK {
			inexpressible = true
			continue
		}
		operands = append(operands, typed)
	}
	if contentConds > 0 {
		operands = append(operands, pdp.Compare(DynamicContentDetectorPath(row.PolicyID), pdp.OpEq, true))
	}
	if inexpressible {
		return pdp.Condition{}, reasons, conditionInexpressible
	}
	switch len(operands) {
	case 0:
		return pdp.Condition{Kind: pdp.CondTrue}, reasons, conditionCompiled
	case 1:
		return operands[0], reasons, conditionCompiled
	default:
		return pdp.And(operands...), reasons, conditionCompiled
	}
}

// conditionToTyped maps one legacy NON-CONTENT operator to a typed condition.
// The four content operators never reach it; conditionsToTyped compiles them
// to a detector reference first.
func conditionToTyped(c legacyCondition, opts Options) (pdp.Condition, []Reason, bool) {
	path := opts.AttributePathFor(c.Field)
	switch c.Operator {
	case "equals":
		return pdp.Compare(path, pdp.OpEq, c.Value), nil, true
	case "not_equals":
		return pdp.Compare(path, pdp.OpNe, c.Value), nil, true
	case "greater_than":
		return pdp.Compare(path, pdp.OpGt, c.Value), nil, true
	case "less_than":
		return pdp.Compare(path, pdp.OpLt, c.Value), nil, true
	case "in", "not_in":
		items, ok := toList(c.Value)
		if !ok {
			// matchInList returns false for a Value that is neither []any nor
			// []string, so `in` never matches and `not_in` ALWAYS matches.
			// That asymmetry is legacy behaviour and is reported rather than
			// normalised.
			return pdp.Condition{}, []Reason{{
				Code: ReasonUnsupportedConditionOperator,
				Detail: fmt.Sprintf("%q carries a value of shape %T, which matchInList treats as an empty list: `in` never matches and `not_in` always does",
					c.Operator, c.Value),
			}}, false
		}
		var arms []pdp.Condition
		for _, it := range items {
			arms = append(arms, pdp.Compare(path, pdp.OpEq, it))
		}
		or := pdp.Or(arms...)
		if len(arms) == 1 {
			or = arms[0]
		}
		if c.Operator == "not_in" {
			return pdp.Not(or), nil, true
		}
		return or, nil, true
	default:
		return pdp.Condition{}, []Reason{{
			Code:   ReasonUnsupportedConditionOperator,
			Detail: fmt.Sprintf("operator %q is not one the legacy evaluator implements; it falls through the switch and the condition is false", c.Operator),
		}}, false
	}
}

func toList(v any) ([]any, bool) {
	switch vv := v.(type) {
	case []any:
		return vv, true
	case []string:
		out := make([]any, len(vv))
		for i, s := range vv {
			out[i] = s
		}
		return out, true
	default:
		return nil, false
	}
}

// dynamicPolicyFor maps one legacy dynamic action to one ADR-065 policy.
func dynamicPolicyFor(row DynamicRow, spec PlaneSpec, where pdp.Condition, act legacyAction, idx int, opts Options) (*pdp.Policy, []Reason) {
	var reasons []Reason
	id := fmt.Sprintf("%s#%d", PolicyIDFor("dynamic_policies", row.PolicyID, spec.Plane, ""), idx)
	root := pdp.RootOrganization
	if row.Tier == "system" || row.TenantID == "global" {
		root = pdp.RootSystem
	}
	scope := pdp.Scope{Organization: true}
	if !row.SegmentIDNull && row.SegmentID != "" {
		gid, err := contract.ParseID(contract.KindGroup, opts.GroupIDFor(row.SegmentID))
		if err != nil {
			return nil, []Reason{{
				Code: ReasonNoActionableOutcome, Plane: spec.Plane,
				Detail: fmt.Sprintf("segment_id %q does not render a canonical group id: %v", row.SegmentID, err),
			}}
		}
		scope = pdp.Scope{Groups: []contract.ID{gid}}
	}
	base := pdp.Policy{
		ID: id, Root: root, Scope: scope,
		Actions:     pdp.ActionSelector{Any: true},
		Where:       where,
		Description: fmt.Sprintf("compiled from dynamic_policies %s action[%d] type %q for plane %s", row.PolicyID, idx, act.Type, spec.Plane),
	}
	cfgStr := func(k string) string {
		if act.Config == nil {
			return ""
		}
		s, _ := act.Config[k].(string)
		return s
	}

	switch act.Type {
	case "block":
		base.Authority = contract.AuthorityConstraint
		return &base, nil

	case "require_approval":
		pool, ok := opts.ApprovalPool(row.OrgID, row.TenantID)
		if !ok {
			return nil, []Reason{{
				Code: ReasonApprovalPoolNotStored, Plane: spec.Plane,
				Detail: "require_approval stores a reason and a severity but no approver pool; ADR-065's approval obligation needs an eligible set and a quorum",
			}}
		}
		base.Authority = contract.AuthorityRequirement
		base.Mandatory = true
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObApprovalChallenge,
			Params:        map[string]string{"quorum": strconv.Itoa(pool.Quorum), "eligible": strings.Join(pool.Eligible, ",")},
			Mandatory:     true,
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		return &base, nil

	case "route":
		// ADR-065's route restriction is a SET OF ALLOWED DESTINATIONS and
		// nothing else: contract.composeRouting intersects the sets from every
		// matched policy and denies when the intersection is empty, which is
		// what makes "most restrictive wins" a property of the algebra rather
		// than of the order policies happen to be evaluated in. The parameter
		// name is part of that contract, and getting it wrong produces a
		// decision of DENY with reason unsupported_obligation - a routing
		// preference silently becoming a refusal.
		allowed := configStringList(act.Config, "allowed_providers")
		preferred := cfgStr("preferred_provider")
		if len(allowed) == 0 {
			// A legacy route action carrying only a preferred provider is a
			// PREFERENCE: it sets result.PreferredProvider and restricts
			// nothing. There is no ADR-065 obligation for that, and compiling
			// it to an allowed set of one would turn a hint into a hard
			// restriction - a tightening the operator never authored.
			detail := "a route action naming no allowed_providers restricts nothing"
			if preferred != "" {
				detail = fmt.Sprintf("this route action sets preferred_provider=%q and no allowed_providers: it is a routing PREFERENCE, "+
					"and ADR-065's route_restriction is a set of allowed destinations. Compiling a preference into a restriction of one "+
					"would tighten what the operator authored, so it is reported instead", preferred)
			}
			return nil, []Reason{{
				Code: ReasonNoActionableOutcome, Plane: spec.Plane, Detail: detail,
			}}
		}
		sort.Strings(allowed)
		base.Authority = contract.AuthorityRequirement
		base.Mandatory = true
		base.Obligations = []contract.Obligation{{
			Type:          contract.ObRouteRestriction,
			Params:        map[string]string{"allowed_destinations": strings.Join(allowed, ",")},
			Mandatory:     true,
			SourcePolicy:  id,
			SchemaVersion: 1,
		}}
		if preferred != "" {
			reasons = append(reasons, Reason{
				Code: ReasonNoActionableOutcome, Plane: spec.Plane,
				Detail: fmt.Sprintf("preferred_provider=%q is not carried into the route restriction: ADR-065 restricts destinations and does not rank them", preferred),
			})
		}
		return &base, reasons

	case "redact":
		fields := configStringList(act.Config, "fields")
		if len(fields) == 0 {
			return nil, []Reason{{
				Code: ReasonNoActionableOutcome, Plane: spec.Plane,
				Detail: "a redact action naming no fields appends nothing to RequiredActions and is a no-op",
			}}
		}
		base.Authority = contract.AuthorityRequirement
		base.Mandatory = true
		sort.Strings(fields)
		for _, f := range fields {
			base.Obligations = append(base.Obligations, contract.Obligation{
				Type: contract.ObFieldRedact, Target: f,
				Mandatory: true, SourcePolicy: id, SchemaVersion: 1,
			})
		}
		return &base, nil

	case "log":
		base.Authority = contract.AuthorityRequirement
		base.Obligations = []contract.Obligation{{
			Type: contract.ObImmutableAudit,
			Params: map[string]string{
				"level":   orDefault(cfgStr("level"), "info"),
				"message": orDefault(cfgStr("message"), "policy matched"),
			},
			SourcePolicy: id, SchemaVersion: 1,
		}}
		return &base, nil

	case "alert", "warn":
		base.Authority = contract.AuthorityRequirement
		base.Obligations = []contract.Obligation{{
			Type: contract.ObNotification,
			Params: map[string]string{
				"kind":     act.Type,
				"severity": orDefault(cfgStr("severity"), "medium"),
				"channel":  cfgStr("channel"),
			},
			SourcePolicy: id, SchemaVersion: 1,
		}}
		return &base, nil

	case "modify_risk":
		return nil, []Reason{{
			Code: ReasonRiskMutationHasNoObligation, Plane: spec.Plane,
			Detail: "modify_risk adds to the in-flight risk score, which a later policy's risk_score condition can read; it is a mutation of evaluation state, not an instruction to the enforcement point",
		}}

	default:
		return nil, []Reason{{
			Code: ReasonInertLegacyAction, Issue: "#3563", Plane: spec.Plane,
			Detail: fmt.Sprintf("action type %q has no arm in the orchestrator's action switch, so a matching policy applies nothing at all; it is preserved as the no-op the running system performs", act.Type),
		}}
	}
}

// legacyAppliesActionType reports whether the orchestrator's action switch has
// an arm for a type, i.e. whether a matching policy carrying it changes
// anything in production.
//
// modify_risk is deliberately excluded even though it HAS an arm: it adds to
// the in-flight risk score rather than instructing the enforcement point, and
// the model does not reproduce that accumulation (see ModelLimitations). An
// unknown type is excluded because it falls through the switch and applies
// nothing at all.
func legacyAppliesActionType(t string) bool {
	switch t {
	case "block", "require_approval", "route", "redact", "log", "alert", "warn":
		return true
	default:
		return false
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func configStringList(cfg map[string]any, key string) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	switch v := cfg[key].(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	}
	return out
}
