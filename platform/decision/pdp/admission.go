package pdp

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
)

// ActionEntry is one registered action. Every operation resolves to a
// registered action; string heuristics and terminal-name matching are migration
// adapters only.
type ActionEntry struct {
	ID   contract.ID `json:"id"`
	Tags []string    `json:"tags"`
	// MaxDelegationDepth bounds the actor chain. Depth is a topology
	// constraint checked before any policy runs, not a permission question.
	MaxDelegationDepth int `json:"max_delegation_depth"`
	// Arguments declares the caller-supplied argument schema. Binding the
	// policy editor to a typed schema WITH UNITS is what makes the classic
	// unit bug structural rather than a code review's job: a policy reading
	// `amount <= 5000` against a cents-denominated API is a limit of 50 that
	// everyone believes is 5000.
	Arguments map[string]ValueType `json:"arguments"`
	// RequiredArguments must be present.
	RequiredArguments []string `json:"required_arguments"`
	// PayloadLeaves is the canonical leaf field schema of the response, over
	// which disclosure obligations expand.
	PayloadLeaves []string `json:"payload_leaves"`
	// Irreversible, DataEgress and Privileged are the risk classes that make
	// an action ineligible for the temporary compatibility posture.
	Irreversible bool `json:"irreversible"`
	DataEgress   bool `json:"data_egress"`
	Privileged   bool `json:"privileged"`
}

// Registry is the action, tool and realm registry consulted at admission.
type Registry struct {
	Actions map[string]ActionEntry
	// Realms is the set of declared realm identifiers. A validly signed token
	// from an undeclared realm is denied before any policy loads: valid
	// signature is not the same as declared trust, and admitting one lets a
	// principal reach evaluation with an undefined realm, where a falsy
	// default reads as "this realm has no group graph" and every group-scoped
	// constraint is silently skipped.
	Realms map[string]bool
}

// AdmissionResult reports the outcome of the pre-policy checks.
type AdmissionResult struct {
	// Failed is true when the request is refused before any policy runs.
	Failed bool
	Reason contract.ReasonCode
	Detail string
	// Entry is the resolved action registry entry when admission succeeded.
	Entry ActionEntry
}

// Admit runs the checks that precede policy evaluation.
//
// Every check here refuses an UNKNOWN SURFACE rather than deciding a policy
// question, and each refusal is distinguishable in the trace from a policy
// denial, because "this tool is not registered" and "this registered tool has
// no matching permission" need different fixes.
func (r *Registry) Admit(req *contract.Request) AdmissionResult {
	if r == nil {
		return AdmissionResult{Failed: true, Reason: contract.ReasonEvaluationError, Detail: "no action registry is configured"}
	}
	entry, ok := r.Actions[req.Action.String()]
	if !ok {
		return AdmissionResult{Failed: true, Reason: contract.ReasonUnknownAction,
			Detail: fmt.Sprintf("action %q is not in the registry", req.Action)}
	}
	for i, actor := range req.Context.ActorChain {
		if !r.Realms[actor.ID.Qualifier] {
			return AdmissionResult{Failed: true, Reason: contract.ReasonUnknownRealm,
				Detail: fmt.Sprintf("actor_chain[%d] %q resolves in realm %q, which has no declared trust realm", i, actor.ID, actor.ID.Qualifier)}
		}
	}
	// A registry entry that declares no depth is a registry defect, not an
	// action without a depth limit. Reading the zero value as "unbounded"
	// turns a missing field into the most permissive setting available.
	if entry.MaxDelegationDepth <= 0 {
		return AdmissionResult{Failed: true, Reason: contract.ReasonUnknownAction,
			Detail: fmt.Sprintf("action %q declares no maximum delegation depth", req.Action)}
	}
	if len(req.Context.ActorChain) > entry.MaxDelegationDepth {
		return AdmissionResult{Failed: true, Reason: contract.ReasonDelegationDepth,
			Detail: fmt.Sprintf("actor chain of length %d exceeds the declared maximum delegation depth %d for %q",
				len(req.Context.ActorChain), entry.MaxDelegationDepth, req.Action)}
	}
	if detail := validateArguments(entry, req.Attributes); detail != "" {
		return AdmissionResult{Failed: true, Reason: contract.ReasonSchemaViolation, Detail: detail}
	}
	return AdmissionResult{Entry: entry}
}

// validateArguments checks the caller-supplied arguments against the declared
// argument schema, refusing both unknown fields and missing required ones.
func validateArguments(entry ActionEntry, attrs contract.AttributeSet) string {
	var unknown, missing, mistyped []string
	present := map[string]contract.Attribute{}
	for _, p := range attrs.Paths() {
		if contract.NamespaceOf(p) != contract.NsArgs {
			continue
		}
		name := strings.TrimPrefix(p, "args.")
		// A required argument that is present but ABSENT or UNKNOWN has not
		// been supplied. Counting the entry rather than its state would let a
		// caller satisfy a required field by naming it and giving it nothing.
		if attrs[p].State == contract.StateKnown {
			present[name] = attrs[p]
		}
		declared, ok := entry.Arguments[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		a := attrs[p]
		if a.State == contract.StateKnown && !valueMatchesType(a.Value, declared) {
			mistyped = append(mistyped, fmt.Sprintf("%s (declared %s)", name, declared))
		}
	}
	for _, req := range entry.RequiredArguments {
		if _, ok := present[req]; !ok {
			missing = append(missing, req)
		}
	}
	sort.Strings(unknown)
	sort.Strings(missing)
	sort.Strings(mistyped)
	var parts []string
	if len(unknown) > 0 {
		parts = append(parts, "unknown argument fields "+strings.Join(unknown, ", "))
	}
	if len(missing) > 0 {
		parts = append(parts, "missing required argument fields "+strings.Join(missing, ", "))
	}
	if len(mistyped) > 0 {
		parts = append(parts, "wrongly typed argument fields "+strings.Join(mistyped, ", "))
	}
	return strings.Join(parts, "; ")
}

func valueMatchesType(v any, t ValueType) bool {
	switch t {
	case TypeNumber:
		switch v.(type) {
		case int, int32, int64, float32, float64:
			return true
		}
		return false
	case TypeString:
		_, ok := v.(string)
		return ok
	case TypeBoolean:
		_, ok := v.(bool)
		return ok
	case TypeArray:
		switch v.(type) {
		case []any, []string:
			return true
		}
		return false
	case TypeAny, "":
		return true
	default:
		return false
	}
}

// CompatibilityEntry is one temporary, explicit, action-scoped exception that
// maps NotApplicable to a permit during shadow migration.
//
// ADR-065 owns default deny as a product and security decision, and this is the
// only sanctioned deviation. It is not a per-tool posture field and it cannot
// become a steady-state product option: each entry names an owner, an expiry
// and a removal issue, and the registry refuses to apply it to a privileged,
// irreversible or data-egress action however it was configured.
type CompatibilityEntry struct {
	Action       contract.ID `json:"action"`
	Owner        string      `json:"owner"`
	ExpiresAt    time.Time   `json:"expires_at"`
	RemovalIssue string      `json:"removal_issue"`
}

// CompatibilityProfile is the set of active exceptions.
type CompatibilityProfile struct {
	Entries []CompatibilityEntry
}

// CompatOutcome reports whether the profile applies.
type CompatOutcome struct {
	Applies bool
	Detail  string
	// Refusal explains why an entry that names this action was NOT applied.
	Refusal string
}

// Apply reports whether a compatibility entry converts this NotApplicable
// result into a permit.
//
// It is called only for NotApplicable. A Deny is a decision and a compatibility
// posture never reverses one; an Indeterminate is an unresolved dependency and
// permitting on one would reintroduce exactly the on_error=Permit behaviour
// that turns any outage into a widening of access.
func (p *CompatibilityProfile) Apply(entry ActionEntry, action contract.ID, now time.Time) CompatOutcome {
	if p == nil {
		return CompatOutcome{}
	}
	for _, e := range p.Entries {
		if e.Action != action {
			continue
		}
		if !now.Before(e.ExpiresAt) {
			return CompatOutcome{Refusal: fmt.Sprintf("compatibility exception for %q expired at %s", action, e.ExpiresAt.Format(time.RFC3339))}
		}
		if entry.Privileged || entry.Irreversible || entry.DataEgress {
			return CompatOutcome{Refusal: fmt.Sprintf(
				"compatibility exception for %q is unavailable: the action is declared privileged=%t irreversible=%t data_egress=%t",
				action, entry.Privileged, entry.Irreversible, entry.DataEgress)}
		}
		if e.Owner == "" || e.RemovalIssue == "" {
			return CompatOutcome{Refusal: fmt.Sprintf("compatibility exception for %q declares no owner or removal issue", action)}
		}
		return CompatOutcome{Applies: true, Detail: fmt.Sprintf(
			"temporary compatibility exception owned by %s, expires %s, removal tracked in %s",
			e.Owner, e.ExpiresAt.Format(time.RFC3339), e.RemovalIssue)}
	}
	return CompatOutcome{}
}

// CompatibilityObligations are attached whenever the compatibility posture
// fires, so a permit reached this way is never quiet.
func CompatibilityObligations(action contract.ID) []contract.Obligation {
	return []contract.Obligation{{
		Type:          contract.ObImmutableAudit,
		Params:        map[string]string{"level": "high", "channel": "compatibility_posture", "delivery": string(contract.DeliveryDurable)},
		Mandatory:     true,
		SourcePolicy:  "compatibility:" + action.String(),
		SchemaVersion: 1,
	}}
}
