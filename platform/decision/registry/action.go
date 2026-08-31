package registry

import (
	"sort"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// Effects are the declared risk classes of an action.
//
// Every field is a Declaration rather than a bool, because every one of them is
// read by a rule for which false is the permissive answer. pdp.CompatibilityProfile
// refuses to apply an exception to a privileged, irreversible or data-egress
// action; with plain bools, an action whose classes nobody filled in is
// indistinguishable from one somebody classified as harmless, and the
// difference decides whether a fail-open exception attaches to it.
type Effects struct {
	// Irreversible reports whether the action cannot be undone.
	Irreversible Declaration `json:"irreversible"`
	// Spend reports whether the action moves money or consumes a paid
	// resource.
	Spend Declaration `json:"spend"`
	// DataEgress reports whether the action moves data out of the
	// organization.
	DataEgress Declaration `json:"data_egress"`
	// Privileged reports whether the action administers the governed system
	// itself.
	Privileged Declaration `json:"privileged"`
}

// Validate refuses an undeclared class.
func (e Effects) Validate(subject string) Findings {
	var out Findings
	for _, f := range []struct {
		name  string
		value Declaration
	}{
		{"irreversible", e.Irreversible},
		{"spend", e.Spend},
		{"data_egress", e.DataEgress},
		{"privileged", e.Privileged},
	} {
		if !f.value.IsValid() {
			out = out.errorf(CodeEffectNotDeclared, subject,
				"risk class %s is %s; every class is declared explicitly, because an unfilled class reads as the permissive answer at every rule that consults it",
				f.name, f.value)
		}
	}
	return out
}

// CompatibilityIneligible reports whether these effects make the temporary
// compatibility posture unavailable, and names why.
//
// ADR-065: the legacy compatibility posture "is unavailable for privileged,
// irreversible, data-egress, identity-dependent, or security-control-dependent
// actions". The first three are declared classes here. The last two are
// properties of the POLICY set rather than of the action, so they are enforced
// where that information exists, at publication, and are named in the
// documentation of CheckPublication rather than silently dropped.
func (e Effects) CompatibilityIneligible() []string {
	var why []string
	if e.Privileged.Yes() {
		why = append(why, "privileged")
	}
	if e.Irreversible.Yes() {
		why = append(why, "irreversible")
	}
	if e.DataEgress.Yes() {
		why = append(why, "data_egress")
	}
	return why
}

// ActionRecord is one canonical governed operation.
//
// It is the ADR-065 promotion of the source specification's Tool: a canonical
// identity with aliases, so that two connectors exposing the same operation
// under two names are one governed thing rather than two.
type ActionRecord struct {
	// ID is the canonical action identifier.
	ID contract.ID `json:"id"`
	// Aliases are legacy connector and terminal names that resolve to this
	// action. They are a MIGRATION surface: ADR-065 keeps string-heuristic
	// naming only in an observable, time-bound adapter, and an alias is how
	// that adapter resolves without a heuristic.
	Aliases []string `json:"aliases,omitempty"`
	// Tags are the governed vocabulary a policy selects on. Every tag must be
	// declared in the catalog's tag registry.
	Tags []string `json:"tags"`
	// Posture is the declared failure semantics. Both axes are mandatory.
	Posture Posture `json:"posture"`
	// MaxDelegationDepth bounds the actor chain.
	MaxDelegationDepth int `json:"max_delegation_depth"`
	// Arguments is the typed, unit-carrying argument schema.
	Arguments map[string]pdp.ValueType `json:"arguments"`
	// RequiredArguments must be present and known.
	RequiredArguments []string `json:"required_arguments,omitempty"`
	// PayloadLeaves are the canonical response leaf paths a disclosure
	// obligation expands over.
	PayloadLeaves []string `json:"payload_leaves,omitempty"`
	// ResourceType names the registered resource type this action operates on.
	// Empty means the action has no resource beyond itself, which is the case
	// for a tool that declares no resource mapping.
	ResourceType string `json:"resource_type,omitempty"`
	// Effects are the declared risk classes.
	Effects Effects `json:"effects"`
	// RequiredCapabilities are obligation types and versions that any
	// enforcement point admitting this action must advertise, independently of
	// which policies happen to be published. It is the action's own statement
	// of what enforcing it requires.
	RequiredCapabilities []contract.Capability `json:"required_capabilities,omitempty"`
}

// Validate checks the record in isolation. Cross-record rules, such as whether
// its tags are declared and whether a permissive posture has an exception
// behind it, belong to the catalog and are not repeated here.
func (a ActionRecord) Validate() Findings {
	subject := a.ID.String()
	var out Findings
	if a.ID.Kind != contract.KindAction {
		out = out.errorf(CodeIdentifierInvalid, subject,
			"an action record carries an action identifier, got kind %q", a.ID.Kind)
	}
	if err := a.ID.Validate(); err != nil {
		out = out.errorf(CodeIdentifierInvalid, subject, "%v", err)
	}
	out = append(out, a.Posture.Validate(subject)...)
	out = append(out, a.Effects.Validate(subject)...)
	if a.MaxDelegationDepth <= 0 {
		// The same rule pdp.Registry.Admit enforces. Reading a missing depth as
		// unbounded turns an unfilled field into the most permissive setting
		// available, and this is the registration that could have refused it.
		out = out.errorf(CodeDelegationDepthNotDeclared, subject,
			"maximum delegation depth is %d; a non-positive depth is a registry defect, not an action without a limit",
			a.MaxDelegationDepth)
	}
	for _, name := range sortedStrings(a.RequiredArguments) {
		if _, ok := a.Arguments[name]; !ok {
			out = out.errorf(CodeArgumentNotDeclared, subject,
				"argument %q is required but the argument schema does not declare it", name)
		}
	}
	for name, typ := range a.Arguments {
		if !validValueType(typ) {
			out = out.errorf(CodeArgumentNotDeclared, subject,
				"argument %q declares value type %q, which is not one the admission validator can check", name, typ)
		}
	}
	out = append(out, validateCapabilities(subject, "required capability", a.RequiredCapabilities)...)
	return out
}

// validValueType is membership over pdp.ValueType.
//
// pdp.valueMatchesType treats an unrecognized type as a mismatch, which fails
// closed at admission but reports every call as a schema violation. Catching it
// at registration names the real defect, which is the schema and not the call.
func validValueType(t pdp.ValueType) bool {
	switch t {
	case pdp.TypeString, pdp.TypeNumber, pdp.TypeBoolean, pdp.TypeArray, pdp.TypeAny:
		return true
	default:
		return false
	}
}

// validateCapabilities refuses a capability naming an undeclared obligation
// type or a non-positive version.
//
// Version zero is the trap this closes. contract.PEPProfile.Supports matches on
// exact version equality, so a capability advertised at version 0 matches an
// obligation whose SchemaVersion nobody set, and two unset fields agreeing is
// not evidence that the enforcement point implements anything.
func validateCapabilities(subject, label string, caps []contract.Capability) Findings {
	var out Findings
	declared := map[contract.ObligationType]bool{}
	for _, t := range contract.AllObligationTypes() {
		declared[t] = true
	}
	sorted := append([]contract.Capability(nil), caps...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].Version < sorted[j].Version
	})
	for _, c := range sorted {
		if !declared[c.Type] {
			out = out.errorf(CodeObligationTypeUndeclared, subject,
				"%s names obligation type %q, which the contract does not declare", label, c.Type)
		}
		if c.Version <= 0 {
			out = out.errorf(CodeCapabilityVersionInvalid, subject,
				"%s %q declares version %d; capability matching is exact, so a non-positive version would match only an obligation whose version was never set",
				label, c.Type, c.Version)
		}
	}
	return out
}

// entry projects the record into the admission-time action entry.
//
// It is unexported and reached only through Catalog.PDPRegistry, which refuses
// to project an invalid catalog. That ordering is what makes the Declaration
// reads below safe: an UNSPECIFIED class would project as false, which is why
// no path reaches this function without validation.
func (a ActionRecord) entry() pdp.ActionEntry {
	args := make(map[string]pdp.ValueType, len(a.Arguments))
	for k, v := range a.Arguments {
		args[k] = v
	}
	return pdp.ActionEntry{
		ID:                 a.ID,
		Tags:               sortedStrings(a.Tags),
		MaxDelegationDepth: a.MaxDelegationDepth,
		Arguments:          args,
		RequiredArguments:  sortedStrings(a.RequiredArguments),
		PayloadLeaves:      sortedStrings(a.PayloadLeaves),
		Irreversible:       a.Effects.Irreversible.Yes(),
		DataEgress:         a.Effects.DataEgress.Yes(),
		Privileged:         a.Effects.Privileged.Yes(),
	}
}

// clone returns a deep copy of the record.
//
// Every accessor and every store goes through it. Without it the catalog hands
// out its own slices and its own argument map: a caller could add an argument,
// remove a governed tag or raise a required capability AFTER registration, past
// every rule that would have refused it, and the change would reach the next
// projection. The catalog is the authority for these values, so nothing outside
// it may hold a writable reference to them.
func (a ActionRecord) clone() ActionRecord {
	out := a
	out.Tags = sortedStrings(a.Tags)
	out.Aliases = append([]string(nil), a.Aliases...)
	out.RequiredArguments = append([]string(nil), a.RequiredArguments...)
	out.PayloadLeaves = append([]string(nil), a.PayloadLeaves...)
	out.RequiredCapabilities = append([]contract.Capability(nil), a.RequiredCapabilities...)
	if a.Arguments != nil {
		out.Arguments = make(map[string]pdp.ValueType, len(a.Arguments))
		for k, v := range a.Arguments {
			out.Arguments[k] = v
		}
	}
	return out
}

func sortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
