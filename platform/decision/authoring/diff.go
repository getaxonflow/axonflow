package authoring

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// ChangeKind is what happened to one policy between two document versions.
type ChangeKind string

const (
	ChangeAdded    ChangeKind = "added"
	ChangeRemoved  ChangeKind = "removed"
	ChangeModified ChangeKind = "modified"
)

// Effect is the authorization direction of a change.
//
// EffectUndetermined is a first-class answer rather than a failure, and using
// it freely is the point. Whether an edited condition admits more requests than
// it did is not decidable by looking at two condition trees, and a diff that
// guessed would put "narrowing" next to a change that widened. An operator who
// is told a change is undetermined goes and looks; an operator who is told it
// narrows does not.
type Effect string

const (
	// EffectWidening means the change can only make more requests permitted.
	EffectWidening Effect = "widening"
	// EffectNarrowing means the change can only make fewer requests permitted.
	EffectNarrowing Effect = "narrowing"
	// EffectNeutral means the change cannot affect any decision.
	EffectNeutral Effect = "neutral"
	// EffectMixed means the change contains both directions.
	EffectMixed Effect = "mixed"
	// EffectUndetermined means the direction is not decidable from the source.
	EffectUndetermined Effect = "undetermined"
)

// FieldChange is one changed field, rendered so a portal can display it without
// knowing the Go types.
type FieldChange struct {
	// Field is the JSON field name inside the object that changed.
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// PolicyChange is what happened to one policy.
type PolicyChange struct {
	PolicyID  string             `json:"policy_id"`
	Kind      ChangeKind         `json:"kind"`
	Authority contract.Authority `json:"authority"`
	Effect    Effect             `json:"effect"`
	// Rationale states in one sentence why the effect is what it is. It is the
	// half an operator reads when the effect is undetermined.
	Rationale string        `json:"rationale"`
	Fields    []FieldChange `json:"fields,omitempty"`
}

// Diff is the semantic difference between two authoring documents. It is what
// the portal's dry-run consumes and it is computed from the typed source, never
// from generated Rego: a diff of compiled output would report a formatting
// change as a policy change and would report a policy change in terms nobody
// authored.
type Diff struct {
	FromVersion int            `json:"from_version"`
	ToVersion   int            `json:"to_version"`
	FromDigest  string         `json:"from_digest"`
	ToDigest    string         `json:"to_digest"`
	Effect      Effect         `json:"effect"`
	Metadata    []FieldChange  `json:"metadata,omitempty"`
	Attributes  []FieldChange  `json:"attributes,omitempty"`
	Policies    []PolicyChange `json:"policies,omitempty"`
}

// Empty reports whether the two documents are identical.
func (d Diff) Empty() bool {
	return len(d.Metadata) == 0 && len(d.Attributes) == 0 && len(d.Policies) == 0
}

// DiffDocuments computes the semantic difference between two documents.
//
// Nil on the "from" side is the first version of a document, which makes every
// policy an addition rather than an error.
func DiffDocuments(from, to *Document) (Diff, error) {
	if to == nil {
		return Diff{}, fmt.Errorf("authoring: cannot diff to a nil document")
	}
	out := Diff{ToVersion: to.Policy.Version}
	toDigest, err := Digest(to)
	if err != nil {
		return Diff{}, err
	}
	out.ToDigest = toDigest

	var fromPolicies []pdp.Policy
	var fromAttrs []pdp.AttributeSchema
	if from != nil {
		out.FromVersion = from.Policy.Version
		fromDigest, err := Digest(from)
		if err != nil {
			return Diff{}, err
		}
		out.FromDigest = fromDigest
		fromPolicies = from.Policy.Policies
		fromAttrs = from.Policy.Attributes
		meta, err := diffStruct(from.Metadata, to.Metadata)
		if err != nil {
			return Diff{}, err
		}
		out.Metadata = meta
	}

	attrs, err := diffAttributes(fromAttrs, to.Policy.Attributes)
	if err != nil {
		return Diff{}, err
	}
	out.Attributes = attrs

	policies, err := diffPolicies(fromPolicies, to.Policy.Policies)
	if err != nil {
		return Diff{}, err
	}
	out.Policies = policies
	out.Effect = combineEffects(policies)
	return out, nil
}

func diffPolicies(from, to []pdp.Policy) ([]PolicyChange, error) {
	fromIdx := map[string]pdp.Policy{}
	for _, p := range from {
		fromIdx[p.ID] = p
	}
	toIdx := map[string]pdp.Policy{}
	for _, p := range to {
		toIdx[p.ID] = p
	}
	ids := map[string]struct{}{}
	for id := range fromIdx {
		ids[id] = struct{}{}
	}
	for id := range toIdx {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)

	var out []PolicyChange
	for _, id := range ordered {
		before, hadBefore := fromIdx[id]
		after, hasAfter := toIdx[id]
		switch {
		case !hadBefore && hasAfter:
			effect, why := effectOfPresence(after.Authority, true)
			out = append(out, PolicyChange{PolicyID: id, Kind: ChangeAdded, Authority: after.Authority, Effect: effect, Rationale: why})
		case hadBefore && !hasAfter:
			effect, why := effectOfPresence(before.Authority, false)
			out = append(out, PolicyChange{PolicyID: id, Kind: ChangeRemoved, Authority: before.Authority, Effect: effect, Rationale: why})
		default:
			fields, err := diffStruct(before, after)
			if err != nil {
				return nil, err
			}
			if len(fields) == 0 {
				continue
			}
			effect, why := effectOfModification(before, after, fields)
			out = append(out, PolicyChange{
				PolicyID: id, Kind: ChangeModified, Authority: after.Authority,
				Effect: effect, Rationale: why, Fields: fields,
			})
		}
	}
	return out, nil
}

// effectOfPresence classifies adding or removing a whole policy.
//
// This is the one part of the direction that IS decidable from the authority
// alone, because ADR-065 gives each authority exactly one direction: a
// permission only widens, a constraint only restricts, a requirement only
// attaches obligations that must be discharged, and an inspection policy can
// attach only recording and transforming obligations and can never grant.
func effectOfPresence(a contract.Authority, added bool) (Effect, string) {
	var widensWhenAdded bool
	var why string
	switch a {
	case contract.AuthorityPermission:
		widensWhenAdded = true
		why = "a permission policy can only widen, and permissions compose by union"
	case contract.AuthorityConstraint:
		widensWhenAdded = false
		why = "a constraint policy can only restrict, and a matched constraint always overrides a permission"
	case contract.AuthorityRequirement:
		widensWhenAdded = false
		why = "a requirement policy attaches an obligation that must be discharged before the request proceeds"
	case contract.AuthorityInspection:
		widensWhenAdded = false
		why = "an inspection policy cannot grant, and the obligations it may attach record or transform"
	default:
		return EffectUndetermined, fmt.Sprintf("authority %q is not declared, so the direction of this change is unknown", a)
	}
	if added == widensWhenAdded {
		return EffectWidening, "adding it widens: " + why
	}
	if added {
		return EffectNarrowing, "adding it narrows: " + why
	}
	if widensWhenAdded {
		return EffectNarrowing, "removing it narrows: " + why
	}
	return EffectWidening, "removing it widens: " + why
}

// effectOfModification classifies an edit to an existing policy.
//
// It claims a direction only for changes whose direction follows from the model
// rather than from the data, and returns undetermined for everything else.
// Editing a condition is the everything else: whether the new condition admits
// a superset of what the old one admitted is a question about every possible
// request, and two condition trees do not answer it.
func effectOfModification(before, after pdp.Policy, fields []FieldChange) (Effect, string) {
	changed := map[string]struct{}{}
	for _, f := range fields {
		changed[f.Field] = struct{}{}
	}
	delete(changed, "description")
	if len(changed) == 0 {
		return EffectNeutral, "only the operator-facing description changed, which no decision reads"
	}

	// A break-glass pierce appearing on a constraint makes the constraint
	// suspendable, which widens; the last one disappearing makes it unbreakable,
	// which narrows. That direction follows from the model and not from any
	// request data, so it is safe to state.
	if len(changed) == 1 {
		if _, only := changed["pierceable_by"]; only {
			switch {
			case len(before.PierceableBy) == 0 && len(after.PierceableBy) > 0:
				return EffectWidening, "the policy gained a break-glass pierce, so an approved emergency grant can now suspend it"
			case len(before.PierceableBy) > 0 && len(after.PierceableBy) == 0:
				return EffectNarrowing, "the policy lost its break-glass pierce, so it is now unbreakable by construction"
			}
		}
		// Obligations added to or removed from a requirement move in one
		// direction: more to discharge is narrower, less is wider. It is stated
		// only when the obligation set is a strict superset or subset, because
		// a replaced obligation is a different instruction and not a count.
		if _, only := changed["obligations"]; only {
			switch {
			case obligationsSubset(before.Obligations, after.Obligations):
				return EffectNarrowing, "the policy attaches every obligation it did before, and more"
			case obligationsSubset(after.Obligations, before.Obligations):
				return EffectWidening, "the policy attaches a strict subset of the obligations it did before"
			}
		}
	}

	names := make([]string, 0, len(changed))
	for f := range changed {
		names = append(names, f)
	}
	sort.Strings(names)
	return EffectUndetermined, fmt.Sprintf(
		"fields %s changed; whether the new policy admits more requests than the old one is a question about every possible request, which the source does not answer. Run the shadow diff.",
		strings.Join(names, ", "))
}

func obligationsSubset(sub, super []contract.Obligation) bool {
	if len(sub) >= len(super) {
		return false
	}
	index := map[string]int{}
	for _, o := range super {
		index[obligationKey(o)]++
	}
	for _, o := range sub {
		k := obligationKey(o)
		if index[k] == 0 {
			return false
		}
		index[k]--
	}
	return true
}

func obligationKey(o contract.Obligation) string {
	params := make([]string, 0, len(o.Params))
	for k, v := range o.Params {
		params = append(params, k+"="+v)
	}
	sort.Strings(params)
	return fmt.Sprintf("%s|%s|%v|%t|%d", o.Type, o.Target, params, o.Mandatory, o.SchemaVersion)
}

// combineEffects folds the per-policy directions into one.
func combineEffects(changes []PolicyChange) Effect {
	if len(changes) == 0 {
		return EffectNeutral
	}
	widening, narrowing, undetermined := false, false, false
	for _, c := range changes {
		switch c.Effect {
		case EffectWidening:
			widening = true
		case EffectNarrowing:
			narrowing = true
		case EffectUndetermined, EffectMixed:
			undetermined = true
		}
	}
	// Undetermined dominates. A change set containing one edit whose direction
	// nobody can compute is a change set whose direction nobody can compute,
	// and reporting the majority direction of the rest would be a summary that
	// is wrong in exactly the case an operator needed it.
	switch {
	case undetermined:
		return EffectUndetermined
	case widening && narrowing:
		return EffectMixed
	case widening:
		return EffectWidening
	case narrowing:
		return EffectNarrowing
	default:
		return EffectNeutral
	}
}

func diffAttributes(from, to []pdp.AttributeSchema) ([]FieldChange, error) {
	render := func(list []pdp.AttributeSchema) (map[string]string, error) {
		out := map[string]string{}
		for _, a := range list {
			raw, err := contract.ExactJSON(a)
			if err != nil {
				return nil, err
			}
			out[a.Path] = string(raw)
		}
		return out, nil
	}
	before, err := render(from)
	if err != nil {
		return nil, err
	}
	after, err := render(to)
	if err != nil {
		return nil, err
	}
	paths := map[string]struct{}{}
	for p := range before {
		paths[p] = struct{}{}
	}
	for p := range after {
		paths[p] = struct{}{}
	}
	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	var out []FieldChange
	for _, p := range ordered {
		if before[p] != after[p] {
			out = append(out, FieldChange{Field: p, Before: before[p], After: after[p]})
		}
	}
	return out, nil
}

// diffStruct compares two values of one struct type FIELD BY FIELD, discovered
// by reflection over the type's exported fields.
//
// Reflection rather than a written-out list of fields, and the reason is the
// defect this whole layer exists to prevent. A hand-maintained field list is a
// second declaration of the policy vocabulary: pdp.Policy grows a field, the
// diff keeps returning "no change" for it, and the portal's dry-run reports
// that an edit changed nothing while the compiled bundle changed. The failure
// is silent and it is on the reassuring side. With reflection a new field is
// diffed the moment it exists, and DiffCoversEveryPolicyField holds the walk to
// reflect.NumField so the two cannot drift.
func diffStruct(before, after any) ([]FieldChange, error) {
	bv, av := reflect.ValueOf(before), reflect.ValueOf(after)
	if bv.Type() != av.Type() {
		return nil, fmt.Errorf("authoring: cannot diff a %s against a %s", bv.Type(), av.Type())
	}
	if bv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("authoring: diffStruct requires a struct, got %s", bv.Kind())
	}
	t := bv.Type()
	var out []FieldChange
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := jsonFieldName(f)
		if name == "-" {
			continue
		}
		beforeRaw, err := contract.ExactJSON(bv.Field(i).Interface())
		if err != nil {
			return nil, fmt.Errorf("authoring: rendering %s.%s: %w", t.Name(), f.Name, err)
		}
		afterRaw, err := contract.ExactJSON(av.Field(i).Interface())
		if err != nil {
			return nil, fmt.Errorf("authoring: rendering %s.%s: %w", t.Name(), f.Name, err)
		}
		if string(beforeRaw) != string(afterRaw) {
			out = append(out, FieldChange{Field: name, Before: string(beforeRaw), After: string(afterRaw)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out, nil
}

func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return strings.ToLower(f.Name)
	}
	name := strings.Split(tag, ",")[0]
	if name == "" {
		return strings.ToLower(f.Name)
	}
	return name
}
