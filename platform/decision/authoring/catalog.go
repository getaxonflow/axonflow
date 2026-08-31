package authoring

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// RealmEntry is what the authoring plane needs to know about one trust realm.
//
// Both flags describe the REALM rather than any subject in it, which is
// deliberate. Deciding per subject whether a person could answer an approval
// would put the evaluator in the business of classifying humans, and a service
// account sitting in an approver group for automation reasons is the ordinary
// case that gets misclassified first.
type RealmEntry struct {
	// Interactive reports whether a person in this realm can be asked a
	// question. An approval whose entire eligible set is non-interactive can
	// only expire, and timeout is always deny, so it is refused at save time
	// rather than issued and left to park.
	Interactive bool `json:"interactive"`
	// HasGroupGraph reports whether the realm has a directory group graph at
	// all. In a realm without one the group closure is authoritatively empty
	// rather than unresolvable, so a group-scoped policy is well formed and can
	// never match.
	HasGroupGraph bool `json:"has_group_graph"`
}

// ResourceType is one registered resource type and its hierarchy.
type ResourceType struct {
	// Type is the entity type segment of a resource identifier, for example
	// "JiraIssue".
	Type string `json:"type"`
	// Ancestors are the declared hierarchy level names, from nearest to
	// furthest. A policy may read resource.<level>.* only for a declared level.
	Ancestors []string `json:"ancestors"`
	// Recursive reports whether the hierarchy admits a transitive closure. A
	// containment scope over a non-recursive type would always resolve to the
	// empty set.
	Recursive bool `json:"recursive"`
	// MaxDepth bounds the containment closure of a recursive type, and is zero
	// on a non-recursive one where there is no traversal to bound. It is
	// carried here rather than only in the registry because a bounded closure
	// is what makes truncation a representable condition, and an authoring
	// plane that could not see the bound could not say anything about it.
	MaxDepth int `json:"max_depth,omitempty"`
	// PayloadLeaves are the canonical leaf field paths of this type's
	// representation, over which disclosure obligations expand.
	PayloadLeaves []string `json:"payload_leaves"`
}

// Catalog is the authoring-time registry: the actions, realms and resource
// types a policy may reference.
//
// It is a separate object from the document on purpose. The document is the
// artifact that gets signed and shipped; the catalog is deployment state that
// changes when a connector is added or a realm is federated. Binding the two
// at validation time, rather than embedding the catalog in the document, is
// what makes "this policy references an action that no longer exists" a
// detectable condition instead of a stale copy nobody re-checks.
type Catalog struct {
	// Actions is the action registry, keyed by canonical action identifier
	// string. The entry type is pdp.ActionEntry rather than a local copy: the
	// argument schema, the payload leaves and the risk classes are already
	// declared there, and a second declaration is a second thing to drift.
	Actions map[string]pdp.ActionEntry `json:"actions"`
	// Realms is the trust realm registry, keyed by realm qualifier.
	Realms map[string]RealmEntry `json:"realms"`
	// ResourceTypes is the resource type registry, keyed by type segment.
	ResourceTypes map[string]ResourceType `json:"resource_types"`
}

// Validate rejects a catalog that cannot serve as a validation authority.
//
// A catalog defect has to be caught here rather than surfacing as a policy
// rejection, because an author looking at a rejection that says "this action is
// not registered" has no way to tell whether they typed it wrong or whether the
// registry was loaded empty. Those need different people.
func (c *Catalog) Validate() error {
	if c == nil {
		return fmt.Errorf("authoring: catalog is nil")
	}
	if len(c.Actions) == 0 {
		return fmt.Errorf("authoring: catalog declares no actions; every policy would be refused for naming an unregistered action")
	}
	if len(c.Realms) == 0 {
		return fmt.Errorf("authoring: catalog declares no realms; every scoped policy would be refused for naming an undeclared realm")
	}
	var problems []string
	for key, entry := range c.Actions {
		if entry.ID.String() != key {
			problems = append(problems, fmt.Sprintf("action registry key %q carries entry %q", key, entry.ID))
		}
		if err := entry.ID.Validate(); err != nil {
			problems = append(problems, err.Error())
		}
		if entry.MaxDelegationDepth <= 0 {
			// The same rule the admission path enforces. Reading a missing
			// depth as unbounded turns an unfilled field into the most
			// permissive setting available.
			problems = append(problems, fmt.Sprintf("action %q declares no maximum delegation depth", key))
		}
		for _, name := range entry.RequiredArguments {
			if _, ok := entry.Arguments[name]; !ok {
				problems = append(problems, fmt.Sprintf("action %q requires argument %q, which its argument schema does not declare", key, name))
			}
		}
	}
	for qualifier := range c.Realms {
		if qualifier == "" {
			problems = append(problems, "the realm registry carries an empty realm qualifier")
		}
	}
	for name, rt := range c.ResourceTypes {
		if rt.Type != name {
			problems = append(problems, fmt.Sprintf("resource type registry key %q carries entry %q", name, rt.Type))
		}
		seen := map[string]struct{}{}
		for _, a := range rt.Ancestors {
			if a == "" {
				problems = append(problems, fmt.Sprintf("resource type %q declares an empty ancestor level", name))
			}
			if _, dup := seen[a]; dup {
				problems = append(problems, fmt.Sprintf("resource type %q declares ancestor level %q more than once", name, a))
			}
			seen[a] = struct{}{}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("authoring: the catalog is not usable as a validation authority:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// InteractiveRealms projects the realm registry into the map a compiled
// document carries.
//
// The document needs its own copy because a signed bundle has to be self
// contained: an evaluator verifying a bundle offline cannot call back into a
// registry. This projection is the ONLY writer of that copy, and
// CodeCatalogDisagreement refuses a document whose copy says something the
// registry does not, so the copy can never become a second source of truth
// that an author edits directly.
func (c *Catalog) InteractiveRealms() map[string]bool {
	if c == nil {
		return nil
	}
	out := make(map[string]bool, len(c.Realms))
	for q, r := range c.Realms {
		out[q] = r.Interactive
	}
	return out
}

// Registry projects the catalog into the admission-time registry, so that the
// registry a request is admitted against and the registry a policy was
// authored against are the same object rendered twice rather than two
// independently maintained tables.
func (c *Catalog) Registry() *pdp.Registry {
	if c == nil {
		return nil
	}
	realms := make(map[string]bool, len(c.Realms))
	for q := range c.Realms {
		realms[q] = true
	}
	actions := make(map[string]pdp.ActionEntry, len(c.Actions))
	for k, v := range c.Actions {
		actions[k] = v
	}
	return &pdp.Registry{Actions: actions, Realms: realms}
}

// actionsReached returns the registered actions a selector can match, and
// whether the selector is exhaustive over the registry.
//
// A selector reaches an action when the action satisfies every axis the
// selector declares. Named actions and required tags NARROW together, matching
// how the compiler folds them, because two selector axes that widened each
// other would make "this action, but only when it also carries the pii_egress
// tag" inexpressible.
func (c *Catalog) actionsReached(sel pdp.ActionSelector) []pdp.ActionEntry {
	// Any short-circuits both other axes, matching compileActions, which
	// returns the unconditional verdict for Any without looking at the named
	// actions or the required tags. A reach computed from a different reading
	// of the same selector would make every catalog-aware check disagree with
	// the bundle it is validating.
	if sel.Any {
		out := make([]pdp.ActionEntry, 0, len(c.Actions))
		for _, entry := range c.Actions {
			out = append(out, entry)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
		return out
	}
	named := map[string]struct{}{}
	for _, id := range sel.Actions {
		named[id.String()] = struct{}{}
	}
	var out []pdp.ActionEntry
	for key, entry := range c.Actions {
		if len(named) > 0 {
			if _, ok := named[key]; !ok {
				continue
			}
		}
		if !hasEveryTag(entry.Tags, sel.RequiredTags) {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out
}

func hasEveryTag(have, want []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, t := range have {
		set[t] = struct{}{}
	}
	for _, t := range want {
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return true
}

// resourceTypesReached returns the resource types a policy can be evaluated
// against.
//
// A policy does not name a resource type directly; it names actions, and an
// action's payload and hierarchy belong to the types it operates on. Rather
// than invent a link the registry does not have, this returns EVERY declared
// resource type when the policy reaches any action, and the level and
// containment checks then require a level to be declared by every type. That
// direction matters: requiring the level on every reachable type refuses a
// level that exists for only some of them, which is the case where a
// constraint silently does not apply to the rest.
func (c *Catalog) resourceTypesReached() []ResourceType {
	out := make([]ResourceType, 0, len(c.ResourceTypes))
	for _, rt := range c.ResourceTypes {
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// payloadLeaves returns the union of declared payload leaves across a set of
// actions, which is the field surface a disclosure obligation may target.
func payloadLeaves(entries []pdp.ActionEntry) []string {
	set := map[string]struct{}{}
	for _, e := range entries {
		for _, leaf := range e.PayloadLeaves {
			set[leaf] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// realmsScoped returns every realm qualifier a policy's scope names.
func realmsScoped(s pdp.Scope) []contract.ID {
	var out []contract.ID
	out = append(out, s.Principals...)
	out = append(out, s.Groups...)
	return out
}
