package authoring

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// NewCatalogFromRegistry derives the authoring-time catalog from the registry.
//
// The two are not two tables. platform/decision/registry is the registration
// and governance layer: it owns which actions and resource types exist, what
// each declares, and which realms are trusted. This package owns what an AUTHOR
// may reference and how a rejection is worded. Deriving one from the other is
// what keeps "this policy references an action that no longer exists" a
// detectable condition rather than a stale copy nobody re-checks.
//
// It inherits the registry's own refusal: Catalog.PDPRegistry declines to
// project a catalog with any blocking finding, so a registry carrying a record
// with an undeclared posture, an unspecified risk class or a tag outside the
// vocabulary cannot become an authoring catalog either.
//
// Realm ATTRIBUTES are supplied rather than read from the registry, and that
// split is deliberate. The registry declares which realm qualifiers are
// trusted, because that is its half of the symmetric admission check. Whether a
// realm is interactive and whether it has a group graph are identity-plane
// facts owned by platform/shared/identity, and restating them here would make
// the registry a second authority on the directory. What this function DOES
// enforce is that the two agree: a realm the registry trusts and the caller
// does not describe, or the reverse, is a refusal rather than a silent gap.
func NewCatalogFromRegistry(reg *registry.Catalog, realms map[string]RealmEntry) (*Catalog, error) {
	if reg == nil {
		return nil, fmt.Errorf("authoring: the registry catalog is nil")
	}
	projected, err := reg.PDPRegistry()
	if err != nil {
		return nil, fmt.Errorf("authoring: the registry cannot serve as an authoring catalog: %w", err)
	}

	var problems []string
	for qualifier := range projected.Realms {
		if _, ok := realms[qualifier]; !ok {
			problems = append(problems, fmt.Sprintf(
				"the registry trusts realm %q, which the supplied realm attributes do not describe; an approval pool resolving there could not be checked for interactivity", qualifier))
		}
	}
	for qualifier := range realms {
		if !projected.Realms[qualifier] {
			problems = append(problems, fmt.Sprintf(
				"realm attributes were supplied for %q, which the registry does not trust; an author could scope a policy to a realm no request can arrive from", qualifier))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("authoring: the registry and the realm attributes disagree:\n  %s", strings.Join(problems, "\n  "))
	}

	types := map[string]ResourceType{}
	for _, name := range reg.ResourceTypeNames() {
		rec, ok := reg.ResourceType(name)
		if !ok {
			// Unreachable through ResourceTypeNames, and refused rather than
			// skipped: a derivation that quietly dropped a type would leave the
			// level and containment checks unable to see it, which is the
			// direction that accepts a policy it should have refused.
			return nil, fmt.Errorf("authoring: the registry lists resource type %q but does not hold it", name)
		}
		types[name] = ResourceType{
			Type:          rec.Type,
			Ancestors:     append([]string(nil), rec.Ancestors...),
			Recursive:     rec.Recursion.Recursive(),
			MaxDepth:      rec.MaxDepth,
			PayloadLeaves: append([]string(nil), rec.PayloadLeaves...),
		}
	}

	actions := make(map[string]pdp.ActionEntry, len(projected.Actions))
	for k, v := range projected.Actions {
		actions[k] = v
	}
	realmCopy := make(map[string]RealmEntry, len(realms))
	for k, v := range realms {
		realmCopy[k] = v
	}

	cat := &Catalog{Actions: actions, Realms: realmCopy, ResourceTypes: types}
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	return cat, nil
}
