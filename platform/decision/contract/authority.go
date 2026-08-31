package contract

import "fmt"

// Authority is the semantic class of a policy. Policies are classified by what
// they are allowed to do, not by where they execute. The current split, where
// "static" means "evaluated in the agent" and "dynamic" means "evaluated in the
// orchestrator", is what made the same stored policy mean different things on
// different planes.
type Authority string

const (
	// AuthorityPermission grants an action when it matches. A permission can
	// only widen, and permissions compose by union.
	AuthorityPermission Authority = "permission"
	// AuthorityConstraint denies or narrows an otherwise granted action. A
	// constraint can only restrict, and an explicit matched constraint always
	// overrides a permission.
	AuthorityConstraint Authority = "constraint"
	// AuthorityRequirement attaches a mandatory typed obligation.
	AuthorityRequirement Authority = "requirement"
	// AuthorityInspection selects content controls. It cannot grant
	// authorization: a detector can never attest that a request is legitimate,
	// only that nothing looked wrong, which is a different claim.
	AuthorityInspection Authority = "inspection"
)

// AllAuthorities returns every declared authority in a stable order.
func AllAuthorities() []Authority {
	return []Authority{AuthorityPermission, AuthorityConstraint, AuthorityRequirement, AuthorityInspection}
}

// Validate rejects an undeclared authority.
func (a Authority) Validate() error {
	for _, k := range AllAuthorities() {
		if k == a {
			return nil
		}
	}
	return fmt.Errorf("policy authority %q is not declared", a)
}

// MayGrant reports whether a policy of this authority can contribute a permit.
// Exactly one authority can, which is the mechanical form of "only one
// operation in the whole algorithm widens a decision".
func (a Authority) MayGrant() bool { return a == AuthorityPermission }
