package registry

import "fmt"

// Declaration is a three-valued boolean whose zero value is invalid.
//
// A plain bool cannot carry "nobody said". Every risk class on an action is
// read by a rule that treats false as the permissive answer: the compatibility
// posture refuses to apply to a privileged, irreversible or data-egress action,
// and an unfilled bool makes an action look like none of those. Making the zero
// value UNSPECIFIED and refusing it at registration turns "the field was never
// filled in" from the most permissive setting available into a rejection.
//
// It is validated by MEMBERSHIP with a default arm rather than by comparison
// against the zero value. Checking d != DeclarationUnspecified would accept
// every other out-of-range value, which is #3576's finding restated: a
// tri-state guarded against its zero value is defeated by any value that is not
// its zero value.
type Declaration int

const (
	// DeclarationUnspecified is the zero value and is never valid.
	DeclarationUnspecified Declaration = iota
	// DeclarationNo is an explicit "this is not the case".
	DeclarationNo
	// DeclarationYes is an explicit "this is the case".
	DeclarationYes
)

// String renders the declaration.
func (d Declaration) String() string {
	switch d {
	case DeclarationNo:
		return "no"
	case DeclarationYes:
		return "yes"
	case DeclarationUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("Declaration(%d)", int(d))
	}
}

// IsValid reports whether the declaration is one of the declared members.
func (d Declaration) IsValid() bool {
	switch d {
	case DeclarationNo, DeclarationYes:
		return true
	case DeclarationUnspecified:
		return false
	default:
		return false
	}
}

// Yes reports whether the declaration is an explicit yes.
//
// It answers false for UNSPECIFIED and for any undeclared value, which is the
// safe direction ONLY because IsValid is checked first: a caller reading Yes on
// a record nothing validated would read an undeclared value as a "no". The two
// readers that matter are ActionRecord.entry and Effects.CompatibilityIneligible,
// and neither is reachable without a passing validation:
// Catalog.PDPRegistry refuses to project a catalog with any blocking finding,
// which TestProjectionRefusesAnInvalidCatalog proves by writing an unvalidated
// record straight into the catalog and requiring the projection to refuse it.
func (d Declaration) Yes() bool { return d == DeclarationYes }

// Edition is the build and licence class of a Policy Enforcement Point.
//
// It describes the enforcement point, not the process holding this registry.
// See the package documentation for why that distinction is load bearing.
type Edition int

const (
	// EditionUnspecified is the zero value and is never valid.
	EditionUnspecified Edition = iota
	// EditionCommunity is a community build, which does not carry the
	// Enterprise-only obligation families.
	EditionCommunity
	// EditionEnterprise is an Enterprise build.
	EditionEnterprise
)

// String renders the edition.
func (e Edition) String() string {
	switch e {
	case EditionCommunity:
		return "community"
	case EditionEnterprise:
		return "enterprise"
	case EditionUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("Edition(%d)", int(e))
	}
}

// IsValid reports whether the edition is one of the declared members.
func (e Edition) IsValid() bool {
	switch e {
	case EditionCommunity, EditionEnterprise:
		return true
	case EditionUnspecified:
		return false
	default:
		return false
	}
}

// AllEditions returns every declared edition in a stable order.
func AllEditions() []Edition { return []Edition{EditionCommunity, EditionEnterprise} }

// Severity is how loudly a finding or an event has to be surfaced.
//
// It is ORDERED: a caller asks whether anything at or above SeverityError was
// produced. An ordered enumeration must be checked for membership BEFORE it is
// compared, because a comparison converts an unrecognized value into an answer
// at one end of the range: Severity(99) >= SeverityError is true, so an
// undeclared severity would read as a blocking error, and Severity(-1) would
// read as quieter than every real finding. AtLeast therefore refuses both.
type Severity int

const (
	// SeverityUnspecified is the zero value and is never valid.
	SeverityUnspecified Severity = iota
	// SeverityInfo records something that happened.
	SeverityInfo
	// SeverityAlarm is a change that widens or narrows what policy reaches
	// without any policy document being edited. It does not block, because the
	// change has already been authorised; it pages the owner.
	SeverityAlarm
	// SeverityError refuses the registration or the projection.
	SeverityError
)

// String renders the severity.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityAlarm:
		return "alarm"
	case SeverityError:
		return "error"
	case SeverityUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("Severity(%d)", int(s))
	}
}

// IsValid reports whether the severity is one of the declared members.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityAlarm, SeverityError:
		return true
	case SeverityUnspecified:
		return false
	default:
		return false
	}
}

// AllSeverities returns every declared severity in ascending order.
func AllSeverities() []Severity { return []Severity{SeverityInfo, SeverityAlarm, SeverityError} }

// AtLeast reports whether s is at or above floor, refusing either operand if it
// is not a declared member.
//
// The error return is not decoration. An ordered comparison on an undeclared
// value silently produces a position in the order, and both ends of that range
// are wrong in a way no assertion would notice: an out-of-range value above the
// top outranks every real severity, and one below the bottom is quieter than
// all of them.
func (s Severity) AtLeast(floor Severity) (bool, error) {
	if !s.IsValid() {
		return false, fmt.Errorf("registry: severity %s is not a declared member and cannot be ordered", s)
	}
	if !floor.IsValid() {
		return false, fmt.Errorf("registry: severity floor %s is not a declared member and cannot be ordered", floor)
	}
	return s >= floor, nil
}
