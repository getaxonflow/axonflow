package registry

import (
	"fmt"

	"axonflow/platform/decision/contract"
)

// Posture is the declared failure semantics of one action: what happens when
// nothing granted it, and what happens when the evaluation could not complete.
//
// The two axes are INDEPENDENT. "No permission matched" and "the directory did
// not answer" are different facts with different fixes, and a single field
// covering both would force one of them to be misreported.
//
// Neither axis has a default, an inference, or a global fallback. That is the
// whole point of the type: the source specification's catalog let a tool omit a
// posture and inherit one, and an inherited fail-open is invisible in exactly
// the place an operator looks for it.
type Posture struct {
	// Unmatched is the seed of the permission fold: the outcome when no
	// permission policy matched.
	Unmatched contract.Authorization `json:"unmatched"`
	// OnError is the outcome when the evaluation could not be established.
	OnError contract.Authorization `json:"on_error"`
}

// unmatchedValues are the outcomes an Unmatched axis may declare.
//
// not_applicable, NOT deny, is the fail-closed value. Under ADR-065's
// four-valued outcome deny means an explicit constraint matched; seeding the
// fold with deny would report a constraint that never fired, and EX-36 requires
// exactly that distinction to survive to the trace. Both reach the PEP state
// DENY through contract.StateFor, so the choice costs no permissiveness.
var unmatchedValues = map[contract.Authorization]bool{
	contract.AuthzNotApplicable: true,
	contract.AuthzPermit:        true,
}

// onErrorValues are the outcomes an OnError axis may declare, by the same
// argument: an evaluation that could not complete is indeterminate, not an
// explicit constraint.
var onErrorValues = map[contract.Authorization]bool{
	contract.AuthzIndeterminate: true,
	contract.AuthzPermit:        true,
}

// FailClosedPosture is the production posture: nothing matched is
// not_applicable, an evaluation failure is indeterminate.
//
// It is a function rather than a package variable so that a caller cannot
// mutate the value every registration is compared against.
func FailClosedPosture() Posture {
	return Posture{Unmatched: contract.AuthzNotApplicable, OnError: contract.AuthzIndeterminate}
}

// Permissive reports whether either axis declares a permit.
func (p Posture) Permissive() bool {
	return p.Unmatched == contract.AuthzPermit || p.OnError == contract.AuthzPermit
}

// Validate checks the posture in isolation, returning every reason it is
// refused.
//
// It deliberately does NOT decide whether a permissive Unmatched axis is
// allowed: that depends on the action's risk classes and on whether a live
// compatibility exception names it, neither of which a posture knows. The
// catalog makes that call, in one place, in validateActionPosture.
func (p Posture) Validate(subject string) Findings {
	var out Findings
	for _, axis := range []struct {
		name    string
		value   contract.Authorization
		allowed map[contract.Authorization]bool
		closed  contract.Authorization
	}{
		{"unmatched", p.Unmatched, unmatchedValues, contract.AuthzNotApplicable},
		{"on_error", p.OnError, onErrorValues, contract.AuthzIndeterminate},
	} {
		if axis.value == "" {
			out = out.errorf(CodePostureNotDeclared, subject,
				"posture axis %s is not declared; there is no default, no inference and no global fallback, so declare it as %q to fail closed",
				axis.name, axis.closed)
			continue
		}
		// The declared-outcome check runs first and separately from the
		// per-axis membership check. Without it, an outcome that is not one of
		// the four at all would be reported as "not permitted on this axis",
		// which reads as a policy choice rather than as a typo.
		if err := axis.value.Validate(); err != nil {
			out = out.errorf(CodePostureNotPermitted, subject, "posture axis %s: %v", axis.name, err)
			continue
		}
		if !axis.allowed[axis.value] {
			out = out.errorf(CodePostureNotPermitted, subject,
				"posture axis %s cannot be %q; the declarable values are %s, and %q is the fail-closed one",
				axis.name, axis.value, describeSet(axis.allowed), axis.closed)
		}
	}
	// on_error=permit has no exception path at all, so it is refused here
	// rather than deferred to the catalog. ADR-065 reverses the source
	// proposal's on_error=Permit as an owned decision, and the merged
	// contract.StateFor maps indeterminate to ERROR unconditionally: a
	// registry that accepted a value no evaluator can honour would be
	// recording a permission that does not exist.
	if p.OnError == contract.AuthzPermit {
		out = out.errorf(CodePostureNotPermitted, subject,
			"posture axis on_error cannot be %q under any exception: a permissive error posture converts every dependency outage into a widening of access, and contract.StateFor maps an indeterminate outcome to ERROR unconditionally",
			contract.AuthzPermit)
	}
	return out
}

func describeSet(m map[contract.Authorization]bool) string {
	// AllAuthorizations gives the stable order; ranging the map would make the
	// message text depend on iteration order.
	var out string
	for _, a := range contract.AllAuthorizations() {
		if !m[a] {
			continue
		}
		if out != "" {
			out += " or "
		}
		out += fmt.Sprintf("%q", a)
	}
	return out
}
