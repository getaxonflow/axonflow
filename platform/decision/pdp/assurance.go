// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"fmt"

	"axonflow/platform/decision/contract"
)

// THE ASSURANCE CLASS OF A CONTROL (#3884)
//
// ADR-065 "Inspection and risk" says each control declares an assurance class,
// and names three:
//
//	Enforcement   required deterministic control   on timeout or error: deny
//	Gating risk   required score or detector       on timeout or error: deny
//	Advisory      audit, warning, tuning evidence  continue, record unavailable
//
// The ADR names the classes and not how they map onto a policy's shape. The
// mapping is not a choice to make here, because the combiner already decides
// what happens to a policy that cannot be evaluated (combine.go):
//
//   - a constraint that is UNKNOWN makes the decision indeterminate (step 2);
//   - a MANDATORY requirement that is UNKNOWN makes it indeterminate (step 4);
//   - a requirement that is not mandatory, and an inspection policy, are
//     skipped with a warning when UNKNOWN (step 4), and an inspection policy's
//     obligations are forced advisory (step 5);
//   - a permission widens, and has no failure behaviour of its own to declare.
//
// So a control that fails closed is enforcement or gating risk, and the two
// are told apart by what the control READS: a verdict that depends on the
// signal namespace depends on a detector or a scorer having answered, which is
// what "gating risk" means. A control that fails open is advisory.
//
// # WHY A DECLARED FIELD, WHEN THE CLASS IS DERIVABLE
//
// Because the declaration and the derivation are held against each other, and
// the disagreement is the thing worth refusing. A declared class is the
// author's statement of intent, readable by an operator beside the control;
// the derivation is what the combiner will actually do. A structural edit that
// silently turns a fail-closed control into an advisory one - `mandatory`
// cleared on a redaction, say - leaves the declaration saying gating_risk, and
// the document is refused rather than published weaker. The shipped corpus
// declares a class on every control and is refused at load when one is missing
// (RequireDeclaredAssurance), so nothing downstream ever defaults one.
//
// The derivation here is not the evidence that the mapping is right. That is
// TestTheDeclaredAssuranceClassIsWhatTheCombinerDoes, which drives the
// combiner itself with each shipped control UNKNOWN and reads the decision it
// makes, without calling this function.

// AssuranceClass is a control's declared failure behaviour.
type AssuranceClass string

const (
	// AssuranceEnforcement is a required deterministic control: it denies when
	// it cannot be evaluated, and it reads no signal.
	AssuranceEnforcement AssuranceClass = "enforcement"
	// AssuranceGatingRisk is a required control whose verdict depends on a
	// detector or a scorer: it denies when it cannot be evaluated.
	AssuranceGatingRisk AssuranceClass = "gating_risk"
	// AssuranceAdvisory is audit, warning or tuning evidence: when it cannot be
	// evaluated the decision continues and the gap is recorded. It cannot deny.
	AssuranceAdvisory AssuranceClass = "advisory"
)

// AllAssuranceClasses returns every declared class.
func AllAssuranceClasses() []AssuranceClass {
	return []AssuranceClass{AssuranceEnforcement, AssuranceGatingRisk, AssuranceAdvisory}
}

// Validate rejects an undeclared class.
func (c AssuranceClass) Validate() error {
	for _, k := range AllAssuranceClasses() {
		if k == c {
			return nil
		}
	}
	return fmt.Errorf("assurance class %q is not declared; the classes are %v", c, AllAssuranceClasses())
}

// DeriveAssurance returns the assurance class the combiner's failure semantics
// give a policy, and whether the policy is a control at all. A permission, and
// an undeclared authority, is not.
func DeriveAssurance(p Policy) (AssuranceClass, bool) {
	switch p.Authority {
	case contract.AuthorityInspection:
		return AssuranceAdvisory, true
	case contract.AuthorityRequirement:
		if !p.Mandatory {
			return AssuranceAdvisory, true
		}
	case contract.AuthorityConstraint:
	default:
		return "", false
	}
	if paths := signalPaths(p); len(paths) > 0 {
		return AssuranceGatingRisk, true
	}
	return AssuranceEnforcement, true
}

// signalPaths returns the attribute paths a policy reads from the signal
// namespace, sorted, because ReferencedPaths is.
func signalPaths(p Policy) []string {
	var out []string
	for _, path := range p.ReferencedPaths() {
		if contract.NamespaceOf(path) == contract.NsSignal {
			out = append(out, path)
		}
	}
	return out
}

// validateAssurance holds a declared class to the policy's shape. It is called
// only when a class is declared.
func validateAssurance(p Policy) []ValidationError {
	if err := p.Assurance.Validate(); err != nil {
		return []ValidationError{{RuleAssuranceUnknown, p.ID, err.Error()}}
	}
	derived, control := DeriveAssurance(p)
	if !control {
		return []ValidationError{{RuleAssuranceOnPermission, p.ID, fmt.Sprintf(
			"a %s policy declares assurance class %q; only a control - a constraint, a requirement or an inspection - "+
				"has a failure behaviour to declare, and a permission only widens", p.Authority, p.Assurance)}}
	}
	if p.Assurance != derived {
		return []ValidationError{{RuleAssuranceMismatch, p.ID, assuranceMismatchDetail(p, derived)}}
	}
	return nil
}

// assuranceMismatchDetail says which way a declaration is wrong, because the
// remedy differs by direction.
func assuranceMismatchDetail(p Policy, derived AssuranceClass) string {
	switch {
	case p.Assurance == AssuranceAdvisory:
		return fmt.Sprintf("declared advisory, but this %s denies when it cannot be evaluated, which makes it %s; an advisory "+
			"control cannot return deny", describeShape(p), derived)
	case derived == AssuranceAdvisory:
		return fmt.Sprintf("declared %s, but this %s is skipped with a warning when it cannot be evaluated, which makes it "+
			"advisory; a control that fails closed is a constraint or a mandatory requirement", p.Assurance, describeShape(p))
	case p.Assurance == AssuranceEnforcement:
		return fmt.Sprintf("declared enforcement, but it reads %v from the signal namespace, so its verdict depends on a "+
			"detector or scorer answering, which makes it gating_risk", signalPaths(p))
	default:
		return "declared gating_risk, but it reads nothing from the signal namespace, so it is a deterministic control, " +
			"which makes it enforcement"
	}
}

func describeShape(p Policy) string {
	if p.Authority == contract.AuthorityRequirement {
		if p.Mandatory {
			return "mandatory requirement"
		}
		return "non-mandatory requirement"
	}
	return string(p.Authority)
}

// RequireDeclaredAssurance refuses a document in which a control declares no
// assurance class, or declares one its shape contradicts.
//
// It is the rule for the SHIPPED corpus. An organization-authored document may
// declare a class and is held to it by Validate, but is not yet required to:
// every stored artifact predates the field, and requiring it there would stop
// them loading.
func RequireDeclaredAssurance(d *Document) error {
	if d == nil {
		return fmt.Errorf("pdp: there is no document to check for declared assurance classes")
	}
	for _, p := range d.Policies {
		_, isAControl := DeriveAssurance(p)
		if isAControl && p.Assurance == "" {
			return fmt.Errorf("pdp: control %q in the %s document declares no assurance class; every shipped control "+
				"declares one (ADR-065, Inspection and risk) and nothing defaults it", p.ID, d.Root)
		}
		if p.Assurance == "" {
			continue
		}
		if errs := validateAssurance(p); len(errs) > 0 {
			return fmt.Errorf("pdp: the %s document: %v", d.Root, errs[0])
		}
	}
	return nil
}
