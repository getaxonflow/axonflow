// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// stepLabels are the two paths the ruling names, written out rather than read
// from CallerTypedLabelPaths: a cell that iterates the list under test passes
// with the list emptied, having checked nothing (plant f found exactly that).
var stepLabels = []string{"args.context.step__name", "args.context.tool__name"}

// labelDoc declares the two caller-typed step labels (optional, as a label must
// be) beside the attributes the pinned authority cases use, so a refusal below
// is about the label and never about an undeclared path.
func labelDoc(policies ...Policy) *Document {
	d := authoringDoc(policies...)
	d.Attributes = append(d.Attributes,
		AttributeSchema{Path: "args.context.step__name", Type: TypeString, Optional: true},
		AttributeSchema{Path: "args.context.tool__name", Type: TypeString, Optional: true},
	)
	return d
}

func policyOver(authority contract.Authority, where Condition) Policy {
	return Policy{
		ID: "P", Authority: authority, Root: RootOrganization,
		Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true}, Where: where,
	}
}

// labelEq is the one admitted read: a positive eq against a string, absence a
// non-match.
func labelEq(path, name string) Condition {
	return Compare(path, OpEq, name).HandlingAbsence(AbsentIsNoMatch)
}

// refusedAsLabel reports whether errs carry the caller-typed label refusal for
// path with a detail containing why: the AUTHORITY_FROM_UNTRUSTED rule, the
// path named as a caller-typed label, and the specific reason. A bare rule match
// would also be satisfied by checkAuthorityRule's own findings.
func refusedAsLabel(errs []ValidationError, path, why string) bool {
	for _, e := range errs {
		if e.Rule == RuleAuthorityFromUntrusted && strings.Contains(e.Detail, `"`+path+`" is a caller-typed label`) && strings.Contains(e.Detail, why) {
			return true
		}
	}
	return false
}

func absenceRefusal(errs []ValidationError, fragment string) bool {
	for _, e := range errs {
		if e.Rule == RuleAbsenceNotHandled && strings.Contains(e.Detail, fragment) {
			return true
		}
	}
	return false
}

// TestAPermissionKeyedOnACallerTypedStepLabelIsRefused is #4249 row 5703546409
// as ruled for the two step labels (option B'): a permission that reads either
// label, in any shape and any clause, is refused.
func TestAPermissionKeyedOnACallerTypedStepLabelIsRefused(t *testing.T) {
	const why = "a permit the caller selects"
	for _, path := range stepLabels {
		cases := map[string]func() Policy{
			"eq":          func() Policy { return policyOver(contract.AuthorityPermission, labelEq(path, "read_only_lookup")) },
			"ne":          func() Policy { return policyOver(contract.AuthorityPermission, Compare(path, OpNe, "export_ledger")) },
			"membership":  func() Policy { return policyOver(contract.AuthorityPermission, Member(path, "read_only_lookup")) },
			"intersects":  func() Policy { return policyOver(contract.AuthorityPermission, Intersects(path, "a", "b")) },
			"in an and":   func() Policy { return policyOver(contract.AuthorityPermission, And(True(), labelEq(path, "x"))) },
			"in an or":    func() Policy { return policyOver(contract.AuthorityPermission, Or(True(), labelEq(path, "x"))) },
			"under a not": func() Policy { return policyOver(contract.AuthorityPermission, Not(labelEq(path, "x"))) },
			"as the right side of attr_compare": func() Policy {
				return policyOver(contract.AuthorityPermission, AttrCompare("args.ticket_owner", OpEq, path))
			},
			"in the unless clause (it only narrows; refused fail-closed)": func() Policy {
				p := policyOver(contract.AuthorityPermission, True())
				u := labelEq(path, "export_ledger")
				p.Unless = &u
				return p
			},
			"in the resource scope": func() Policy {
				p := policyOver(contract.AuthorityPermission, True())
				r := labelEq(path, "read_only_lookup")
				p.ResourceScope = &r
				return p
			},
		}
		for name, build := range cases {
			t.Run(path+"/"+name, func(t *testing.T) {
				if errs := labelDoc(build()).Validate(); !refusedAsLabel(errs, path, why) {
					t.Fatalf("a permission reading %s (%s) was not refused as a caller-typed label: %v", path, name, errs)
				}
			})
		}
	}
}

// TestALabelIsReadOnlyAsAPositiveRestrictingRead is the R3 polarity ruling: in a
// constraint (and a requirement and an inspection, which take the same walk) a
// label read that is negated, sits in unless, uses any operator but eq, or is a
// set or pair comparison, is refused, each with the reason for its shape.
func TestALabelIsReadOnlyAsAPositiveRestrictingRead(t *testing.T) {
	for _, path := range stepLabels {
		cases := map[string]struct {
			build func() Policy
			why   string
		}{
			"under a not": {func() Policy { return policyOver(contract.AuthorityConstraint, Not(labelEq(path, "x"))) }, "may not be read under not"},
			"under a not inside an and": {func() Policy {
				return policyOver(contract.AuthorityConstraint, And(True(), Not(labelEq(path, "x"))))
			}, "may not be read under not"},
			"inside unless": {func() Policy {
				p := policyOver(contract.AuthorityConstraint, True())
				u := labelEq(path, "trusted")
				p.Unless = &u
				return p
			}, "may not be read inside unless"},
			"ne": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Compare(path, OpNe, "x").HandlingAbsence(AbsentIsNoMatch))
			}, "not ne"},
			"lt": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Compare(path, OpLt, "m").HandlingAbsence(AbsentIsNoMatch))
			}, "not lt"},
			"le": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Compare(path, OpLe, "m").HandlingAbsence(AbsentIsNoMatch))
			}, "not le"},
			"gt": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Compare(path, OpGt, "m").HandlingAbsence(AbsentIsNoMatch))
			}, "not gt"},
			"ge": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Compare(path, OpGe, "m").HandlingAbsence(AbsentIsNoMatch))
			}, "not ge"},
			"member": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Member(path, "x").HandlingAbsence(AbsentIsNoMatch))
			}, "not as member"},
			"superset": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Superset(path, "x").HandlingAbsence(AbsentIsNoMatch))
			}, "not as superset"},
			"intersects": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Intersects(path, "x", "y").HandlingAbsence(AbsentIsNoMatch))
			}, "not as intersects"},
			"attr_compare, label on the left": {func() Policy {
				return policyOver(contract.AuthorityConstraint, AttrCompare(path, OpEq, "args.ticket_owner"))
			}, "not as attr_compare"},
			"attr_compare, label on the right": {func() Policy {
				return policyOver(contract.AuthorityConstraint, AttrCompare("args.ticket_owner", OpEq, path))
			}, "not as attr_compare"},
			"under a not over an or": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Not(Or(labelEq(path, "a"), labelEq(path, "b"))))
			}, "may not be read under not"},
			"under a not over an and": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Not(And(True(), labelEq(path, "a"))))
			}, "may not be read under not"},
			"inside unless, in an or": {func() Policy {
				p := policyOver(contract.AuthorityConstraint, True())
				u := Or(labelEq(path, "a"), labelEq(path, "b"))
				p.Unless = &u
				return p
			}, "may not be read inside unless"},
			"the empty string": {func() Policy {
				return policyOver(contract.AuthorityConstraint, labelEq(path, ""))
			}, "may not be compared with the empty string"},
			"a non-string literal": {func() Policy {
				return policyOver(contract.AuthorityConstraint, Compare(path, OpEq, 7).HandlingAbsence(AbsentIsNoMatch))
			}, "only against a string literal"},
		}
		for name, c := range cases {
			t.Run(path+"/"+name, func(t *testing.T) {
				if errs := labelDoc(c.build()).Validate(); !refusedAsLabel(errs, path, c.why) {
					t.Fatalf("a constraint reading %s %s was not refused naming %q: %v", path, name, c.why, errs)
				}
			})
		}
		for _, authority := range []contract.Authority{contract.AuthorityRequirement, contract.AuthorityInspection} {
			t.Run(path+"/"+string(authority)+" inside unless", func(t *testing.T) {
				p := policyOver(authority, True())
				u := labelEq(path, "trusted")
				p.Unless = &u
				if errs := labelDoc(p).Validate(); !refusedAsLabel(errs, path, "may not be read inside unless") {
					t.Fatalf("a %s with %s inside unless was not refused: %v", authority, path, errs)
				}
			})
		}
	}
}

// TestAPositiveLabelReadIsAdmitted is the admitted half: eq, an or of eq ("any
// of these names"), and eq in an and with another positive term, in a
// constraint, a requirement and an inspection, and in resource_scope.
func TestAPositiveLabelReadIsAdmitted(t *testing.T) {
	for _, path := range stepLabels {
		wheres := map[string]Condition{
			"eq":       labelEq(path, "export_ledger"),
			"or of eq": Or(labelEq(path, "export_ledger"), labelEq(path, "wire_funds")),
			"eq in an and with another positive term": And(labelEq(path, "export_ledger"),
				Compare("args.amount_cents", OpGt, 1000).HandlingAbsence(AbsentIsUnknown)),
			"an and of an or of eq": And(True(), Or(labelEq(path, "a"), labelEq(path, "b"))),
			// An EVEN number of not is a positive read: k_not swaps MATCH and
			// NO_MATCH and keeps UNKNOWN, so not(not(eq)) evaluates exactly as eq.
			"not of not of eq": Not(Not(labelEq(path, "export_ledger"))),
		}
		for _, authority := range []contract.Authority{contract.AuthorityConstraint, contract.AuthorityRequirement, contract.AuthorityInspection} {
			for name, where := range wheres {
				t.Run(path+"/"+string(authority)+"/"+name, func(t *testing.T) {
					errs := labelDoc(policyOver(authority, where)).Validate()
					// The two rules under test; a requirement with no obligation is
					// refused SELECTOR_MATCHES_NOTHING for its own reason.
					if firedRule(errs, RuleAuthorityFromUntrusted) || firedRule(errs, RuleAbsenceNotHandled) {
						t.Fatalf("a %s reading %s as %s was refused: %v", authority, path, name, errs)
					}
				})
			}
		}
		t.Run(path+"/in resource_scope", func(t *testing.T) {
			p := policyOver(contract.AuthorityConstraint, True())
			r := labelEq(path, "export_ledger")
			p.ResourceScope = &r
			if errs := labelDoc(p).Validate(); firedRule(errs, RuleAuthorityFromUntrusted) || firedRule(errs, RuleAbsenceNotHandled) {
				t.Fatalf("a positive %s read in resource_scope was refused: %v", path, errs)
			}
		})
	}
}

// TestALabelConditionMustTreatAbsenceAsANonMatch is master's ruling (A): every
// request that is not a step carries no label, so a positive label read that
// answered unknown on absence would withhold every such request on every plane.
// no_match is REQUIRED, and the label must be declared optional.
func TestALabelConditionMustTreatAbsenceAsANonMatch(t *testing.T) {
	for _, path := range stepLabels {
		for _, authority := range []contract.Authority{contract.AuthorityConstraint, contract.AuthorityRequirement, contract.AuthorityInspection} {
			for name, cond := range map[string]Condition{
				"on_absent unknown":   Compare(path, OpEq, "export_ledger").HandlingAbsence(AbsentIsUnknown),
				"no absence handling": Compare(path, OpEq, "export_ledger"),
			} {
				t.Run(path+"/"+string(authority)+"/"+name, func(t *testing.T) {
					errs := labelDoc(policyOver(authority, cond)).Validate()
					if !absenceRefusal(errs, `must be "no_match"`) || !absenceRefusal(errs, "same dodge as a renamed one") {
						t.Fatalf("a %s over %s with %s was not refused naming why no_match is required: %v", authority, path, name, errs)
					}
				})
			}
			t.Run(path+"/"+string(authority)+"/declared required", func(t *testing.T) {
				d := labelDoc(policyOver(authority, labelEq(path, "export_ledger")))
				for i := range d.Attributes {
					if d.Attributes[i].Path == path {
						d.Attributes[i].Optional = false
					}
				}
				if errs := d.Validate(); !absenceRefusal(errs, "must be declared optional") {
					t.Fatalf("a required declaration of %s was not refused: %v", path, errs)
				}
			})
		}
	}
	// An ordinary argument keeps the opposite rule: its absence may NOT be a
	// non-match, because there omitting the field is a dodge a caller controls.
	errs := labelDoc(policyOver(contract.AuthorityConstraint, Compare("args.ticket_owner", OpEq, "SUP-42").HandlingAbsence(AbsentIsNoMatch))).Validate()
	if !absenceRefusal(errs, "treats its absence as a non-match") {
		t.Fatalf("no_match on an ordinary caller-supplied argument was admitted: %v", errs)
	}
}

// TestTheLabelListLeavesThePinnedArgumentShapesAlone holds the ruling's
// boundary: the list is NARROW, so an argument bound and the equality against a
// string literal pinned legal in TestAuthorityRuleIsNotEvadedByOrderingComparisons
// stay legal on a permission. Widening the list to every args.* path, or to a
// rule over shapes, is a design decision recorded on row 5703546409, and it has
// to move that pin on purpose rather than here by accident.
func TestTheLabelListLeavesThePinnedArgumentShapesAlone(t *testing.T) {
	for name, where := range map[string]Condition{
		"an argument bound":                    Compare("args.amount_cents", OpLe, 500000).HandlingAbsence(AbsentIsUnknown),
		"an equality against a string literal": Compare("args.ticket_owner", OpEq, "SUP-42").HandlingAbsence(AbsentIsUnknown),
	} {
		if errs := labelDoc(permissionOver(where)).Validate(); firedRule(errs, RuleAuthorityFromUntrusted) {
			t.Errorf("%s on a permission was refused: %v", name, errs)
		}
	}
	for _, path := range CallerTypedLabelPaths {
		if !strings.HasPrefix(path, string(contract.NsArgs)+".") {
			t.Errorf("%q is listed as a caller-typed label but is not a caller-supplied path", path)
		}
	}
	if len(CallerTypedLabelPaths) != 2 {
		t.Errorf("the label list has %d paths %v; the ruling names exactly args.context.step__name and args.context.tool__name, and a change to it is a ruling", len(CallerTypedLabelPaths), CallerTypedLabelPaths)
	}
}
