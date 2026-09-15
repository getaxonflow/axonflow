// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// THE GOLDEN TABLE FOR THE ONE OBLIGATION ALGEBRA (#3891).
//
// Every expectation below is a LITERAL. None is derived by calling the function
// under test, comparing two implementations, or re-rendering the input, because
// a cross-check between two algebras becomes `f(x) == f(x)` the day one
// delegates to the other, and a table that renders its expectations through the
// code it tests proves the renderer. The stateful planner in
// platform/shared/requirements/obligation consumes this algebra; the cases it
// drives through Plan assert the same literals, which is what makes that
// consumption checkable rather than tautological.
//
// The table is grouped by the property it pins. Absent-target and
// unknown-target are the first group because they are the divergence #3891
// reproduced: the two shipped algebras collapsed the two facts in opposite
// directions.

var goldenNow = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

// goldenPEP advertises every declared type at schema version 1, so a case that
// is not about capability negotiation never trips over it.
func goldenPEP() *PEPProfile {
	p := &PEPProfile{ID: "golden"}
	for _, t := range AllObligationTypes() {
		p.Capabilities = append(p.Capabilities, Capability{Type: t, Version: 1})
	}
	return p
}

func gob(t ObligationType, target string, mandatory bool, src string, params map[string]string) Obligation {
	return Obligation{Type: t, Target: target, Mandatory: mandatory, SourcePolicy: src, SchemaVersion: 1, Params: params}
}

// renderObligation is the ONE rendering the table's literals are written in:
// `type target binding sources params`. It reads only exported fields.
// budgetOb builds a complete quota_reservation in the vocabulary the tree
// actually emits: the CAP is carried, the quantity is a reference the
// reservation service resolves from the request.
func budgetOb(src, counter, limit string, mandatory bool) Obligation {
	return gob(ObQuotaReservation, "", mandatory, src, map[string]string{
		ParamCounter: counter, ParamWindow: "P1D", ParamUnit: "cents",
		ParamLimit: limit, ParamAmountFrom: "args.amount_cents",
	})
}

func renderObligation(o Obligation) string {
	binding := "advisory"
	if o.Mandatory {
		binding = "mandatory"
	}
	target := o.Target
	if target == "" {
		target = "-"
	}
	keys := make([]string, 0, len(o.Params))
	for k := range o.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+o.Params[k])
	}
	params := strings.Join(parts, ";")
	if params == "" {
		params = "-"
	}
	return fmt.Sprintf("%s %s %s %s %s", o.Type, target, binding, o.SourcePolicy, params)
}

func renderAll(in []Obligation) []string {
	out := make([]string, 0, len(in))
	for _, o := range in {
		out = append(out, renderObligation(o))
	}
	return out
}

type goldenApproval struct {
	clauses   []string // "quorum|eligible" per clause, in composed order
	sod       bool
	expiresAt time.Time
}

type goldenCase struct {
	name string
	in   ComposeInput
	// Every field below is a literal expectation.
	denied     bool
	reason     ReasonCode
	detailHas  string
	composed   []string
	unplaced   []string
	dropped    []string
	dropDetail string
	approval   *goldenApproval
}

func mustRules(t *testing.T, rules ...SubsumptionRule) *SubsumptionRules {
	t.Helper()
	s, err := NewSubsumptionRules(rules...)
	if err != nil {
		t.Fatalf("subsumption rules: %v", err)
	}
	return s
}

func goldenCases(t *testing.T) []goldenCase {
	pep := goldenPEP()
	known := KnownPayloadLeaves("user.name", "user.ssn")
	redactSSN := gob(ObFieldRedact, "user.ssn", true, "p1", nil)
	return []goldenCase{
		// ----- absent target vs unknown target ------------------------------
		{
			name:     "known schema, target present: placed",
			in:       ComposeInput{Obligations: []Obligation{redactSSN}, Payload: known, PEP: pep},
			composed: []string{"field_redact user.ssn mandatory p1 -"},
		},
		{
			name: "known schema, target ABSENT: reported as unplaced, not denied",
			in:   ComposeInput{Obligations: []Obligation{redactSSN}, Payload: KnownPayloadLeaves("user.name"), PEP: pep},
			// The instruction is vacuously satisfied by a payload that has no
			// such field; the fact is made visible rather than decided.
			unplaced: []string{"field_redact user.ssn mandatory p1 -"},
		},
		{
			name:     "known EMPTY schema: every target is absent, still not denied",
			in:       ComposeInput{Obligations: []Obligation{redactSSN}, Payload: KnownPayloadLeaves(), PEP: pep},
			unplaced: []string{"field_redact user.ssn mandatory p1 -"},
		},
		{
			name:      "UNKNOWN schema: denied, and the detail names the reason and the distinction",
			in:        ComposeInput{Obligations: []Obligation{redactSSN}, Payload: UnknownPayloadLeaves(ReasonNotSupplied), PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "unknown (attribute_not_supplied)",
		},
		{
			name:      "the registry boundary rule: an undeclared schema is UNKNOWN, not known-empty",
			in:        ComposeInput{Obligations: []Obligation{redactSSN}, Payload: DeclaredPayloadLeaves(nil), PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "unknown (attribute_not_supplied)",
		},
		{
			name:      "a zero-value tri-state is a malformed evaluator input, not a permit",
			in:        ComposeInput{Obligations: []Obligation{redactSSN}, Payload: PayloadLeaves{}, PEP: pep},
			denied:    true,
			reason:    ReasonSchemaViolation,
			detailHas: "state \"\" is not declared",
		},
		{
			name:      "StateAbsent is not a schema-level state",
			in:        ComposeInput{Obligations: []Obligation{redactSSN}, Payload: PayloadLeaves{State: StateAbsent}, PEP: pep},
			denied:    true,
			reason:    ReasonSchemaViolation,
			detailHas: "absence is a fact about one target",
		},
		{
			name:     "an ADVISORY transform with an absent target is neither reported nor applied",
			in:       ComposeInput{Obligations: []Obligation{gob(ObFieldRedact, "user.ssn", false, "d1", nil)}, Payload: KnownPayloadLeaves("user.name"), PEP: pep},
			composed: nil,
			unplaced: nil,
		},
		{
			name: "a non-disclosure family never reads the payload schema, unknown or not",
			in: ComposeInput{Obligations: []Obligation{gob(ObImmutableAudit, "", true, "a1", map[string]string{"channel": "siem"})},
				Payload: UnknownPayloadLeaves(ReasonStale), PEP: pep},
			composed: []string{"immutable_audit - mandatory a1 channel=siem"},
		},
		// ----- the disclosure order, per leaf --------------------------------
		{
			name: "ADR-065's named case: broad redact + narrow hash resolves to redact on both leaves",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldRedact, "user", true, "p1", nil),
				gob(ObFieldHash, "user.ssn", true, "p2", nil),
			}, Payload: known, PEP: pep},
			composed: []string{
				"field_redact user.name mandatory p1 -",
				"field_redact user.ssn mandatory p1,p2 -",
			},
		},
		{
			name: "the mirror: broad hash + narrow redact keeps hash on the other leaf only",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldHash, "user", true, "p1", nil),
				gob(ObFieldRedact, "user.ssn", true, "p2", nil),
			}, Payload: known, PEP: pep},
			composed: []string{
				"field_hash user.name mandatory p1 -",
				"field_redact user.ssn mandatory p1,p2 -",
			},
		},
		{
			name: "remove beats every comparable kind whatever its parameters",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldMask, "user.ssn", true, "p1", map[string]string{"keep": "last4"}),
				gob(ObFieldRemove, "user.ssn", true, "p2", nil),
			}, Payload: known, PEP: pep},
			composed: []string{"field_remove user.ssn mandatory p1,p2 -"},
		},
		{
			name: "annotate is the top of the order: any other comparable transform beats it",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldAnnotate, "user.ssn", true, "p1", map[string]string{"note": "pii"}),
				gob(ObFieldMask, "user.ssn", true, "p2", map[string]string{"keep": "last4"}),
			}, Payload: known, PEP: pep},
			composed: []string{"field_mask user.ssn mandatory p1,p2 keep=last4"},
		},
		{
			name: "same rank, different parameters: incomparable, denied",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldMask, "user.ssn", true, "p1", map[string]string{"keep": "last4"}),
				gob(ObFieldMask, "user.ssn", true, "p2", map[string]string{"keep": "first6"}),
			}, Payload: known, PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "differing parameters",
		},
		{
			name: "an ambiguous LOSER does not deny: two masks plus a remove resolve to remove",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldMask, "user.ssn", true, "p1", map[string]string{"keep": "last4"}),
				gob(ObFieldMask, "user.ssn", true, "p2", map[string]string{"keep": "first6"}),
				gob(ObFieldRemove, "user.ssn", true, "p3", nil),
			}, Payload: known, PEP: pep},
			composed: []string{"field_remove user.ssn mandatory p1,p2,p3 -"},
		},
		{
			name: "an incomparable kind beside a comparable one denies",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldTokenize, "user.ssn", true, "p1", nil),
				gob(ObFieldRedact, "user.ssn", true, "p2", nil),
			}, Payload: known, PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "not comparable with the disclosure order",
		},
		{
			name: "an incomparable kind standing ALONE applies as authored",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldTokenize, "user.ssn", true, "p1", map[string]string{"vault": "v1"}),
			}, Payload: known, PEP: pep},
			composed: []string{"field_tokenize user.ssn mandatory p1 vault=v1"},
		},
		{
			name: "a reviewed subsumption rule rescues the pair, and the winner keeps every source",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldTokenize, "user.ssn", true, "p1", map[string]string{"vault": "v1"}),
				gob(ObFieldRedact, "user.ssn", true, "p2", nil),
			}, Payload: known, PEP: pep,
				Subsumption: mustRules(t, SubsumptionRule{
					Weaker:   TransformRef{Type: ObFieldTokenize, Params: map[string]string{"vault": "v1"}},
					Stronger: TransformRef{Type: ObFieldRedact},
					Reason:   "golden: a constant reveals no more than a vault-recoverable surrogate",
				})},
			composed: []string{"field_redact user.ssn mandatory p1,p2 -"},
		},
		{
			name: "a rule names an INSTRUCTION: the same pair with other parameters is still incomparable",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldTokenize, "user.ssn", true, "p1", map[string]string{"vault": "v2"}),
				gob(ObFieldRedact, "user.ssn", true, "p2", nil),
			}, Payload: known, PEP: pep,
				Subsumption: mustRules(t, SubsumptionRule{
					Weaker:   TransformRef{Type: ObFieldTokenize, Params: map[string]string{"vault": "v1"}},
					Stronger: TransformRef{Type: ObFieldRedact},
					Reason:   "golden",
				})},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "not comparable",
		},
		{
			name: "one leaf covered at two schema versions denies",
			in: ComposeInput{Obligations: []Obligation{
				redactSSN,
				{Type: ObFieldRedact, Target: "user.ssn", Mandatory: true, SourcePolicy: "p2", SchemaVersion: 2},
			}, Payload: known, PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "2 different schema versions",
		},
		// ----- advisory and mandatory interaction ---------------------------
		{
			name: "an advisory contribution that does not compose is DROPPED and recorded, never a denial",
			in: ComposeInput{Obligations: []Obligation{
				redactSSN,
				gob(ObFieldTokenize, "user.ssn", false, "d1", nil),
			}, Payload: known, PEP: pep},
			composed:   []string{"field_redact user.ssn mandatory p1 -"},
			dropped:    []string{"field_tokenize user.ssn advisory d1 -"},
			dropDetail: "not comparable",
		},
		{
			name: "the same instruction attached advisory and mandatory is ONE mandatory instruction",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldRedact, "user.ssn", false, "d1", nil),
				redactSSN,
			}, Payload: known, PEP: pep},
			composed: []string{"field_redact user.ssn mandatory d1,p1 -"},
		},
		{
			name: "an advisory transform that discloses LESS cannot take a leaf away from a mandatory requirement's binding",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObFieldRemove, "user.ssn", false, "d1", nil),
				gob(ObFieldMask, "user.ssn", true, "p1", map[string]string{"keep": "last4"}),
			}, Payload: known, PEP: pep},
			// remove wins the order, and the leaf stays MANDATORY because a
			// policy required a transform on it; the capability check then
			// still runs on the winner.
			composed: []string{"field_remove user.ssn mandatory d1,p1 -"},
		},
		{
			name: "an obligation whose mandatory member was never supplied is refused before the split",
			in: ComposeInput{Obligations: []Obligation{
				{Type: ObFieldRedact, Target: "user.ssn", SourcePolicy: "p1", SchemaVersion: 1, absent: absentMandatory},
			}, Payload: known, PEP: pep},
			denied: true,
			reason: ReasonSchemaViolation,
		},
		// ----- approval -----------------------------------------------------
		{
			name: "2-of-{A,B} and 2-of-{B,C} conjoin; the pools are never flattened",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p1", map[string]string{"quorum": "2", "eligible": "Group::r:a,Group::r:b"}),
				gob(ObApprovalChallenge, "", true, "p2", map[string]string{"quorum": "2", "eligible": "Group::r:b,Group::r:c"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour)},
			composed: []string{
				"approval_challenge - mandatory p1 eligible=Group::r:a,Group::r:b;quorum=2",
				"approval_challenge - mandatory p2 eligible=Group::r:b,Group::r:c;quorum=2",
			},
			approval: &goldenApproval{
				clauses:   []string{"2|Group::r:a,Group::r:b", "2|Group::r:b,Group::r:c"},
				expiresAt: goldenNow.Add(time.Hour),
			},
		},
		{
			name: "identical clauses deduplicate; separation of duties is a conjunction over a boolean",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p1", map[string]string{"quorum": "1", "eligible": "Group::r:b,Group::r:a"}),
				gob(ObApprovalChallenge, "", true, "p2", map[string]string{"quorum": "1", "eligible": "Group::r:a,Group::r:b", "separation_of_duties": "true"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour)},
			// Composed order is by instruction identity, so the clause whose
			// eligible csv sorts first leads whatever order the policies came in.
			composed: []string{
				"approval_challenge - mandatory p2 eligible=Group::r:a,Group::r:b;quorum=1;separation_of_duties=true",
				"approval_challenge - mandatory p1 eligible=Group::r:b,Group::r:a;quorum=1",
			},
			approval: &goldenApproval{
				clauses:   []string{"1|Group::r:a,Group::r:b"},
				sod:       true,
				expiresAt: goldenNow.Add(time.Hour),
			},
		},
		{
			name: "the SHORTEST expiry wins across policies",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p1", map[string]string{"quorum": "1", "eligible": "Group::r:a", ParamExpirySeconds: "600"}),
				gob(ObApprovalChallenge, "", true, "p2", map[string]string{"quorum": "1", "eligible": "Group::r:b", ParamExpirySeconds: "300"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			composed: []string{
				"approval_challenge - mandatory p1 eligible=Group::r:a;expiry_seconds=600;quorum=1",
				"approval_challenge - mandatory p2 eligible=Group::r:b;expiry_seconds=300;quorum=1",
			},
			approval: &goldenApproval{
				clauses:   []string{"1|Group::r:a", "1|Group::r:b"},
				expiresAt: goldenNow.Add(300 * time.Second),
			},
		},
		{
			name: "the evaluator's own stamp takes part in the same minimum",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p1", map[string]string{"quorum": "1", "eligible": "Group::r:a", ParamExpirySeconds: "600"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(100 * time.Second), Now: goldenNow},
			composed: []string{"approval_challenge - mandatory p1 eligible=Group::r:a;expiry_seconds=600;quorum=1"},
			approval: &goldenApproval{clauses: []string{"1|Group::r:a"}, expiresAt: goldenNow.Add(100 * time.Second)},
		},
		{
			// R3 ROUND 2, PINNED. An advisory-only approval must produce NO
			// hold. Measured before the fix: it composed to
			// `{1 of [Group::r:nobody]}` with nothing dropped, so the PDP
			// returned a PERMIT carrying an approval outstanding - a challenge
			// nothing waits on, whose timeout is deny. A detector alone could
			// stop a request.
			name: "an ADVISORY-only approval produces no approval requirement at all",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", false, "d1", map[string]string{"quorum": "1", "eligible": "Group::r:nobody"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			// The instruction is still CARRIED - an advisory obligation is
			// recorded rather than hidden - but it binds nothing.
			composed: []string{"approval_challenge - advisory d1 eligible=Group::r:nobody;quorum=1"},
			approval: nil,
		},
		{
			// The other half of the same finding: an advisory clause may not
			// be added to a mandatory requirement either. Every clause is a
			// conjunct, so adding one makes the challenge STRICTLY harder.
			name: "an ADVISORY clause is not added to a MANDATORY approval requirement",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "m1", map[string]string{"quorum": "1", "eligible": "Group::r:a"}),
				gob(ObApprovalChallenge, "", false, "d1", map[string]string{"quorum": "1", "eligible": "Group::r:nobody"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			composed: []string{
				"approval_challenge - mandatory m1 eligible=Group::r:a;quorum=1",
				"approval_challenge - advisory d1 eligible=Group::r:nobody;quorum=1",
			},
			approval: &goldenApproval{clauses: []string{"1|Group::r:a"}, expiresAt: goldenNow.Add(time.Hour)},
		},
		{
			// And separation of duties: an advisory `true` must not tighten a
			// mandatory `false`. Measured before the fix: it did.
			name: "an ADVISORY separation-of-duties does not tighten a MANDATORY approval",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "m1", map[string]string{"quorum": "1", "eligible": "Group::r:a", "separation_of_duties": "false"}),
				gob(ObApprovalChallenge, "", false, "d1", map[string]string{"quorum": "1", "eligible": "Group::r:b", "separation_of_duties": "true"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			composed: []string{
				"approval_challenge - mandatory m1 eligible=Group::r:a;quorum=1;separation_of_duties=false",
				"approval_challenge - advisory d1 eligible=Group::r:b;quorum=1;separation_of_duties=true",
			},
			approval: &goldenApproval{clauses: []string{"1|Group::r:a"}, sod: false, expiresAt: goldenNow.Add(time.Hour)},
		},
		{
			// THE R3 FINDING, PINNED. An advisory obligation may not shorten a
			// mandatory approval window. Timeout is always deny, so an
			// advisory expiry_seconds at the floor would turn a mandatory
			// hour-long hold into a request that denies a minute after issue -
			// a detector deciding a request cannot proceed, which is the one
			// thing an advisory control may never do. Measured before the fix:
			// the composed expiry followed the advisory value.
			name: "an ADVISORY expiry cannot shorten a MANDATORY approval window",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p-required", map[string]string{"quorum": "1", "eligible": "Group::r:a"}),
				gob(ObApprovalChallenge, "", false, "p-detector", map[string]string{"quorum": "1", "eligible": "Group::r:b", ParamExpirySeconds: "60"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			composed: []string{
				"approval_challenge - mandatory p-required eligible=Group::r:a;quorum=1",
				"approval_challenge - advisory p-detector eligible=Group::r:b;expiry_seconds=60;quorum=1",
			},
			// The evaluator's stamp survives: the advisory 60s did NOT win.
			// Nor did the advisory CLAUSE - only the mandatory policy's
			// requirement is in the composed hold.
			approval: &goldenApproval{
				clauses:   []string{"1|Group::r:a"},
				expiresAt: goldenNow.Add(time.Hour),
			},
		},
		{
			name: "a MANDATORY expiry still shortens it, so the rule above is about the binding and not about expiry",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p-required", map[string]string{"quorum": "1", "eligible": "Group::r:a"}),
				gob(ObApprovalChallenge, "", true, "p-strict", map[string]string{"quorum": "1", "eligible": "Group::r:b", ParamExpirySeconds: "60"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			composed: []string{
				"approval_challenge - mandatory p-required eligible=Group::r:a;quorum=1",
				"approval_challenge - mandatory p-strict eligible=Group::r:b;expiry_seconds=60;quorum=1",
			},
			approval: &goldenApproval{
				clauses:   []string{"1|Group::r:a", "1|Group::r:b"},
				expiresAt: goldenNow.Add(60 * time.Second),
			},
		},
		{
			name: "an expiry above the coordinated-reservation maximum is refused",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p1", map[string]string{"quorum": "1", "eligible": "Group::r:a", ParamExpirySeconds: "604801"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "above the 604800-second maximum",
		},
		{
			name: "a routing parameter that is neither the destinations nor a namespaced property is refused",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObRouteRestriction, "", true, "r1", map[string]string{ParamAllowedDestinations: "eu", "note": "authored-by-alice"}),
			}, PEP: pep},
			// Without the namespace two policies annotating themselves
			// differently intersect to an empty permitted set and DENY a
			// request neither said anything about routing for.
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "turns an annotation into a deny",
		},
		{
			name: "step-up methods are OPTIONAL: assurance alone constrains nothing else",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObStepUpAuth, "", true, "s1", map[string]string{"assurance": "aal3"}),
			}, PEP: pep},
			composed: []string{"step_up_authentication - mandatory s1 assurance=aal3"},
		},
		{
			name: "an unconstrained step-up composed with a constrained one keeps the constraint",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObStepUpAuth, "", true, "s1", map[string]string{"assurance": "aal1"}),
				gob(ObStepUpAuth, "", true, "s2", map[string]string{"assurance": "aal2", "methods": "webauthn"}),
			}, PEP: pep},
			composed: []string{"step_up_authentication - mandatory s1,s2 assurance=aal2;methods=webauthn"},
		},
		{
			name: "a CARRIED but empty method set is refused rather than denied at runtime",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObStepUpAuth, "", true, "s1", map[string]string{"assurance": "aal2", "methods": " "}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "omit it to mean unconstrained",
		},
		{
			name: "constraints on DIFFERENT counters both survive the conjunction",
			in: ComposeInput{Obligations: []Obligation{
				budgetOb("b1", "tokens", "100", true),
				budgetOb("b2", "calls", "5", true),
			}, PEP: pep},
			composed: []string{
				"quota_reservation - mandatory b2 amount_from=args.amount_cents;counter=calls;limit=5;unit=cents;window=P1D",
				"quota_reservation - mandatory b1 amount_from=args.amount_cents;counter=tokens;limit=100;unit=cents;window=P1D",
			},
		},
		{
			name: "a reservation naming no counter is refused, not handed to the reservation service",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObQuotaReservation, "", true, "b1", nil),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "is required; a reservation that does not name it cannot be discharged",
		},
		{
			name: "a reservation carrying a parameter the family never reads is refused",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObQuotaReservation, "", true, "b1", map[string]string{
					ParamCounter: "c", ParamWindow: "P1D", ParamUnit: "cents",
					ParamLimit: "100", ParamAmountFrom: "args.amount_cents", "amount": "50",
				}),
			}, PEP: pep},
			// `amount` is the shape a literal-quantity model would use, and it
			// is exactly the wrong instinct here: the quantity is the
			// REQUEST's. Refusing it stops a policy asserting a number the
			// reservation service will never read.
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: `declares no "amount" parameter`,
		},
		{
			name: "a reservation whose cap is not a positive whole number is refused",
			in: ComposeInput{Obligations: []Obligation{
				budgetOb("b1", "tokens", "0", true),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "a denial written as a budget",
		},
		{
			name: "a carried expiry with no clock is refused, not defaulted",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p1", map[string]string{"quorum": "1", "eligible": "Group::r:a", ParamExpirySeconds: "600"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour)},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "supplied no clock",
		},
		{
			name: "an expiry below the floor is refused, because the shortest wins and timeout is deny",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObApprovalChallenge, "", true, "p1", map[string]string{"quorum": "1", "eligible": "Group::r:a", ParamExpirySeconds: "0"}),
			}, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "below the 60-second minimum",
		},
		{
			name: "expiry_seconds on a family that would never read it is refused",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObImmutableAudit, "", true, "a1", map[string]string{ParamExpirySeconds: "600"}),
			}, PEP: pep, Now: goldenNow},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "would be read by nothing",
		},
		// ----- routing ------------------------------------------------------
		{
			name: "destinations intersect, and route PROPERTIES intersect per key",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObRouteRestriction, "", true, "r1", map[string]string{ParamAllowedDestinations: "eu,us", "route.tls": "1.2,1.3"}),
				gob(ObRouteRestriction, "", false, "r2", map[string]string{ParamAllowedDestinations: "eu", "route.tls": "1.3", "route.region": "eu-central-1"}),
			}, PEP: pep},
			composed: []string{"route_restriction - mandatory r1,r2 allowed_destinations=eu;route.region=eu-central-1;route.tls=1.3"},
		},
		{
			name: "an empty destination intersection denies",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObRouteRestriction, "", true, "r1", map[string]string{ParamAllowedDestinations: "eu"}),
				gob(ObRouteRestriction, "", true, "r2", map[string]string{ParamAllowedDestinations: "us"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "empty destination set",
		},
		{
			name: "an empty PROPERTY intersection denies and names the property",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObRouteRestriction, "", true, "r1", map[string]string{ParamAllowedDestinations: "eu", "route.tls": "1.2"}),
				gob(ObRouteRestriction, "", true, "r2", map[string]string{ParamAllowedDestinations: "eu", "route.tls": "1.3"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "route property \"route.tls\"",
		},
		{
			name: "the bare route-property prefix names no property and is refused",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObRouteRestriction, "", true, "r1", map[string]string{ParamAllowedDestinations: "eu", "route.": "1.3"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "names no route property",
		},
		{
			name: "a route restriction naming no destinations is unsupported, not unconstrained",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObRouteRestriction, "", true, "r1", map[string]string{"route.tls": "1.3"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "declares no allowed destinations",
		},
		{
			name: "a route property with no permitted values is unsupported",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObRouteRestriction, "", true, "r1", map[string]string{ParamAllowedDestinations: "eu", "route.tls": " "}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "route property \"route.tls\" with no permitted values",
		},
		// ----- step-up ------------------------------------------------------
		{
			name: "step-up takes the MAXIMUM assurance and intersects methods",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObStepUpAuth, "", true, "s1", map[string]string{"assurance": "aal1", "methods": "webauthn,totp"}),
				gob(ObStepUpAuth, "", true, "s2", map[string]string{"assurance": "aal3", "methods": "webauthn"}),
			}, PEP: pep},
			composed: []string{"step_up_authentication - mandatory s1,s2 assurance=aal3;methods=webauthn"},
		},
		{
			name: "an empty method intersection denies",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObStepUpAuth, "", true, "s1", map[string]string{"assurance": "aal2", "methods": "totp"}),
				gob(ObStepUpAuth, "", true, "s2", map[string]string{"assurance": "aal2", "methods": "webauthn"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonObligationConflict,
			detailHas: "empty authentication method set",
		},
		{
			name: "an undeclared step-up parameter is REFUSED, not silently dropped by the rebuild",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObStepUpAuth, "", true, "s1", map[string]string{"assurance": "aal2", "methods": "totp", "channel": "sms"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "would be read by nothing and composition would drop it",
		},
		{
			name: "an undeclared assurance label is unsupported, never ranked lexically",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObStepUpAuth, "", true, "s1", map[string]string{"assurance": "high", "methods": "totp"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "not one of [aal1 aal2 aal3]",
		},
		// ----- budget -------------------------------------------------------
		{
			name: "the same constraint stated by two policies is ONE instruction carrying both sources",
			in: ComposeInput{Obligations: []Obligation{
				budgetOb("b1", "tokens", "100", false),
				budgetOb("b2", "tokens", "100", true),
				budgetOb("b3", "tokens", "50", true),
			}, PEP: pep},
			// b1 and b2 state the SAME cap and deduplicate into one mandatory
			// instruction naming both policies; b3 states a DIFFERENT cap and
			// is a second constraint the reservation service must also satisfy.
			// Nothing is summed: the quantity is not in the policy at all.
			composed: []string{
				"quota_reservation - mandatory b1,b2 amount_from=args.amount_cents;counter=tokens;limit=100;unit=cents;window=P1D",
				"quota_reservation - mandatory b3 amount_from=args.amount_cents;counter=tokens;limit=50;unit=cents;window=P1D",
			},
		},
		// ----- audit and notification ---------------------------------------
		{
			name: "the same target twice keeps ONE instruction with the STRONGEST delivery guarantee",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObImmutableAudit, "", true, "a1", map[string]string{"channel": "siem", "delivery": "best_effort"}),
				gob(ObImmutableAudit, "", false, "a2", map[string]string{"channel": "siem", "delivery": "durable"}),
			}, PEP: pep},
			composed: []string{"immutable_audit - mandatory a1,a2 channel=siem;delivery=durable"},
		},
		{
			name: "an absent delivery guarantee is the weakest declared rank, not an undeclared one",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObNotification, "", true, "n1", map[string]string{"channel": "ops"}),
				gob(ObNotification, "", true, "n2", map[string]string{"channel": "ops", "delivery": "at_least_once"}),
			}, PEP: pep},
			composed: []string{"notification - mandatory n1,n2 channel=ops;delivery=at_least_once"},
		},
		{
			name: "an undeclared delivery guarantee is refused at the boundary",
			in: ComposeInput{Obligations: []Obligation{
				gob(ObNotification, "", true, "n1", map[string]string{"channel": "ops", "delivery": "exactly_once"}),
			}, PEP: pep},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "delivery guarantee \"exactly_once\" is not declared",
		},
		// ----- capability negotiation ---------------------------------------
		{
			name: "a mandatory obligation the enforcement point does not advertise denies",
			in: ComposeInput{Obligations: []Obligation{redactSSN}, Payload: known,
				PEP: &PEPProfile{ID: "narrow", Capabilities: []Capability{{Type: ObImmutableAudit, Version: 1}}}},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "enforcement point \"narrow\" advertises no field_redact at schema version 1",
		},
		{
			name: "the version is part of the identity: v1 advertised, v2 demanded, denied",
			in: ComposeInput{Obligations: []Obligation{
				{Type: ObFieldRedact, Target: "user.ssn", Mandatory: true, SourcePolicy: "p1", SchemaVersion: 2},
			}, Payload: known, PEP: goldenPEP()},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "no field_redact at schema version 2",
		},
		{
			name:      "no profile at all: a mandatory obligation denies with the profile named as missing",
			in:        ComposeInput{Obligations: []Obligation{redactSSN}, Payload: known, PEP: nil},
			denied:    true,
			reason:    ReasonUnsupportedObligation,
			detailHas: "advertised no profile",
		},
		{
			name: "an ADVISORY obligation the point does not advertise is composed and left to the point to decline",
			in: ComposeInput{Obligations: []Obligation{gob(ObFieldRedact, "user.ssn", false, "d1", nil)}, Payload: known,
				PEP: &PEPProfile{ID: "narrow", Capabilities: nil}},
			composed: []string{"field_redact user.ssn advisory d1 -"},
		},
		// ----- no ranking across families ------------------------------------
		{
			name: "one obligation of every family: every one survives, because there is no severity scale",
			in: ComposeInput{Obligations: []Obligation{
				redactSSN,
				gob(ObApprovalChallenge, "", true, "p2", map[string]string{"quorum": "1", "eligible": "Group::r:a"}),
				gob(ObRouteRestriction, "", true, "p3", map[string]string{ParamAllowedDestinations: "eu"}),
				gob(ObStepUpAuth, "", true, "p4", map[string]string{"assurance": "aal2", "methods": "totp"}),
				budgetOb("p5", "calls", "1", true),
				gob(ObImmutableAudit, "", true, "p6", map[string]string{"channel": "siem"}),
			}, Payload: known, PEP: pep, ApprovalExpiry: goldenNow.Add(time.Hour)},
			composed: []string{
				"approval_challenge - mandatory p2 eligible=Group::r:a;quorum=1",
				"field_redact user.ssn mandatory p1 -",
				"immutable_audit - mandatory p6 channel=siem",
				"quota_reservation - mandatory p5 amount_from=args.amount_cents;counter=calls;limit=1;unit=cents;window=P1D",
				"route_restriction - mandatory p3 allowed_destinations=eu",
				"step_up_authentication - mandatory p4 assurance=aal2;methods=totp",
			},
			approval: &goldenApproval{clauses: []string{"1|Group::r:a"}, expiresAt: goldenNow.Add(time.Hour)},
		},
	}
}

func TestObligationAlgebraGoldenTable(t *testing.T) {
	cases := goldenCases(t)
	if len(cases) < 56 {
		t.Fatalf("the golden table has %d rows; it is the pinned semantics of the one algebra and must not shrink", len(cases))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComposeObligations(c.in)
			if got.Denied != c.denied {
				t.Fatalf("denied = %v, want %v (reason %q, detail %q)", got.Denied, c.denied, got.Reason, got.Detail)
			}
			if c.denied {
				if got.Reason != c.reason {
					t.Errorf("reason = %q, want %q (detail %q)", got.Reason, c.reason, got.Detail)
				}
				if c.detailHas != "" && !strings.Contains(got.Detail, c.detailHas) {
					t.Errorf("detail %q does not contain %q", got.Detail, c.detailHas)
				}
				return
			}
			if gotR := renderAll(got.Obligations); !sameStrings(gotR, c.composed) {
				t.Errorf("composed =\n  %s\nwant\n  %s", strings.Join(gotR, "\n  "), strings.Join(c.composed, "\n  "))
			}
			if gotR := renderAll(got.Unplaced); !sameStrings(gotR, c.unplaced) {
				t.Errorf("unplaced = %v, want %v", gotR, c.unplaced)
			}
			if gotR := renderAll(got.DroppedAdvisory); !sameStrings(gotR, c.dropped) {
				t.Errorf("dropped advisory = %v, want %v", gotR, c.dropped)
			}
			if c.dropDetail != "" && !strings.Contains(got.DropDetail, c.dropDetail) {
				t.Errorf("drop detail %q does not contain %q", got.DropDetail, c.dropDetail)
			}
			if len(c.unplaced) > 0 && !strings.Contains(got.UnplacedDetail, "target no leaf of the declared payload schema") {
				t.Errorf("unplaced detail %q does not say the target names no leaf", got.UnplacedDetail)
			}
			if c.approval == nil {
				if got.Approval != nil {
					t.Errorf("approval = %+v, want none", got.Approval)
				}
				return
			}
			if got.Approval == nil {
				t.Fatalf("approval = nil, want %+v", c.approval)
			}
			var clauses []string
			for _, cl := range got.Approval.AllOf {
				ids := make([]string, 0, len(cl.Eligible))
				for _, e := range cl.Eligible {
					ids = append(ids, e.String())
				}
				clauses = append(clauses, fmt.Sprintf("%d|%s", cl.Quorum, strings.Join(ids, ",")))
			}
			if !sameStrings(clauses, c.approval.clauses) {
				t.Errorf("approval clauses = %v, want %v", clauses, c.approval.clauses)
			}
			if got.Approval.SeparationOfDuties != c.approval.sod {
				t.Errorf("separation_of_duties = %v, want %v", got.Approval.SeparationOfDuties, c.approval.sod)
			}
			if !got.Approval.ExpiresAt.Equal(c.approval.expiresAt) {
				t.Errorf("expires_at = %s, want %s", got.Approval.ExpiresAt, c.approval.expiresAt)
			}
		})
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSubsumptionRulesRefuseWhatTheyMustRefuse pins each refusal by its own
// failing input; a rule set that accepted any of these would make "the least
// disclosing transform" depend on which rule the loop visited first.
func TestSubsumptionRulesRefuseWhatTheyMustRefuse(t *testing.T) {
	tok := TransformRef{Type: ObFieldTokenize}
	red := TransformRef{Type: ObFieldRedact}
	sch := TransformRef{Type: ObSchemaTransform}
	cases := []struct {
		name  string
		rules []SubsumptionRule
		want  string
	}{
		{"no reason", []SubsumptionRule{{Weaker: tok, Stronger: red}}, "no recorded review reason"},
		{"reflexive", []SubsumptionRule{{Weaker: tok, Stronger: tok, Reason: "r"}}, "reflexive"},
		{"two rules for one weaker", []SubsumptionRule{{Weaker: tok, Stronger: red, Reason: "r"}, {Weaker: tok, Stronger: sch, Reason: "r"}}, "already subsumed"},
		{"cycle", []SubsumptionRule{{Weaker: tok, Stronger: red, Reason: "r"}, {Weaker: red, Stronger: sch, Reason: "r"}, {Weaker: sch, Stronger: tok, Reason: "r"}}, "cycle"},
		{"a non-disclosure type", []SubsumptionRule{{Weaker: TransformRef{Type: ObImmutableAudit}, Stronger: red, Reason: "r"}}, "only the disclosure order"},
		{"an unregistered type", []SubsumptionRule{{Weaker: TransformRef{Type: "teleport"}, Stronger: red, Reason: "r"}}, "not registered"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewSubsumptionRules(c.rules...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
	// The positive control for the refusals above: a chain is accepted and
	// followed transitively.
	rules := mustRules(t,
		SubsumptionRule{Weaker: tok, Stronger: sch, Reason: "golden chain 1"},
		SubsumptionRule{Weaker: sch, Stronger: red, Reason: "golden chain 2"})
	if !rules.subsumes(tok.key(), red.key()) {
		t.Fatal("a two-step chain must be followed transitively")
	}
	if rules.subsumes(red.key(), tok.key()) {
		t.Fatal("subsumption is directed; the reverse must not hold")
	}
	if got := rules.Rules(); len(got) != 2 || got[0].Weaker.Type != ObFieldTokenize || got[1].Weaker.Type != ObSchemaTransform {
		t.Fatalf("Rules() = %+v, want two rules sorted by weaker key", got)
	}
	var nilRules *SubsumptionRules
	if nilRules.subsumes("a", "b") || nilRules.Rules() != nil {
		t.Fatal("a nil rule set is the empty set")
	}
}

// TestPayloadLeavesTriStateIsExplicit pins the constructors and the boundary
// rule, so that "empty means unknown" is a stated rule at one site rather than
// a coincidence of the list being empty.
func TestPayloadLeavesTriStateIsExplicit(t *testing.T) {
	if p := DeclaredPayloadLeaves(nil); p.State != StateUnknown || p.Reason != ReasonNotSupplied {
		t.Fatalf("an undeclared schema must be unknown(attribute_not_supplied), got %+v", p)
	}
	if p := DeclaredPayloadLeaves([]string{"a"}); p.State != StateKnown || len(p.Leaves) != 1 {
		t.Fatalf("a declared schema must be known, got %+v", p)
	}
	if p := KnownPayloadLeaves(); p.State != StateKnown || len(p.Leaves) != 0 || p.Validate() != nil {
		t.Fatalf("a known empty schema is a valid, distinct state, got %+v", p)
	}
	if err := (PayloadLeaves{State: StateUnknown, Reason: "because"}).Validate(); err == nil {
		t.Fatal("an unknown schema must carry a DECLARED reason")
	}
	if err := (PayloadLeaves{State: StateUnknown, Reason: ReasonStale, Leaves: []string{"a"}}).Validate(); err == nil {
		t.Fatal("an unknown schema must not carry leaves")
	}
	if err := (PayloadLeaves{State: StateKnown, Reason: ReasonStale}).Validate(); err == nil {
		t.Fatal("a known schema must not carry a reason")
	}
	// The constructor copies its input: a caller mutating its slice afterwards
	// does not mutate the schema composition read.
	src := []string{"a"}
	p := KnownPayloadLeaves(src...)
	src[0] = "b"
	if p.Leaves[0] != "a" {
		t.Fatal("KnownPayloadLeaves must copy the leaf list")
	}
}

// TestExportedRankAccessorsAgreeWithTheAlgebra: the planner describes the
// order through these; they must be the algebra's own tables.
func TestExportedRankAccessorsAgreeWithTheAlgebra(t *testing.T) {
	want := map[ObligationType]int{ObFieldRemove: 0, ObFieldRedact: 1, ObFieldHash: 2, ObFieldMask: 3, ObFieldAnnotate: 4}
	for typ, rank := range want {
		if r, ok := DisclosureRank(typ); !ok || r != rank {
			t.Errorf("DisclosureRank(%s) = %d,%v want %d,true", typ, r, ok, rank)
		}
		if IncomparableDisclosure(typ) {
			t.Errorf("%s is on the order and must not be incomparable", typ)
		}
	}
	for _, typ := range []ObligationType{ObFieldTokenize, ObSchemaTransform, ObResponseFilter} {
		if _, ok := DisclosureRank(typ); ok {
			t.Errorf("%s must not carry a rank", typ)
		}
		if !IncomparableDisclosure(typ) {
			t.Errorf("%s must be declared incomparable", typ)
		}
	}
	if _, ok := DisclosureRank("teleport"); ok {
		t.Error("an undeclared type must not read as ranked")
	}
	for i, a := range AllAssurances() {
		if s, ok := a.Strength(); !ok || s != i+1 {
			t.Errorf("%s.Strength() = %d,%v want %d,true", a, s, ok, i+1)
		}
	}
	if _, ok := Assurance("high").Strength(); ok {
		t.Error("an undeclared assurance must not read as ranked")
	}
	if got := (Capability{Type: ObFieldRedact, Version: 3}).String(); got != "field_redact@v3" {
		t.Errorf("Capability.String() = %q", got)
	}
	if got := gob(ObFieldMask, "x", true, "p", nil).CapabilityOf(); got != (Capability{Type: ObFieldMask, Version: 1}) {
		t.Errorf("CapabilityOf() = %+v", got)
	}
}

// TestCanonicalParamsIsTheAlgebrasOwnRendering: the planner builds a
// deduplication key from an obligation's parameters, and it must use the
// order the algebra compares parameters in rather than rendering its own. A
// second rendering is a second idea of when two instructions are the same.
func TestCanonicalParamsIsTheAlgebrasOwnRendering(t *testing.T) {
	a := gob(ObRouteRestriction, "", true, "p", map[string]string{"route.tls": "1.3", ParamAllowedDestinations: "eu"})
	b := gob(ObRouteRestriction, "", true, "p", map[string]string{ParamAllowedDestinations: "eu", "route.tls": "1.3"})
	if a.CanonicalParams() != b.CanonicalParams() {
		t.Fatalf("map order changed the rendering: %q vs %q", a.CanonicalParams(), b.CanonicalParams())
	}
	if a.CanonicalParams() == "" {
		t.Fatal("a non-empty parameter set rendered as empty")
	}
	if got := gob(ObFieldRemove, "x", true, "p", nil).CanonicalParams(); got != "" {
		t.Fatalf("an empty parameter set rendered as %q", got)
	}
	// Different values must not collide: the rendering is a deduplication key.
	c := gob(ObRouteRestriction, "", true, "p", map[string]string{ParamAllowedDestinations: "eu", "route.tls": "1.2"})
	if a.CanonicalParams() == c.CanonicalParams() {
		t.Fatalf("two different parameter sets render identically: %q", a.CanonicalParams())
	}
}
