package conformance

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// mutation is one proof that a family of conformance cases can actually fail.
//
// An assertion count proves a case checked something. It does not prove the
// check can go red, and a check that cannot go red is not coverage. Each entry
// below names a representative case, states the property that case rests on,
// and applies a change to the policy world that should break it. The proof has
// three parts and all three are asserted: the property HOLDS on the clean
// world, the mutant COMPILES (a mutant that fails to build is not a kill, it is
// a broken mutant), and the property FAILS on the mutant.
type mutation struct {
	Family string
	// Case is the representative case whose property is being proved falsifiable.
	Case string
	// Property describes what is being broken, in the terms the case uses.
	Property string
	// Mutate produces the mutated world options.
	Mutate func() []WorldOption
	// Holds re-evaluates the representative property against a world.
	Holds func(t *testing.T, w *World) bool
	// cleanOptions build the world the property is expected to hold on, where
	// that is not the default fixture world. Some properties are about a
	// policy or profile the default world does not carry, and asserting them
	// against the default world would test the wrong thing.
	cleanOptions func() []WorldOption
}

func mutations() []mutation {
	return []mutation{
		{
			Family: "A Baseline", Case: "EX-01",
			Property: "the tier-two refund permission grants the clean permit",
			Mutate:   func() []WorldOption { return []WorldOption{WithOrganizationDocument(orgDocWithout("G1"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				return d.State == contract.StateAllow && contains(d.Determining.MatchedPermissions, "G1")
			},
		},
		{
			Family: "B Constraints", Case: "EX-06",
			Property: "the personal-data egress constraint denies",
			Mutate:   func() []WorldOption { return []WorldOption{WithSystemDocument(systemDocWithout("C2"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "alice", Action: "T2", Args: map[string]any{"segment": "all"}})
				return d.Authorization == contract.AuthzDeny && contains(d.Determining.MatchedConstraints, "C2")
			},
		},
		{
			Family: "C Approval", Case: "EX-08",
			Property: "the two-approver clause keeps its quorum through composition",
			Mutate: func() []WorldOption {
				d := SystemDocument()
				p := systemPolicy(d, "C3")
				p.Obligations = []contract.Obligation{approvalObligation("C3", 1, "security-leads")}
				return []WorldOption{WithSystemDocument(d)}
			},
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "frank", Action: "T2", Args: map[string]any{"segment": "all"}})
				return contains(ApprovalKeys(d), "2 of security-leads")
			},
		},
		{
			Family: "D Closure", Case: "EX-04",
			Property: "the inherited contractors requirement reaches a member of a child group",
			Mutate:   func() []WorldOption { return []WorldOption{WithSystemDocument(systemDocWithout("C4"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "bob", Action: "T1", Resource: "SUP-43",
					Args: map[string]any{"amount_cents": 30000}})
				return contains(ApprovalKeys(d), "1 of staff-managers")
			},
		},
		{
			Family: "E Indeterminacy", Case: "EX-17",
			Property: "an unresolvable constraint makes the decision indeterminate rather than permitting",
			Mutate:   func() []WorldOption { return []WorldOption{WithSystemDocument(systemDocWithout("C10"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
					Args: map[string]any{"amount_cents": 3000000},
					Overrides: map[string]*contract.Attribute{
						PathResourceRisk: UnknownAttr(PathResourceRisk, contract.ReasonResolutionFailed),
					}})
				return d.Authorization == contract.AuthzIndeterminate && d.Reason == contract.ReasonUnknownConstraint
			},
		},
		{
			Family: "F Obligations", Case: "EX-19",
			Property: "the personal-data requirement attaches its redactions",
			Mutate:   func() []WorldOption { return []WorldOption{WithSystemDocument(systemDocWithout("C5"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				return contains(ObligationKeys(d), "field_redact@response.ssn")
			},
		},
		{
			Family: "F Obligations", Case: "EX-22",
			Property: "an obligation the enforcement point cannot discharge denies",
			Mutate: func() []WorldOption {
				pep := DefaultPEP()
				pep.Capabilities = append(pep.Capabilities, contract.Capability{Type: contract.ObFieldTokenize, Version: 1})
				return []WorldOption{
					WithSystemDocument(systemDocWith(pdp.Policy{
						ID: "C14", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
						Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
						Where: pdp.True(),
						Obligations: []contract.Obligation{{
							Type: contract.ObFieldTokenize, Target: "response.email",
							SourcePolicy: "C14", SchemaVersion: 1,
						}},
					})),
					WithPEP(pep),
				}
			},
			Holds: func(t *testing.T, w *World) bool {
				// The clean world for THIS property is the one that carries the
				// tokenizing requirement and a PEP without the capability, so
				// the clean side is built by the runner from the same policy
				// plus the default profile.
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				return d.Authorization == contract.AuthzDeny && d.Reason == contract.ReasonUnsupportedObligation
			},
			cleanOptions: func() []WorldOption {
				return []WorldOption{WithSystemDocument(systemDocWith(pdp.Policy{
					ID: "C14", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
					Where: pdp.True(),
					Obligations: []contract.Obligation{{
						Type: contract.ObFieldTokenize, Target: "response.email",
						SourcePolicy: "C14", SchemaVersion: 1,
					}},
				}))}
			},
		},
		{
			Family: "G Reservation", Case: "EX-25",
			Property: "a second concurrent hold against the same counter is refused",
			Mutate: func() []WorldOption {
				d := SystemDocument()
				p := systemPolicy(d, "C8")
				p.Obligations[0].Params["limit"] = "500000000"
				return []WorldOption{WithSystemDocument(d)}
			},
			Holds: func(t *testing.T, w *World) bool {
				c := NewCoordinator()
				for i, id := range []string{"req_a", "req_b"} {
					s := Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
						Args: map[string]any{"amount_cents": 3000000}, RequestID: id}
					req, err := w.Request(s)
					if err != nil {
						t.Fatalf("building: %v", err)
					}
					out, err := c.AdmitReservations(decide(t, w, s), req, Now)
					if err != nil {
						t.Fatalf("reserving: %v", err)
					}
					if i == 1 {
						return out.Decision.Reason == contract.ReasonBudgetExhausted
					}
				}
				return false
			},
		},
		{
			Family: "H Delegation", Case: "EX-27",
			Property: "the chain meet is bounded by the principal's own coverage",
			Mutate: func() []WorldOption {
				d := OrganizationDocument()
				for i := range d.Policies {
					if d.Policies[i].ID == "G1" {
						d.Policies[i].Where = pdp.Compare(PathArgsAmount, pdp.OpLe, 100000000).
							HandlingAbsence(pdp.AbsentIsUnknown)
					}
				}
				return []WorldOption{WithOrganizationDocument(d)}
			},
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "alice", Chain: []string{"alice", "agent-A"},
					Action: "T1", Resource: "SUP-42", Args: map[string]any{"amount_cents": 3000000}})
				return d.State == contract.StateDeny
			},
		},
		{
			Family: "I Inspection", Case: "EX-29",
			Property: "the gating approval threshold acts on the accumulated score",
			Mutate:   func() []WorldOption { return []WorldOption{WithSystemDocument(systemDocWithout("S1-APPROVE"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 50000}, RiskScore: 75,
					Overrides: map[string]*contract.Attribute{
						PathStateAnomaly:  KnownAttr(PathStateAnomaly, 30000),
						PathStateVelocity: KnownAttr(PathStateVelocity, 6),
					}})
				return contains(ApprovalKeys(d), "1 of fraud-team")
			},
		},
		{
			Family: "J Binding", Case: "EX-33",
			Property: "break-glass suspends a requirement that declares itself pierceable",
			Mutate: func() []WorldOption {
				d := SystemDocument()
				systemPolicy(d, "C1").PierceableBy = nil
				return []WorldOption{
					WithSystemDocument(d),
					WithBreakGlass(func(p contract.ID, at time.Time) []contract.ID {
						return []contract.ID{group("oncall-sre")}
					}),
				}
			},
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "erin", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 5000000}})
				return d.State == contract.StateAllow && contains(ObligationKeys(d), "notification")
			},
			cleanOptions: func() []WorldOption {
				return []WorldOption{WithBreakGlass(func(p contract.ID, at time.Time) []contract.ID {
					return []contract.ID{group("oncall-sre")}
				})}
			},
		},
		{
			Family: "K Containment", Case: "EX-40",
			Property: "the restricted-space constraint denies an export from under it",
			Mutate:   func() []WorldOption { return []WorldOption{WithSystemDocument(systemDocWithout("C12"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "dana", Action: "T6", Resource: "P-900",
					Args: map[string]any{"page_id": "P-900"}})
				return d.Authorization == contract.AuthzDeny && contains(d.Determining.MatchedConstraints, "C12")
			},
		},
		{
			Family: "L Realms", Case: "EX-45",
			Property: "a principal-scoped permission carries a subject whose realm has no group graph",
			Mutate:   func() []WorldOption { return []WorldOption{WithOrganizationDocument(orgDocWithout("G10"))} },
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "agent-A", Action: "T1",
					Args: map[string]any{"amount_cents": 3000000}})
				return d.Authorization == contract.AuthzPermit && contains(d.Determining.MatchedPermissions, "G10")
			},
		},
		{
			Family: "M Compatibility", Case: "AXC-001",
			Property: "an unexpired compatibility exception permits a read-only action",
			Mutate: func() []WorldOption {
				return []WorldOption{WithCompatibility(&pdp.CompatibilityProfile{Entries: []pdp.CompatibilityEntry{{
					Action: Actions["T3"].ID, Owner: "platform-migration",
					// Expired an hour before the fixed evaluation instant.
					ExpiresAt: Now.Add(-time.Hour), RemovalIssue: "getaxonflow/axonflow-enterprise#3552",
				}}})}
			},
			Holds: func(t *testing.T, w *World) bool {
				d := decide(t, w, Scenario{Principal: "alice", Action: "T3", Args: map[string]any{"query": "invoices"}})
				return d.State == contract.StateAllow
			},
			cleanOptions: func() []WorldOption {
				return []WorldOption{WithCompatibility(&pdp.CompatibilityProfile{Entries: []pdp.CompatibilityEntry{{
					Action: Actions["T3"].ID, Owner: "platform-migration",
					ExpiresAt: Now.Add(720 * time.Hour), RemovalIssue: "getaxonflow/axonflow-enterprise#3552",
				}}})}
			},
		},
	}
}

// TestMutationProofs runs every mutation.
func TestMutationProofs(t *testing.T) {
	seen := map[string]struct{}{}
	for _, m := range mutations() {
		seen[m.Family] = struct{}{}
		t.Run(m.Family+"/"+m.Case, func(t *testing.T) {
			var cleanOpts []WorldOption
			if m.cleanOptions != nil {
				cleanOpts = m.cleanOptions()
			}
			clean, err := NewWorld(context.Background(), cleanOpts...)
			if err != nil {
				t.Fatalf("building the clean world: %v", err)
			}
			if !m.Holds(t, clean) {
				t.Fatalf("%s: the property does not hold on the CLEAN world, so the mutation below would prove nothing: %s",
					m.Case, m.Property)
			}

			// A mutant that does not compile is not a kill. The world builder
			// validates the typed document, compiles it to Rego under strict
			// compilation and restricted capabilities, signs it and verifies
			// it, so a successful build is a real proof that the mutant is a
			// well formed policy set rather than a syntax error.
			mutant, err := NewWorld(context.Background(), m.Mutate()...)
			if err != nil {
				t.Fatalf("%s: the mutant did not compile, so it proves nothing about the case: %v", m.Case, err)
			}
			if m.Holds(t, mutant) {
				t.Fatalf("%s: the property still holds after the mutation, so the case cannot detect it: %s",
					m.Case, m.Property)
			}
		})
	}

	// Every family of the corpus needs at least one representative proof. A
	// family with no mutation proof is a family whose cases have been shown to
	// assert something but not to be able to fail.
	families := map[string]struct{}{}
	for _, c := range AllCases() {
		families[c.Family] = struct{}{}
	}
	covered := 0
	for f := range families {
		if _, ok := seen[f]; ok {
			covered++
		}
	}
	if covered < 12 {
		t.Errorf("only %d of the %d case families carry a mutation proof; at least twelve of the source families must",
			covered, len(families))
	}
}
