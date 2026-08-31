package authoring

import (
	"reflect"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

func TestDiffClassifiesPresenceByAuthority(t *testing.T) {
	cat := baseCatalog(t)
	base := documentWith(t, cat, nil)

	cases := []struct {
		name   string
		edit   func(*Metadata, *pdp.Document)
		policy string
		kind   ChangeKind
		effect Effect
	}{
		{
			name:   "adding a permission widens",
			policy: "perm.extra",
			kind:   ChangeAdded, effect: EffectWidening,
			edit: func(_ *Metadata, d *pdp.Document) {
				p := *policyByIDIn(d, "perm.refund")
				p.ID = "perm.extra"
				p.Actions = pdp.ActionSelector{Actions: []contract.ID{aid(t, actionTicket)}}
				d.Policies = append(d.Policies, p)
			},
		},
		{
			name:   "removing a constraint widens",
			policy: "con.owner",
			kind:   ChangeRemoved, effect: EffectWidening,
			edit: func(_ *Metadata, d *pdp.Document) {
				var kept []pdp.Policy
				for _, p := range d.Policies {
					if p.ID != "con.owner" {
						kept = append(kept, p)
					}
				}
				d.Policies = kept
			},
		},
		{
			name:   "adding a constraint narrows",
			policy: "con.extra",
			kind:   ChangeAdded, effect: EffectNarrowing,
			edit: func(_ *Metadata, d *pdp.Document) {
				p := *policyByIDIn(d, "con.owner")
				p.ID = "con.extra"
				p.Actions = pdp.ActionSelector{Actions: []contract.ID{aid(t, actionExport)}}
				d.Policies = append(d.Policies, p)
			},
		},
		{
			name:   "removing a requirement widens",
			policy: "req.audit",
			kind:   ChangeRemoved, effect: EffectWidening,
			edit: func(_ *Metadata, d *pdp.Document) {
				var kept []pdp.Policy
				for _, p := range d.Policies {
					if p.ID != "req.audit" {
						kept = append(kept, p)
					}
				}
				d.Policies = kept
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			to := documentWith(t, cat, tc.edit)
			to.Policy.Version = base.Policy.Version + 1
			diff, err := DiffDocuments(base, to)
			if err != nil {
				t.Fatal(err)
			}
			var got *PolicyChange
			for i := range diff.Policies {
				if diff.Policies[i].PolicyID == tc.policy {
					got = &diff.Policies[i]
				}
			}
			if got == nil {
				t.Fatalf("the diff does not mention %q: %+v", tc.policy, diff.Policies)
			}
			if got.Kind != tc.kind || got.Effect != tc.effect {
				t.Fatalf("expected %s/%s, got %s/%s (%s)", tc.kind, tc.effect, got.Kind, got.Effect, got.Rationale)
			}
			if got.Rationale == "" {
				t.Fatal("a classified change with no rationale gives an operator nothing to check")
			}
		})
	}
}

// TestDiffRefusesToGuessAtAnEditedCondition is the honesty gate.
//
// Whether an edited condition admits more requests than it did is a question
// about every possible request, and two condition trees do not answer it. A
// diff that answered anyway would put "narrowing" beside a change that widened,
// and an operator who is told a change narrows does not go and look.
func TestDiffRefusesToGuessAtAnEditedCondition(t *testing.T) {
	cat := baseCatalog(t)
	base := documentWith(t, cat, nil)
	to := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
		policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.amount_cents", pdp.OpLe, 900000)
	})
	to.Policy.Version = 2
	diff, err := DiffDocuments(base, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Policies) != 1 {
		t.Fatalf("expected exactly one changed policy, got %+v", diff.Policies)
	}
	change := diff.Policies[0]
	if change.Effect != EffectUndetermined {
		t.Fatalf("a widened numeric bound was classified %s, which the source cannot support", change.Effect)
	}
	if diff.Effect != EffectUndetermined {
		t.Fatalf("the overall effect is %s; one undetermined change makes the whole change set undetermined", diff.Effect)
	}
	if len(change.Fields) != 1 || change.Fields[0].Field != "where" {
		t.Fatalf("expected the where field to be reported as changed, got %+v", change.Fields)
	}
}

func TestDiffClassifiesTheChangesItCanDecide(t *testing.T) {
	cat := baseCatalog(t)
	base := documentWith(t, cat, nil)

	t.Run("only the description changed", func(t *testing.T) {
		to := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
			policyByIDIn(d, "perm.refund").Description = "reworded"
		})
		diff, err := DiffDocuments(base, to)
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Policies) != 1 || diff.Policies[0].Effect != EffectNeutral {
			t.Fatalf("a description-only edit must be neutral, got %+v", diff.Policies)
		}
	})

	t.Run("a constraint gains a break-glass pierce", func(t *testing.T) {
		from := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
			policyByIDIn(d, "con.big").PierceableBy = nil
		})
		diff, err := DiffDocuments(from, base)
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Policies) != 1 || diff.Policies[0].Effect != EffectWidening {
			t.Fatalf("gaining a pierce must widen, got %+v", diff.Policies)
		}
	})

	t.Run("a constraint loses its break-glass pierce", func(t *testing.T) {
		to := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
			policyByIDIn(d, "con.big").PierceableBy = nil
		})
		diff, err := DiffDocuments(base, to)
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Policies) != 1 || diff.Policies[0].Effect != EffectNarrowing {
			t.Fatalf("losing a pierce must narrow, got %+v", diff.Policies)
		}
	})

	t.Run("a requirement gains an obligation", func(t *testing.T) {
		to := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
			p := policyByIDIn(d, "req.audit")
			extra := contract.Obligation{
				Type: contract.ObNotification, Params: map[string]string{"channel": "soc"},
				Mandatory: true, SourcePolicy: "req.audit", SchemaVersion: 1,
			}
			p.Obligations = append(p.Obligations, extra)
		})
		diff, err := DiffDocuments(base, to)
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Policies) != 1 || diff.Policies[0].Effect != EffectNarrowing {
			t.Fatalf("gaining an obligation must narrow, got %+v", diff.Policies)
		}
	})
}

func TestDiffOfIdenticalDocumentsIsEmpty(t *testing.T) {
	cat := baseCatalog(t)
	a := documentWith(t, cat, nil)
	b := documentWith(t, cat, nil)
	diff, err := DiffDocuments(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Empty() {
		t.Fatalf("two identical documents diff to %+v", diff)
	}
	if diff.Effect != EffectNeutral {
		t.Fatalf("an empty diff has effect %s", diff.Effect)
	}
}

func TestDiffAgainstNothingIsAllAdditions(t *testing.T) {
	cat := baseCatalog(t)
	to := documentWith(t, cat, nil)
	diff, err := DiffDocuments(nil, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Policies) != len(to.Policy.Policies) {
		t.Fatalf("expected %d additions, got %d", len(to.Policy.Policies), len(diff.Policies))
	}
	for _, c := range diff.Policies {
		if c.Kind != ChangeAdded {
			t.Fatalf("policy %q is %s against an empty baseline", c.PolicyID, c.Kind)
		}
	}
}

// TestDiffCoversEveryPolicyField is the anti-drift gate for the reflective
// walk, and it is the whole reason the walk is reflective.
//
// A hand-written field list would be a second declaration of the policy
// vocabulary. pdp.Policy grows a field, the diff keeps reporting "no change"
// for it, and the portal's dry-run tells an operator that an edit changed
// nothing while the compiled bundle changed. This changes a field at a time and
// requires the diff to notice each one, so a new field that the walk cannot
// reach fails here rather than in production.
func TestDiffCoversEveryPolicyField(t *testing.T) {
	typ := reflect.TypeOf(pdp.Policy{})
	cat := baseCatalog(t)
	base := documentWith(t, cat, nil)

	// Field-by-field mutators. The map is keyed by the Go field name, and the
	// completeness assertion below is against reflect.NumField, so a field with
	// no mutator is a named failure rather than a silent gap.
	mutators := map[string]func(*pdp.Policy){
		"ID":            func(p *pdp.Policy) { p.ID = "renamed" },
		"Authority":     func(p *pdp.Policy) { p.Authority = contract.AuthorityInspection },
		"Root":          func(p *pdp.Policy) { p.Root = pdp.RootOrganization },
		"Scope":         func(p *pdp.Policy) { p.Scope = pdp.Scope{Organization: true} },
		"Actions":       func(p *pdp.Policy) { p.Actions = pdp.ActionSelector{Any: true} },
		"ResourceScope": func(p *pdp.Policy) { c := pdp.True(); p.ResourceScope = &c },
		"Where":         func(p *pdp.Policy) { p.Where = pdp.Compare("args.amount_cents", pdp.OpLt, 1) },
		"Unless":        func(p *pdp.Policy) { c := pdp.Compare("args.amount_cents", pdp.OpGt, 7); p.Unless = &c },
		"Obligations":   func(p *pdp.Policy) { p.Obligations = []contract.Obligation{auditObligation("x")} },
		"Mandatory":     func(p *pdp.Policy) { p.Mandatory = !p.Mandatory },
		"PierceableBy":  func(p *pdp.Policy) { p.PierceableBy = []contract.ID{gid(t, groupIncident)} },
		"Description":   func(p *pdp.Policy) { p.Description = "changed" },
	}
	if len(mutators) != typ.NumField() {
		var names []string
		for i := 0; i < typ.NumField(); i++ {
			if _, ok := mutators[typ.Field(i).Name]; !ok {
				names = append(names, typ.Field(i).Name)
			}
		}
		t.Fatalf("pdp.Policy has %d fields and %d have a mutator; missing: %v", typ.NumField(), len(mutators), names)
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		t.Run(field.Name, func(t *testing.T) {
			to := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
				mutators[field.Name](policyByIDIn(d, "perm.refund"))
			})
			diff, err := DiffDocuments(base, to)
			if err != nil {
				t.Fatal(err)
			}
			if len(diff.Policies) == 0 {
				t.Fatalf("changing %s produced no diff at all", field.Name)
			}
			// Renaming the identifier is a removal plus an addition rather than
			// a modification, which is correct: a policy identifier is the
			// thing a decision names, so a renamed policy is a different policy.
			if field.Name == "ID" {
				kinds := map[ChangeKind]int{}
				for _, c := range diff.Policies {
					kinds[c.Kind]++
				}
				if kinds[ChangeAdded] != 1 || kinds[ChangeRemoved] != 1 {
					t.Fatalf("renaming a policy should read as one addition and one removal, got %+v", diff.Policies)
				}
				return
			}
			wantField := jsonFieldName(field)
			for _, c := range diff.Policies {
				for _, f := range c.Fields {
					if f.Field == wantField {
						return
					}
				}
			}
			t.Fatalf("changing %s did not surface a %q field change: %+v", field.Name, wantField, diff.Policies)
		})
	}
}

// TestDiffReportsAttributeSchemaChanges covers the half of a document that is
// not policies. An attribute whose declared type or optionality moved changes
// what every condition over it means, and a diff that showed only policies
// would report that edit as no change at all.
func TestDiffReportsAttributeSchemaChanges(t *testing.T) {
	cat := baseCatalog(t)
	base := documentWith(t, cat, nil)
	to := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
		for i := range d.Attributes {
			if d.Attributes[i].Path == "args.amount_cents" {
				d.Attributes[i].MaxAgeSeconds = 30
			}
		}
		d.Attributes = append(d.Attributes, pdp.AttributeSchema{Path: "env.zone", Type: pdp.TypeString, Optional: true})
	})
	diff, err := DiffDocuments(base, to)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range diff.Attributes {
		seen[f.Field] = true
	}
	if !seen["args.amount_cents"] || !seen["env.zone"] {
		t.Fatalf("expected both the edited and the added attribute, got %+v", diff.Attributes)
	}
}

// TestAPIDiffComparesAgainstWhatIsActive proves the dry-run compares a
// candidate against enforcement rather than against the last thing published.
// Those differ the moment a version is published and not promoted, which is the
// ordinary state during a review.
func TestAPIDiffComparesAgainstWhatIsActive(t *testing.T) {
	cat := baseCatalog(t)
	trust, priv := systemTrust(t)
	api, err := NewAPI(cat, trust)
	if err != nil {
		t.Fatal(err)
	}
	v1, _, err := api.Publish(t.Context(), baseDocument(t), publishOptions(t, priv))
	if err != nil {
		t.Fatal(err)
	}

	// Before promotion nothing is active, so a candidate diffs as all additions.
	candidate := documentWith(t, cat, func(m *Metadata, d *pdp.Document) {
		d.Version = 2
		m.Supersedes = v1.Digest()
		policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.amount_cents", pdp.OpLe, 250000)
	})
	diff, err := api.Diff(candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range diff.Policies {
		if c.Kind != ChangeAdded {
			t.Fatalf("with nothing active every policy is an addition, got %s for %q", c.Kind, c.PolicyID)
		}
	}

	if _, err := api.Promote(pdp.RootSystem, v1.Digest(), pid(t, principalBob), timeFixture(), "rollout"); err != nil {
		t.Fatal(err)
	}
	diff, err = api.Diff(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Policies) != 1 || diff.Policies[0].PolicyID != "perm.refund" {
		t.Fatalf("against the active version only perm.refund changed, got %+v", diff.Policies)
	}
	if diff.FromDigest == "" || diff.FromVersion != 1 || diff.ToVersion != 2 {
		t.Fatalf("the diff does not identify both sides: %+v", diff)
	}
}
