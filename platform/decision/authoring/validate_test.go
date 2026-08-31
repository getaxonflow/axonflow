package authoring

import (
	"context"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// documentWith builds a document from the clean baseline with one edit applied.
//
// It deliberately does NOT go through NewDocument: most cases below are meant
// to be refused, and a constructor that returns nil on refusal cannot hand a
// test the document to inspect. The derived realm copy is filled the same way
// NewDocument fills it, so a case that does not touch it starts from agreement.
func documentWith(t *testing.T, cat *Catalog, edit func(*Metadata, *pdp.Document)) *Document {
	t.Helper()
	meta := baseMetadata(t)
	policy := basePDPDocument(t)
	if edit != nil {
		edit(&meta, &policy)
	}
	policy.InteractiveRealms = cat.InteractiveRealms()
	return &Document{APIVersion: APIVersion, Metadata: meta, Policy: policy}
}

func approvalObligation(source, quorum, eligible string) contract.Obligation {
	return contract.Obligation{
		Type:          contract.ObApprovalChallenge,
		Params:        map[string]string{"quorum": quorum, "eligible": eligible},
		Mandatory:     true,
		SourcePolicy:  source,
		SchemaVersion: 1,
	}
}

// rejectionCase is one save-time check, the single edit that provokes it, and
// the registry it is checked against.
type rejectionCase struct {
	code string
	// detail is a substring the finding's Detail must contain.
	//
	// It is REQUIRED, and the mutation harness is why. Asserting only that a
	// code appeared is satisfied by the code appearing for the wrong reason,
	// and two mutants proved it: inverting the dead-permission test and
	// inverting the catalog-agreement test both keep the code firing, on other
	// policies and other realms, and a presence-only case reported both checks
	// as guarded. Naming the offending value is what makes the case about the
	// defect rather than about the code.
	detail string
	// catalog defaults to baseCatalog.
	catalog func(*testing.T) *Catalog
	// edit is the one change to the clean baseline that provokes the code.
	edit func(*Metadata, *pdp.Document)
	// after runs on the assembled document, for cases that corrupt something
	// the constructor would otherwise derive.
	after func(*Document)
	// run replaces the default validate path for checks that are not reachable
	// through Validate, which today is publication-time separation of duties.
	run func(*testing.T) Findings
}

func rejectionCases() []rejectionCase {
	return []rejectionCase{
		// Relayed from the deterministic PDP's own authoring validator. Eight of
		// these had no test anywhere in the module asserting that they fire at
		// all before this table existed.
		{
			code: pdp.RuleAuthorityFromUntrusted, detail: "state.spend_cents",
			edit: func(_ *Metadata, d *pdp.Document) {
				// Caller-supplied input compared against a platform-owned term:
				// "allow if the requester says the number is right".
				policyByIDIn(d, "perm.refund").Where = pdp.AttrCompare("args.amount_cents", pdp.OpEq, "state.spend_cents")
			},
		},
		{
			code: pdp.RuleFieldNotInSchema, detail: "env.network_zone",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "perm.refund").Where = pdp.Compare("env.network_zone", pdp.OpEq, "corp")
			},
		},
		{
			code: pdp.RulePermissionEmitsDeny, detail: "cannot attach obligations",
			edit: func(_ *Metadata, d *pdp.Document) {
				p := policyByIDIn(d, "perm.refund")
				p.Obligations = []contract.Obligation{auditObligation("perm.refund")}
			},
		},
		{
			code: pdp.RuleConstraintObligations, detail: "split it into a constraint",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "con.big").Obligations = []contract.Obligation{auditObligation("con.big")}
			},
		},
		{
			code: pdp.RuleInspectionGrants, detail: "cannot be mandatory",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "insp.pii").Mandatory = true
			},
		},
		{
			code: pdp.RuleEmptySelector, detail: "attaches no obligation",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "req.audit").Obligations = nil
			},
		},
		{
			code: pdp.RuleApprovalUnsatisfiable, detail: "is not a positive integer",
			edit: func(_ *Metadata, d *pdp.Document) {
				p := policyByIDIn(d, "req.audit")
				p.Obligations = append(p.Obligations, approvalObligation("req.audit", "0", groupFinance))
			},
		},
		{
			code: pdp.RuleOrgPolicyPiercesSystem, detail: "organization root cannot declare it",
			edit: func(_ *Metadata, d *pdp.Document) {
				// An organization document that declares a break-glass pierce.
				// Piercing is declared by the authority that owns the
				// constraint, and the organization root does not own it.
				d.Root = pdp.RootOrganization
				for i := range d.Policies {
					d.Policies[i].Root = pdp.RootOrganization
				}
			},
		},
		{
			code: pdp.RuleMalformedCondition, detail: "sometimes",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "perm.refund").Where = pdp.Condition{Kind: pdp.CondKind("sometimes")}
			},
		},
		{
			code: pdp.RuleDuplicatePolicyID, detail: "more than once",
			edit: func(_ *Metadata, d *pdp.Document) {
				d.Policies = append(d.Policies, *policyByIDIn(d, "perm.refund"))
			},
		},
		{
			code: pdp.RuleRootMismatch, detail: "inside a \"system\" document",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "perm.refund").Root = pdp.RootOrganization
			},
		},
		{
			code: pdp.RulePoolNotInteractive, detail: groupBots,
			edit: func(_ *Metadata, d *pdp.Document) {
				p := policyByIDIn(d, "req.audit")
				p.Obligations = append(p.Obligations, approvalObligation("req.audit", "1", groupBots))
			},
		},
		{
			code: pdp.RuleAbsenceNotHandled, detail: "args.note",
			edit: func(_ *Metadata, d *pdp.Document) {
				// args.note is declared optional and the condition does not say
				// what its absence means.
				policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.note", pdp.OpEq, "approved")
			},
		},

		// Owned by this layer.
		{
			code: CodeActionNotRegistered, detail: "Action::refund.reverse",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "perm.refund").Actions = pdp.ActionSelector{
					Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::refund.reverse")},
				}
			},
		},
		{
			code: CodeSelectorMatchesNoRegisteredAction, detail: "quantum",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "perm.refund").Actions = pdp.ActionSelector{RequiredTags: []string{"quantum"}}
			},
		},
		{
			code: CodeArgumentNotInActionSchema, detail: "args.limit_cents",
			edit: func(_ *Metadata, d *pdp.Document) {
				// Declared in the document so the PDP's own schema rule is
				// satisfied, and absent from the action registry so only the
				// catalog-aware half can catch it. That separation is the point
				// of the case.
				d.Attributes = append(d.Attributes, pdp.AttributeSchema{Path: "args.limit_cents", Type: pdp.TypeNumber})
				policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.limit_cents", pdp.OpLe, 500000)
			},
		},
		{
			code: CodeLevelNotDeclared, detail: "Ledger",
			catalog: catalogWithFlatType,
			edit: func(_ *Metadata, d *pdp.Document) {
				d.Attributes = append(d.Attributes, pdp.AttributeSchema{Path: "resource.space.owner", Type: pdp.TypeString})
				policyByIDIn(d, "con.owner").Where = pdp.Not(pdp.AttrCompare("resource.space.owner", pdp.OpEq, pdp.PrincipalIDPath))
			},
		},
		{
			code: CodeScopeRequiresRecursion, detail: "Ledger",
			catalog: catalogWithFlatType,
			edit: func(_ *Metadata, d *pdp.Document) {
				scope := pdp.Member(pdp.ResourceAncestorsPath, "Resource::acme:project-1")
				policyByIDIn(d, "con.owner").ResourceScope = &scope
			},
		},
		{
			code: CodeRealmNotDeclared, detail: "mars",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "perm.refund").Scope = pdp.Scope{
					Groups: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::mars:finance")},
				}
			},
		},
		{
			code: CodeGroupScopeWithoutGraph, detail: groupFlat,
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "perm.refund").Scope = pdp.Scope{
					Groups: []contract.ID{contract.MustParseID(contract.KindGroup, groupFlat)},
				}
			},
		},
		{
			code: CodeObligationConflict, detail: "insp.pii",
			edit: func(_ *Metadata, d *pdp.Document) {
				p := policyByIDIn(d, "insp.pii")
				// Same transform, same leaf, different parameters. Equal rank
				// and different instructions is incomparable, and the runtime
				// denies rather than silently picking one.
				p.Obligations = append(p.Obligations,
					redactObligation("insp.pii", "report.customer.email", map[string]string{"style": "masked"}))
			},
		},
		{
			code: CodeDisclosureTargetNotALeaf, detail: "report.customer.postcode",
			edit: func(_ *Metadata, d *pdp.Document) {
				policyByIDIn(d, "insp.pii").Obligations = []contract.Obligation{
					redactObligation("insp.pii", "report.customer.postcode", map[string]string{"style": "fixed"}),
				}
			},
		},
		{
			code: CodeConstraintNeverBinds, detail: "exception is structurally true",
			edit: func(_ *Metadata, d *pdp.Document) {
				always := pdp.True()
				policyByIDIn(d, "con.big").Unless = &always
			},
		},
		{
			code: CodeDeadPermission, detail: "con.everything",
			edit: func(_ *Metadata, d *pdp.Document) {
				d.Policies = append(d.Policies, pdp.Policy{
					ID:        "con.everything",
					Authority: contract.AuthorityConstraint,
					Root:      pdp.RootSystem,
					Scope:     pdp.Scope{Organization: true},
					Actions:   pdp.ActionSelector{Any: true},
					Where:     pdp.True(),
				})
			},
		},
		{
			code: CodeCatalogDisagreement, detail: "bots",
			after: func(d *Document) {
				// The registry says the bots realm is non-interactive. A
				// document claiming otherwise would publish an approval into a
				// realm where nobody can answer.
				d.Policy.InteractiveRealms["bots"] = true
			},
		},
		{
			code: CodeEnvelopeInvalid, detail: "metadata.title is empty",
			edit: func(m *Metadata, _ *pdp.Document) { m.Title = "" },
		},
		{
			code: CodeApproverIsAuthor, detail: principalAlice,
			run: func(t *testing.T) Findings {
				t.Helper()
				d := baseDocument(t)
				_, priv := testKeys(t)
				opts := publishOptions(t, priv)
				// The author approving their own document.
				opts.Approvers = []contract.ID{pid(t, principalAlice)}
				_, findings, err := Publish(context.Background(), d, baseCatalog(t), opts)
				if err == nil {
					t.Fatal("self-approved publication was accepted")
				}
				return findings
			},
		},
	}
}

// policyByIDIn is the non-testing form used inside case edits.
func policyByIDIn(d *pdp.Document, id string) *pdp.Policy {
	for i := range d.Policies {
		if d.Policies[i].ID == id {
			return &d.Policies[i]
		}
	}
	panic("the baseline no longer declares policy " + id)
}

// TestTheBaselineDocumentIsClean is the anti-vacuity floor for every case
// below. If the baseline produced findings of its own, every case would find
// its code among them for free and none of the edits would be doing anything.
func TestTheBaselineDocumentIsClean(t *testing.T) {
	cat := baseCatalog(t)
	d := documentWith(t, cat, nil)
	findings := Validate(d, cat)
	if len(findings) != 0 {
		t.Fatalf("the baseline must produce no findings at all, got %d:\n%v", len(findings), findings)
	}
}

func TestSaveTimeChecks(t *testing.T) {
	for _, tc := range rejectionCases() {
		t.Run(tc.code, func(t *testing.T) {
			var findings Findings
			if tc.run != nil {
				findings = tc.run(t)
			} else {
				catFn := tc.catalog
				if catFn == nil {
					catFn = baseCatalog
				}
				cat := catFn(t)
				d := documentWith(t, cat, tc.edit)
				if tc.after != nil {
					tc.after(d)
				}
				findings = Validate(d, cat)
			}
			if !findings.Has(tc.code) {
				t.Fatalf("expected code %s, got %v\nfindings: %v", tc.code, findings.Codes(), findings)
			}
			if tc.detail == "" {
				t.Fatalf("case %s names no expected detail, so it would accept the code firing for any reason", tc.code)
			}
			named := false
			for _, f := range findings {
				if f.Code == tc.code && strings.Contains(f.Detail, tc.detail) {
					named = true
				}
			}
			if !named {
				t.Fatalf("code %s fired but no finding names %q, so it fired for a different reason than the case provoked.\nfindings: %v",
					tc.code, tc.detail, findings)
			}
			// The severity a case observes must be the severity the check table
			// declares. A warning that reaches a caller labelled as a rejection
			// blocks a legitimate save, and a rejection labelled as a warning is
			// a control that does not control.
			decl, ok := checkIndex[tc.code]
			if !ok {
				t.Fatalf("code %s is not in the declaration table", tc.code)
			}
			for _, f := range findings {
				if f.Code != tc.code {
					continue
				}
				if f.Severity != decl.Severity {
					t.Fatalf("code %s fired with severity %q, the table declares %q", tc.code, f.Severity, decl.Severity)
				}
				if f.Summary != decl.Summary {
					t.Fatalf("code %s fired with a summary that is not the declared one", tc.code)
				}
				if f.Detail == "" {
					t.Fatalf("code %s fired with no detail, so nobody can tell which value was refused", tc.code)
				}
			}
			// A rejection must actually block, and a warning must not.
			switch decl.Severity {
			case SeverityReject:
				if !findings.Rejected() {
					t.Fatalf("code %s is declared a rejection and did not block the save", tc.code)
				}
			case SeverityWarn:
				if findings.Rejected() {
					t.Fatalf("code %s is declared a warning but the document was rejected: %v", tc.code, findings.Rejections())
				}
			}
		})
	}
}

// TestEveryDeclaredCheckHasACaseThatFires is the completeness gate. A code
// added to the declaration table without a case that provokes it is a code
// nothing has ever observed firing, and the table is exactly where such a code
// would look finished.
func TestEveryDeclaredCheckHasACaseThatFires(t *testing.T) {
	covered := map[string]struct{}{}
	for _, tc := range rejectionCases() {
		if _, dup := covered[tc.code]; dup {
			t.Fatalf("code %s has two cases; the second is not adding coverage", tc.code)
		}
		covered[tc.code] = struct{}{}
	}
	var missing []string
	for _, decl := range AllChecks() {
		if _, ok := covered[decl.Code]; !ok {
			missing = append(missing, decl.Code)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("declared checks with no case that provokes them: %v", missing)
	}
	for code := range covered {
		if _, ok := checkIndex[code]; !ok {
			t.Fatalf("case %s tests a code the declaration table does not declare", code)
		}
	}
	if len(covered) != len(declaredChecks) {
		t.Fatalf("the table declares %d checks and %d have cases", len(declaredChecks), len(covered))
	}
}

// TestRelayCoversEveryPDPRule holds the relay table to pdp.AllRules.
//
// Without it, a rule added to the deterministic PDP would reach an operator
// through relayPDP's fallback branch as a refusal whose explanation says the
// explanation is missing. That fallback exists so the failure is visible rather
// than fatal, and this is what makes it visible at build time instead.
func TestRelayCoversEveryPDPRule(t *testing.T) {
	declaredHere := map[string]CheckDeclaration{}
	for _, c := range declaredChecks {
		declaredHere[c.Code] = c
	}
	for _, rule := range pdp.AllRules() {
		decl, ok := declaredHere[rule]
		if !ok {
			t.Errorf("pdp rule %q is not relayed by the authoring check table", rule)
			continue
		}
		if !decl.FromPDP {
			t.Errorf("pdp rule %q is declared here but not marked as relayed", rule)
		}
		if decl.Summary == "" {
			t.Errorf("pdp rule %q is relayed with no operator-facing summary", rule)
		}
	}
	for _, c := range declaredChecks {
		if !c.FromPDP {
			continue
		}
		found := false
		for _, rule := range pdp.AllRules() {
			if rule == c.Code {
				found = true
			}
		}
		if !found {
			t.Errorf("check %q is marked as relayed from the PDP, which does not declare it", c.Code)
		}
	}
}

// TestRetiredChecksAreGenuinelyRetired makes the disposition executable.
//
// Recording that a source-specification check was dropped is a claim. This is
// what stops the claim and the code disagreeing: a retired code that quietly
// reappeared in the active set, or an active code someone also listed as
// retired, fails here rather than in a review six months later.
func TestRetiredChecksAreGenuinelyRetired(t *testing.T) {
	if len(retiredChecks) == 0 {
		t.Fatal("no retired checks are recorded, so this gate is asserting nothing")
	}
	for _, r := range retiredChecks {
		if _, active := checkIndex[r.Code]; active {
			t.Errorf("%s is recorded as retired and is in the active check table", r.Code)
		}
		if len(r.Reason) < 80 {
			t.Errorf("%s is retired with a reason too short to be a reason: %q", r.Code, r.Reason)
		}
	}
	// The retired set must not silently shrink either: a check that stops
	// being mentioned is a disposition that stopped being recorded.
	if got := len(RetiredChecks()); got != len(retiredChecks) {
		t.Fatalf("RetiredChecks returned %d entries for %d records, so a code is recorded twice", got, len(retiredChecks))
	}
}

// TestFindingsAreOrderedDeterministically pins the property the portal's
// dry-run depends on: two validations of one document produce the same list in
// the same order, so a diff between two saves is a diff and not map iteration
// noise.
func TestFindingsAreOrderedDeterministically(t *testing.T) {
	cat := baseCatalog(t)
	d := documentWith(t, cat, func(_ *Metadata, doc *pdp.Document) {
		policyByIDIn(doc, "perm.refund").Where = pdp.Compare("env.zone", pdp.OpEq, "corp")
		policyByIDIn(doc, "con.owner").Actions = pdp.ActionSelector{RequiredTags: []string{"nope"}}
		doc.Policies = append(doc.Policies, *policyByIDIn(doc, "req.audit"))
	})
	first := Validate(d, cat)
	if len(first) < 3 {
		t.Fatalf("expected several findings from three defects, got %v", first.Codes())
	}
	for i := 0; i < 12; i++ {
		again := Validate(d, cat)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d findings, the first produced %d", i, len(again), len(first))
		}
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("run %d differs at position %d: %v vs %v", i, j, again[j], first[j])
			}
		}
	}
}

// TestValidateRefusesAnUnusableCatalog proves the catalog defect is reported as
// a catalog defect. An author reading "this action is not registered" cannot
// tell a typo from an empty registry, and those go to different people.
func TestValidateRefusesAnUnusableCatalog(t *testing.T) {
	d := baseDocument(t)
	for name, cat := range map[string]*Catalog{
		"nil":        nil,
		"no actions": {Realms: map[string]RealmEntry{"acme": {}}},
		"no realms":  {Actions: baseCatalog(t).Actions},
		"bad depth":  catalogWithoutDelegationDepth(t),
		"key mismatch": func() *Catalog {
			c := baseCatalog(t)
			c.Actions["Action::wrong.key"] = c.Actions[actionRefund]
			return c
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			findings := Validate(d, cat)
			if !findings.Has(CodeEnvelopeInvalid) {
				t.Fatalf("an unusable catalog must be refused as an envelope defect, got %v", findings.Codes())
			}
		})
	}
}

func catalogWithoutDelegationDepth(t *testing.T) *Catalog {
	c := baseCatalog(t)
	e := c.Actions[actionRefund]
	e.MaxDelegationDepth = 0
	c.Actions[actionRefund] = e
	return c
}
