package conformance

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// correctiveCases are the cases ADR-065 adds. Each one covers a property the
// source proposal either left to a per-tool posture field, resolved unsafely, or
// did not have a mechanism for at all.
func correctiveCases() []Case {
	return []Case{
		{
			ID: "AXC-001", Title: "A temporary compatibility exception can permit a read-only action",
			Family: "M Compatibility", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := newWorld(t, WithCompatibility(&pdp.CompatibilityProfile{Entries: []pdp.CompatibilityEntry{{
					Action: Actions["T3"].ID, Owner: "platform-migration",
					ExpiresAt: Now.Add(720 * time.Hour), RemovalIssue: "getaxonflow/axonflow-enterprise#3552",
				}}}))
				d := decide(t, w, Scenario{Principal: "alice", Action: "T3", Args: map[string]any{"query": "invoices"}})
				// Default deny is correct and is also why programs like this
				// die on day one: nothing is authored and everything breaks.
				// The exception is the sanctioned way through, and it is
				// explicit, action-scoped, time-bound, attributed and audited
				// rather than a posture field on a form.
				rec.Equal("the request is permitted", d.Authorization, contract.AuthzPermit)
				rec.True("no permission matched, so this is not an ordinary permit",
					len(d.Determining.MatchedPermissions) == 0)
				rec.True("the permit carries a mandatory audit record",
					contains(ObligationKeys(d), "immutable_audit"))
				rec.True("the trace says the permit came from an exception",
					anyContains(d.Trace.Warnings, "temporary compatibility exception"))
			},
		},
		{
			ID: "AXC-002", Title: "A compatibility exception is unavailable to an irreversible action",
			Family: "M Compatibility", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := newWorld(t, WithCompatibility(&pdp.CompatibilityProfile{Entries: []pdp.CompatibilityEntry{{
					Action: Actions["T1"].ID, Owner: "platform-migration",
					ExpiresAt: Now.Add(720 * time.Hour), RemovalIssue: "getaxonflow/axonflow-enterprise#3552",
				}}}))
				// bob has no ownership of this ticket, so no permission
				// matches and the exception is the only thing that could
				// produce a permit.
				d := decide(t, w, Scenario{Principal: "dana", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				rec.Equal("the request is still denied", d.State, contract.StateDeny)
				rec.True("the trace explains why the exception did not apply",
					anyContains(d.Trace.Warnings, "irreversible=true"))
			},
		},
		{
			ID: "AXC-003", Title: "A compatibility exception never converts an indeterminate result",
			Family: "M Compatibility", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := newWorld(t, WithCompatibility(&pdp.CompatibilityProfile{Entries: []pdp.CompatibilityEntry{{
					Action: Actions["T3"].ID, Owner: "platform-migration",
					ExpiresAt: Now.Add(720 * time.Hour), RemovalIssue: "getaxonflow/axonflow-enterprise#3552",
				}}}))
				// The gating risk signal is unresolvable, which makes a
				// mandatory requirement unknown.
				d := decide(t, w, Scenario{Principal: "alice", Action: "T3",
					Args: map[string]any{"query": "invoices"},
					Overrides: map[string]*contract.Attribute{
						PathSignalRisk: UnknownAttr(PathSignalRisk, contract.ReasonResolutionFailed),
					}})
				// Permitting on an unresolved dependency would reintroduce
				// exactly the on-error-permit behaviour that turns any outage
				// into a widening of access. The exception applies to absence
				// of coverage, never to absence of information.
				rec.Equal("the result stays indeterminate", d.Authorization, contract.AuthzIndeterminate)
				rec.Equal("and the state is an error", d.State, contract.StateError)
			},
		},
		{
			ID: "AXC-004", Title: "A gating risk signal that cannot be established denies",
			Family: "N Inspection", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000},
					Overrides: map[string]*contract.Attribute{
						PathSignalRisk: UnknownAttr(PathSignalRisk, contract.ReasonResolutionFailed),
					}})
				// The asymmetry with the advisory detector case is deliberate
				// and is ADR-065's assurance table made executable: an advisory
				// control that fails is skipped, a control that GATES and fails
				// denies. A detector may affect authorization only when it is
				// registered as an enforcement control with a fail-closed
				// contract, and this is what fail-closed means.
				rec.Equal("the result is indeterminate", d.Authorization, contract.AuthzIndeterminate)
				rec.Equal("the deny threshold is a constraint, so it binds first",
					d.Reason, contract.ReasonUnknownConstraint)
				rec.True("the unknown names the gating deny threshold",
					anyContains(unknownKeys(d), "S1-DENY"))

				// Both gating policies must fail closed, not just the one that
				// happens to be checked first. With the deny threshold removed,
				// the approval threshold is the only gating policy left, and it
				// must still refuse to resolve rather than being skipped as a
				// requirement that did not apply.
				w2 := newWorld(t, WithSystemDocument(systemDocWithout("S1-DENY")))
				d2 := decide(t, w2, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000},
					Overrides: map[string]*contract.Attribute{
						PathSignalRisk: UnknownAttr(PathSignalRisk, contract.ReasonResolutionFailed),
					}})
				rec.Equal("the approval threshold also fails closed", d2.Authorization, contract.AuthzIndeterminate)
				rec.Equal("and it does so as an unknown mandatory requirement",
					d2.Reason, contract.ReasonUnknownRequirement)
				rec.True("the unknown names the gating approval threshold",
					anyContains(unknownKeys(d2), "S1-APPROVE"))
			},
		},
		{
			ID: "AXC-005", Title: "A risk score above the deny threshold denies",
			Family: "N Inspection", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}, RiskScore: 95})
				rec.Equal("the request is denied", d.Authorization, contract.AuthzDeny)
				rec.EqualStrings("the gating constraint binds", d.Determining.MatchedConstraints, []string{"S1-DENY"})
			},
		},
		{
			ID: "AXC-006", Title: "An enforcement point that advertised no profile cannot receive obligations",
			Family: "O Obligations", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := newWorld(t, WithPEP(nil))
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				// A plane either implements the complete decision profile or
				// refuses the request. A silent nil profile is not "no
				// obligations needed"; it is an enforcement point that never
				// said what it can do.
				rec.Equal("the request is denied", d.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the unsupported obligation", d.Reason, contract.ReasonUnsupportedObligation)
				rec.True("the explanation says no profile was advertised",
					strings.Contains(d.Trace.Remediation, "advertised no profile"))
			},
		},
		{
			ID: "AXC-007", Title: "A reversible surrogate is incomparable with a redaction",
			Family: "O Obligations", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				leaves := []string{"response.email"}
				// Both are MANDATORY. Composition denies on incomparability,
				// and a denial is only a legitimate answer for an obligation a
				// policy REQUIRED; asserting it against two advisory ones would
				// pin the opposite of the rule that an advisory control cannot
				// return deny, which AXC-023 covers from the other side.
				tokenize := contract.Obligation{Type: contract.ObFieldTokenize, Target: "response.email",
					Mandatory: true, SourcePolicy: "X1", SchemaVersion: 1}
				redact := contract.Obligation{Type: contract.ObFieldRedact, Target: "response.email",
					Mandatory: true, SourcePolicy: "X2", SchemaVersion: 1}

				pep := &contract.PEPProfile{ID: "probe", Capabilities: []contract.Capability{
					{Type: contract.ObFieldTokenize, Version: 1}, {Type: contract.ObFieldRedact, Version: 1},
				}}
				alone := contract.ComposeObligations(contract.ComposeInput{
					Obligations: []contract.Obligation{tokenize}, Leaves: leaves, PEP: pep})
				rec.True("a reversible surrogate standing alone applies as authored", !alone.Denied)
				rec.EqualStrings("and it is the transform on the leaf",
					[]string{string(alone.Obligations[0].Type)}, []string{string(contract.ObFieldTokenize)})

				both := contract.ComposeObligations(contract.ComposeInput{
					Obligations: []contract.Obligation{tokenize, redact}, Leaves: leaves, PEP: pep})
				// The source proposal ranked tokenization between a one-way
				// digest and a partial reveal. That placement is wrong: a value
				// recoverable from a vault does not reveal less than a digest,
				// so the two are not on one scale and a reviewed subsumption
				// rule would be needed to order them.
				rec.True("two incomparable transforms on one leaf deny", both.Denied)
				rec.Equal("and the reason names the conflict", both.Reason, contract.ReasonObligationConflict)
			},
		},
		{
			ID: "AXC-023", Title: "An advisory control cannot turn a permit into a denial",
			Family: "N Inspection", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				// An inspection policy attaching a transform that is
				// incomparable with a requirement's on the same leaf. Composed
				// together the two do not resolve, and the question is what
				// happens then.
				org := OrganizationDocument()
				org.Policies = append(org.Policies, pdp.Policy{
					ID: "D9", Authority: contract.AuthorityInspection, Root: pdp.RootOrganization,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
					Where: pdp.True(),
					Obligations: []contract.Obligation{{
						Type: contract.ObFieldMask, Target: "response.phone",
						Params: map[string]string{"keep": "first6"}, SourcePolicy: "D9", SchemaVersion: 1,
					}},
				})
				clean := decide(t, defaultWorld(t), Scenario{Principal: "dana", Action: "T4",
					Args: map[string]any{"contact_id": "c1"}})
				rec.Equal("the request is allowed without the detector", clean.State, contract.StateAllow)

				w := newWorld(t, WithOrganizationDocument(org))
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				// ADR-065 is explicit that an advisory control cannot return
				// deny, and the reason is operational rather than theoretical:
				// a flaky classifier that can deny is a classifier that can
				// take the gateway down. So the advisory contribution is
				// DROPPED and recorded, never promoted into a denial.
				rec.Equal("adding a detector does not deny the request", d.State, contract.StateAllow)
				rec.Equal("the detector still matched", len(d.Determining.MatchedInspections), 1)
				rec.True("and its dropped contribution is recorded",
					anyContains(d.Trace.Warnings, "advisory obligations"))
				rec.EqualStrings("the required transforms are untouched", ObligationKeys(d), ObligationKeys(clean))
			},
		},
		{
			ID: "AXC-024", Title: "An advisory control may not carry an obligation that can refuse",
			Family: "N Inspection", Kind: KindAuthoring,
			Run: func(t *testing.T, rec *Recorder) {
				// Forcing the mandatory flag off is not sufficient, and that is
				// the point of this case. The approval family produces a
				// challenge whose timeout is always deny, and the budget family
				// refuses when the counter is exhausted; neither consults the
				// flag, so an inspection policy carrying one would deny by a
				// route the flag does not cover.
				for _, o := range []contract.Obligation{
					approvalObligation("D8", 2, "security-leads"),
					{Type: contract.ObQuotaReservation, SourcePolicy: "D8", SchemaVersion: 1,
						Params: map[string]string{"counter": "detector_budget", "limit": "1", "window": "P1D",
							"unit": "calls", "amount_from": PathArgsAmount}},
				} {
					d := OrganizationDocument()
					d.Policies = append(d.Policies, pdp.Policy{
						ID: "D8", Authority: contract.AuthorityInspection, Root: pdp.RootOrganization,
						Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
						Where: pdp.True(), Obligations: []contract.Obligation{o},
					})
					errs := d.Validate()
					rec.True("the document carrying a "+string(o.Type)+" on an inspection policy is rejected", len(errs) > 0)
					rec.True("and the rule names the inspection authority", hasRule(errs, pdp.RuleInspectionGrants))
				}

				// A disclosure transform and an audit record stay legal: an
				// inspection policy contributes its obligations on evidence
				// rather than on outcome, and recording that the evidence
				// existed is the whole reason to hang one off a detector.
				legal := OrganizationDocument()
				rec.Equal("the fixture inspection policies are accepted", len(legal.Validate()), 0)
			},
		},
		{
			ID: "AXC-008", Title: "Approval clauses deduplicate without flattening pools",
			Family: "P Approval", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				clause := func(source string, quorum string, groups string) contract.Obligation {
					return contract.Obligation{
						Type: contract.ObApprovalChallenge, SourcePolicy: source, SchemaVersion: 1,
						Params: map[string]string{"quorum": quorum, "eligible": groups, "separation_of_duties": "true"},
					}
				}
				a := group("security-leads").String()
				b := group("staff-managers").String()
				out := contract.ComposeObligations(contract.ComposeInput{
					Obligations: []contract.Obligation{
						clause("P1", "2", a+","+b),
						clause("P2", "2", b+","+a),
						clause("P3", "1", b),
					},
					ApprovalExpiry: Now.Add(time.Hour),
					PEP:            DefaultPEP(),
				})
				rec.True("composition succeeds", !out.Denied)
				// The two identical clauses collapse to one because they are
				// the same clause written twice, not because their pools were
				// merged. The third stays separate: a conjunction of "2 of
				// {A,B}" and "1 of {B}" is not "2 of {B}".
				rec.Equal("identical clauses deduplicate", len(out.Approval.AllOf), 2)
				rec.True("separation of duties survives composition", out.Approval.SeparationOfDuties)
				var pools []int
				for _, c := range out.Approval.AllOf {
					pools = append(pools, len(c.Eligible))
				}
				rec.True("no clause was reduced to an intersection",
					(pools[0] == 2 && pools[1] == 1) || (pools[0] == 1 && pools[1] == 2))
			},
		},
		{
			ID: "AXC-009", Title: "An unsigned or tampered bundle cannot be activated",
			Family: "Q Supply chain", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				doc := SystemDocument()
				b, err := pdp.BuildBundle(doc)
				if err != nil {
					rec.Fatalf("building the bundle: %v", err)
				}
				ts := pdp.NewTrustStore()
				pub, priv, _ := ed25519.GenerateKey(nil)
				ts.Authorize(pdp.RootSystem, "k1", pub)

				rec.True("an unsigned bundle is refused", ts.Verify(b) != nil)
				if err := b.Sign("k1", priv); err != nil {
					rec.Fatalf("signing: %v", err)
				}
				rec.True("a signed bundle verifies", ts.Verify(b) == nil)

				// Editing a live policy row in place is not deployment. A
				// bundle edited after signing must not activate, which is what
				// makes "which policy produced this decision" answerable after
				// the next edit.
				tampered := *b
				tampered.Module = strings.Replace(b.Module, "\"C2\"", "\"C2x\"", 1)
				rec.True("a module edited after signing is refused", ts.Verify(&tampered) != nil)

				wrongKey := *b
				wrongKey.KeyID = "k2"
				rec.True("a bundle signed by an unauthorized key is refused", ts.Verify(&wrongKey) != nil)

				// An organization bundle cannot be activated against the system
				// root's key, so an organization author cannot publish a system
				// constraint.
				orgBundle, err := pdp.BuildBundle(OrganizationDocument())
				if err != nil {
					rec.Fatalf("building the organization bundle: %v", err)
				}
				if err := orgBundle.Sign("k1", priv); err != nil {
					rec.Fatalf("signing the organization bundle: %v", err)
				}
				rec.True("a bundle for another root is refused", ts.Verify(orgBundle) != nil)
			},
		},
		{
			ID: "AXC-010", Title: "The bundle lint accepts only the shape the compiler emits",
			Family: "Q Supply chain", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				doc := SystemDocument()
				b, err := pdp.BuildBundle(doc)
				if err != nil {
					rec.Fatalf("building the bundle: %v", err)
				}
				pkg := pdp.BundlePackage(doc.Root)
				rec.True("the generated module passes the lint", pdp.LintBundleModule(b.Module, pkg) == nil)

				// The lint is a WHITELIST on structure rather than a blacklist
				// on one spelling, and these mutants are why. A rule that
				// refused a reference rooted at `input` with more than two
				// terms catches the first of these and none of the rest: bind
				// the same value to a variable, or take it as a function
				// argument, and the reference is rooted somewhere else. A guard
				// is only as wide as the syntax it matches.
				for name, mutate := range map[string]func(string) string{
					"a literal indexed dereference": func(m string) string {
						return strings.Replace(m, "policy_result := {",
							"sneaky := input.attributes[\"principal.id\"].value\n\npolicy_result := {", 1)
					},
					"the same read aliased through a variable": func(m string) string {
						return strings.Replace(m, "policy_result := {",
							"attrs := input.attributes\n\nsneaky := attrs[\"principal.id\"].value\n\npolicy_result := {", 1)
					},
					"the same read behind a helper of its own": func(m string) string {
						return strings.Replace(m, "policy_result := {",
							"peek(a, p) := a[p].value\n\nsneaky := peek(input.attributes, \"principal.id\")\n\npolicy_result := {", 1)
					},
					"a condition added to a generated rule": func(m string) string {
						return strings.Replace(m, "authorities := {",
							"authorities := {} if {\n\tinput.attributes[\"principal.id\"].value == \"root\"\n}\n\nunused := {", 1)
					},
					"a foreign import": func(m string) string {
						return strings.Replace(m, "import data.axonflow.decision.tri",
							"import data.axonflow.decision.tri\nimport data.something.else", 1)
					},
					"a package that merely ends with the expected one": func(m string) string {
						return strings.Replace(m, "package "+pkg, "package attacker."+pkg, 1)
					},
					"a generated rule removed entirely": func(m string) string {
						i := strings.Index(m, "authorities := {")
						j := strings.Index(m[i:], "}\n")
						return m[:i] + m[i+j+2:]
					},
				} {
					err := pdp.LintBundleModule(mutate(b.Module), pkg)
					rec.True("the lint refuses "+name, err != nil)
				}
			},
		},
		{
			ID: "AXC-011", Title: "A policy missing from the result object is indeterminate",
			Family: "Q Supply chain", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				doc := SystemDocument()
				b, err := pdp.BuildBundle(doc)
				if err != nil {
					rec.Fatalf("building the bundle: %v", err)
				}
				// Declare a policy in the manifest that the compiled module
				// does not produce. This is the shape a defective bundle takes,
				// and reading the absence as "that policy did not apply" is the
				// silent fail-open the sealed complete result object exists to
				// prevent.
				b.Manifest = append(b.Manifest, pdp.PolicyDeclaration{
					ID: "GHOST", Authority: contract.AuthorityConstraint,
				})
				rt, err := pdp.NewRuntime(context.Background(), b, pdp.DefaultLimits())
				if err != nil {
					rec.Fatalf("preparing the runtime: %v", err)
				}
				_, err = rt.Eval(context.Background(), contract.AttributeSet{})
				rec.True("evaluation fails rather than returning a partial result", err != nil)
				rec.True("and the failure names the missing policy",
					err != nil && strings.Contains(err.Error(), "GHOST"))
			},
		},
		{
			ID: "AXC-012", Title: "The next bound is never available to the requester audience",
			Family: "R Trace", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T2", Args: map[string]any{"segment": "all"}})
				full := d.Trace
				full.NextBound = &contract.NextBound{PolicyID: "C3", Authority: contract.AuthorityRequirement,
					Summary: "irreversible personal-data egress requires two security leads"}

				requester, err := full.Project(contract.AudienceRequester)
				if err != nil {
					rec.Fatalf("projecting the requester trace: %v", err)
				}
				// The next bound turns "why did this fail" into "what would it
				// take to make this work", which is the question people are
				// actually asking. It is also a map of the policy structure, so
				// it is operator or auditor data, computed only on an
				// authorized explain request.
				rec.True("the requester does not receive the next bound", requester.NextBound == nil)
				rec.True("the requester does not receive determining policies at all",
					requester.Determining == nil)
				rec.True("the requester does not receive a binding policy", requester.BindingPolicy == "")
				rec.Equal("the requester does receive a coarse category", requester.Category, contract.CategoryNotPermitted)
				rec.Equal("and no machine reason code", requester.Reason, contract.ReasonCode(""))

				operator, err := full.Project(contract.AudienceOperator)
				if err != nil {
					rec.Fatalf("projecting the operator trace: %v", err)
				}
				rec.True("the operator does receive the next bound", operator.NextBound != nil)
				rec.True("the operator does not receive resolved ancestors", operator.ResolvedAncestors == nil)

				pep, err := full.Project(contract.AudiencePEP)
				if err != nil {
					rec.Fatalf("projecting the enforcement trace: %v", err)
				}
				rec.True("the enforcement point does not receive determining policies at all",
					pep.Determining == nil)
				rec.Equal("but it does receive the machine reason it must enforce",
					pep.Reason, contract.ReasonExplicitConstraint)
			},
		},
		{
			ID: "AXC-013", Title: "An unknown envelope key fails closed", Family: "S AuthZEN", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				good := []byte(`{"evaluation":{"subject":{"type":"identity","id":"alice"},` +
					`"action":{"name":"jira.transition_issue"},"resource":{"type":"ticket","id":"SUP-42"}}}`)
				_, err := contract.DecodeAuthZENEnvelope(good)
				rec.True("a well formed singular envelope decodes", err == nil)

				for name, raw := range map[string][]byte{
					"an unknown top level key": []byte(`{"evaluation":{"subject":{"type":"identity","id":"a"},` +
						`"action":{"name":"x"},"resource":{"type":"t","id":"1"}},"evaluate":{}}`),
					"both envelope keys at once": []byte(`{"evaluation":{"subject":{"type":"identity","id":"a"},` +
						`"action":{"name":"x"},"resource":{"type":"t","id":"1"}},"evaluations":{"evaluations":[]}}`),
					"neither envelope key":     []byte(`{}`),
					"an empty plural envelope": []byte(`{"evaluations":{"evaluations":[]}}`),
					"an unknown key inside an entry": []byte(`{"evaluation":{"subject":{"type":"identity","id":"a"},` +
						`"action":{"name":"x"},"resource":{"type":"t","id":"1"},"obligations":[]}}`),
				} {
					_, err := contract.DecodeAuthZENEnvelope(raw)
					rec.True("the boundary refuses "+name, err != nil)
				}
			},
		},
		{
			ID: "AXC-014", Title: "Bulk entries meet and do not fan out", Family: "S AuthZEN", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				raw := []byte(`{"evaluations":{"subject":{"type":"identity","id":"alice"},` +
					`"action":{"name":"jira.move_issue"},"context":{"args":{"ticket_id":"SUP-42"}},` +
					`"evaluations":[{"resource":{"type":"ticket","id":"SUP-42"}},` +
					`{"resource":{"type":"project","id":"LEGAL"}}]}}`)
				env, err := contract.DecodeAuthZENEnvelope(raw)
				if err != nil {
					rec.Fatalf("decoding: %v", err)
				}
				projected, err := env.Project(Now)
				if err != nil {
					rec.Fatalf("projecting: %v", err)
				}
				// The decision count is fixed by the mapping, never by the
				// arguments: letting a runtime list decide how many
				// authorization checks happen would let caller data choose its
				// own scrutiny.
				rec.Equal("the entry count is the mapping's, not the arguments'", len(projected), 2)
				rec.Equal("top level defaults flow into each entry", projected[1].SubjectID, "alice")
				rec.Equal("and each entry overrides only what it names", projected[1].ResourceID, "LEGAL")
				// Caller-supplied data lands only in the untrusted namespace.
				for _, p := range projected {
					for path := range p.CallerAttributes {
						rec.Equal("caller data lands under args", contract.NamespaceOf(path), contract.NsArgs)
					}
				}

				permit := func(id string) *contract.Decision {
					return &contract.Decision{DecisionID: id, RequestID: "r", Authorization: contract.AuthzPermit,
						State: contract.StateAllow, Reason: contract.ReasonPermitted,
						Snapshot: contract.Snapshot{SchemaVersion: contract.SchemaVersion, PolicyBundle: "sha256:x"}}
				}
				// A single entry is validated too: returning it untouched would
				// make the one-entry path the only way a malformed decision
				// reaches a caller as executable.
				broken := permit("d0")
				broken.Authorization = contract.AuthzDeny
				if _, err := contract.MeetDecisions([]*contract.Decision{broken}, contract.MeetOptions{}); err == nil {
					rec.Fatalf("a single malformed decision passed through the meet unvalidated")
				}
				rec.True("a single entry is still validated", true)
				deny := &contract.Decision{DecisionID: "d2", RequestID: "r", Authorization: contract.AuthzDeny,
					State: contract.StateDeny, Reason: contract.ReasonExplicitConstraint,
					Snapshot: contract.Snapshot{SchemaVersion: contract.SchemaVersion, PolicyBundle: "sha256:x"}}
				met, err := contract.MeetDecisions([]*contract.Decision{permit("d1"), deny},
					contract.MeetOptions{PayloadLeaves: []string{"response.body"}, PEP: DefaultPEP()})
				if err != nil {
					rec.Fatalf("meeting: %v", err)
				}
				// Moving a ticket must be authorized against the DESTINATION as
				// well as the ticket, or an agent could relocate anything into
				// a restricted project or out of one.
				rec.Equal("one denied entry denies the operation", met.Authorization, contract.AuthzDeny)
			},
		},
		{
			ID: "AXC-015", Title: "The AuthZEN edge collapses the lattice only at the boundary",
			Family: "S AuthZEN", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				challenge := decide(t, w, Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
					Args: map[string]any{"amount_cents": 3000000}})
				allow := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})

				negotiated, err := challenge.ToAuthZEN(contract.AuthZENProfileV1)
				if err != nil {
					rec.Fatalf("rendering: %v", err)
				}
				rec.Equal("a challenge is not a boolean permit", negotiated.Decision, false)
				rec.Equal("but the profile carries the real state", negotiated.Context.State, contract.StateChallenge)
				rec.True("and the outstanding approval", negotiated.Context.Approval != nil)

				allowed, err := allow.ToAuthZEN(contract.AuthZENProfileV1)
				if err != nil {
					rec.Fatalf("rendering: %v", err)
				}
				rec.Equal("an allow is a boolean permit", allowed.Decision, true)

				// A plane that did not negotiate the profile sees only the
				// boolean. Handing a partial interpretation to a plane that
				// cannot act on it is the failure the complete-profile
				// invariant forbids.
				bare, err := challenge.ToAuthZEN("some-other-profile")
				if err != nil {
					rec.Fatalf("rendering: %v", err)
				}
				rec.True("an unnegotiated plane receives no profile context", bare.Context == nil)
				rec.Equal("and still reads false", bare.Decision, false)
			},
		},
		{
			ID: "AXC-016", Title: "A stale attribute becomes unknown at its declared bound",
			Family: "T Freshness", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				stale := StaleAttr(PathResourceRisk, "low", 300)
				d := decide(t, w, Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
					Args:      map[string]any{"amount_cents": 3000000},
					Overrides: map[string]*contract.Attribute{PathResourceRisk: stale}})
				// Availability is provided without changing the authorization
				// result: a last-known-good value may be used INSIDE the
				// declared freshness bound and becomes unknown outside it. The
				// evaluator applies the bound rather than trusting the caller
				// to have applied it.
				rec.Equal("a stale value does not resolve the constraint", d.Authorization, contract.AuthzIndeterminate)
				rec.Equal("the reason names the constraint", d.Reason, contract.ReasonUnknownConstraint)
				rec.EqualStrings("and the unknown reason is staleness rather than failure",
					unknownKeys(d), []string{"C10:stale"})
			},
		},
		{
			ID: "AXC-017", Title: "An organization document cannot reuse a system policy identifier",
			Family: "U Authority roots", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				org := OrganizationDocument()
				org.Policies = append(org.Policies, pdp.Policy{
					ID: "C2", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true}, Where: pdp.True(),
				})
				_, err := pdp.MetaIndex(SystemDocument(), org)
				// Two policies with one identifier make "which policy denied
				// this" ambiguous in exactly the place it matters most, and an
				// organization document that could shadow a system identifier
				// is one rename away from shadowing its behaviour.
				rec.True("the pair is refused", err != nil)
				rec.True("and the refusal names the identifier",
					err != nil && strings.Contains(err.Error(), "C2"))
			},
		},
		{
			ID: "AXC-018", Title: "An organization policy that pierces is rejected at authoring",
			Family: "U Authority roots", Kind: KindAuthoring,
			Run: func(t *testing.T, rec *Recorder) {
				org := OrganizationDocument()
				org.Policies = append(org.Policies, pdp.Policy{
					ID: "OC1", Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true}, Where: pdp.True(),
					PierceableBy: []contract.ID{group("oncall-sre")},
				})
				errs := org.Validate()
				// Break-glass piercing is declared by the authority that owns
				// the constraint. An organization author who could declare it
				// could declare it on a system boundary next.
				rec.True("the document is rejected", len(errs) > 0)
				rec.True("and the rule names the authority root", hasRule(errs, pdp.RuleOrgPolicyPiercesSystem))
			},
		},
		{
			ID: "AXC-019", Title: "Identical input and bundle reproduce an identical decision",
			Family: "V Replay", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				s := Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
					Args: map[string]any{"amount_cents": 3000000}}
				first := decide(t, w, s)
				second := decide(t, w, s)
				// A decision that cannot be reproduced offline from its
				// normalized input and its pinned bundle cannot be audited, and
				// the identifier is DERIVED from the binding rather than
				// generated so that this is checkable rather than asserted.
				rec.Equal("the decision identifier is reproducible", second.DecisionID, first.DecisionID)
				rec.Equal("the authorization is reproducible", second.Authorization, first.Authorization)
				rec.Equal("the reason is reproducible", second.Reason, first.Reason)
				rec.EqualStrings("the obligations are reproducible", ObligationKeys(second), ObligationKeys(first))
				rec.EqualStrings("the approval clauses are reproducible", ApprovalKeys(second), ApprovalKeys(first))

				a, errA := json.Marshal(first.Determining)
				b, errB := json.Marshal(second.Determining)
				rec.True("the determining sets encode identically",
					errA == nil && errB == nil && string(a) == string(b))
			},
		},
		{
			ID: "AXC-020", Title: "A reservation is keyed on the decision binding, not on the arguments",
			Family: "W Reservation", Kind: KindReservation,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				c := NewCoordinator()
				s := Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}, RequestID: "req_idem"}
				req, err := w.Request(s)
				if err != nil {
					rec.Fatalf("building the request: %v", err)
				}
				d := decide(t, w, s)
				first, err := c.AdmitReservations(d, req, Now)
				if err != nil {
					rec.Fatalf("reserving: %v", err)
				}
				key := ReservationKey(reservationObligation(t, d), req)
				// An identical scoped retry returns the ORIGINAL hold rather
				// than a second one, so a client retry of the same request does
				// not consume the budget twice.
				retry, err := c.AdmitReservations(d, req, Now)
				if err != nil {
					rec.Fatalf("retrying: %v", err)
				}
				rec.EqualStrings("the retry returns the same hold", retry.Held, first.Held)
				rec.Equal("the counter is charged once", c.Held(key, Now), int64(30000))

				// A DIFFERENT request with identical arguments must not share
				// the hold. Hashing tool arguments alone is prohibited as an
				// idempotency key precisely because two different decisions can
				// carry the same arguments.
				other := s
				other.RequestID = "req_idem_other"
				otherReq, err := w.Request(other)
				if err != nil {
					rec.Fatalf("building the second request: %v", err)
				}
				otherDec := decide(t, w, other)
				second, err := c.AdmitReservations(otherDec, otherReq, Now)
				if err != nil {
					rec.Fatalf("reserving the second: %v", err)
				}
				rec.True("a different decision takes its own hold", second.Held[0] != first.Held[0])
				rec.Equal("and the counter is charged twice", c.Held(key, Now), int64(60000))
			},
		},
		{
			ID: "AXC-021", Title: "Adding an actor to the chain can only narrow authority",
			Family: "X Delegation", Kind: KindDecision,
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				for _, amount := range []int{30000, 300000, 3000000, 8000000} {
					alone := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
						Args: map[string]any{"amount_cents": amount}})
					chained := decide(t, w, Scenario{Principal: "alice", Chain: []string{"alice", "agent-A"},
						Action: "T1", Resource: "SUP-42", Args: map[string]any{"amount_cents": amount}})
					// Adding a hop may narrow and may leave the outcome
					// unchanged; it may never widen. Union across the chain
					// would do exactly that, and every policy involved would
					// still look correct in isolation.
					rec.True("adding an actor never widens the outcome",
						permissiveness(chained) <= permissiveness(alone))
				}
				// At an amount only the agent is permitted for, the meet
				// narrows rather than lending the agent's reach upward.
				narrowed := decide(t, w, Scenario{Principal: "alice", Chain: []string{"alice", "agent-A"},
					Action: "T1", Resource: "SUP-42", Args: map[string]any{"amount_cents": 3000000}})
				rec.Equal("and at an amount only the agent could reach, it denies",
					narrowed.State, contract.StateDeny)
			},
		},
		{
			ID: "AXC-022", Title: "A caller cannot place a value outside the untrusted namespace",
			Family: "Y Provenance", Kind: KindContract,
			Run: func(t *testing.T, rec *Recorder) {
				raw := []byte(`{"evaluation":{"subject":{"type":"identity","id":"alice",` +
					`"properties":{"groups":["Group::realm_ws:finance"]}},` +
					`"action":{"name":"stripe.create_refund"},"resource":{"type":"ticket","id":"SUP-42",` +
					`"properties":{"owner":"User::realm_ws:alice"}},"context":{"args":{"amount_cents":30000}}}}`)
				env, err := contract.DecodeAuthZENEnvelope(raw)
				if err != nil {
					rec.Fatalf("decoding: %v", err)
				}
				projected, err := env.Project(Now)
				if err != nil {
					rec.Fatalf("projecting: %v", err)
				}
				// A mapping may route caller data into ANY AuthZEN field, so
				// the rule cannot be about which field a value lands in. It is
				// about provenance, and the only namespace whose declared
				// provenance is caller-supplied is args.
				rec.True("the caller supplied something", len(projected[0].CallerAttributes) > 0)
				for path, a := range projected[0].CallerAttributes {
					rec.Equal("every projected value is under args", contract.NamespaceOf(path), contract.NsArgs)
					rec.Equal("and carries caller provenance", a.Source, contract.ProvCaller)
				}
				rec.True("the claimed group membership did not become a principal attribute",
					projected[0].CallerAttributes["principal.groups"].State == "")
				rec.True("and the claimed owner did not become a resource attribute",
					projected[0].CallerAttributes["resource.owner"].State == "")
			},
		},
	}
}
