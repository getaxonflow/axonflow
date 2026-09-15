// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE NO-DATABASE HALF OF THE SUPERSESSION AND ENABLED-STATE GUARDS
//
// TestSupersessionLedgerIsCompleteAndHonest asserts the strength inversion of
// all nine superseded pairs - and only against a migrated database, on a tier
// that does not run on a pull_request. So on the tier that gates a merge,
// deciding to drop one of the five, removing a kept row from the corpus
// TOGETHER with the divergences that describe it, or switching on a disabled
// integration seed consistently in the census or the artifact, was green.
// Removing a kept row's policy alone was already caught, by
// TestTheRootChangeIsAccountedForRowByRow. Everything below reads the
// checked-in artifacts only.

func shippedLedgerAndCensus(t *testing.T) ([]registry.SupersessionRow, []registry.CensusRow) {
	t.Helper()
	ledger, err := registry.ShippedSupersessionLedger()
	if err != nil {
		t.Fatalf("ShippedSupersessionLedger: %v", err)
	}
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	return ledger, census
}

func mustErrContaining(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want a refusal containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused for the wrong reason: want %q, got %v", want, err)
	}
}

// TestTheShippedSupersessionDecisionsHoldAgainstTheCensus checks every recorded
// decision against the stored actions the census holds to the database, and
// shows each refusal is reachable from the real rows.
func TestTheShippedSupersessionDecisionsHoldAgainstTheCensus(t *testing.T) {
	ledger, census := shippedLedgerAndCensus(t)
	if err := CheckSupersessionDecisions(ledger, census); err != nil {
		t.Fatal(err)
	}

	decide := func(id string, d registry.SupersessionDecision) []registry.SupersessionRow {
		out := append([]registry.SupersessionRow(nil), ledger...)
		for i := range out {
			if out[i].PolicyID == id {
				out[i].Decision = d
			}
		}
		return out
	}
	storedAction := func(id, action string) []registry.CensusRow {
		out := append([]registry.CensusRow(nil), census...)
		for i := range out {
			if out[i].PolicyID == id {
				out[i].LegacyAction = action
			}
		}
		return out
	}

	t.Run("deciding to drop a row that enforces more than its superseders", func(t *testing.T) {
		mustErrContaining(t, CheckSupersessionDecisions(decide("drop_table_prevention", registry.SupersessionDropSuperseded), census),
			`drop_table_prevention is decided drop_superseded and its action "block" outranks sys_sqli_drop_table (warn), sys_sqli_stacked_drop (warn), sys_sqli_drop_database (warn)`)
	})
	t.Run("keeping both once the pre-canonical row no longer enforces more", func(t *testing.T) {
		mustErrContaining(t, CheckSupersessionDecisions(ledger, storedAction("truncate_prevention", "warn")),
			`truncate_prevention is decided keep_both on the ground that it enforces more than a superseder, and its action "warn" outranks none`)
	})
	t.Run("a drop is permitted once the stronger action has been carried forward", func(t *testing.T) {
		// The negative control: without it the refusal above would pass on a
		// check that refused every drop. A drop permitted here has passed its
		// strength ground only; its coverage ground is not derivable.
		if err := CheckSupersessionDecisions(decide("truncate_prevention", registry.SupersessionDropSuperseded),
			storedAction("sys_sqli_truncate", "block")); err != nil {
			t.Fatalf("a drop whose superseder now enforces as much was refused: %v", err)
		}
	})
	t.Run("an action the ranking cannot place", func(t *testing.T) {
		mustErrContaining(t, CheckSupersessionDecisions(ledger, storedAction("sys_pii_ssn", "shout")), `cannot be ranked`)
	})
}

// TestTheShippedCorpusRepresentsEveryCensusRowsEnabledState is the enabled-state
// guard over the checked-in artifact, with each planted defect shown red.
func TestTheShippedCorpusRepresentsEveryCensusRowsEnabledState(t *testing.T) {
	_, census := shippedLedgerAndCensus(t)
	if err := CheckCorpusRepresentsTheCensus(shippedCorpusFromDisk(t), census); err != nil {
		t.Fatal(err)
	}
	enabled, disabled := 0, 0
	for _, r := range census {
		if r.Enabled {
			enabled++
		} else {
			disabled++
		}
	}
	if enabled == 0 || disabled == 0 {
		t.Fatalf("the census has %d enabled and %d disabled row(s); both arms of the guard need a population or one of them compared nothing", enabled, disabled)
	}
	t.Logf("census rows: %d enabled, %d disabled", enabled, disabled)

	without := func(doc *pdp.Document, key string) {
		kept := doc.Policies[:0]
		for _, p := range doc.Policies {
			if control, _, _ := CorpusControlOf(p.ID); control != key {
				kept = append(kept, p)
			}
		}
		doc.Policies = kept
	}

	t.Run("one of the five stronger superseded rows is dropped from the corpus", func(t *testing.T) {
		c := shippedCorpusFromDisk(t)
		without(c.OrganizationTemplate, CorpusPolicyIDFor("static_policies", "truncate_prevention"))
		mustErrContaining(t, CheckCorpusRepresentsTheCensus(c, census),
			"truncate_prevention is enabled in the census (tier tenant) and the organization template carries no policy")
	})
	t.Run("a disabled integration seed is silently enabled in the corpus", func(t *testing.T) {
		c := shippedCorpusFromDisk(t)
		planted := c.System.Policies[0]
		planted.ID = CorpusPolicyIDFor("static_policies", "int_claude_hooks")
		c.OrganizationTemplate.Policies = append(c.OrganizationTemplate.Policies, planted)
		mustErrContaining(t, CheckCorpusRepresentsTheCensus(c, census), "int_claude_hooks is DISABLED in the census and the corpus carries 1 policy")
	})
	t.Run("a disabled integration seed is silently enabled in the census", func(t *testing.T) {
		flipped := append([]registry.CensusRow(nil), census...)
		for i := range flipped {
			if flipped[i].PolicyID == "int_codex_settings" {
				flipped[i].Enabled = true
			}
		}
		mustErrContaining(t, CheckCorpusRepresentsTheCensus(shippedCorpusFromDisk(t), flipped),
			"int_codex_settings is enabled in the census (tier tenant) and the organization template carries no policy")
	})
	t.Run("a disabled row's absence is no longer declared", func(t *testing.T) {
		c := shippedCorpusFromDisk(t)
		kept := c.Divergences[:0]
		for _, d := range c.Divergences {
			if !(d.PolicyID == "int_cursor_rules" && d.Kind == DivergenceRowNotRepresented) {
				kept = append(kept, d)
			}
		}
		c.Divergences = kept
		mustErrContaining(t, CheckCorpusRepresentsTheCensus(c, census), "int_cursor_rules is disabled in the census and the corpus declares no row_not_represented")
	})
	t.Run("a system control lands in the customer-editable document", func(t *testing.T) {
		c := shippedCorpusFromDisk(t)
		key := CorpusPolicyIDFor("static_policies", "sys_sqli_truncate")
		for _, p := range c.System.Policies {
			if p.ID == key {
				c.OrganizationTemplate.Policies = append(c.OrganizationTemplate.Policies, p)
			}
		}
		mustErrContaining(t, CheckCorpusRepresentsTheCensus(c, census), "sys_sqli_truncate is enabled in the census (tier system) and the organization template carries 1 policy")
	})
}

// TestAKeptGenerationIsNotWeakenedInTheShippedCorpus asks the question presence
// cannot: whether the migrated policy for a generation the ledger keeps still
// enforces at least what the row stores.
//
// ADR-065 has no action ranking over policies, and a second, inverse mapping
// from a policy back to a legacy action would be the migration's substance
// written twice. So the action a corpus policy carries is RECOVERED by running
// the one forward mapping - the compiler itself - over each action and matching
// the shape it emits, and it is then ranked with the ranking the corpus
// collapse already declares.
func TestAKeptGenerationIsNotWeakenedInTheShippedCorpus(t *testing.T) {
	ledger, census := shippedLedgerAndCensus(t)
	stored := map[string]string{}
	// ONE WEAKENING IS KNOWN, RECORDED, AND NOT THE LEDGER'S. A require_approval
	// row cannot reach ADR-065 approval because static_policies stores neither
	// an eligible pool nor a quorum, so the compiler carries it as an audit
	// obligation and records approval_pool_not_stored (#3786 operator question
	// 4). That is exempted BY THE CENSUS'S OWN REASON rather than by name, is
	// still required to be present, and is logged, so a second weakening cannot
	// hide inside the same exemption. Since #4253 no plane resolves a stored hold
	// at all - the tier pass that read the stored column is retired and the
	// proxy_request arm keeps no hold - so the census raises that reason for no
	// row, and the exemption also reads the stored action itself.
	poolNotStored := map[string]bool{}
	for _, r := range census {
		stored[r.PolicyID] = r.LegacyAction
		for _, reason := range r.DispositionReasons {
			if reason == string(ReasonApprovalPoolNotStored) {
				poolNotStored[r.PolicyID] = true
			}
		}
	}

	type shape struct {
		authority   contract.Authority
		mandatory   bool
		obligations string
	}
	shapeOf := func(p pdp.Policy) shape {
		var types []string
		for _, o := range p.Obligations {
			types = append(types, string(o.Type))
		}
		sort.Strings(types)
		return shape{p.Authority, p.Mandatory, strings.Join(types, ",")}
	}
	actionOf := map[shape]LegacyAction{}
	for _, a := range []LegacyAction{ActionBlock, ActionRedact, ActionWarn, ActionLog} {
		row := staticRow(t, "probe_"+string(a), map[string]any{"action": string(a), "action_request": string(a), "action_response": string(a)})
		rep, err := Compile([]RawRow{row}, testOptions())
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		found := false
		for _, pr := range rep.Records[0].Planes {
			if pr.Plane == PlaneDecide && len(pr.Policies) > 0 {
				s := shapeOf(pr.Policies[0])
				if prev, dup := actionOf[s]; dup {
					t.Fatalf("the compiler emits the same policy shape for %q and %q, so a shape cannot identify an action", prev, a)
				}
				actionOf[s] = a
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the compiler emitted no decide policy for action %q; the recovery table would be incomplete", a)
		}
	}

	c := shippedCorpusFromDisk(t)
	policies := map[string][]pdp.Policy{}
	for _, doc := range []*pdp.Document{c.System, c.OrganizationTemplate} {
		for _, p := range doc.Policies {
			key, _, _ := CorpusControlOf(p.ID)
			policies[key] = append(policies[key], p)
		}
	}

	// A TEMPLATE REDACTION BOUND BY DISCHARGE (#4131) ships a warn policy for
	// the scopes that cannot carry a redaction out, beside the redact one. That
	// is exempted BY THE CORPUS'S OWN DIVERGENCE, and only while the variant
	// carrying the stored action still ships. Whether that variant binds on any
	// scope is not judged here: activation's dormant ledger lists the ones that
	// bind on no scope (dormant_template_variants.tsv, #4230).
	boundByDischarge := map[string]bool{}
	for _, d := range c.Divergences {
		if d.Kind == DivergenceRedactionBoundByDischarge {
			boundByDischarge[d.PolicyID] = true
		}
	}
	carriesStored := func(ps []pdp.Policy, action string) bool {
		for _, p := range ps {
			if a, known := actionOf[shapeOf(p)]; known && string(a) == action {
				return true
			}
		}
		return false
	}

	checked := 0
	for _, l := range ledger {
		if l.Decision.RemovesAGeneration() {
			continue
		}
		for _, id := range append([]string{l.PolicyID}, l.SupersededBy...) {
			want, _, ok := corpusRestrictiveness(stored[id])
			if !ok {
				t.Errorf("%s stores action %q, which the corpus ranking cannot place", id, stored[id])
				continue
			}
			ps := policies[CorpusPolicyIDFor("static_policies", id)]
			if len(ps) == 0 {
				t.Errorf("%s is a generation the ledger keeps (%s) and the corpus carries no policy for it", id, l.Decision)
				continue
			}
			for _, p := range ps {
				got, known := actionOf[shapeOf(p)]
				if !known {
					t.Errorf("%s: corpus policy %q has a shape (%+v) no single legacy action compiles to", id, p.ID, shapeOf(p))
					continue
				}
				rank, _, _ := corpusRestrictiveness(string(got))
				if rank < want && got == ActionWarn && boundByDischarge[id] && carriesStored(ps, stored[id]) {
					t.Logf("%s stores %q and %s carries %q on the scopes that cannot discharge a redaction (%s); its %q variant ships beside it, and whether that variant binds anywhere is the dormant ledger's to judge",
						id, stored[id], p.ID, got, DivergenceRedactionBoundByDischarge, stored[id])
					checked++
					continue
				}
				if rank < want && (poolNotStored[id] || LegacyAction(stored[id]) == ActionRequireApproval) {
					t.Logf("%s stores %q and is carried as %q: a stored hold ADR-065 cannot carry without a stored pool (approval_pool_not_stored), which no plane resolves since #4253 retired the tier pass; holds return with #4254, not a supersession effect", id, stored[id], got)
					checked++
					continue
				}
				if rank < want {
					t.Errorf("%s stores %q and the corpus carries it as %q; the ledger keeps this generation because of what it enforces, and the migration weakened it",
						id, stored[id], got)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no kept generation was checked; the ledger keeps rows and this compared none of them")
	}
	t.Logf("kept generations checked against their stored action: %d", checked)
}

// syntheticCorpus is a small, VALID BuildCorpus input: one algorithmic
// detector that gates on decide, half-gates on gateway_request and runs bare on
// openai_compatible (synthetic: no shipped plane is bare since #3963), and one
// pre-canonical pattern row it supersedes, which enforces
// more (block over redact) and is decided keep_both. Census and ledger are
// kept as TEXT so a test can plant a defect with a string edit and have the
// real parsers read it.
type syntheticCorpus struct {
	census, ledger string
	rows           []RawRow
}

func newSyntheticCorpus(t *testing.T) syntheticCorpus {
	t.Helper()
	header := strings.Join([]string{
		"policy_id", "name", "category", "tier", "enabled", "class", "impl_site", "legacy_action", "severity",
		"adr065_emit", "obligations", "posture_lever", "disposition", "disposition_reasons", "planes",
		"validator_planes", "seed_migration", "exceptions",
	}, "\t")
	return syntheticCorpus{
		census: header + "\n" +
			strings.Join([]string{"synthetic_card", "Synthetic card", "pii-global", "system", "true", "algorithmic",
				"platform/shared/policy/validators.go::ValidateCreditCard", "redact", "high", "Signal", "field_redact", "-",
				"compiled", "-", "decide,gateway_request,openai_compatible", "decide,gateway_request(mixed)", "031_x.sql", "-"}, "\t") + "\n" +
			strings.Join([]string{"old_card", "Old card", "pii_detection", "tenant", "true", "pattern",
				"re2:sha256:0123456789ab", "block", "high", "Deny", "-", "-",
				"compiled", "-", "decide,openai_compatible", "decide,openai_compatible", "010_x.sql", "-"}, "\t") + "\n",
		ledger: "policy_id\tseeded_by\tsuperseded_by\tstill_live\ttracking\tdecision\tnote\n" +
			"old_card\t010_x.sql\tsynthetic_card\tyes\t-\tkeep_both\tstronger than its superseder\n",
		rows: []RawRow{
			staticRow(t, "synthetic_card", map[string]any{"category": "pii-global", "action": "redact", "action_request": "redact"}),
			staticRow(t, "old_card", map[string]any{"category": "pii_detection", "tier": "tenant"}),
		},
	}
}

// build parses the census and ledger text and runs the real compiler and the
// real BuildCorpus over the rows.
func (s syntheticCorpus) build(t *testing.T) (*Corpus, error) {
	t.Helper()
	census, err := registry.ParseDetectorCensus(s.census)
	if err != nil {
		t.Fatalf("the synthetic census does not parse: %v", err)
	}
	ledger, err := registry.ParseSupersessionLedger(s.ledger)
	if err != nil {
		t.Fatalf("the synthetic ledger does not parse: %v", err)
	}
	rep, err := Compile(s.rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return BuildCorpus(*rep, CorpusOptions{ContentTarget: DefaultContentTarget, Rows: s.rows, Census: census, Ledger: ledger})
}

// TestBuildCorpusRefusesWhatItsGuardsRefuse proves BuildCorpus INVOKES its three
// guards, not merely that the guards work.
//
// Each guard is covered by its own tests, but the only caller that would drive
// a refusal through BuildCorpus is the capture test, which needs a migrated
// database. So deleting any of the three calls left every test that runs on a
// pull request green (R3 round 2, F1): the wiring that makes a bad regeneration
// impossible was protected only by the post-merge lane. One synthetic build per
// refusal, each shown to succeed unmutated by
// TestAPlaneDependentDetectorIsDeclaredPerPlaneInTheCorpus.
func TestBuildCorpusRefusesWhatItsGuardsRefuse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(*syntheticCorpus)
		want  string
	}{
		{
			name: "the ledger names a row the census does not hold",
			plant: func(s *syntheticCorpus) {
				s.ledger += "ghost_row\t010_x.sql\t-\tyes\t-\tkeep_first_class\tnot censused\n"
			},
			want: "ghost_row is ledgered and is not a census row",
		},
		{
			name: "the ledger decides to drop the row that enforces more",
			plant: func(s *syntheticCorpus) {
				s.ledger = strings.Replace(s.ledger, "\tkeep_both\t", "\tdrop_superseded\t", 1)
			},
			want: `old_card is decided drop_superseded and its action "block" outranks synthetic_card (redact)`,
		},
		{
			name: "an enabled census row has no captured row, so the corpus carries no policy for it",
			plant: func(s *syntheticCorpus) {
				s.census += strings.Join([]string{"absent_row", "Absent row", "security-sqli", "system", "true", "pattern",
					"re2:sha256:ba9876543210", "warn", "high", "Signal", "-", "-",
					"compiled", "-", "decide,openai_compatible", "decide,openai_compatible", "031_x.sql", "-"}, "\t") + "\n"
			},
			want: "absent_row is enabled in the census (tier system) and the system document carries no policy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSyntheticCorpus(t)
			tc.plant(&s)
			_, err := s.build(t)
			mustErrContaining(t, err, tc.want)
		})
	}
}

// TestAPlaneDependentDetectorIsDeclaredPerPlaneInTheCorpus drives BuildCorpus
// with a census in which one algorithmic detector gates on decide, half-gates
// on gateway_request and runs bare on openai_compatible.
//
// The shipped census has no such row since #3963, so the bare-plane divergence
// has nothing to fire on in the artifact, and a builder that stopped declaring
// it would leave TestTheArtifactsBarePlaneDivergencesMatchTheRegistry green on
// both sides of its comparison. This is the side of that relationship that can
// still disagree. It is also the unmutated control for
// TestBuildCorpusRefusesWhatItsGuardsRefuse: the same inputs build cleanly.
func TestAPlaneDependentDetectorIsDeclaredPerPlaneInTheCorpus(t *testing.T) {
	c, err := newSyntheticCorpus(t).build(t)
	if err != nil {
		t.Fatalf("BuildCorpus: %v", err)
	}

	var detail string
	for _, d := range c.Divergences {
		if d.Kind != DivergenceDetectorRanBareOnSomePlanes {
			continue
		}
		if d.PolicyID != "synthetic_card" {
			t.Errorf("%s carries a bare-plane divergence; it is a pattern detector and gates wherever it runs", d.PolicyID)
			continue
		}
		detail = d.Detail
	}
	if detail == "" {
		t.Fatal("synthetic_card runs bare on openai_compatible and half-gated on gateway_request and the corpus declares no divergence for it: " +
			"the migrated policy reads ONE detector verdict, so a plane-dependent control collapsed into one class with nothing to say so")
	}
	for _, want := range []string{`"openai_compatible"`, `"gateway_request"`, "ValidateCreditCard", "1 plane(s) ran it bare, 1 partially"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the divergence does not name %s, so a reader cannot tell which plane disagrees: %s", want, detail)
		}
	}
	if strings.Contains(detail, `"decide"`) {
		t.Errorf("the divergence names decide, where the implementation gates: %s", detail)
	}
}
