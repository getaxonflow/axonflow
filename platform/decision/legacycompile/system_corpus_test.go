// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE CORPUS CHECKS THAT NEED NO DATABASE
//
// The real-database half of this lane lives in system_corpus_capture_test.go
// and runs on the tier that has Postgres. That tier does not fire on a
// pull_request, so everything that CAN be asserted from the tree is asserted
// here instead - and the two halves ask different questions rather than the
// same one twice. The database half asks "is the checked-in artifact what a
// fresh build against a migrated database produces". This half asks "is the
// checked-in artifact internally coherent, and does it cover what the census
// says exists".

func shippedCorpusFromDisk(t *testing.T) *Corpus {
	t.Helper()
	path := filepath.Join("..", "pdp", ShippedCorpusFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var c Corpus
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return &c
}

// TestTheShippedCorpusArtifactIsCoherent holds the checked-in artifact to
// itself.
func TestTheShippedCorpusArtifactIsCoherent(t *testing.T) {
	c := shippedCorpusFromDisk(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("the shipped corpus does not validate: %v", err)
	}
	if c.System.Root != pdp.RootSystem || c.OrganizationTemplate.Root != pdp.RootOrganization {
		t.Fatalf("the artifact's documents declare roots %q and %q", c.System.Root, c.OrganizationTemplate.Root)
	}
	// Anti-vacuity, in the direction that matters: an emptied system document
	// would pass every per-policy loop below having checked nothing, and it is
	// exactly what a broken regeneration produces.
	if len(c.System.Policies) == 0 {
		t.Fatal("the shipped corpus's system document carries no policy")
	}
	if len(c.Divergences) == 0 {
		t.Fatal("the shipped corpus declares no divergence; the legacy engines resolve different actions on different planes " +
			"for forty of its rows, so an empty enumeration means the enumeration stopped being produced rather than that the " +
			"migration became exact")
	}

	seen := map[string]bool{}
	for _, doc := range []*pdp.Document{c.System, c.OrganizationTemplate} {
		declared := doc.AttributeIndex()
		for _, p := range doc.Policies {
			if seen[p.ID] {
				t.Errorf("policy %q appears twice in the artifact; two policies with one identifier make the bundle's manifest ambiguous", p.ID)
			}
			seen[p.ID] = true
			if p.Root != doc.Root {
				t.Errorf("policy %q declares root %q inside the %q document", p.ID, p.Root, doc.Root)
			}
			if !strings.HasPrefix(p.ID, "corpus:") {
				t.Errorf("policy %q does not carry the corpus identifier prefix; a plane-embedding legacy identifier here would "+
					"mean the shadow compilation leaked into the migration", p.ID)
			}
			for _, path := range conditionPaths(p.Where) {
				if _, ok := declared[path]; !ok {
					t.Errorf("policy %q reads attribute %q, which the %q document does not declare; an undeclared attribute is "+
						"refused at admission, so this policy could never be evaluated", p.ID, path, doc.Root)
				}
			}
			for _, o := range p.Obligations {
				if o.SourcePolicy != p.ID {
					t.Errorf("policy %q carries an obligation whose source policy is %q; a dangling source is how an obligation "+
						"stops being traceable to the rule that required it", p.ID, o.SourcePolicy)
				}
			}
		}
	}
}

// conditionPaths returns every attribute path a condition reads.
func conditionPaths(c pdp.Condition) []string {
	var out []string
	if c.Path != "" {
		out = append(out, c.Path)
	}
	for _, sub := range c.Operands {
		out = append(out, conditionPaths(sub)...)
	}
	return out
}

// TestTheShippedCorpusCoversTheCensusInBothDirections is the no-database
// coverage ratchet.
//
// It is deliberately BOTH directions. A corpus missing a censused system row
// is a shipped control that stopped existing; a corpus carrying a system
// policy from a static row the census does not class as system-tier is a
// control that moved into the platform's own document without anybody deciding
// it should.
func TestTheShippedCorpusCoversTheCensusInBothDirections(t *testing.T) {
	c := shippedCorpusFromDisk(t)
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}

	want := map[string]bool{}
	for _, r := range census {
		if r.SystemTier() {
			want[CorpusPolicyIDFor("static_policies", r.PolicyID)] = true
		}
	}
	if len(want) == 0 {
		t.Fatal("the census names no system-tier row; this comparison would be vacuous")
	}
	got := map[string]bool{}
	for _, p := range c.System.Policies {
		if strings.HasPrefix(p.ID, "corpus:static_policies:") {
			control, _, _ := CorpusControlOf(p.ID)
			got[control] = true
		}
	}
	var missing, extra []string
	for id := range want {
		if !got[id] {
			missing = append(missing, id)
		}
	}
	for id := range got {
		if !want[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%d censused system-tier row(s) have no system-root policy in the shipped corpus: %v", len(missing), missing)
	}
	if len(extra) > 0 {
		t.Errorf("%d system-root corpus policy(ies) come from a static row the census does not class as system tier: %v", len(extra), extra)
	}
	t.Logf("system-tier census rows %d; system-root static corpus policies %d", len(want), len(got))
}

// TestTheCorpusRankingIsTotalOverEveryDeclaredLegacyAction is the check that
// makes the migration's one deliberate divergence from the engine safe.
//
// `shadow.restrictiveness` mirrors the engine, whose ranking returns zero for
// four declared actions - putting them BELOW `log`. The corpus must not
// inherit that, and it must not silently acquire a gap either: an action the
// ranking cannot place is a row that does not migrate.
func TestTheCorpusRankingIsTotalOverEveryDeclaredLegacyAction(t *testing.T) {
	known := KnownActions()
	// KnownActions is the STATIC column's CHECK constraint set. The dynamic
	// vocabulary adds two more, and they are named explicitly because a
	// ranking that covered only the static set left four real dynamic rows
	// unmigratable - found by measurement against a real capture, not by
	// reading this list.
	all := append(append([]LegacyAction(nil), known...), ActionRoute, ActionAlert)
	for _, a := range all {
		if _, _, ok := corpusRestrictiveness(string(a)); !ok {
			t.Errorf("the corpus ranking cannot place declared legacy action %q, so any row resolving it does not migrate", a)
		}
	}
	// A comma-joined list is what the dynamic read path produces, and its rank
	// is its strongest member.
	if r, _, ok := corpusRestrictiveness("redact,log"); !ok || r == 0 {
		t.Errorf("the ranking cannot place the comma-joined action list a dynamic row resolves; got rank=%d ok=%v", r, ok)
	}
	if strong, _, _ := corpusRestrictiveness("block"); true {
		if joint, _, _ := corpusRestrictiveness("block,log"); joint != strong {
			t.Errorf("a list containing `block` ranks %d and `block` alone ranks %d; the list's rank is its strongest member", joint, strong)
		}
	}
	// An action nobody declared is REFUSED rather than ranked zero. This is
	// the arm that must never become a default.
	if _, _, ok := corpusRestrictiveness("teleport"); ok {
		t.Error("the ranking placed an undeclared action; a default here would order it below `log` and ship a weaker control than the row it came from")
	}
	// The engine's own relative order is preserved for the five it ranks.
	engineOrder := []LegacyAction{ActionLog, ActionWarn, ActionRedact, ActionRequireApproval, ActionBlock}
	for i := 1; i < len(engineOrder); i++ {
		lo, _, _ := corpusRestrictiveness(string(engineOrder[i-1]))
		hi, _, _ := corpusRestrictiveness(string(engineOrder[i]))
		if hi <= lo {
			t.Errorf("the corpus ranking reorders the engine's own ranking: %q(%d) is not above %q(%d)",
				engineOrder[i], hi, engineOrder[i-1], lo)
		}
	}
	// The four the engine does NOT rank are flagged as declared rather than
	// derived, so a collapse decided by one of them says so.
	for _, a := range []LegacyAction{ActionDeny, ActionLogOnly, ActionRoute, ActionAlert} {
		if _, engineRanked, _ := corpusRestrictiveness(string(a)); engineRanked {
			t.Errorf("%q is reported as ranked by the engine; agent.ActionRestrictiveness returns zero for it, and a collapse "+
				"decided by it is a judgement that must be named as one", a)
		}
	}
}

// TestTheArtifactShapeMatchesWhatPDPParses holds the two independent
// declarations of the artifact's shape equal.
//
// `pdp` parses the artifact with its own private struct rather than importing
// this package, because the decision core must not depend on the migration
// tool that produced the file. Two declarations of one shape is the hazard
// that treatment always carries, so it is closed the way
// `legacy_plane_peps.tsv` closes it: by a test that compares them.
func TestTheArtifactShapeMatchesWhatPDPParses(t *testing.T) {
	mine := shippedCorpusFromDisk(t)

	sys, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatalf("pdp.SystemCorpusDocument: %v", err)
	}
	org, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("pdp.SystemCorpusOrganizationTemplate: %v", err)
	}
	if len(sys.Policies) != len(mine.System.Policies) {
		t.Errorf("pdp parses %d system policy(ies) and this package parses %d from the same bytes",
			len(sys.Policies), len(mine.System.Policies))
	}
	if len(org.Policies) != len(mine.OrganizationTemplate.Policies) {
		t.Errorf("pdp parses %d organization policy(ies) and this package parses %d from the same bytes",
			len(org.Policies), len(mine.OrganizationTemplate.Policies))
	}
	for i := range sys.Policies {
		if i >= len(mine.System.Policies) {
			break
		}
		if sys.Policies[i].ID != mine.System.Policies[i].ID {
			t.Errorf("system policy %d is %q to pdp and %q here", i, sys.Policies[i].ID, mine.System.Policies[i].ID)
		}
	}
}

// TestTheArtifactsBarePlaneDivergencesMatchTheRegistry holds the artifact's
// account of ungated planes to the registry's, in BOTH directions.
//
// It used to assert that all twenty algorithmic rows carry a bare-plane
// divergence, because until #3963 all twenty ran ungated on `proxy_tier`. That
// wiring landed, `BarePlanes()` is empty for every shipped detector, and the
// artifact correctly carries no such divergence.
//
// SO THE ASSERTION IS NOW A RELATIONSHIP RATHER THAN A COUNT, and that is the
// point: "zero divergences" on its own is satisfied by a builder that stopped
// producing them. Holding the artifact's set EQUAL to the registry's derived
// set means the day any plane stops consulting the validator, the registry says
// so and the artifact must say so too - and a builder that went silent fails
// the same check from the other side.
func TestTheArtifactsBarePlaneDivergencesMatchTheRegistry(t *testing.T) {
	c := shippedCorpusFromDisk(t)
	records, err := registry.ShippedDetectors()
	if err != nil {
		t.Fatalf("ShippedDetectors: %v", err)
	}

	want := map[string]string{}
	algorithmic := 0
	for _, d := range records {
		if d.Class != registry.DetectorClassAlgorithmic {
			continue
		}
		algorithmic++
		if len(d.BarePlanes()) > 0 || len(d.MixedPlanes) > 0 {
			want[string(d.ID)] = d.Impl
		}
	}
	// Anti-vacuity on the DENOMINATOR, not on the answer. The expected set is
	// legitimately empty today; a corpus with no algorithmic rows at all is
	// not, and would make this comparison meaningless in the same way.
	if algorithmic == 0 {
		t.Fatal("no algorithmic detector in the shipped corpus; this comparison would be vacuous")
	}

	got := map[string]string{}
	for _, d := range c.Divergences {
		if d.Kind == DivergenceDetectorRanBareOnSomePlanes {
			got[d.PolicyID] = d.Detail
		}
	}
	for id, impl := range want {
		detail, ok := got[id]
		if !ok {
			t.Errorf("%s does not gate on every plane it runs on and the shipped corpus declares no divergence for it", id)
			continue
		}
		if !strings.Contains(detail, impl) {
			t.Errorf("%s's divergence does not name its implementation %q; a reader cannot tell which algorithm did not run", id, impl)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("the shipped corpus declares a bare-plane divergence for %q, and the registry says its implementation "+
				"gates on every plane it runs on. Since #3963 that set is expected to be EMPTY, so this is either a stale "+
				"artifact or a census that has gone stale against the wiring", id)
		}
	}
	t.Logf("%d algorithmic detector(s); %d with an ungated plane, %d bare-plane divergence(s) in the artifact",
		algorithmic, len(want), len(got))
}

// TestTheRootChangeIsAccountedForRowByRow holds the authority-root move to the
// rows it actually happened to, rather than to a number somebody wrote down.
//
// THE COUNT IN THE PR BODY AND THE CHANGELOG WAS WRONG BY TEN BEFORE THIS
// EXISTED, and it was wrong in the direction that reads as a bigger change than
// it is: an earlier build emitted TWO root divergences for every dynamic row -
// one for the compiled root disagreeing, one for "no tier recorded" - and the
// prose was written from that run. A count nothing reproduces is worse than a
// stale one, so this asserts a RELATIONSHIP instead: every row whose authority
// root moved is a row in the organization template, and every row in the
// organization template is a row whose authority root moved. The number falls
// out of the corpus rather than being maintained beside it.
func TestTheRootChangeIsAccountedForRowByRow(t *testing.T) {
	c := shippedCorpusFromDisk(t)

	// DIRECTION-AWARE. The kind fires whenever the compiled root and the tier
	// root differ, in EITHER direction, and every row happens to move org-ward
	// today. Keying on the kind alone therefore asserted a coincidence: a
	// correct system-ward move would have failed this test with a message
	// blaming "a move that did not happen". The divergence now carries
	// FromRoot/ToRoot and this reads them.
	moved := map[string]bool{}
	systemWard := map[string]bool{}
	for _, d := range c.Divergences {
		if d.Kind != DivergenceRootDisagreesWithTier {
			continue
		}
		if d.ToRoot == "" || d.FromRoot == "" {
			t.Errorf("%s declares a root change with no direction (from=%q to=%q); the kind alone cannot say which document "+
				"the row ended up in", d.PolicyID, d.FromRoot, d.ToRoot)
			continue
		}
		key := CorpusPolicyIDFor(d.Table, d.PolicyID)
		if d.ToRoot == string(pdp.RootOrganization) {
			moved[key] = true
			continue
		}
		systemWard[key] = true
	}
	inTemplate := map[string]bool{}
	for _, p := range c.OrganizationTemplate.Policies {
		control, _, _ := CorpusControlOf(p.ID)
		inTemplate[control] = true
	}
	if len(moved) == 0 || len(inTemplate) == 0 {
		t.Fatalf("moved=%d template=%d; a comparison with an empty side is not evidence", len(moved), len(inTemplate))
	}

	var onlyMoved, onlyTemplate []string
	for id := range moved {
		if !inTemplate[id] {
			onlyMoved = append(onlyMoved, id)
		}
	}
	for id := range inTemplate {
		if !moved[id] {
			onlyTemplate = append(onlyTemplate, id)
		}
	}
	sort.Strings(onlyMoved)
	sort.Strings(onlyTemplate)
	if len(onlyMoved) > 0 {
		t.Errorf("%d row(s) declare an authority-root change and are not in the organization template: %v\n"+
			"Either the row went somewhere neither document holds, or the divergence describes a move that did not happen.",
			len(onlyMoved), onlyMoved)
	}
	if len(onlyTemplate) > 0 {
		t.Errorf("%d row(s) are in the organization template with no declared root change: %v\n"+
			"A control that left the platform's own document without saying so is exactly the divergence a reader must not "+
			"discover for themselves.", len(onlyTemplate), onlyTemplate)
	}
	// The other direction, asserted rather than assumed absent: a row whose
	// tier makes it the platform's own while the shadow compilation put it on
	// the organization root belongs in the SYSTEM document.
	inSystem := map[string]bool{}
	for _, p := range c.System.Policies {
		control, _, _ := CorpusControlOf(p.ID)
		inSystem[control] = true
	}
	for id := range systemWard {
		if !inSystem[id] {
			t.Errorf("%s declares a move TO the system root and is not in the system document", id)
		}
	}
	t.Logf("%d row(s) moved to the organization template and %d to the system document, each declared with its direction",
		len(moved), len(systemWard))
}

// TestSanitizeRoundTripsAndMatchesTheRegistrysEncoding holds the two halves of
// the identifier bijection together.
//
// The FORWARD direction now has one implementation - `sanitizePathSegment`
// delegates to `registry.EncodePathSegment` - but the INVERSE,
// `UnsanitizePolicyID`, lives here, so the pair can still drift the day the
// encoding changes and the decoder does not. R3 found the forward direction
// duplicated with a doc comment claiming it was not; this is what stops the
// same claim being made about the pair.
func TestSanitizeRoundTripsAndMatchesTheRegistrysEncoding(t *testing.T) {
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	ids := make([]string, 0, len(census)+8)
	for _, r := range census {
		ids = append(ids, r.PolicyID)
	}
	// Identifiers the encoding exists FOR, which no shipped row happens to
	// contain: `policy_id` is VARCHAR(100) with no character constraint.
	ids = append(ids, "a.b", "a_b", "a__b", "üñî", "x:y", "_", "a-b", "A1")
	if len(ids) < 50 {
		t.Fatalf("only %d identifier(s) to check; the census cannot have shrunk this far", len(ids))
	}
	// THE GOLDEN TABLE IS THE WHOLE PIN, AND IT REPLACES A TAUTOLOGY.
	//
	// The earlier version asserted `SanitizePolicyID(id) == registry.EncodePathSegment(id)`.
	// Round 1's own fix made that `f(x) == f(x)`: `SanitizePolicyID` delegates
	// to `EncodePathSegment`. R3 drove it - upper-casing the hex escape inside
	// the encoder left the whole of `registry` and `legacycompile` green,
	// because no shipped `policy_id` contains a character that hex-escapes, so
	// the artifact does not pin the escape branch either.
	//
	// So the expectations are WRITTEN OUT. A change to the encoding has to
	// change these literals, and changing them is the moment somebody asks
	// what reads the old form - which is every compiled policy identifier and
	// every detector signal path already in a bundle.
	for _, tc := range []struct{ in, want string }{
		{"sys_pii_ssn", "sys__pii__ssn"},
		{"a.b", "a_2e_b"},
		{"a_b", "a__b"},
		{"a__b", "a____b"},
		{"x:y", "x_3a_y"},
		{"_", "__"},
		{"a-b", "a-b"},
		{"A1", "A1"},
		{"üñî", "_fc__f1__ee_"},
	} {
		if got := registry.EncodePathSegment(tc.in); got != tc.want {
			t.Errorf("EncodePathSegment(%q) = %q, want %q. This encoding is embedded in every compiled policy identifier and "+
				"every detector signal path; changing it renames attributes that published bundles already read", tc.in, got, tc.want)
		}
	}

	for _, id := range ids {
		enc := SanitizePolicyID(id)
		if got := registry.EncodePathSegment(id); got != enc {
			t.Errorf("%q: this package encodes %q and the registry encodes %q", id, enc, got)
		}
		back, ok := UnsanitizePolicyID(enc)
		if !ok || back != id {
			t.Errorf("%q encodes to %q and decodes back to %q (ok=%v); the bijection is broken and a compiled policy can no "+
				"longer be read back to the row it came from", id, enc, back, ok)
		}
		if want := registry.DetectorID(id).SignalPath(); DetectorSignalPath(id) != want {
			t.Errorf("%q: DetectorSignalPath is %q and the registry's is %q", id, DetectorSignalPath(id), want)
		}
	}
	t.Logf("checked the encoding, its inverse and the signal path over %d identifier(s)", len(ids))
}

// TestTheSystemDocumentCarriesMorePoliciesThanRows pins the fact the ADR-065
// amendment states, because "one policy per row" is the obvious reading and it
// is wrong.
//
// A dynamic row applies ALL of its actions together, so `dynamic.go` emits one
// policy per obligation and the corpus re-keys each with a "#n" suffix. The
// amendment says "one PLANE'S compilation per row", which is the true claim;
// this is what stops the looser one being written back in.
func TestTheSystemDocumentCarriesMorePoliciesThanRows(t *testing.T) {
	c := shippedCorpusFromDisk(t)
	rows := map[string]bool{}
	suffixed := 0
	for _, p := range c.System.Policies {
		base := strings.SplitN(p.ID, "#", 2)[0]
		if base != p.ID {
			suffixed++
		}
		rows[base] = true
	}
	if len(c.System.Policies) <= len(rows) {
		t.Errorf("the system document holds %d policy(ies) from %d row(s); if those are equal, either no row splits by "+
			"obligation any more or the suffixing has stopped, and the ADR-065 amendment's wording is now the wrong one",
			len(c.System.Policies), len(rows))
	}
	if suffixed == 0 {
		t.Error("no system policy carries a per-obligation suffix; the multi-obligation dynamic rows are the reason the " +
			"amendment says PLANE'S COMPILATION rather than POLICY, and with none of them present that distinction is unpinned")
	}
	// Every suffix must be a real sibling: a "#1" with no "#2" is a re-key that
	// lost a policy rather than a row that split.
	byBase := map[string]int{}
	for _, p := range c.System.Policies {
		byBase[strings.SplitN(p.ID, "#", 2)[0]]++
	}
	for _, p := range c.System.Policies {
		base := strings.SplitN(p.ID, "#", 2)[0]
		if base != p.ID && byBase[base] < 2 {
			t.Errorf("%s carries a per-obligation suffix and has no sibling; a suffixed policy standing alone is a re-key "+
				"that dropped one", p.ID)
		}
	}
	// THAT CHECK IS COMPLETE ONLY FOR A TWO-WAY SPLIT, so its bound is enforced
	// rather than assumed. Losing one policy of a two-way split leaves a lone
	// suffix, and losing both leaves the row unrepresented, which
	// TestEveryShippedSystemControlExistsInBothModels refuses. Losing the last of
	// a three-way split leaves two siblings that look whole, and nothing on this
	// board could see it.
	for base, n := range byBase {
		if n > 2 {
			t.Errorf("%s splits into %d policies; the sibling check above cannot see the removal of the last of three or more, "+
				"so hold each split row to its obligation count before shipping a split wider than two", base, n)
		}
	}
	t.Logf("system document: %d policies from %d rows, %d carrying a per-obligation suffix", len(c.System.Policies), len(rows), suffixed)
}
