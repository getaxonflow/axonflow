// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// censusPath is the rendered census, relative to the repository root.
//
// It lives under technical-docs/ rather than beside the registry, and the
// reason is the bands. The registry itself must reach the community mirror —
// the community build projects its own /health from it — but the derived
// Community and Evaluation percentages are commercial positioning, and
// technical-docs/ is excluded from the sync. The census also belongs beside the
// living feature matrix it reconciles against, which is in the same directory.
const censusPath = "technical-docs/EDITION_CAPABILITY_CENSUS.md"

// TestCensusIsUpToDate regenerates the census from the registry and fails if
// the checked-in file differs.
//
// Regenerate with:
//
//	UPDATE_CENSUS=1 go test ./shared/capability/ -run TestCensusIsUpToDate
//
// The census is generated rather than written so that it cannot drift from the
// registry the way the /health list drifted from the platform — which is the
// entire subject of the document it produces.
func TestCensusIsUpToDate(t *testing.T) {
	root := repoRoot(t)
	full := filepath.Join(root, censusPath)

	if _, err := os.Stat(filepath.Join(root, "technical-docs")); err != nil {
		// The community mirror excludes technical-docs/ wholesale, so there is
		// nothing here to compare against and its absence is correct. This is
		// the ONLY condition under which this test does not assert: a tree that
		// HAS the directory and not the file fails below.
		t.Skip("community mirror: technical-docs/ is excluded from the sync")
	}

	narratives, nerr := LoadNarratives(root)
	if nerr != nil {
		t.Fatalf("loading the disagreement narratives: %v", nerr)
	}
	if problems := Load().Reconcile(narratives); len(problems) > 0 {
		t.Fatalf("the registry and %s disagree:\n  %s",
			DisagreementNarrativesPath, strings.Join(problems, "\n  "))
	}
	want := RenderCensus(Load(), narratives)

	if os.Getenv("UPDATE_CENSUS") == "1" {
		if err := os.WriteFile(full, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", censusPath, len(want))
		return
	}

	got, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("this tree has technical-docs/ but not %s: %v\n\n"+
			"Generate it with: UPDATE_CENSUS=1 go test ./shared/capability/ "+
			"-run TestCensusIsUpToDate", censusPath, err)
	}
	if string(got) != want {
		t.Fatalf("%s is stale: it disagrees with the registry it is generated from.\n"+
			"Regenerate with: UPDATE_CENSUS=1 go test ./shared/capability/ "+
			"-run TestCensusIsUpToDate\n\nfirst difference at byte %d",
			censusPath, firstDiff(string(got), want))
	}
}

func firstDiff(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// TestTheCensusReportsWhatTheRegistryHolds is the anti-vacuity control on the
// renderer. A generator that emitted a well-formed document with no rows would
// satisfy the golden test above forever, because the golden file would be
// regenerated to match it.
func TestTheCensusReportsWhatTheRegistryHolds(t *testing.T) {
	narratives, err := LoadNarratives(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	out := RenderCensus(Load(), narratives)
	for _, must := range []string{
		"# AxonFlow Edition Capability Census",
		"## The two bands",
		"### 1. The `/health` capability list is edition-blind",
		"### 2. Client-observable surfaces with no capability name",
		"### 3. Where the living feature matrix and the tree disagree",
		"## The census",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("the rendered census has no %q section", must)
		}
	}
	// Every capability must appear as a row, or the census is not a census.
	for _, e := range Load().Entries {
		if !strings.Contains(out, "| `"+e.ID+"` |") {
			t.Errorf("the census has no row for %s", e.ID)
		}
	}
	// And every finding the registry holds must be rendered, or a reader would
	// conclude from the document that there are none.
	for _, e := range Load().MatrixDisagreements() {
		if !strings.Contains(out, "**`"+e.ID+"`** —") {
			t.Errorf("the census does not render %s's matrix disagreement", e.ID)
		}
	}
	if len(Load().HealthGaps()) == 0 {
		t.Error("no capability is marked health_gap, so section 2 renders an empty table " +
			"and reads as 'there are no gaps'")
	}
	if len(Load().AdvertisedButAbsentInCommunity()) == 0 {
		t.Error("no capability is advertised-but-absent-in-Community, so section 1 reads " +
			"as 'the served list is edition-correct'")
	}
}

// TestBandsExcludeUnscorableCapabilities pins the one arithmetic choice that
// could quietly move the published numbers.
//
// An unscorable capability counted as zero would deflate the Community band; as
// full, inflate it. It is excluded, and this proves the exclusion by comparing
// against a hand-computed expectation on a small synthetic registry rather than
// by re-implementing the same sum.
func TestBandsExcludeUnscorableCapabilities(t *testing.T) {
	r := &Registry{Entries: []Entry{
		{ID: "f.a", Family: "f", Score: Score{Basis: BasisMeasured,
			Community: AvailFull, Evaluation: AvailFull, Enterprise: AvailFull}},
		{ID: "f.b", Family: "f", Score: Score{Basis: BasisMeasured,
			Community: AvailNone, Evaluation: AvailLimited, Enterprise: AvailFull}},
		{ID: "f.c", Family: "f", Score: Score{Basis: BasisUnscorable,
			Reason: "no live call site"}},
	}}
	b := r.Score()
	// Two scored capabilities: community (1.0 + 0.0)/2 = 50%, evaluation
	// (1.0 + 0.5)/2 = 75%. The unscorable one is in neither numerator nor
	// denominator.
	if b.Scored != 2 || b.Unscorable != 1 {
		t.Fatalf("Scored=%d Unscorable=%d, want 2 and 1", b.Scored, b.Unscorable)
	}
	if b.CommunityByCapability != 50 {
		t.Errorf("community band %.1f%%, want 50%%. Counting the unscorable row as zero "+
			"would give 33.3%%", b.CommunityByCapability)
	}
	if b.EvaluationByCapability != 75 {
		t.Errorf("evaluation band %.1f%%, want 75%%", b.EvaluationByCapability)
	}
}

// TestTheTwoWeightingsDifferOnTheRealRegistry proves the spread the census
// publishes is real. If the two weightings agreed exactly, printing both would
// imply a robustness the method does not have, and one of them would be dead
// weight a later reader would delete.
func TestTheTwoWeightingsDifferOnTheRealRegistry(t *testing.T) {
	b := Load().Score()
	if b.Scored == 0 {
		t.Fatal("nothing is scored, so both bands are zero and agree vacuously")
	}
	if b.CommunityByCapability == b.CommunityByFamily {
		t.Log("the two weightings agree exactly on the Community band; that is possible " +
			"but worth a look, because it usually means one of them is not being computed")
	}
	for name, v := range map[string]float64{
		"community by capability":  b.CommunityByCapability,
		"community by family":      b.CommunityByFamily,
		"evaluation by capability": b.EvaluationByCapability,
		"evaluation by family":     b.EvaluationByFamily,
	} {
		if v <= 0 || v >= 100 {
			t.Errorf("%s is %.1f%%, which is not a plausible band", name, v)
		}
	}
	// Entitlement is monotonic, so the Evaluation band cannot be below the
	// Community one. This is the sanity check that catches a sign or a
	// column-order error in the aggregation.
	if b.EvaluationByCapability < b.CommunityByCapability {
		t.Errorf("the Evaluation band (%.1f%%) is below the Community band (%.1f%%)",
			b.EvaluationByCapability, b.CommunityByCapability)
	}
}

// TestTheDisagreementNarrativesReconcileWithTheRegistry holds the split master
// ruled on: the CLASS ships in registry.json, the narrative stays in
// technical-docs/, and the two must agree.
//
// Both directions, because either alone is not a check. Forward-only accepts a
// classified row nothing explains; backward-only accepts a narrative for a row
// that no longer disagrees — which is the shape a stale finding takes, and the
// one a reader trusts precisely because somebody wrote it down.
func TestTheDisagreementNarrativesReconcileWithTheRegistry(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "technical-docs")); err != nil {
		t.Skip("community mirror: technical-docs/ is excluded from the sync, which is the " +
			"property this split relies on rather than one this test can check here")
	}
	n, err := LoadNarratives(root)
	if err != nil {
		t.Fatalf("loading %s: %v", DisagreementNarrativesPath, err)
	}
	if len(n) == 0 {
		t.Fatalf("%s parsed to zero narratives in a tree that has technical-docs/; "+
			"the reconciliation below would be vacuous", DisagreementNarrativesPath)
	}
	if problems := Load().Reconcile(n); len(problems) > 0 {
		t.Fatalf("the registry and %s disagree:\n  %s",
			DisagreementNarrativesPath, strings.Join(problems, "\n  "))
	}
	t.Logf("reconciled %d classified disagreement(s) against their narratives", len(n))
}

// TestReconcileCatchesBothDirections proves the reconciliation discriminates.
// A function that returned no problems for every input would make the test
// above pass forever.
func TestReconcileCatchesBothDirections(t *testing.T) {
	r := &Registry{Entries: []Entry{
		{ID: "f.a", Family: "f", MatrixDisagreement: DisagreeMatrixStricter},
		{ID: "f.b", Family: "f"},
	}}
	full := Narratives{"f.a": {ID: "f.a", Class: DisagreeMatrixStricter, Detail: "x"}}
	if got := r.Reconcile(full); len(got) != 0 {
		t.Fatalf("a matching pair reported problems: %v", got)
	}
	for name, n := range map[string]Narratives{
		"a classified row with no narrative": {},
		"a narrative for a row that does not disagree": {
			"f.a": {ID: "f.a", Class: DisagreeMatrixStricter, Detail: "x"},
			"f.b": {ID: "f.b", Class: DisagreeStaleCitation, Detail: "stale"},
		},
		"a narrative whose class differs from the registry": {
			"f.a": {ID: "f.a", Class: DisagreeStaleCitation, Detail: "x"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := r.Reconcile(n); len(got) == 0 {
				t.Fatalf("Reconcile accepted %s", name)
			}
		})
	}
}

// TestTheMirroredRegistryCarriesNoNarrative is the control on the split
// itself, and it is the one that actually enforces the ruling.
//
// Moving prose out of registry.json is only worth doing if it STAYS out, and
// nothing about the schema stops the next author pasting a sentence back into
// a `notes` field. R3 proved a hand-written phrase list cannot hold that: the
// first version listed four phrases drawn from the four rows that happened to
// be redacted, and `decision.shadow`'s note — "A Community deployment therefore
// gets the shadow observer in full", 75% word overlap with its off-mirror
// narrative and the highest of the eighteen — matched none of them. A guard
// keyed on remembered instances is exactly as wide as the memory.
//
// So the check is DERIVED from the TSV instead. For every capability whose
// disagreement has a narrative, the mirrored `notes` must not restate it: the
// fraction of the narrative's distinctive words that also appear in `notes`
// must stay below a threshold. The subject IS text, so the check is textual;
// what changed is that its subject set is now the whole population rather than
// the part somebody listed.
func TestTheMirroredRegistryCarriesNoNarrative(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "technical-docs")); err != nil {
		t.Skip("community mirror: the narratives are excluded here, which is the property " +
			"being relied on rather than one this test can check from inside it")
	}
	narratives, err := LoadNarratives(root)
	if err != nil {
		t.Fatalf("loading %s: %v", DisagreementNarrativesPath, err)
	}
	if len(narratives) == 0 {
		t.Fatalf("%s parsed to zero narratives; every comparison below would be vacuous",
			DisagreementNarrativesPath)
	}

	var checked int
	var worst float64
	var worstID string
	for _, e := range Load().Entries {
		n, ok := narratives[e.ID]
		if !ok {
			continue
		}
		checked++
		// PER-ROW anti-vacuity, and it is a different check from the global
		// one below. overlap() divides by the narrative's distinctive-word
		// count, so a narrative of a few stock words has almost nothing to
		// divide by and scores every notes field at or near zero — the guard
		// would be inert FOR THAT ROW while the aggregate still looked
		// healthy. A thin narrative is also a bad narrative in its own right,
		// so failing here is not only about the measure.
		if thin, count := narrativeIsTooThin(n.Detail); thin {
			t.Errorf("%s: its narrative has only %d distinctive words, below the floor of "+
				"%d — too few for the overlap measure to say anything about, so the guard "+
				"would be inert for this row. Write the finding out",
				e.ID, count, narrativeWordFloor)
		}
		got := overlap(n.Detail, mirroredText(e))
		if got > worst {
			worst, worstID = got, e.ID
		}
		// AND a sentence-level check, because a percentage is an average and an
		// average hides a sentence. A narrative split across two fields scores
		// low on each and low on the whole, while one of its sentences sits on
		// the mirror verbatim. R3 measured exactly that: the same sentence in
		// `summary` instead of `notes` passed, and decision.proof's narrative
		// split across the two passed at 47%.
		if sentence := restatedSentence(n.Detail, mirroredText(e)); sentence != "" {
			t.Errorf("%s: a sentence of its off-mirror narrative is restated in the mirrored "+
				"free text, whatever the overall percentage says:\n  %q", e.ID, sentence)
		}
		if got > mirrorOverlapThreshold {
			t.Errorf("%s: its mirrored free text restates %.0f%% of its off-mirror narrative "+
				"(threshold %.0f%%). The narrative belongs in %s, which the community sync "+
				"excludes; registry.json does not.\n  mirrored:  %q\n  narrative: %q",
				e.ID, got*100, mirrorOverlapThreshold*100, DisagreementNarrativesPath,
				mirroredText(e), n.Detail)
		}
	}
	if checked != len(narratives) {
		t.Errorf("%d narratives but only %d matched a registry entry", len(narratives), checked)
	}
	// Anti-vacuity: overlap() must return a non-zero number somewhere on this
	// data, or every comparison above passed because the measure always
	// answers zero.
	if worst == 0 {
		t.Fatalf("every notes/narrative pair scored 0%% overlap, which means overlap() is " +
			"not measuring anything")
	}
	t.Logf("checked %d pairs; highest overlap %.0f%% (%s), threshold %.0f%%",
		checked, worst*100, worstID, mirrorOverlapThreshold*100)
}

// TestOverlapDiscriminates is the survivor control on the measure itself. A
// function that always answered 0 would make the test above pass for ever, and
// its own anti-vacuity check is the only other thing standing in the way.
func TestOverlapDiscriminates(t *testing.T) {
	narrative := "The matrix marks budget CRUD Enterprise-only but the handler carries no " +
		"build constraint so the routes are reachable on a Community build"
	for name, tc := range map[string]struct {
		notes string
		want  bool // true = must exceed the threshold
	}{
		"a verbatim restatement": {notes: narrative, want: true},
		"most of it, reworded": {notes: "the matrix marks budget CRUD enterprise-only but " +
			"the handler carries no build constraint, so those routes are reachable on a " +
			"community build", want: true},
		"a structural pointer": {notes: "The matrix and the tree disagree about this row; " +
			"the class is on matrix_disagreement.", want: false},
		"empty": {notes: "", want: false},
	} {
		t.Run(name, func(t *testing.T) {
			got := overlap(narrative, tc.notes)
			if (got > 0.5) != tc.want {
				t.Errorf("overlap = %.2f, want >0.5 == %v (notes: %q)", got, tc.want, tc.notes)
			}
		})
	}
}

// overlap is the fraction of the narrative's distinctive words that also appear
// in the notes.
//
// Short and very common words are dropped, and so are the four words every row
// in this census uses ("matrix", "tree", "census", "row"). They appear in every
// pair and would put a floor under all of them, which is what makes a
// similarity measure useless in the only direction that matters.
func overlap(narrative, notes string) float64 {
	want := distinctiveWords(narrative)
	if len(want) == 0 {
		return 0
	}
	got := distinctiveWords(notes)
	var hit int
	for w := range want {
		if got[w] {
			hit++
		}
	}
	return float64(hit) / float64(len(want))
}

// The census's headline counts, pinned.
//
// R3 found that TestTheCensusReportsWhatTheRegistryHolds iterated
// MatrixDisagreements() with no floor, so deleting seventeen of the eighteen
// disagreements left the whole package green: the loop simply had less to do,
// and a census that had quietly stopped recording its findings rendered a
// shorter document that still "matched the registry". A generated document
// compared against itself cannot notice that its subject shrank.
//
// These are EXACT rather than floors, in both directions. A floor would let the
// gap count grow silently, which is the number that must not; an exact pin makes
// every movement a line somebody had to edit and defend in review. Update them
// in the same commit as the registry change, and say in the PR body which
// direction moved and why.
const (
	pinnedCapabilities        = 85
	pinnedFamilies            = 20
	pinnedMatrixDisagreements = 17
	pinnedHealthGaps          = 9
	pinnedEditionBlindAdverts = 5
	pinnedAgentHealthEntries  = 30
	pinnedOrchHealthEntries   = 17
	// Round 8 moved this from 1 to 8, in the direction that costs coverage
	// rather than invents it. Inverting the receiver default means a package
	// -level router assigned inside a function body is no longer assumed to be
	// the root, and `globalRouter` in platform/agent/run.go is exactly that
	// shape: seven registrations on it are now REPORTED rather than claimed.
	// Each has an exemption naming the literal path it registers, so the URL
	// space is still accounted for — by inspection, which is what an exemption
	// is, instead of by a derivation that could not prove what it was asserting.
	pinnedRouteExemptions    = 8
	pinnedOutOfScopeSections = 12
)

// TestTheSensitivityParagraphIsDerivedNotWritten pins the one count in the
// census that was still prose.
//
// The paragraph used to say "four capabilities ... budget CRUD, usage
// analytics, checkpoint resume, webhooks" as literal text, in a document whose
// entire claim is that its numbers are measured. It was right, and it was
// right the way a comment is right: until a row is added or reclassified, at
// which point it becomes a confident wrong number in the sensitivity argument
// the headline bands rest on. Round 10 found six copies of exactly that shape
// in other documents; this was the seventh, and the only one inside the
// generator itself.
//
// The test is a mutation of the DATA rather than of the code: reclassify one
// more row and the rendered prose must follow.
func TestTheSensitivityParagraphIsDerivedNotWritten(t *testing.T) {
	r := Load()
	base := RenderCensus(r, Narratives{})
	rows := r.rowsRescoredFromTree()
	if len(rows) != 4 {
		t.Fatalf("control: %d rows carry DisagreeMatrixStricter, not 4. If that is a real "+
			"change, this test's expectations move with it — but check the CENSUS says so "+
			"too, which is the whole point", len(rows))
	}
	if !strings.Contains(base, "score four capabilities FROM THE MATRIX") {
		t.Errorf("the rendered census does not spell the count; got a paragraph that reads:\n%s",
			sensitivityParagraph(base))
	}
	for _, want := range rows {
		if !strings.Contains(base, want) {
			t.Errorf("the rendered census names the rescored rows but omits %q; a reader "+
				"cannot check a sensitivity claim whose subjects are not listed", want)
		}
	}

	// Reclassify a fifth row and re-render. Both the word and the list must
	// move; if either is still literal text, one of these fails.
	mutated := *r
	mutated.Entries = append([]Entry{}, r.Entries...)
	var planted string
	for i := range mutated.Entries {
		if mutated.Entries[i].MatrixDisagreement == "" && mutated.Entries[i].Title != "" {
			mutated.Entries[i].MatrixDisagreement = DisagreeMatrixStricter
			planted = mutated.Entries[i].Title
			break
		}
	}
	if planted == "" {
		t.Fatal("control: no row was available to reclassify, so the mutation below is a no-op")
	}
	got := RenderCensus(&mutated, Narratives{})
	if !strings.Contains(got, "score five capabilities FROM THE MATRIX") {
		t.Errorf("with a fifth row reclassified the census still says four. The count is "+
			"written, not derived, and the sensitivity argument the bands rest on will go "+
			"stale silently. Paragraph:\n%s", sensitivityParagraph(got))
	}
	if !strings.Contains(got, planted) {
		t.Errorf("with %q reclassified the census does not name it; the list is written, "+
			"not derived", planted)
	}
}

// sensitivityParagraph extracts the section under test so a failure prints the
// prose rather than the whole document.
func sensitivityParagraph(doc string) string {
	i := strings.Index(doc, "### The sensitivity this table rests on")
	if i < 0 {
		return "(the sensitivity section is absent entirely)"
	}
	rest := doc[i:]
	if j := strings.Index(rest, "| Weighting"); j > 0 {
		return rest[:j]
	}
	return rest
}

func TestTheCensusHeadlineCountsArePinned(t *testing.T) {
	r := Load()
	for name, got := range map[string]struct{ have, want int }{
		"capabilities":                       {len(r.Entries), pinnedCapabilities},
		"families":                           {len(r.Families()), pinnedFamilies},
		"matrix disagreements":               {len(r.MatrixDisagreements()), pinnedMatrixDisagreements},
		"/health gaps":                       {len(r.HealthGaps()), pinnedHealthGaps},
		"advertised but absent in Community": {len(r.AdvertisedButAbsentInCommunity()), pinnedEditionBlindAdverts},
		"agent /health entries":              {len(r.Advertise(PlaneAgent)), pinnedAgentHealthEntries},
		"orchestrator /health entries":       {len(r.Advertise(PlaneOrchestrator)), pinnedOrchHealthEntries},
		"route exemptions":                   {len(r.RouteExemptions), pinnedRouteExemptions},
		"matrix sections out of scope":       {len(r.MatrixSectionsOutOfScope), pinnedOutOfScopeSections},
	} {
		if got.have != got.want {
			t.Errorf("%s: %d, pinned at %d. If the change is deliberate, update the pin in "+
				"the same commit and say in the PR body which direction it moved and why. "+
				"The two that matter most: /health gaps must only go DOWN, and matrix "+
				"disagreements going down means either a real fix or a finding that "+
				"stopped being recorded",
				name, got.have, got.want)
		}
	}
}

// TestTheGapCountOnlyEverFalls states the ratchet in its own test, so the
// intent survives a bulk edit of the pins above. Nine client-observable
// surfaces have no capability name; that is a debt this PR records and does not
// pay, and the only legal direction is down.
func TestTheGapCountOnlyEverFalls(t *testing.T) {
	if got := len(Load().HealthGaps()); got > pinnedHealthGaps {
		t.Errorf("%d capabilities are marked health_gap, up from %d. A gap is a surface a "+
			"client can observe and cannot feature-detect; the count is a ratchet and the "+
			"only legal direction is down", got, pinnedHealthGaps)
	}
}

// TestTheTargetBandsArePinnedAndAttributed.
//
// R3: the census hardcoded 35-40 / 50-55 in four places and cited ADR-066 for
// them. ADR-066 contains no percentage at all — the figures come from #3590's
// own scope, which asks this census to establish them. A number attributed to
// an accepted architectural decision carries more weight than the same number
// stated as a target in an issue, and the difference matters when the
// measurement misses it.
const (
	targetCommunityLow   = 35
	targetCommunityHigh  = 40
	targetEvaluationLow  = 50
	targetEvaluationHigh = 55
)

func TestTheTargetBandsArePinnedAndAttributed(t *testing.T) {
	out := RenderCensus(Load(), nil)
	for _, must := range []string{
		"issues/3590",
		"**ADR-066 does not",
		"35-40%",
		"50-55%",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("the census does not state %q; the bands must carry their real source, "+
				"and the correction that ADR-066 is not it", must)
		}
	}
	// The targets are constants here so a silent edit to the render moves a
	// test, not only a document.
	for name, band := range map[string][2]float64{
		"community":  {targetCommunityLow, targetCommunityHigh},
		"evaluation": {targetEvaluationLow, targetEvaluationHigh},
	} {
		if band[0] >= band[1] {
			t.Errorf("the %s target band is inverted: %v", name, band)
		}
	}
}

// TestTheRescoredBandIsPublishedAndDiffers is the anti-vacuity control on the
// sensitivity disclosure. Publishing a second figure that always equals the
// first tells a reader the result is robust when it has not been tested.
func TestTheRescoredBandIsPublishedAndDiffers(t *testing.T) {
	as := Load().Score()
	tree := Load().ScoreRescoredFromTree()
	if tree.CommunityByFamily <= as.CommunityByFamily {
		t.Errorf("rescoring the contradicted rows from the tree gave %.2f%%, not above the "+
			"as-scored %.2f%%. Those four rows are scored from the matrix precisely "+
			"because the tree gates nothing, so the rescored figure must be higher — if "+
			"it is not, the rescoring is not being applied",
			tree.CommunityByFamily, as.CommunityByFamily)
	}
	if !strings.Contains(RenderCensus(Load(), nil), "rescored from the tree") {
		t.Error("the census does not publish the rescored figures")
	}
	// And the rows it rescores must exist, or the disclosure is about nothing.
	var stricter int
	for _, e := range Load().Entries {
		if e.MatrixDisagreement == DisagreeMatrixStricter {
			stricter++
		}
	}
	if stricter == 0 {
		t.Fatal("no capability is classified matrix_stricter_than_tree, so the rescoring " +
			"has nothing to rescore and both figures are the same number twice")
	}
	t.Logf("as scored %.2f%% / rescored %.2f%% per family, over %d contradicted rows",
		as.CommunityByFamily, tree.CommunityByFamily, stricter)
}

// distinctiveWords is the token set overlap() compares.
//
// Short and very common words are dropped, and so are the four every row in
// this census uses ("matrix", "tree", "census", "row"). They appear in every
// pair and would put a floor under all of them, which is what makes a
// similarity measure useless in the only direction that matters.
var censusStopWords = map[string]bool{
	"the": true, "and": true, "that": true, "this": true, "with": true, "from": true,
	"for": true, "not": true, "but": true, "its": true, "which": true, "than": true,
	"are": true, "was": true, "has": true, "have": true, "been": true, "does": true,
	"row": true, "matrix": true, "tree": true, "census": true,
}

func distinctiveWords(s string) map[string]bool {
	stop := censusStopWords
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if len(w) > 3 && !stop[w] {
			out[w] = true
		}
	}
	return out
}

// mirroredText is every free-text field of an entry that reaches the community
// mirror, concatenated.
//
// The first version read `notes` alone, and R3 walked round it three ways: the
// same sentence in `summary` passed, a narrative split across `summary` and
// `notes` passed at 47%, and one already sat at 48% unnoticed. A guard that
// names one field is a guard on that field, not on the mirror.
func mirroredText(e Entry) string {
	return strings.Join([]string{
		e.Title, e.Summary, e.Notes, e.HealthAbsentReason, e.Score.Reason,
	}, " ")
}

// restatedSentence returns the first sentence of the narrative that is
// restated in the mirrored text, or "".
//
// A percentage is an average, and an average hides a sentence: a narrative
// split across two fields scores low on each and low on the whole while one of
// its sentences sits on the mirror verbatim.
//
// THE FLOOR EXEMPTED THE ONE SENTENCE THE GUARD WAS BUILT AROUND. The first
// version skipped sentences under eight distinctive words, and "A Community
// deployment gets the shadow observer in full." has six — so the exact sentence
// this whole split exists to keep off the mirror could be pasted back into
// `summary` and both mirror tests passed. The survivor control could not tell
// me, because its fixture sentence was long enough to clear the floor by
// construction: a fixture that cannot express the defect reads as a disproof.
//
// So the rule is now graded by length rather than gated by it:
//
//   - 5+ distinctive words: every one must appear in the mirrored text. Long
//     sentences do not collide by accident.
//   - 3-4: the words must appear CONTIGUOUSLY and IN ORDER. A short sentence
//     can share its words with unrelated prose, so bare presence would fire on
//     coincidence; a contiguous run of them is a restatement.
//   - under 3: skipped, and countSkippableSentences reports how many of the
//     shipped narratives' sentences fall there, so the exemption is measured
//     rather than assumed.
//
// Matching is on lightly stemmed words, because "a Community deployment gets"
// and "Community deployments get" are the same claim and only one of them is
// the sentence somebody wrote down.
func restatedSentence(narrative, mirrored string) string {
	haveSet, haveSeq := stemmedWords(mirrored)
	for _, sentence := range splitSentences(narrative) {
		wantSet, wantSeq := stemmedWords(sentence)
		switch {
		case len(wantSeq) >= 5:
			all := true
			for w := range wantSet {
				if !haveSet[w] {
					all = false
					break
				}
			}
			if all {
				return strings.TrimSpace(sentence)
			}
		case len(wantSeq) >= 3:
			if containsRun(haveSeq, wantSeq) {
				return strings.TrimSpace(sentence)
			}
		}
	}
	return ""
}

// countSkippableSentences reports how many sentences across the given
// narratives are too short for restatedSentence to judge. It is what turns
// "the floor exempts something" from an assumption into a number.
func countSkippableSentences(narratives Narratives) (skipped, total int) {
	for _, n := range narratives {
		for _, sentence := range splitSentences(n.Detail) {
			_, seq := stemmedWords(sentence)
			total++
			if len(seq) < 3 {
				skipped++
			}
		}
	}
	return skipped, total
}

// splitSentences breaks prose into sentences on ". " rather than on ".".
//
// A bare period splits "9.1.0", "platform/agent/license/tier.go" and
// "//go:build enterprise." into fragments, and a fragment is under any word
// floor — which inflates the exemption the floor leaves and hides real
// sentences among the debris. Measured: splitting on "." left 27% of the
// shipped narratives' sentences unjudged; splitting on a sentence boundary
// leaves a fraction of that.
func splitSentences(s string) []string {
	s = strings.ReplaceAll(s, "\n", ". ")
	s = strings.ReplaceAll(s, "; ", ". ")
	parts := strings.Split(s, ". ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// containsRun reports whether want appears contiguously inside have.
func containsRun(have, want []string) bool {
	if len(want) == 0 || len(want) > len(have) {
		return false
	}
	for i := 0; i+len(want) <= len(have); i++ {
		match := true
		for j := range want {
			if have[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// stemmedWords returns the distinctive words of s as a set and, in order, as a
// sequence. A trailing plural "s" is dropped so "deployment" and "deployments"
// compare equal: they are the same claim, and only one of them is the sentence
// somebody wrote down.
func stemmedWords(s string) (map[string]bool, []string) {
	set := map[string]bool{}
	var seq []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if censusStopWords[w] {
			continue
		}
		// Stem FIRST, then apply the length floor to the stem. Filtering on the
		// raw word made matching asymmetric: "gets" (four letters) survived and
		// stemmed to "get", while a paraphrase's "get" (three) was dropped
		// before it could stem — so the two spellings of one claim could never
		// match, and the plural paraphrase walked past the guard.
		w = strings.TrimSuffix(w, "s")
		if len(w) < 3 {
			continue
		}
		set[w] = true
		seq = append(seq, w)
	}
	return set, seq
}

// TestTheMirrorGuardSeesEveryFieldAndEverySentence is the survivor control on
// the two ways R3 walked round the first version.
//
// The first guard read `notes` alone and compared a PERCENTAGE. Both are
// bypassable and both were bypassed: the same sentence in `summary` scored
// nothing at all, and a narrative split across two fields scored below the
// threshold on each and on the whole while one of its sentences sat on the
// mirror verbatim. An average hides a sentence, and a named field is a guard on
// that field rather than on the mirror.
func TestTheMirrorGuardSeesEveryFieldAndEverySentence(t *testing.T) {
	narrative := "The matrix marks budget CRUD Enterprise-only but the handler carries no " +
		"build constraint and no TierLimits field gates budgets so the routes are " +
		"registered and reachable on a Community build."

	// THE MOTIVATING SENTENCE, planted as its own control.
	//
	// "A Community deployment gets the shadow observer in full." is the exact
	// sentence this whole split exists to keep off the mirror — the round-1
	// leak. It has SIX distinctive words, and the first sentence rule skipped
	// anything under eight, so the one case the guard was built around was
	// below its own floor and could be pasted straight back into `summary`.
	// The old survivor control could not tell me: its fixture sentence was long
	// enough to clear the floor by construction, so it was a fixture that
	// could not express the defect and read as a disproof.
	//
	// All three spellings must be caught: the verbatim sentence, the round-1
	// wording with "therefore", and a plural paraphrase — which is why matching
	// is on lightly stemmed words.
	shadowNarrative := "Every file of platform/shared/planeshadow carries no build " +
		"constraint. A Community deployment gets the shadow observer in full. The ADR " +
		"states intent."
	// M-D: the SHORT arm had no control. All three spellings above carry six
	// distinctive words, so they exercise the five-or-more all-words rule and
	// never the 3-4 contiguous one — which could have been deleted whole and
	// survived. These two are four words and three words.
	// Measured, not guessed: "The handler gates budgets" is three distinctive
	// words after stemming and stop-word removal, and "Community deployments
	// lose nothing" is four. Both sit in the contiguous arm.
	shortNarrative := "The handler gates budgets. Community deployments lose nothing."
	for name, tc := range map[string]struct {
		mirrored string
		caught   bool
	}{
		"a three-word sentence restated contiguously": {
			mirrored: "the handler gates budgets", caught: true},
		"a four-word sentence restated contiguously": {
			mirrored: "community deployments lose nothing", caught: true},
		// The negative MUST contain every word of the sentence, or it is not
		// testing contiguity at all — it is testing presence, which the
		// all-words arm already covers. R5 caught the first version missing
		// the stem "gate" entirely.
		"all three words present but not contiguous": {
			mirrored: "the handler is fine, budgets are elsewhere, and nothing gates them",
			caught:   false},
	} {
		t.Run(name, func(t *testing.T) {
			got := restatedSentence(shortNarrative, tc.mirrored) != ""
			if got != tc.caught {
				t.Errorf("restatedSentence(short) caught=%v, want %v. The 3-4 word arm "+
					"requires the words CONTIGUOUSLY and IN ORDER: bare presence would "+
					"fire on coincidence, and no requirement at all would let a short "+
					"restatement through", got, tc.caught)
			}
		})
	}

	for name, mirrored := range map[string]string{
		"the motivating sentence, verbatim": "A Community deployment gets the shadow observer in full.",
		"the round-1 wording":               "A Community deployment therefore gets the shadow observer in full.",
		"a plural paraphrase":               "Community deployments get the shadow observer in full.",
	} {
		t.Run(name, func(t *testing.T) {
			if got := restatedSentence(shadowNarrative, mirrored); got == "" {
				t.Errorf("the sentence check did not catch %s. This is the exact sentence "+
					"the split exists for, and it has six distinctive words: a floor above "+
					"that exempts the motivating case", name)
			}
		})
	}

	for name, e := range map[string]Entry{
		"the sentence hidden in summary": {
			Summary: narrative,
		},
		"the sentence hidden in the score reason": {
			Score: Score{Reason: narrative},
		},
		"the sentence hidden in the health-absent reason": {
			HealthAbsentReason: narrative,
		},
		"split across summary and notes": {
			Summary: "The matrix marks budget CRUD Enterprise-only but the handler carries",
			Notes: "no build constraint and no TierLimits field gates budgets so the routes " +
				"are registered and reachable on a Community build.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			text := mirroredText(e)
			if overlap(narrative, text) <= 0.5 && restatedSentence(narrative, text) == "" {
				t.Errorf("neither the overlap (%.2f) nor the sentence check caught %s; the "+
					"narrative is on the mirror and the guard says it is not",
					overlap(narrative, text), name)
			}
		})
	}

	// And the negative: a structural pointer must NOT trip either check, or the
	// guard would force every row's notes to be empty and somebody would delete
	// the guard rather than the notes.
	ok := Entry{
		Title:   "Budget management",
		Summary: "CRUD over /api/v1/budgets with status, alerts and the check route.",
		Notes:   "The class of the disagreement is on matrix_disagreement.",
	}
	text := mirroredText(ok)
	if got := overlap(narrative, text); got > 0.5 {
		t.Errorf("a structural pointer scored %.2f overlap; the guard would force every "+
			"notes field empty", got)
	}
	if s := restatedSentence(narrative, text); s != "" {
		t.Errorf("a structural pointer tripped the sentence check: %q", s)
	}
}

// TestTheNarrativeFloorFires pins M-7, THROUGH THE GUARD'S OWN CODE PATH.
//
// The previous version re-implemented `len(distinctiveWords(...)) < 10` in its
// own body, so `false && n < 10` in the guard survived the whole package: the
// test moved with the mutant instead of dying under it. Both the guard and this
// pin now call narrativeIsTooThin, so there is one implementation and no
// restatement to drift.
func TestTheNarrativeFloorFires(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		thin bool
	}{
		"a real narrative": {text: "The matrix marks budget CRUD Enterprise-only but the " +
			"handler carries no build constraint and no TierLimits field gates budgets.",
			thin: false},
		"stock words only":   {text: "The matrix and the tree disagree about this row.", thin: true},
		"a handful of words": {text: "Enterprise only, not gated.", thin: true},
		"long but not distinct": {text: "The matrix and the tree and this row and that row " +
			"and the census and the matrix and the tree again.", thin: true},
	} {
		t.Run(name, func(t *testing.T) {
			thin, count := narrativeIsTooThin(tc.text)
			if thin != tc.thin {
				t.Errorf("narrativeIsTooThin(%q) = %v (%d words), want %v",
					tc.text, thin, count, tc.thin)
			}
		})
	}
}

// TestEveryShippedNarrativeClearsTheFloor is the positive control on it: a
// floor no shipped row is anywhere near is a floor nobody has tested against
// reality.
func TestEveryShippedNarrativeClearsTheFloor(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "technical-docs")); err != nil {
		t.Skip("community mirror: the narratives are excluded here")
	}
	narratives, err := LoadNarratives(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(narratives) == 0 {
		t.Fatal("no narratives to check")
	}
	thinnest, thinnestID := 1<<30, ""
	for id, n := range narratives {
		if got := len(distinctiveWords(n.Detail)); got < thinnest {
			thinnest, thinnestID = got, id
		}
	}
	if thinnest < 10 {
		t.Errorf("%s has only %d distinctive words", thinnestID, thinnest)
	}
	t.Logf("thinnest shipped narrative: %d distinctive words (%s), floor 10",
		thinnest, thinnestID)
}

// TestTheSentenceFloorExemptionIsMeasured reports how many of the shipped
// narratives' sentences are too short for the sentence check to judge.
//
// Every rule that skips something leaves an exemption, and an unmeasured
// exemption is where the last defect lived: the old eight-word floor exempted
// the one sentence the guard was built around and nobody knew, because nobody
// had counted. This turns "the floor exempts something" into a number, and
// fails if that number ever becomes a large share of the whole.
func TestTheSentenceFloorExemptionIsMeasured(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "technical-docs")); err != nil {
		t.Skip("community mirror: the narratives are excluded here")
	}
	narratives, err := LoadNarratives(root)
	if err != nil {
		t.Fatal(err)
	}
	skipped, total := countSkippableSentences(narratives)
	if total == 0 {
		t.Fatal("no sentences were counted at all")
	}
	share := float64(skipped) / float64(total)
	t.Logf("sentence-check coverage: %d of %d sentences across %d narratives are under the "+
		"3-word floor and are not judged (%.0f%%)", skipped, total, len(narratives), share*100)
	if share > 0.25 {
		t.Errorf("%.0f%% of narrative sentences are below the floor, so the sentence check "+
			"is judging only part of what it claims to. Either the floor is too high or the "+
			"narratives are written in fragments", share*100)
	}
}

// narrativeWordFloor is the minimum number of distinctive words a narrative
// needs before overlap() can say anything about it. overlap() divides by that
// count, so a narrative of a few stock words scores every mirrored field at or
// near zero and the guard goes inert for its row.
const narrativeWordFloor = 10

// mirrorOverlapThreshold is the share of a narrative's distinctive words that
// may appear in an entry's mirrored free text before it counts as a
// restatement. Pinned by TestTheMirrorGuardsOwnParametersArePinned, because
// raising it to 1.0 turns the check off and nothing else would notice.
const mirrorOverlapThreshold = 0.5

// narrativeIsTooThin is the ONE implementation of the floor, called by the
// guard and by its own pin.
//
// R3 killed the previous pin as a lookalike: it re-implemented
// `len(distinctiveWords(...)) < 10` in its own body, so `false && n < 10` in
// the guard survived the whole package. A test that restates the condition it
// is pinning tests its own restatement — it moves with the mutant instead of
// dying under it.
func narrativeIsTooThin(detail string) (bool, int) {
	n := len(distinctiveWords(detail))
	return n < narrativeWordFloor, n
}

// TestTheMirrorGuardsOwnParametersArePinned closes the three mutants R3 found
// surviving on the guard itself rather than on the data it reads.
//
// A guard has parameters — a threshold, a field list, a helper's return — and
// each is a place the guard can be turned off without any test noticing,
// because every test reads the guard's OUTPUT on data that is clean. These
// assert the parameters directly.
func TestTheMirrorGuardsOwnParametersArePinned(t *testing.T) {
	narrative := "The matrix marks budget CRUD Enterprise-only but the handler carries no " +
		"build constraint and no TierLimits field gates budgets so the routes are " +
		"registered and reachable on a Community build."

	// 1. The threshold. Raising it to 1.0 turns the percentage check off, and
	// no other test notices because no shipped row is near 1.0. A verbatim
	// restatement must exceed the threshold the guard actually applies.
	if got := overlap(narrative, narrative); got <= mirrorOverlapThreshold {
		t.Errorf("a verbatim restatement scores %.2f against a threshold of %.2f; the "+
			"threshold is above what a total copy scores, so it can never fire",
			got, mirrorOverlapThreshold)
	}
	if mirrorOverlapThreshold >= 1.0 || mirrorOverlapThreshold <= 0.0 {
		t.Errorf("the overlap threshold is %.2f, which is outside the range where it can "+
			"discriminate anything", mirrorOverlapThreshold)
	}

	// 2. The field set. Dropping any field from mirroredText silently stops the
	// guard reading it, and R3 walked through `summary` doing exactly that.
	// Each field is asserted to REACH the concatenation.
	probe := Entry{
		Title:              "TITLEPROBE",
		Summary:            "SUMMARYPROBE",
		Notes:              "NOTESPROBE",
		HealthAbsentReason: "ABSENTPROBE",
		Score:              Score{Reason: "REASONPROBE"},
	}
	text := mirroredText(probe)
	for _, want := range []string{
		"TITLEPROBE", "SUMMARYPROBE", "NOTESPROBE", "ABSENTPROBE", "REASONPROBE",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("mirroredText does not include the field carrying %s; a narrative "+
				"parked there would reach the mirror unread", want)
		}
	}

	// 3. restatedSentence must be capable of returning something. Making it
	// return "" unconditionally passes every test that only ever feeds it clean
	// data.
	if got := restatedSentence(narrative, narrative); got == "" {
		t.Error("restatedSentence returned nothing for a narrative restated verbatim; it " +
			"cannot fire at all")
	}
}
