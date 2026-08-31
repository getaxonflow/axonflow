package conformance

import (
	"regexp"
	"sort"
	"testing"
)

// AllCases is the complete executable corpus: the transcribed source cases plus
// the corrective cases ADR-065 adds.
func AllCases() []Case {
	out := append([]Case(nil), sourceCases()...)
	out = append(out, correctiveCases()...)
	return out
}

var caseIDPattern = regexp.MustCompile(`^(EX-\d{2}|AXC-\d{3})$`)

// TestConformanceCorpus runs every case.
//
// The runner refuses a case that recorded zero assertions. A conformance suite
// fails in one characteristic way, which is a case that runs, does not error,
// and checks nothing; the assertion count turns that from an invisible pass
// into a named failure.
func TestConformanceCorpus(t *testing.T) {
	cases := AllCases()
	if len(cases) == 0 {
		t.Fatal("the corpus is empty")
	}
	seen := map[string]struct{}{}
	for _, c := range cases {
		if !caseIDPattern.MatchString(c.ID) {
			t.Errorf("case id %q does not match the EX-NN or AXC-NNN namespace", c.ID)
		}
		if _, dup := seen[c.ID]; dup {
			t.Errorf("case id %q appears more than once", c.ID)
		}
		seen[c.ID] = struct{}{}
		if c.Title == "" || c.Family == "" || c.Kind == "" || c.Run == nil {
			t.Errorf("case %q is incompletely declared", c.ID)
		}
	}

	for _, c := range cases {
		t.Run(c.ID+" "+c.Title, func(t *testing.T) {
			rec := &Recorder{t: t}
			c.Run(t, rec)
			if rec.Assertions() == 0 {
				t.Fatalf("case %s asserted nothing; a case that checks no property cannot fail and is not coverage", c.ID)
			}
			if len(c.Produces) == 0 {
				return
			}
			// A case that declares an outcome must have OBSERVED it. The
			// declaration is what the ledger's result column is checked
			// against, so a declaration nothing produced would put an
			// unverified value into the gate.
			want := map[string]struct{}{}
			for _, o := range c.Produces {
				want[o] = struct{}{}
			}
			got := map[string]struct{}{}
			for _, o := range rec.Observed() {
				got[o] = struct{}{}
			}
			for o := range want {
				if _, ok := got[o]; !ok {
					t.Errorf("case %s declares it produces %q but never recorded it; the ledger row for %s cites that value",
						c.ID, o, c.ID)
				}
			}
			for o := range got {
				if _, ok := want[o]; !ok {
					t.Errorf("case %s produced %q, which it does not declare; the ledger row would then understate the outcome",
						c.ID, o)
				}
			}
		})
	}
}

// TestCorpusIdentifierRangesDoNotCollide proves this package stays inside the
// identifier range it agreed with the identity-plane workstream, so that two
// corpora can cite each other's cases in one ledger without either silently
// claiming the other's identifier.
func TestCorpusIdentifierRangesDoNotCollide(t *testing.T) {
	var corrective []string
	for _, c := range AllCases() {
		if len(c.ID) > 4 && c.ID[:4] == "AXC-" {
			corrective = append(corrective, c.ID)
		}
	}
	sort.Strings(corrective)
	if len(corrective) == 0 {
		t.Fatal("the corpus declares no corrective cases, so the range agreement is untested")
	}
	for _, id := range corrective {
		if id >= "AXC-200" {
			t.Errorf("corrective case %q is outside the AXC-001 to AXC-199 range reserved for the decision core", id)
		}
	}
}
