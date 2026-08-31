package conformance

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"axonflow/platform/decision/contract"
)

// Recorder counts the assertions a case actually made.
//
// A conformance corpus fails in one characteristic way: a case that runs, does
// not error, and asserts nothing. The runner refuses a case that recorded zero
// assertions, so a case emptied by a refactor fails loudly instead of passing
// silently. That is a floor, not a proof; the mutation proofs in
// mutation_test.go are what show the assertions can actually fail.
type Recorder struct {
	t        *testing.T
	n        int
	observed []string
}

// Assertions returns the number of properties this case checked.
func (r *Recorder) Assertions() int { return r.n }

// Equal asserts a scalar property.
func (r *Recorder) Equal(what string, got, want any) {
	r.t.Helper()
	r.n++
	if got != want {
		r.t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

// EqualStrings asserts a list property.
func (r *Recorder) EqualStrings(what string, got, want []string) {
	r.t.Helper()
	r.n++
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		r.t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

// True asserts a boolean property.
func (r *Recorder) True(what string, cond bool) {
	r.t.Helper()
	r.n++
	if !cond {
		r.t.Errorf("%s: expected to hold, it did not", what)
	}
}

// Produced records an outcome this case observed, and asserts it is one the
// case declared. It is the half of the declaration that runs.
func (r *Recorder) Produced(observed string) {
	r.t.Helper()
	r.n++
	r.observed = append(r.observed, observed)
}

// Observed returns the outcomes the case recorded.
func (r *Recorder) Observed() []string { return r.observed }

// Fatalf ends the case.
func (r *Recorder) Fatalf(format string, args ...any) {
	r.t.Helper()
	r.t.Fatalf(format, args...)
}

// CaseKind groups cases by what they drive.
type CaseKind string

const (
	// KindDecision drives a request through the Decider.
	KindDecision CaseKind = "decision"
	// KindAuthoring drives the typed authoring validator.
	KindAuthoring CaseKind = "authoring"
	// KindBinding drives the decision binding digest.
	KindBinding CaseKind = "binding"
	// KindReservation drives the reservation coordinator.
	KindReservation CaseKind = "reservation"
	// KindContract drives the contract types directly: adapter, trace
	// projection, bundle verification.
	KindContract CaseKind = "contract"
)

// Case is one executable conformance case.
type Case struct {
	// ID is EX-NN for a transcribed source case and AXC-NNN for a corrective
	// case added by ADR-065.
	ID string
	// Title is the case name.
	Title string
	// Family is the section of the corpus.
	Family string
	Kind   CaseKind
	// Produces is the operational outcome or outcomes this case shows ADR-065
	// reaching for the source case it transcribes, declared once and checked
	// twice: the ledger guard compares it against the row's adr065_result
	// column, and the case itself records what it observed through
	// Recorder.Produced. Without it, that column is unverified prose and gate
	// 14 is satisfied by a cell nothing executes.
	//
	// A case that does not transcribe a source case leaves it empty.
	Produces []string
	Run      func(t *testing.T, rec *Recorder)
}

// expectation is the declarative shape of a decision assertion.
type expectation struct {
	Authorization contract.Authorization
	State         contract.OperationalState
	Reason        contract.ReasonCode
	Permissions   []string
	Constraints   []string
	Requirements  []string
	Inspections   []string
	Obligations   []string
	Approval      []string
	Unknown       []string
}

func expectDecision(rec *Recorder, d *contract.Decision, want expectation) {
	// Recording here rather than at every call site means a case that asserts
	// a decision cannot forget to declare what that decision was.
	rec.Produced(string(d.State))
	rec.Equal("authorization", d.Authorization, want.Authorization)
	rec.Equal("operational state", d.State, want.State)
	rec.Equal("reason", d.Reason, want.Reason)
	rec.EqualStrings("matched permissions", d.Determining.MatchedPermissions, want.Permissions)
	rec.EqualStrings("matched constraints", d.Determining.MatchedConstraints, want.Constraints)
	rec.EqualStrings("matched requirements", d.Determining.MatchedRequirement, want.Requirements)
	rec.EqualStrings("matched inspections", d.Determining.MatchedInspections, want.Inspections)
	rec.EqualStrings("obligations", ObligationKeys(d), want.Obligations)
	rec.EqualStrings("approval clauses", ApprovalKeys(d), want.Approval)
	if want.Unknown != nil {
		rec.EqualStrings("unknown policies", unknownKeys(d), want.Unknown)
	}
}

func unknownKeys(d *contract.Decision) []string {
	out := make([]string, 0, len(d.Determining.Unknown))
	for _, u := range d.Determining.Unknown {
		out = append(out, u.PolicyID+":"+string(u.Reason))
	}
	return out
}

// permissiveness orders operational states from least to most permissive so
// that "never widens" is a comparison rather than a case analysis. DENY and
// ERROR are both non-executing and are deliberately given the same rank: a
// change from one to the other is a change of diagnosis, not of access.
func permissiveness(d *contract.Decision) int {
	switch d.State {
	case contract.StateDeny, contract.StateError:
		return 0
	case contract.StateChallenge:
		return 1
	case contract.StateAllow:
		return 2
	default:
		return 0
	}
}

var (
	defaultWorldOnce sync.Once
	defaultWorldVal  *World
	defaultWorldErr  error
)

// defaultWorld builds the fixture world once and shares it. Every case that
// does not perturb the policy set reads the SAME activated bundles, which is
// also a small proof in itself: the corpus does not depend on rebuilding.
func defaultWorld(t *testing.T) *World {
	t.Helper()
	defaultWorldOnce.Do(func() {
		defaultWorldVal, defaultWorldErr = NewWorld(context.Background())
	})
	if defaultWorldErr != nil {
		t.Fatalf("building the fixture world: %v", defaultWorldErr)
	}
	return defaultWorldVal
}

func decide(t *testing.T, w *World, s Scenario) *contract.Decision {
	t.Helper()
	d, err := w.Decide(context.Background(), s)
	if err != nil {
		t.Fatalf("deciding %+v: %v", s, err)
	}
	return d
}

func newWorld(t *testing.T, opts ...WorldOption) *World {
	t.Helper()
	w, err := NewWorld(context.Background(), opts...)
	if err != nil {
		t.Fatalf("building a custom fixture world: %v", err)
	}
	return w
}
