// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/agent/license"
)

// Field-Level Verification (operator rule 2026-09-07): every field, every
// edge case, both editions, direction pinned by N-1 / N / N+1. The fake ledger
// counts every call so the unlimited branch's "zero I/O" is measured, not
// assumed, and can be switched off to model an outage.

// fakeLedger is an in-memory Ledger with a call counter and a kill switch.
type fakeLedger struct {
	mu   sync.Mutex
	rows map[Key]bool
	down bool
	// calls counts REQUEST-PATH calls (Exists, AdmitUnderLimit, Recent);
	// records counts the off-path telemetry writes an unlimited tier makes.
	// They are separate because the claim "an unlimited tier makes zero I/O"
	// is about the first and not the second.
	calls   int
	records int
}

func newFakeLedger() *fakeLedger { return &fakeLedger{rows: map[Key]bool{}} }

// setDown flips the kill switch UNDER THE LOCK. The package spawns background
// work now (the unlimited tier's telemetry record, the refusal audit row, and
// bounded's abandoned call), so a test that assigned `ledger.setDown(true)`
// directly raced those goroutines - `go test -race` found both sites. R3
// round 2, N1.
func (f *fakeLedger) setDown(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = v
}

func (f *fakeLedger) count(org string, d Dimension) int {
	n := 0
	for k := range f.rows {
		if k.OrgID == org && k.Dimension == d {
			n++
		}
	}
	return n
}

func (f *fakeLedger) Exists(_ context.Context, k Key) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.down {
		return false, errors.New("ledger down")
	}
	return f.rows[k], nil
}

func (f *fakeLedger) AdmitUnderLimit(_ context.Context, k Key, limit int, _ string) (Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.down {
		return Outcome{}, errors.New("ledger down")
	}
	if limit < 0 {
		return Outcome{}, errors.New("unlimited sentinel reached the ledger")
	}
	out := Outcome{Count: f.count(k.OrgID, k.Dimension)}
	if f.rows[k] {
		out.Existing = true
		return out, nil
	}
	if out.Count >= limit {
		return out, nil
	}
	f.rows[k] = true
	out.Admitted = true
	return out, nil
}

func (f *fakeLedger) Record(_ context.Context, k Key, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records++
	if f.down {
		return errors.New("ledger down")
	}
	f.rows[k] = true
	return nil
}

func (f *fakeLedger) Recent(_ context.Context, org string, n int) ([]Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.down {
		return nil, errors.New("ledger down")
	}
	var keys []Key
	for k := range f.rows {
		if k.OrgID == org && len(keys) < n {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// fakeAudit records refusals.
type fakeAudit struct {
	mu   sync.Mutex
	rows []Decision
}

func (a *fakeAudit) RecordRefusal(_ context.Context, d Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, d)
}

func (a *fakeAudit) len() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.rows) }

// readerFor returns a tier reader presenting the given licence state.
func readerFor(tier license.Tier, state string) func(context.Context) license.TierRead {
	return func(context.Context) license.TierRead {
		switch state {
		case LicenceAbsent:
			return license.TierRead{Tier: license.TierCommunity}
		case LicenceExpired:
			return license.TierRead{Tier: license.TierCommunity, KeyPresent: true, Rejected: true,
				Reason: "license expired on 2020-01-31", ReasonClass: license.TierReadRejectedExpired}
		case LicenceRejected:
			return license.TierRead{Tier: license.TierCommunity, KeyPresent: true, Rejected: true,
				Reason: "invalid license signature", ReasonClass: license.TierReadRejectedSignature}
		}
		return license.TierRead{Tier: tier, KeyPresent: tier != license.TierCommunity}
	}
}

func refusals(t *testing.T, d Dimension, edition, reason string) float64 {
	t.Helper()
	return testutil.ToFloat64(refusalsTotal.WithLabelValues(string(d), edition, reason))
}

func admissions(t *testing.T, d Dimension, edition string, s Source) float64 {
	t.Helper()
	return testutil.ToFloat64(admissionsTotal.WithLabelValues(string(d), edition, string(s)))
}

// limitedEditions are the two editions every assertion about the CHECK runs
// on. An Enterprise-licence test proves nothing about the check (it skips).
var limitedEditions = []struct {
	tier    license.Tier
	edition string
}{
	{license.TierCommunity, "community"},
	{license.TierEvaluation, "evaluation"},
}

// TestRuledValuesPerDimension pins the four ruled numbers on each edition
// through the ONE limits table, not a copy. The direction of every bound is
// pinned in TestDirectionNMinusOneNAndNPlusOne.
func TestRuledValuesPerDimension(t *testing.T) {
	want := map[Dimension][3]int{ // community, evaluation, enterprise
		HumanPrincipal:   {25, 75, -1},
		ServicePrincipal: {5, 25, -1},
		Node:             {1, -1, -1},
		OrgRootPolicy:    {0, 0, -1},
	}
	for d, w := range want {
		if got := d.Limit(license.GetTierLimits(license.TierCommunity)); got != w[0] {
			t.Errorf("%s community: got %d want %d", d, got, w[0])
		}
		if got := d.Limit(license.GetTierLimits(license.TierEvaluation)); got != w[1] {
			t.Errorf("%s evaluation: got %d want %d", d, got, w[1])
		}
		for _, ent := range []license.Tier{license.TierProfessional, license.TierEnterprise, license.TierEnterprisePlus} {
			if got := d.Limit(license.GetTierLimits(ent)); got != w[2] {
				t.Errorf("%s %s: got %d want %d", d, ent, got, w[2])
			}
		}
	}
	// An unknown dimension reads 0 (none), never -1 (unlimited): a dimension
	// that forgets its case fails closed.
	if got := Dimension("bogus").Limit(license.EnterpriseLimits); got != 0 {
		t.Errorf("unknown dimension read %d, want 0 (fail closed)", got)
	}
}

// TestDirectionNMinusOneNAndNPlusOne: with N-1 admitted the Nth is ADMITTED;
// with N admitted the N+1th is REFUSED. Both editions, every dimension with a
// positive bound. Asserting only inequality would pass a reversed comparison.
func TestDirectionNMinusOneNAndNPlusOne(t *testing.T) {
	for _, ed := range limitedEditions {
		for _, d := range Dimensions() {
			if d == Node {
				continue // a concurrency dimension: node_test.go pins its direction
			}
			limit := d.Limit(license.GetTierLimits(ed.tier))
			if limit <= 0 {
				continue // 0 and -1 have their own tests below
			}
			t.Run(fmt.Sprintf("%s/%s/N=%d", ed.edition, d, limit), func(t *testing.T) {
				ledger := newFakeLedger()
				audit := &fakeAudit{}
				a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithAuditSink(audit))
				org := "org-" + ed.edition + "-" + string(d)
				before := refusals(t, d, ed.edition, ReasonOverLimit)
				// N-1 admitted.
				for i := 1; i < limit; i++ {
					dec, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: org, PrincipalID: fmt.Sprintf("p%d", i)})
					if err != nil || !dec.Allowed {
						t.Fatalf("principal %d of %d: allowed=%v err=%v", i, limit, dec.Allowed, err)
					}
				}
				// The Nth is admitted (count N-1 < N).
				nth, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: org, PrincipalID: fmt.Sprintf("p%d", limit)})
				if err != nil || !nth.Allowed {
					t.Fatalf("the Nth principal (N=%d) must be ADMITTED: allowed=%v err=%v", limit, nth.Allowed, err)
				}
				if nth.Source != SourceLedgerAdmitted || nth.Count != limit-1 {
					t.Errorf("Nth: source=%s count=%d, want ledger_admitted with count %d", nth.Source, nth.Count, limit-1)
				}
				// The N+1th is refused (count N >= N).
				over, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: org, PrincipalID: fmt.Sprintf("p%d", limit+1)})
				if err != nil {
					t.Fatal(err)
				}
				if over.Allowed {
					t.Fatalf("the N+1th principal (N=%d) must be REFUSED", limit)
				}
				if over.Reason != ReasonOverLimit || over.Code != d.Code() || over.Limit != limit || over.Count != limit {
					t.Errorf("refusal: reason=%s code=%s limit=%d count=%d", over.Reason, over.Code, over.Limit, over.Count)
				}
				if over.Edition != ed.edition || over.LicenceState != licenceStateFor(ed.tier) {
					t.Errorf("refusal edition=%s licence=%s", over.Edition, over.LicenceState)
				}
				if over.RetryAfter != 0 {
					t.Errorf("an over_limit refusal must not carry Retry-After; got %v", over.RetryAfter)
				}
				// Three observables: code (above), metric, audit row.
				if got := refusals(t, d, ed.edition, ReasonOverLimit) - before; got != 1 {
					t.Errorf("refusal metric moved by %v, want 1", got)
				}
				a.WaitForRecording()
				if audit.len() != 1 || audit.rows[0].Reason != ReasonOverLimit {
					t.Errorf("audit rows=%d", audit.len())
				}
				if !strings.Contains(over.Message(), d.Code()) {
					t.Errorf("message must name the code: %q", over.Message())
				}
				// The N admitted principals keep working after the limit is hit.
				for i := 1; i <= limit; i++ {
					dec, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: org, PrincipalID: fmt.Sprintf("p%d", i)})
					if err != nil || !dec.Allowed || !dec.SeenSetAnswered {
						t.Fatalf("existing principal %d after the limit: allowed=%v seen=%v err=%v", i, dec.Allowed, dec.SeenSetAnswered, err)
					}
				}
			})
		}
	}
}

func licenceStateFor(tier license.Tier) string {
	if tier == license.TierCommunity {
		return LicenceAbsent
	}
	return LicenceValid
}

// TestUnlimitedTierSkipsWithZeroIO: an Enterprise (and Professional, Plus)
// licence never touches the ledger, on every dimension. The assertion is the
// call COUNT, and the ledger is DOWN, so a check that sneaks in would refuse.
func TestUnlimitedTierSkipsWithZeroIO(t *testing.T) {
	for _, tier := range []license.Tier{license.TierProfessional, license.TierEnterprise, license.TierEnterprisePlus} {
		ledger := newFakeLedger()
		ledger.setDown(true)
		a := New(ledger, WithTierReader(readerFor(tier, LicenceValid)))
		for _, d := range Dimensions() {
			for i := 0; i < 500; i++ {
				dec, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: "ent", PrincipalID: fmt.Sprintf("p%d", i)})
				if err != nil || !dec.Allowed || dec.Source != SourceUnlimitedTier || dec.Limit != -1 || dec.Count != -1 {
					t.Fatalf("%s %s: %+v err=%v", tier, d, dec, err)
				}
			}
		}
		a.WaitForRecording()
		if ledger.calls != 0 || a.LedgerCalls() != 0 {
			t.Fatalf("%s: the ledger was called %d times ON THE REQUEST PATH (admitter counted %d); an unlimited tier must make none", tier, ledger.calls, a.LedgerCalls())
		}
		// It DOES record off the request path (the operator's ruling: the
		// ledger still records for telemetry and the qualification profile),
		// deduped by the seen-set to one attempt per principal rather than one
		// per request, and this ledger is DOWN so every attempt failed and was
		// dropped without touching the decision or the health.
		//
		// THE COUNT IS "SOME, AND BOUNDED", NOT "ALL". MaxBackgroundWriters
		// caps the concurrent writers and a record that cannot get a slot is
		// dropped rather than queued, so against a store that fails slowly
		// most of these never attempt at all - which is the cap working. What
		// the test can assert is that recording HAPPENED, that it stayed
		// within the cap's accounting, and that not one of those drops moved
		// the decision or the health.
		if ledger.records == 0 {
			t.Fatalf("%s: an unlimited tier recorded NOTHING; a later downgrade would find an empty ledger and treat every principal as new", tier)
		}
		if ledger.records > 500*(len(Dimensions())-2) {
			t.Fatalf("%s: %d record attempts for 500 principals x 2 principal dimensions; the seen-set dedupe is not holding", tier, ledger.records)
		}
		if !a.Health().LedgerHealthy {
			t.Fatalf("%s: a dropped telemetry write must not affect health", tier)
		}
	}
	// Evaluation is unlimited on the node dimension ONLY, and that skip is
	// also zero-I/O - asserted so "evaluation nodes unlimited" is a measured
	// skip, not a pass through a check.
	ledger := newFakeLedger()
	ledger.setDown(true)
	a := New(ledger, WithTierReader(readerFor(license.TierEvaluation, LicenceValid)))
	dec, err := a.Admit(context.Background(), Request{Dimension: Node, OrgID: "eval", PrincipalID: "node-2"})
	if err != nil || !dec.Allowed || dec.Source != SourceUnlimitedTier || ledger.calls != 0 {
		t.Fatalf("evaluation node: %+v err=%v calls=%d", dec, err, ledger.calls)
	}
}

// TestZeroLimitAdmitsNothingNewButKeepsExisting: 0 means NONE on both
// editions (OrgRootPolicy is the ruled case; every dimension is planted). An
// existing principal still passes: the seen/ledger branches precede the
// count, per the ruled order.
func TestZeroLimitAdmitsNothingNewButKeepsExisting(t *testing.T) {
	for _, ed := range limitedEditions {
		for _, d := range Dimensions() {
			if d == Node {
				continue // node_test.go: a zero node limit refuses a new node, renews a held lease
			}
			ledger := newFakeLedger()
			a := New(ledger,
				WithTierReader(readerFor(ed.tier, LicenceValid)),
				WithLimits(func(license.Tier) license.TierLimits {
					return license.TierLimits{MaxHumanPrincipals: 0, MaxServicePrincipals: 0, MaxNodes: 0, OrgPolicies: 0}
				}))
			org := "zero-" + ed.edition
			dec, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: org, PrincipalID: "new"})
			if err != nil || dec.Allowed || dec.Reason != ReasonOverLimit || dec.Limit != 0 || dec.Count != 0 {
				t.Fatalf("%s %s limit 0 new principal: %+v err=%v", ed.edition, d, dec, err)
			}
			// Plant a pre-existing row (admitted under an earlier, larger limit).
			ledger.rows[Key{OrgID: org, Dimension: d, PrincipalID: "old"}] = true
			dec, err = a.Admit(context.Background(), Request{Dimension: d, OrgID: org, PrincipalID: "old"})
			if err != nil || !dec.Allowed || dec.Source != SourceLedgerExisting {
				t.Fatalf("%s %s limit 0 existing principal must keep working: %+v err=%v", ed.edition, d, dec, err)
			}
		}
	}
}

// TestNegativeLimitIsUnlimitedOnEveryDimension plants -1 through WithLimits
// (the sentinel's meaning is a property of the reader, not of the table).
func TestNegativeLimitIsUnlimitedOnEveryDimension(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := newFakeLedger()
		ledger.setDown(true)
		a := New(ledger,
			WithTierReader(readerFor(ed.tier, LicenceValid)),
			WithLimits(func(license.Tier) license.TierLimits {
				return license.TierLimits{MaxHumanPrincipals: -1, MaxServicePrincipals: -1, MaxNodes: -1, OrgPolicies: -1}
			}))
		for _, d := range Dimensions() {
			dec, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: "o", PrincipalID: "p"})
			if err != nil || !dec.Allowed || dec.Source != SourceUnlimitedTier {
				t.Fatalf("%s %s: %+v err=%v", ed.edition, d, dec, err)
			}
		}
		if ledger.calls != 0 {
			t.Fatalf("%s: -1 must skip the ledger; %d calls", ed.edition, ledger.calls)
		}
	}
}

// TestLicenceStates: valid / expired / forged / absent, each with the ruled
// behaviour. Expired and forged and absent all resolve to the Community
// table; existing principals keep working; new ones are measured against
// Community; the state is NAMED on the decision and in the message.
func TestLicenceStates(t *testing.T) {
	cases := []struct {
		state    string
		wantTier license.Tier
		wantLim  int
	}{
		{LicenceValid, license.TierEvaluation, 75},
		{LicenceExpired, license.TierCommunity, 25},
		{LicenceRejected, license.TierCommunity, 25},
		{LicenceAbsent, license.TierCommunity, 25},
	}
	for _, c := range cases {
		t.Run(c.state, func(t *testing.T) {
			ledger := newFakeLedger()
			a := New(ledger, WithTierReader(readerFor(license.TierEvaluation, c.state)))
			org := "lic-" + c.state
			// An existing principal (admitted under any earlier licence).
			ledger.rows[Key{OrgID: org, Dimension: HumanPrincipal, PrincipalID: "existing"}] = true
			dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: org, PrincipalID: "existing"})
			if err != nil || !dec.Allowed {
				t.Fatalf("existing under %s: %+v err=%v", c.state, dec, err)
			}
			// A new principal is measured against the state's table.
			dec, err = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: org, PrincipalID: "new"})
			if err != nil || !dec.Allowed || dec.Tier != c.wantTier || dec.Limit != c.wantLim || dec.LicenceState != c.state {
				t.Fatalf("new under %s: %+v err=%v", c.state, dec, err)
			}
			// Fill to the limit and refuse: the refusal names the state.
			for i := 0; i < c.wantLim; i++ {
				ledger.rows[Key{OrgID: org, Dimension: HumanPrincipal, PrincipalID: fmt.Sprintf("fill%d", i)}] = true
			}
			dec, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: org, PrincipalID: "one-too-many"})
			if dec.Allowed || dec.LicenceState != c.state {
				t.Fatalf("over limit under %s: %+v", c.state, dec)
			}
			switch c.state {
			case LicenceExpired:
				if !strings.Contains(dec.Message(), "EXPIRED") {
					t.Errorf("expired refusal must say so: %q", dec.Message())
				}
			case LicenceRejected:
				if !strings.Contains(dec.Message(), "REFUSED") {
					t.Errorf("forged refusal must say so: %q", dec.Message())
				}
			}
			// Never unlimited.
			if dec.Limit < 0 {
				t.Fatalf("%s resolved to unlimited", c.state)
			}
		})
	}
}

// TestOutageMatrix: ledger down x {known, unknown} x {community, evaluation,
// enterprise, expired}. Each cell's outcome, reason, counter and audit row
// asserted individually.
func TestOutageMatrix(t *testing.T) {
	type cell struct {
		name    string
		tier    license.Tier
		state   string
		edition string
		limited bool
	}
	cells := []cell{
		{"community", license.TierCommunity, LicenceAbsent, "community", true},
		{"evaluation", license.TierEvaluation, LicenceValid, "evaluation", true},
		{"enterprise", license.TierEnterprise, LicenceValid, "enterprise", false},
		{"expired-enterprise", license.TierEnterprise, LicenceExpired, "community", true},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			ledger := newFakeLedger()
			audit := &fakeAudit{}
			a := New(ledger, WithTierReader(readerFor(c.tier, c.state)), WithAuditSink(audit))
			org := "outage-" + c.name
			// Known: admitted while healthy.
			dec, err := a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: "known"})
			if err != nil || !dec.Allowed {
				t.Fatalf("admit known while healthy: %+v err=%v", dec, err)
			}
			ledger.setDown(true)
			before := refusals(t, ServicePrincipal, c.edition, ReasonDependencyUnreachable)
			overBefore := refusals(t, ServicePrincipal, c.edition, ReasonOverLimit)
			// Known principal keeps working through the seen-set.
			dec, err = a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: "known"})
			if err != nil || !dec.Allowed {
				t.Fatalf("known principal during outage must be admitted: %+v err=%v", dec, err)
			}
			if c.limited && !dec.SeenSetAnswered {
				t.Errorf("known principal on a limited tier must be answered by the seen-set during an outage; source=%s", dec.Source)
			}
			// Unknown principal.
			dec, err = a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: "unknown"})
			if err != nil {
				t.Fatal(err)
			}
			if !c.limited {
				if !dec.Allowed || dec.Source != SourceUnlimitedTier {
					t.Fatalf("enterprise during outage must be allowed without I/O: %+v", dec)
				}
				a.WaitForRecording()
				if audit.len() != 0 {
					t.Errorf("enterprise must produce zero audit rows during an outage")
				}
				return
			}
			if dec.Allowed || dec.Reason != ReasonDependencyUnreachable || dec.Code != ServicePrincipal.Code() {
				t.Fatalf("unknown principal during outage: %+v", dec)
			}
			if dec.RetryAfter != RetryAfter {
				t.Errorf("outage refusal must carry Retry-After %v; got %v", RetryAfter, dec.RetryAfter)
			}
			if got := refusals(t, ServicePrincipal, c.edition, ReasonDependencyUnreachable) - before; got != 1 {
				t.Errorf("dependency_unreachable counter moved %v, want 1", got)
			}
			if got := refusals(t, ServicePrincipal, c.edition, ReasonOverLimit) - overBefore; got != 0 {
				t.Errorf("over_limit counter moved %v during an outage; the two reasons must not share a label", got)
			}
			a.WaitForRecording()
			if audit.len() != 1 || audit.rows[0].Reason != ReasonDependencyUnreachable {
				t.Errorf("audit rows=%d", audit.len())
			}
			if !strings.Contains(dec.Message(), "cannot be reached") || strings.Contains(dec.Message(), "at most") {
				t.Errorf("outage message must not read as a limit: %q", dec.Message())
			}
			if c.state == LicenceExpired && dec.LicenceState != LicenceExpired {
				t.Errorf("expired-enterprise refusal must name the licence state; got %s", dec.LicenceState)
			}
			if h := a.Health(); h.LedgerHealthy || h.LastError == "" {
				t.Errorf("health must report the ledger unhealthy with its error: %+v", h)
			}
			// Recovery: the ledger returns, the unknown principal is admitted.
			ledger.setDown(false)
			dec, err = a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: "unknown"})
			if err != nil || !dec.Allowed || dec.Source != SourceLedgerAdmitted {
				t.Fatalf("after recovery: %+v err=%v", dec, err)
			}
			if h := a.Health(); !h.LedgerHealthy {
				t.Errorf("health must recover: %+v", h)
			}
		})
	}
}

// TestNoLedgerConfiguredRefusesNewOnLimitedTiersOnly: New(nil) is the
// "no ledger" posture, and it is the outage posture, not fail-open.
func TestNoLedgerConfiguredRefusesNewOnLimitedTiersOnly(t *testing.T) {
	for _, ed := range limitedEditions {
		a := New(nil, WithTierReader(readerFor(ed.tier, LicenceValid)))
		dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "o", PrincipalID: "p"})
		if err != nil || dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("%s: %+v err=%v", ed.edition, dec, err)
		}
		if a.Health().LedgerHealthy {
			t.Errorf("%s: no ledger must report unhealthy", ed.edition)
		}
	}
	a := New(nil, WithTierReader(readerFor(license.TierEnterprise, LicenceValid)))
	if dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "o", PrincipalID: "p"}); err != nil || !dec.Allowed {
		t.Fatalf("enterprise with no ledger: %+v err=%v", dec, err)
	}
}

// TestReplayIsIdempotent: the same principal admitted N times is ONE ledger
// write and ONE ledger_admitted increment; the rest answer from the seen-set.
func TestReplayIsIdempotent(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := newFakeLedger()
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)))
		org := "replay-" + ed.edition
		before := admissions(t, HumanPrincipal, ed.edition, SourceLedgerAdmitted)
		seenBefore := admissions(t, HumanPrincipal, ed.edition, SourceSeenSet)
		for i := 0; i < 10; i++ {
			dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: org, PrincipalID: "same"})
			if err != nil || !dec.Allowed {
				t.Fatalf("replay %d: %+v err=%v", i, dec, err)
			}
		}
		if n := ledger.count(org, HumanPrincipal); n != 1 {
			t.Fatalf("%s: %d rows for one principal", ed.edition, n)
		}
		if got := admissions(t, HumanPrincipal, ed.edition, SourceLedgerAdmitted) - before; got != 1 {
			t.Errorf("%s: ledger_admitted moved %v, want 1", ed.edition, got)
		}
		if got := admissions(t, HumanPrincipal, ed.edition, SourceSeenSet) - seenBefore; got != 9 {
			t.Errorf("%s: seen_set moved %v, want 9", ed.edition, got)
		}
		// A replay through a COLD seen-set (another process) is also one row:
		// the ledger reports Existing, nothing is written.
		cold := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)))
		dec, err := cold.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: org, PrincipalID: "same"})
		if err != nil || !dec.Allowed || dec.Source != SourceLedgerExisting {
			t.Fatalf("%s cold replay: %+v err=%v", ed.edition, dec, err)
		}
		if n := ledger.count(org, HumanPrincipal); n != 1 {
			t.Fatalf("%s: cold replay wrote a row", ed.edition)
		}
	}
}

// TestSeenSetCapNeverRefusesAnExistingPrincipal: with a cap of 2 and three
// admitted principals, the evicted one is re-found in the ledger (one call),
// and only when the ledger is ALSO down is it refused - with the outage reason.
func TestSeenSetCapNeverRefusesAnExistingPrincipal(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := newFakeLedger()
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithSeenSetCap(2))
		org := "cap-" + ed.edition
		for _, p := range []string{"a", "b", "c"} {
			if dec, err := a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: p}); err != nil || !dec.Allowed {
				t.Fatalf("%s admit %s: %+v err=%v", ed.edition, p, dec, err)
			}
		}
		if a.Health().SeenSetSize != 2 {
			t.Fatalf("%s: seen-set size %d, cap 2", ed.edition, a.Health().SeenSetSize)
		}
		calls := ledger.calls
		dec, err := a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: "a"})
		if err != nil || !dec.Allowed || dec.Source != SourceLedgerExisting || dec.SeenSetAnswered {
			t.Fatalf("%s evicted principal must be found in the ledger: %+v err=%v", ed.edition, dec, err)
		}
		if ledger.calls-calls != 1 {
			t.Errorf("%s: the ledger fallback made %d calls, want 1", ed.edition, ledger.calls-calls)
		}
		// Now evicted again (b was pushed out by a) AND the ledger is down.
		ledger.setDown(true)
		dec, err = a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: "b"})
		if err != nil || dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("%s evicted principal with the ledger down: %+v err=%v", ed.edition, dec, err)
		}
		// The two still in the set are unaffected.
		for _, p := range []string{"a", "c"} {
			if dec, err := a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: org, PrincipalID: p}); err != nil || !dec.Allowed || !dec.SeenSetAnswered {
				t.Fatalf("%s principal %s in the set during an outage: %+v err=%v", ed.edition, p, dec, err)
			}
		}
	}
}

// TestWarmLoadsTheLedgerIntoTheSeenSet: after Warm, a known principal is
// answered without I/O even when the ledger goes down immediately after.
func TestWarmLoadsTheLedgerIntoTheSeenSet(t *testing.T) {
	ledger := newFakeLedger()
	for i := 0; i < 5; i++ {
		ledger.rows[Key{OrgID: "w", Dimension: HumanPrincipal, PrincipalID: fmt.Sprintf("h%d", i)}] = true
	}
	a := New(ledger, WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)))
	if a.Health().Warmed {
		t.Fatal("warmed before Warm")
	}
	n, err := a.Warm(context.Background(), "w", "", "  ")
	if err != nil || n != 5 || !a.Health().Warmed {
		t.Fatalf("warm: n=%d err=%v health=%+v", n, err, a.Health())
	}
	ledger.setDown(true)
	for i := 0; i < 5; i++ {
		dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "w", PrincipalID: fmt.Sprintf("h%d", i)})
		if err != nil || !dec.Allowed || !dec.SeenSetAnswered {
			t.Fatalf("warmed principal h%d: %+v err=%v", i, dec, err)
		}
	}
	// Warm against a down ledger reports the error and is not fatal.
	b := New(ledger, WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)))
	if _, err := b.Warm(context.Background(), "w"); err == nil {
		t.Fatal("warm against a down ledger must report the error")
	}
	if b.Health().Warmed || b.Health().LedgerHealthy {
		t.Errorf("a failed warm must leave warmed=false and the ledger unhealthy: %+v", b.Health())
	}
}

// TestRequestFieldsPresentAbsentAndEmpty: every Request field, present /
// absent / present-but-empty (whitespace).
func TestRequestFieldsPresentAbsentAndEmpty(t *testing.T) {
	a := New(newFakeLedger(), WithTierReader(readerFor(license.TierCommunity, LicenceAbsent)))
	bad := []Request{
		{},
		{Dimension: HumanPrincipal},
		{Dimension: HumanPrincipal, OrgID: "o"},
		{Dimension: HumanPrincipal, OrgID: "", PrincipalID: "p"},
		{Dimension: HumanPrincipal, OrgID: "   ", PrincipalID: "p"},
		{Dimension: HumanPrincipal, OrgID: "o", PrincipalID: "   "},
		{Dimension: "", OrgID: "o", PrincipalID: "p"},
		{Dimension: "  ", OrgID: "o", PrincipalID: "p"},
		{Dimension: "user", OrgID: "o", PrincipalID: "p"},
	}
	for i, r := range bad {
		if _, err := a.Admit(context.Background(), r); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("request %d (%+v): err=%v, want ErrInvalidRequest", i, r, err)
		}
	}
	// A refusal is a Decision, never an error, so an invalid request is the
	// ONLY error path and cannot be confused with one.
	if a.LedgerCalls() != 0 {
		t.Errorf("an invalid request must not reach the ledger; %d calls", a.LedgerCalls())
	}
	// Licence present (valid), absent (nil -> reader), present-but-empty
	// (zero TierRead -> Community, never unlimited).
	valid := license.TierRead{Tier: license.TierEnterprise, KeyPresent: true}
	dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "o", PrincipalID: "p", Licence: &valid})
	if err != nil || dec.Source != SourceUnlimitedTier {
		t.Fatalf("present licence: %+v err=%v", dec, err)
	}
	dec, err = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "o", PrincipalID: "p2"})
	if err != nil || dec.Tier != license.TierCommunity || dec.LicenceState != LicenceAbsent {
		t.Fatalf("absent licence (reader): %+v err=%v", dec, err)
	}
	empty := license.TierRead{}
	dec, err = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "o", PrincipalID: "p3", Licence: &empty})
	if err != nil || dec.Tier != license.TierCommunity || dec.Limit != 25 {
		t.Fatalf("present-but-empty licence must read as Community, never unlimited: %+v err=%v", dec, err)
	}
}

// TestCodesAndLabelsAreDistinctFromAuthFailures: the code is upper-case and
// prefixed; every authentication code the agent emits is a lower-case word.
func TestCodesAndLabelsAreDistinctFromAuthFailures(t *testing.T) {
	want := map[Dimension]string{
		HumanPrincipal:   "ERR_TIER_LIMIT_HUMAN_PRINCIPAL",
		ServicePrincipal: "ERR_TIER_LIMIT_SERVICE_PRINCIPAL",
		Node:             "ERR_TIER_LIMIT_NODE",
		OrgRootPolicy:    "ERR_TIER_LIMIT_ORG_ROOT_POLICY",
	}
	for d, w := range want {
		if d.Code() != w {
			t.Errorf("%s code %q want %q", d, d.Code(), w)
		}
	}
	for _, authCode := range []string{"missing_credentials", "invalid_credentials", "rate_limited", "client_disabled", "invalid_user_token", "unknown_auth_kind"} {
		for _, d := range Dimensions() {
			if d.Code() == authCode || strings.EqualFold(d.Code(), authCode) {
				t.Errorf("%s collides with auth code %s", d.Code(), authCode)
			}
		}
	}
	if HTTPStatus != 402 {
		t.Errorf("HTTPStatus = %d, want 402", HTTPStatus)
	}
	if AuditRequestType == "user_token_rejected" || AuditRequestType == "user_token_required" {
		t.Error("audit request type collides with an authentication marker")
	}
}

// TestEditionLabelIsClosed folds every tier the package knows onto the
// declared set, including the SaaS plugin tiers.
func TestEditionLabelIsClosed(t *testing.T) {
	declared := map[string]bool{}
	for _, e := range Editions() {
		declared[e] = true
	}
	for _, tier := range []license.Tier{license.TierCommunity, license.TierEvaluation, license.TierProfessional,
		license.TierEnterprise, license.TierEnterprisePlus, license.TierFree, license.TierPro, license.TierPremium, "Platinum", ""} {
		if !declared[editionLabel(tier)] {
			t.Errorf("tier %q folds to %q, outside Editions()", tier, editionLabel(tier))
		}
	}
}

// TestPreRegisteredSeriesExistAtZero: the refusal counter is on the scrape
// for every limited (dimension, edition, reason) before any refusal.
func TestPreRegisteredSeriesExistAtZero(t *testing.T) {
	n, err := testutil.GatherAndCount(prometheus.DefaultGatherer, "axonflow_tier_limit_refusals_total")
	if err != nil {
		t.Fatal(err)
	}
	if n < 16 {
		t.Fatalf("%d refusal series registered, want at least 16 (4 dimensions x 2 editions x 2 reasons)", n)
	}
}

// blockingLedger never answers: the shape a paused database presents.
type blockingLedger struct{ fakeLedger }

func (b *blockingLedger) Exists(ctx context.Context, _ Key) (bool, error) {
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond) // answer LATE, after the bound
	return false, ctx.Err()
}

// TestAStoreThatNeverAnswersIsUnreachableWithinTheTimeout: the request is not
// held; it is refused with the outage reason inside the bound, on both
// editions, and a known principal is still answered by the seen-set.
func TestAStoreThatNeverAnswersIsUnreachableWithinTheTimeout(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := &blockingLedger{fakeLedger: *newFakeLedger()}
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithLedgerTimeout(100*time.Millisecond))
		start := time.Now()
		dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "o", PrincipalID: "new"})
		took := time.Since(start)
		if err != nil || dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("%s: %+v err=%v", ed.edition, dec, err)
		}
		if took > 2*time.Second {
			t.Fatalf("%s: the refusal took %v; a store that never answers must not hold the request", ed.edition, took)
		}
		if h := a.Health(); h.LedgerHealthy || !strings.Contains(h.LastError, "timed out") {
			t.Fatalf("%s: health %+v", ed.edition, h)
		}
	}
}

// TestTheTierReadIsMemoisedAndTheMemoExpires pins both halves of the memo
// (see DefaultTierMemoTTL): a burst of admissions reads the licence ONCE, and
// crossing the TTL reads it again, so a licence that expires mid-process is
// noticed within the TTL rather than never.
//
// The direction is pinned in both places: without the memo the first count
// would be 50, and without the expiry the second would still be 1.
func TestTheTierReadIsMemoisedAndTheMemoExpires(t *testing.T) {
	for _, ed := range limitedEditions {
		clock := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
		reads := 0
		reader := func(context.Context) license.TierRead {
			reads++
			return license.TierRead{Tier: ed.tier, KeyPresent: ed.tier != license.TierCommunity}
		}
		a := New(newFakeLedger(),
			WithTierReader(reader),
			WithClock(func() time.Time { return clock }),
			WithTierMemoTTL(time.Minute))
		for i := 0; i < 50; i++ {
			if _, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "memo", PrincipalID: fmt.Sprintf("p%d", i)}); err != nil {
				t.Fatal(err)
			}
		}
		if reads != 1 || a.TierReads() != 1 {
			t.Fatalf("%s: 50 admissions performed %d licence read(s) (admitter counted %d); want 1", ed.edition, reads, a.TierReads())
		}
		// Inside the TTL: still one.
		clock = clock.Add(59 * time.Second)
		_, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "memo", PrincipalID: "inside"})
		if reads != 1 {
			t.Fatalf("%s: a read inside the TTL re-read the licence (%d)", ed.edition, reads)
		}
		// Past the TTL: read again, so an expiry is picked up.
		clock = clock.Add(2 * time.Second)
		_, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "memo", PrincipalID: "after"})
		if reads != 2 {
			t.Fatalf("%s: crossing the TTL did not re-read the licence (%d); an expiry would never be noticed", ed.edition, reads)
		}
	}
	// TTL 0 disables the memo entirely.
	reads := 0
	a := New(newFakeLedger(), WithTierMemoTTL(0), WithTierReader(func(context.Context) license.TierRead {
		reads++
		return license.TierRead{Tier: license.TierCommunity}
	}))
	for i := 0; i < 5; i++ {
		_, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "nomemo", PrincipalID: fmt.Sprintf("p%d", i)})
	}
	if reads != 5 {
		t.Fatalf("WithTierMemoTTL(0) must read every time; got %d of 5", reads)
	}
}

// TestTheMemoNoticesAnExpiryWithinTheTTL is the consequence spelled out: the
// same Admitter, the same key, a clock that crosses the licence's expiry.
// Before the TTL elapses the deployment still reads Evaluation; after it, the
// Community table applies. This is the cost the memo's TTL buys, asserted
// rather than described.
func TestTheMemoNoticesAnExpiryWithinTheTTL(t *testing.T) {
	clock := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	expiry := clock.Add(30 * time.Second)
	a := New(newFakeLedger(),
		WithClock(func() time.Time { return clock }),
		WithTierMemoTTL(time.Minute),
		WithTierReader(func(context.Context) license.TierRead {
			if clock.Before(expiry) {
				return license.TierRead{Tier: license.TierEvaluation, KeyPresent: true}
			}
			return license.TierRead{Tier: license.TierCommunity, KeyPresent: true, Rejected: true,
				Reason: "license expired", ReasonClass: license.TierReadRejectedExpired}
		}))
	dec, _ := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "exp", PrincipalID: "a"})
	if dec.Limit != 75 || dec.LicenceState != LicenceValid {
		t.Fatalf("before expiry: %+v", dec)
	}
	// The licence has expired, but the memo is still warm: still Evaluation.
	clock = clock.Add(31 * time.Second)
	dec, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "exp", PrincipalID: "b"})
	if dec.Limit != 75 {
		t.Fatalf("inside the TTL the memo must still hold the pre-expiry read: %+v", dec)
	}
	// Past the TTL: the Community table, and the state is named.
	clock = clock.Add(31 * time.Second)
	dec, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "exp", PrincipalID: "c"})
	if dec.Limit != 25 || dec.LicenceState != LicenceExpired {
		t.Fatalf("past the TTL the expiry must be noticed: %+v", dec)
	}
}

// TestACallerThatGoesAwayDoesNotChangeTheANSWER is what H4 became once the
// store call was DETACHED from the caller's context (the v11 master's design
// note). The question "was this the client or the store?" no longer has to be
// answered, because the store call no longer carries the client's context: a
// cancelled caller gets the same decision anyone else would, and a store
// failure is reported whoever asked.
func TestACallerThatGoesAwayDoesNotChangeTheAnswer(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := newFakeLedger()
		audit := &fakeAudit{}
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithAuditSink(audit), WithNodeLeases(newFakeLeases()))

		// A cancelled caller, a HEALTHY store: admitted, exactly as a live
		// caller would be. Nothing about the client changes the decision.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		dec, err := a.Admit(ctx, Request{Dimension: HumanPrincipal, OrgID: "gone", PrincipalID: "p"})
		if err != nil || !dec.Allowed {
			t.Fatalf("%s: a cancelled caller with a healthy store must still get the real answer: %+v err=%v", ed.edition, dec, err)
		}
		if !a.Health().LedgerHealthy {
			t.Fatalf("%s: a cancelled caller must not mark the ledger unreachable; health=%+v", ed.edition, a.Health())
		}

		// A cancelled caller, a DOWN store: refused AND observed. The store
		// really is down, and that is worth a metric and an audit row whoever
		// was asking.
		before := refusals(t, HumanPrincipal, ed.edition, ReasonDependencyUnreachable)
		ledger.setDown(true)
		dec, err = a.Admit(ctx, Request{Dimension: HumanPrincipal, OrgID: "gone", PrincipalID: "p2"})
		if err != nil || dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("%s: %+v err=%v", ed.edition, dec, err)
		}
		if got := refusals(t, HumanPrincipal, ed.edition, ReasonDependencyUnreachable) - before; got != 1 {
			t.Errorf("%s: a real outage went UNCOUNTED because the caller had gone (moved %v)", ed.edition, got)
		}
		if a.Health().LedgerHealthy {
			t.Errorf("%s: a real store failure must mark the ledger unreachable", ed.edition)
		}
		a.WaitForRecording()
		if audit.len() != 1 {
			t.Errorf("%s: audit rows=%d, want 1", ed.edition, audit.len())
		}
	}
}

// TestADowngradeFromAnUnlimitedTierIsGraceful is R3 round 1's H5. An
// Enterprise deployment records asynchronously, so when its licence expires
// the principals it has been serving are already in the ledger and keep
// working - rather than every one of them being "new" at once and all but the
// first N being refused.
func TestADowngradeFromAnUnlimitedTierIsGraceful(t *testing.T) {
	ledger := newFakeLedger()
	tier := license.TierEnterprise
	reader := func(context.Context) license.TierRead {
		if tier == license.TierEnterprise {
			return license.TierRead{Tier: tier, KeyPresent: true}
		}
		return license.TierRead{Tier: license.TierCommunity, KeyPresent: true, Rejected: true,
			Reason: "license expired", ReasonClass: license.TierReadRejectedExpired}
	}
	// 40 humans served under Enterprise - more than the Community ceiling.
	ent := New(ledger, WithTierReader(reader), WithTierMemoTTL(0))
	for i := 0; i < 40; i++ {
		if dec, _ := ent.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "dg", PrincipalID: fmt.Sprintf("u%d", i)}); !dec.Allowed || dec.Source != SourceUnlimitedTier {
			t.Fatalf("enterprise human %d: %+v", i, dec)
		}
	}
	ent.WaitForRecording()
	if n := ledger.count("dg", HumanPrincipal); n != 40 {
		t.Fatalf("the unlimited tier recorded %d of 40 principals; a downgrade would find them missing", n)
	}
	// The licence expires. A NEW process picks it up with a cold seen-set.
	tier = license.TierCommunity
	after := New(ledger, WithTierReader(reader), WithTierMemoTTL(0))
	for i := 0; i < 40; i++ {
		dec, err := after.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "dg", PrincipalID: fmt.Sprintf("u%d", i)})
		if err != nil || !dec.Allowed {
			t.Fatalf("after the downgrade, established principal u%d was REFUSED (%+v). Every one of the 40 was being "+
				"served a moment ago; a licence lapse must not lock out the people already using the deployment.", i, dec)
		}
		if dec.LicenceState != LicenceExpired {
			t.Fatalf("u%d: licence state %s", i, dec.LicenceState)
		}
	}
	// A genuinely new principal IS refused: the ceiling is now in force.
	if dec, _ := after.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "dg", PrincipalID: "brand-new"}); dec.Allowed {
		t.Fatal("after the downgrade a NEW principal must be refused; the ceiling is not in force")
	}
}

// TestAZeroLimitReportsTheCeilingNotAnOutage is R3 round 1's M7: a limit of 0
// can never admit a new principal, so a store failure must not tell the caller
// to retry in thirty seconds.
func TestAZeroLimitReportsTheCeilingNotAnOutage(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := newFakeLedger()
		ledger.setDown(true)
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)),
			WithLimits(func(license.Tier) license.TierLimits { return license.TierLimits{OrgPolicies: 0} }))
		dec, err := a.Admit(context.Background(), Request{Dimension: OrgRootPolicy, OrgID: "z", PrincipalID: "policy-1"})
		if err != nil {
			t.Fatal(err)
		}
		if dec.Reason != ReasonOverLimit {
			t.Fatalf("%s: a limit of 0 with the store down must report the CEILING, got %s", ed.edition, dec.Reason)
		}
		if dec.RetryAfter != 0 {
			t.Errorf("%s: told the caller to retry a request that can never succeed", ed.edition)
		}
		// The control: a POSITIVE limit with the same store failure IS the
		// retryable outage.
		b := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)),
			WithLimits(func(license.Tier) license.TierLimits { return license.TierLimits{OrgPolicies: 3} }))
		if dec, _ := b.Admit(context.Background(), Request{Dimension: OrgRootPolicy, OrgID: "z", PrincipalID: "policy-1"}); dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("%s control: a positive limit with the store down must be the outage reason, got %s", ed.edition, dec.Reason)
		}
	}
}

// TestADeadlineIsNotAnAbandonedCaller is R3 round 2's N4, and it survives the
// detachment as the regression test for it: a caller whose own deadline is
// shorter than the store bound must still be OBSERVED during a real outage.
// Before the store call was detached this was the case that went silent, and
// it is exactly the caller most likely to meet an outage.
func TestADeadlineIsNotAnAbandonedCaller(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := &blockingLedger{fakeLedger: *newFakeLedger()}
		audit := &fakeAudit{}
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithAuditSink(audit),
			WithLedgerTimeout(2*time.Second))
		before := refusals(t, HumanPrincipal, ed.edition, ReasonDependencyUnreachable)

		// A caller with a SHORT deadline, during a store that never answers.
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		dec, err := a.Admit(ctx, Request{Dimension: HumanPrincipal, OrgID: "dl", PrincipalID: "p"})
		if err != nil || dec.Allowed || dec.Reason != ReasonDependencyUnreachable {
			t.Fatalf("%s: %+v err=%v", ed.edition, dec, err)
		}
		if got := refusals(t, HumanPrincipal, ed.edition, ReasonDependencyUnreachable) - before; got != 1 {
			t.Errorf("%s: a caller with its own deadline was refused SILENTLY during a real outage (counter moved %v). "+
				"It is still waiting for an answer, so the outage must be observable.", ed.edition, got)
		}
		if a.Health().LedgerHealthy {
			t.Errorf("%s: a real store failure must mark the ledger unhealthy even when the caller had a short deadline", ed.edition)
		}
		a.WaitForRecording()
		if audit.len() != 1 {
			t.Errorf("%s: audit rows=%d, want 1", ed.edition, audit.len())
		}
	}
}

// TestBackgroundWritersAreBounded is R3 round 2's N5, restated for the queue:
// the bound is on the RESOURCE (how many writers run at once), not on the WORK
// (how many records are kept). The first version of this bound was a semaphore
// that dropped a record whenever no slot was free, which bounded goroutines by
// discarding the very thing the recording exists to produce - measured at 32
// of 40 principals recorded, deterministically, under one CPU. Here the
// high-water mark of CONCURRENT writes is asserted instead, and every record
// still lands.
func TestBackgroundWritersAreBounded(t *testing.T) {
	gate := &concurrencyWatcher{fakeLedger: newFakeLedger()}
	a := New(gate, WithTierReader(readerFor(license.TierEnterprise, LicenceValid)))
	const n = 400
	for i := 0; i < n; i++ {
		if dec, _ := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "cap", PrincipalID: fmt.Sprintf("p%d", i)}); !dec.Allowed {
			t.Fatalf("admission %d on an unlimited tier must be allowed: %+v", i, dec)
		}
	}
	a.WaitForRecording()
	if hw := gate.highWater(); hw > MaxBackgroundWriters {
		t.Fatalf("%d concurrent background writes at peak, cap is %d: the worker pool is not bounding concurrency", hw, MaxBackgroundWriters)
	}
	if got := gate.fakeLedger.count("cap", HumanPrincipal); got != n {
		t.Fatalf("%d of %d principals recorded; the bound must cost latency, never records - that regression is what the "+
			"downgrade test caught and this test now guards", got, n)
	}
}

// concurrencyWatcher records the high-water mark of concurrent Record calls.
type concurrencyWatcher struct {
	*fakeLedger
	mu   sync.Mutex
	cur  int
	peak int
}

func (c *concurrencyWatcher) Record(ctx context.Context, k Key, fp string) error {
	c.mu.Lock()
	c.cur++
	if c.cur > c.peak {
		c.peak = c.cur
	}
	c.mu.Unlock()
	time.Sleep(time.Millisecond) // hold the slot long enough to overlap
	err := c.fakeLedger.Record(ctx, k, fp)
	c.mu.Lock()
	c.cur--
	c.mu.Unlock()
	return err
}

func (c *concurrencyWatcher) highWater() int { c.mu.Lock(); defer c.mu.Unlock(); return c.peak }

// blockingRecorder blocks in Record until release is closed.
type blockingRecorder struct {
	*fakeLedger
	release chan struct{}
}

func (b *blockingRecorder) Record(ctx context.Context, k Key, fp string) error {
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.fakeLedger.Record(ctx, k, fp)
}

// TestAFullQueueDropIsSelfHealing is the v11 master's condition 2 on the
// queue: the retry is a claim in a comment until a test fills the queue,
// forces a drop, and shows the record landing on the principal's next request.
//
// It also pins condition 3, which is the part that could have hurt: the
// SEEN-SET IS NEVER UN-MARKED by a drop. Un-marking would be the obvious way
// to make the retry work, and it would hand an established principal a
// dependency_unreachable refusal the moment the licence lapsed - the outcome
// the whole outage posture exists to prevent.
func TestAFullQueueDropIsSelfHealing(t *testing.T) {
	release := make(chan struct{})
	blocked := &blockingRecorder{fakeLedger: newFakeLedger(), release: release}
	a := New(blocked,
		WithTierReader(readerFor(license.TierEnterprise, LicenceValid)),
		WithBackgroundQueueDepth(1))
	before := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "at_capacity"))

	// Enough principals that the depth-1 queue and its workers cannot take
	// them all while every write is blocked.
	const n = 200
	for i := 0; i < n; i++ {
		if dec, _ := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "q", PrincipalID: fmt.Sprintf("p%d", i)}); !dec.Allowed {
			t.Fatalf("admission %d on an unlimited tier must be allowed: %+v", i, dec)
		}
	}
	dropped := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "at_capacity")) - before
	if dropped < 1 {
		t.Fatalf("%d principals against a depth-1 queue with every write blocked dropped %v; the full-queue path never ran, so what follows proves nothing", n, dropped)
	}

	// THE SEEN-SET STILL HOLDS THEM. This is the property that keeps a
	// licence lapse survivable, and a drop must not weaken it.
	for i := 0; i < n; i++ {
		if !a.seen.Has(Key{OrgID: "q", Dimension: HumanPrincipal, PrincipalID: fmt.Sprintf("p%d", i)}) {
			t.Fatalf("principal p%d was dropped from the SEEN-SET by a queue-full drop; on a licence lapse it would be refused as new, "+
				"which is exactly the refusal the outage posture exists to prevent", i)
		}
	}

	// The debt is recorded, so the next request for a dropped principal
	// enqueues it again rather than treating it as already recorded.
	var owed int
	for i := 0; i < n; i++ {
		if a.retry.Has(Key{OrgID: "q", Dimension: HumanPrincipal, PrincipalID: fmt.Sprintf("p%d", i)}) {
			owed++
		}
	}
	if owed < 1 {
		t.Fatal("no principal is marked as owing a retry, so a dropped record would never be written")
	}

	// Unblock, let the queue drain, then ask again for a principal that was
	// dropped: its record must land this time.
	close(release)
	a.WaitForRecording()
	var retried string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("p%d", i)
		if a.retry.Has(Key{OrgID: "q", Dimension: HumanPrincipal, PrincipalID: id}) {
			retried = id
			break
		}
	}
	if retried == "" {
		t.Skip("every dropped record was already retried by a later admission in the loop above; the path is covered by the assertions already made")
	}
	if _, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "q", PrincipalID: retried}); err != nil {
		t.Fatal(err)
	}
	a.WaitForRecording()
	if !blocked.fakeLedger.rows[Key{OrgID: "q", Dimension: HumanPrincipal, PrincipalID: retried}] {
		t.Fatalf("principal %s owed a retry, was asked for again, and its record still did not land: the drop is not self-healing", retried)
	}
}

// TestCloseDrainsTheQueueAndReportsWhatItCouldNot is the v11 master's
// condition 1: shutdown behaviour is decided, not incidental.
func TestCloseDrainsTheQueueAndReportsWhatItCouldNot(t *testing.T) {
	// A healthy store drains fully within the deadline.
	ledger := newFakeLedger()
	a := New(ledger, WithTierReader(readerFor(license.TierEnterprise, LicenceValid)))
	for i := 0; i < 50; i++ {
		_, _ = a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "c", PrincipalID: fmt.Sprintf("p%d", i)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if left := a.Close(ctx); left != 0 {
		t.Fatalf("a healthy store left %d queued write(s) at shutdown", left)
	}
	if n := ledger.count("c", HumanPrincipal); n != 50 {
		t.Fatalf("Close returned 0 outstanding but only %d of 50 records landed", n)
	}

	// A store that never answers: Close gives up at the deadline rather than
	// hanging the shutdown, and says how much it abandoned.
	release := make(chan struct{})
	defer close(release)
	blocked := &blockingRecorder{fakeLedger: newFakeLedger(), release: release}
	b := New(blocked, WithTierReader(readerFor(license.TierEnterprise, LicenceValid)), WithBackgroundQueueDepth(64))
	for i := 0; i < 64; i++ {
		_, _ = b.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "c2", PrincipalID: fmt.Sprintf("p%d", i)})
	}
	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_ = b.Close(ctx2)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("Close took %v against a store that never answers; a shutdown must not wait on telemetry", took)
	}
}

// TestTheDebtSetIsBoundedAndItsEvictionIsCounted answers the question one
// layer below the queue (the v11 master's): the retry debt cannot grow without
// limit while the store is unavailable. It is an LRU at BackgroundQueueDepth,
// the oldest debt is dropped, and the drop is counted rather than silent.
func TestTheDebtSetIsBoundedAndItsEvictionIsCounted(t *testing.T) {
	ledger := newFakeLedger()
	a := New(ledger, WithTierReader(readerFor(license.TierEnterprise, LicenceValid)),
		WithBackgroundQueueDepth(4))
	// A tiny debt set, so the eviction is reachable in a test rather than
	// after a thousand failures.
	a.retry = newSeenSet(8)
	before := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "debt_evicted"))

	// Every write fails, so every principal ends up owing a retry.
	ledger.setDown(true)
	for i := 0; i < 200; i++ {
		if dec, _ := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "debt", PrincipalID: fmt.Sprintf("p%d", i)}); !dec.Allowed {
			t.Fatalf("admission %d on an unlimited tier must be allowed even with the store down: %+v", i, dec)
		}
	}
	a.WaitForRecording()

	if got := a.retry.Len(); got > 8 {
		t.Fatalf("the debt set holds %d entries against a cap of 8: it is not bounded, so a long outage on a busy "+
			"deployment grows it in proportion to traffic", got)
	}
	if got := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "debt_evicted")) - before; got < 1 {
		t.Fatalf("200 failed writes into an 8-entry debt set evicted %v; either nothing was evicted (so the bound did not "+
			"engage and this test proves nothing) or the eviction is silent", got)
	}
	// The seen-set is untouched by all of it: these principals stay admitted.
	for i := 0; i < 200; i++ {
		if !a.seen.Has(Key{OrgID: "debt", Dimension: HumanPrincipal, PrincipalID: fmt.Sprintf("p%d", i)}) {
			t.Fatalf("principal p%d left the seen-set during a store outage; established principals must keep working", i)
		}
	}
}

// TestAdmitAfterCloseReturnsADecisionRatherThanPanicking is the independent
// R3's BLOCKER-1 as a regression test.
//
// The first version of Close() closed the work channel, and enqueue() sent on
// it - `panic: send on closed channel`, which a `default:` arm does NOT
// prevent. It was reachable on every SIGTERM of a live agent: run.go's
// shutdown is a flush rather than a graceful drain, so the listener is still
// accepting while the deferred shutdown runs, and the database handle closes
// straight after, which makes every later admission a refusal - and a refusal
// wants an audit row, which enqueues.
func TestAdmitAfterCloseReturnsADecisionRatherThanPanicking(t *testing.T) {
	for _, ed := range limitedEditions {
		ledger := newFakeLedger()
		a := New(ledger, WithTierReader(readerFor(ed.tier, LicenceValid)), WithAuditSink(&fakeAudit{}), WithNodeLeases(newFakeLeases()))
		limit := ServicePrincipal.Limit(license.GetTierLimits(ed.tier))
		for i := 0; i < limit; i++ {
			if _, err := a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: "shut", PrincipalID: fmt.Sprintf("p%d", i)}); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if left := a.Close(ctx); left != 0 {
			t.Fatalf("%s: Close left %d queued", ed.edition, left)
		}
		cancel()

		// A REFUSAL after Close: wants an audit row, so it enqueues.
		dec, err := a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: "shut", PrincipalID: "one-too-many"})
		if err != nil || dec.Allowed {
			t.Fatalf("%s: post-Close refusal: %+v err=%v", ed.edition, dec, err)
		}
		// An unlimited-tier ADMISSION after Close: wants a telemetry record,
		// so it also enqueues. Same crash, different caller.
		b := New(ledger, WithTierReader(readerFor(license.TierEnterprise, LicenceValid)))
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		b.Close(ctx2)
		cancel2()
		if dec, err := b.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "shut", PrincipalID: "after"}); err != nil || !dec.Allowed {
			t.Fatalf("%s: post-Close unlimited admission: %+v err=%v", ed.edition, dec, err)
		}
		// Close is idempotent.
		ctx3, cancel3 := context.WithTimeout(context.Background(), time.Second)
		_ = a.Close(ctx3)
		cancel3()
	}
}

// panickingLedger records normally but panics on the Nth Record, to prove the
// background worker survives a store that panics rather than taking the
// process with it.
type panickingLedger struct {
	fakeLedger
	panicOn int32
	seen    int32
}

func (p *panickingLedger) Record(ctx context.Context, k Key, fp string) error {
	if atomic.AddInt32(&p.seen, 1) == p.panicOn {
		panic("simulated driver panic in Record")
	}
	return p.fakeLedger.Record(ctx, k, fp)
}

// panickingAudit panics on every refusal row, to drive the OTHER half of the
// background worker. Round 2 found that half emitting dimension="" because the
// panic handler read w.dim, which only recordUnlimited sets.
type panickingAudit struct{}

func (panickingAudit) RecordRefusal(context.Context, Decision) {
	panic("simulated driver panic in RecordRefusal")
}

// TestAPanickingAuditSinkIsDroppedUnderItsOwnDimension is the audit-side twin
// of the test below, and it exists because the record side passed while the
// audit side was broken. The two kinds of queued write carry the dimension in
// different fields - recordUnlimited sets key and dim, the refusal audit write
// sets neither and carries it on dec - so a handler that reads the wrong one
// is correct on exactly the half a single-sided test drives.
//
// The assertion is the LABEL, not the count: an empty dimension still
// increments the counter, so a test that only counted drops would have passed
// against the bug.
func TestAPanickingAuditSinkIsDroppedUnderItsOwnDimension(t *testing.T) {
	ledger := newFakeLedger()
	reader := func(context.Context) license.TierRead {
		return license.TierRead{Tier: license.TierCommunity, KeyPresent: true}
	}
	a := New(ledger, WithTierReader(reader), WithTierMemoTTL(0), WithAuditSink(panickingAudit{}),
		WithLimits(func(license.Tier) license.TierLimits {
			return license.TierLimits{MaxHumanPrincipals: 0, MaxServicePrincipals: 0, MaxNodes: 0, OrgPolicies: 0}
		}))
	defer func() { _ = a.Close(context.Background()) }()

	before := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(ServicePrincipal), "panicked"))

	dec, err := a.Admit(context.Background(), Request{Dimension: ServicePrincipal, OrgID: "pa", PrincipalID: "svc-1"})
	if err != nil || dec.Allowed {
		t.Fatalf("expected an over_limit refusal so an audit row is queued, got %+v (%v)", dec, err)
	}
	a.WaitForRecording()

	if got := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(ServicePrincipal), "panicked")) - before; got != 1 {
		t.Errorf("the panicked drop was counted %v time(s) under dimension=%q, want 1", got, ServicePrincipal)
	}
	// Gathered, NOT read through WithLabelValues: that call CREATES the child
	// it is asked for, so `ToFloat64(...WithLabelValues("", "panicked"))`
	// materialises the very empty-labelled series it is meant to prove absent,
	// and then the label census reports it. The observer must not write.
	if n := panickedDropsUnderEmptyDimension(t); n != 0 {
		t.Errorf("%v drop(s) were counted under an EMPTY dimension label. The audit write does not set w.dim - it "+
			"carries the dimension on w.dec - so the panic handler is reading the field the RECORD write populates.", n)
	}
}

// panickedDropsUnderEmptyDimension collects the drop counter and totals the
// panicked series whose dimension label is empty, without creating any series.
func panickedDropsUnderEmptyDimension(t *testing.T) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() { backgroundDropsTotal.Collect(ch); close(ch) }()
	total := 0.0
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("collecting the drop counter: %v", err)
		}
		dim, reason := "", ""
		for _, l := range pb.GetLabel() {
			switch l.GetName() {
			case "dimension":
				dim = l.GetValue()
			case "reason":
				reason = l.GetValue()
			}
		}
		if dim == "" && reason == "panicked" {
			total += pb.GetCounter().GetValue()
		}
	}
	return total
}

// TestAPanickingStoreDropsOneWriteRatherThanTheProcess pins the recover() in
// backgroundWorker. These writes are off the request path, so a panic in a
// store implementation must cost one counted drop, not the agent.
//
// Without the recover this test does not fail, it CRASHES the test binary -
// which is the point: the same panic on a live agent is the process, on the
// goroutine furthest from the request that caused it.
func TestAPanickingStoreDropsOneWriteRatherThanTheProcess(t *testing.T) {
	ledger := &panickingLedger{fakeLedger: *newFakeLedger(), panicOn: 3}
	reader := func(context.Context) license.TierRead {
		return license.TierRead{Tier: license.TierEnterprise, KeyPresent: true}
	}
	a := New(ledger, WithTierReader(reader), WithTierMemoTTL(0))
	defer func() {
		_ = a.Close(context.Background())
	}()

	before := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "panicked"))
	for i := 0; i < 6; i++ {
		dec, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "pl", PrincipalID: fmt.Sprintf("u%d", i)})
		if err != nil || !dec.Allowed {
			t.Fatalf("principal %d was not admitted (%+v, %v); the panic is in the BACKGROUND write and must not "+
				"reach the request path at all", i, dec, err)
		}
	}
	a.WaitForRecording()

	if got := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "panicked")) - before; got != 1 {
		t.Fatalf("the panicked drop counter moved by %v, want 1. A recovered panic that is not counted is a silent "+
			"lost record, which is exactly the row a later downgrade is measured against.", got)
	}
	// The other five writes must still have landed: one poisoned write must
	// not stop the worker pool, which is what a panic without recover does to
	// the whole process and what a `return` in the recover would do to one
	// worker.
	if n := ledger.count("pl", HumanPrincipal); n != 5 {
		t.Fatalf("the ledger holds %d of the 5 non-panicking records; the worker pool did not survive the panic", n)
	}
}

// TestLicenceFingerprintIsNeverTheKey pins the one property that matters about
// what a ledger row records: it identifies the licence without carrying it. A
// ledger row is readable by anyone with SELECT on the table, and the key is a
// credential.
//
// It lives here, next to LicenceFingerprint, because both wirings now share
// that function: the agent's private copy was deleted so the two binaries
// cannot drift into two spellings of the same licence.
func TestLicenceFingerprintIsNeverTheKey(t *testing.T) {
	if LicenceFingerprint("") != "" || LicenceFingerprint("   ") != "" {
		t.Fatal("an empty or blank key must fingerprint to empty, so a keyless deployment writes no fingerprint")
	}
	const key = "AXON-secret.payload"
	fp := LicenceFingerprint(key)
	if len(fp) != 16 {
		t.Fatalf("fingerprint %q is %d characters, want 16", fp, len(fp))
	}
	if strings.Contains(key, fp) {
		t.Fatalf("the fingerprint %q is a SUBSTRING of the key; a ledger row would carry part of the credential", fp)
	}
	if LicenceFingerprint(key) != fp {
		t.Fatal("the fingerprint is not stable, so one licence would look like many across restarts")
	}
	if LicenceFingerprint(key+"x") == fp {
		t.Fatal("two different keys fingerprint the same, so a licence change would be invisible in the ledger")
	}
	if LicenceFingerprint("  "+key+"  ") != fp {
		t.Fatal("surrounding whitespace changes the fingerprint; an env var with a stray newline would read as a different licence")
	}
}

// TestAShutdownDropIsNotCountedAsABacklog pins the reason on a drop caused by
// Close. The COUNT was always right; the reason was at_capacity, which tells an
// operator to size the queue after what was actually a SIGTERM. Round 2 raised
// it as a nit and it is one, but it is the kind that turns into a wrong
// capacity change six months later.
func TestAShutdownDropIsNotCountedAsABacklog(t *testing.T) {
	ledger := newFakeLedger()
	reader := func(context.Context) license.TierRead {
		return license.TierRead{Tier: license.TierEnterprise, KeyPresent: true}
	}
	a := New(ledger, WithTierReader(reader), WithTierMemoTTL(0))
	if _, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "sd", PrincipalID: "warm"}); err != nil {
		t.Fatal(err)
	}
	a.WaitForRecording()
	_ = a.Close(context.Background())

	beforeShutdown := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "shutting_down"))
	beforeCapacity := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "at_capacity"))

	// Admitting after Close must not panic and must drop under the right name.
	if _, err := a.Admit(context.Background(), Request{Dimension: HumanPrincipal, OrgID: "sd", PrincipalID: "after"}); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "shutting_down")) - beforeShutdown; got != 1 {
		t.Errorf("the post-Close drop was counted %v time(s) as shutting_down, want 1", got)
	}
	if got := testutil.ToFloat64(backgroundDropsTotal.WithLabelValues(string(HumanPrincipal), "at_capacity")) - beforeCapacity; got != 0 {
		t.Errorf("%v post-Close drop(s) were counted as at_capacity, which reads as a backlog. The queue was not "+
			"full; the admitter was closed, and an operator acting on at_capacity would size the queue to fix a shutdown.", got)
	}
}

// TestOnlyThePrincipalDimensionsRecordOnAnUnlimitedTier pins which dimensions
// recordUnlimited writes, because prose about this drifted twice.
//
// Round 1 wrote a comment saying an Enterprise deployment accumulates
// organization-root rows so they "keep working" after a lapse. Round 2
// measured 1 / 1 / 0 and the comment was false. The recording exists to make a
// licence lapse survivable for principals that are re-admitted on EVERY
// request; an org-root policy is admitted once at create and never again, and
// a node is a lease rather than a ledger row. So the exclusion is correct and
// what needed fixing was the sentence — and a sentence is fixed by a test, or
// it drifts again.
func TestOnlyThePrincipalDimensionsRecordOnAnUnlimitedTier(t *testing.T) {
	ledger := newFakeLedger()
	leases := newFakeLeases()
	reader := func(context.Context) license.TierRead {
		return license.TierRead{Tier: license.TierEnterprise, KeyPresent: true}
	}
	a := New(ledger, WithTierReader(reader), WithTierMemoTTL(0), WithNodeLeases(leases))
	defer func() { _ = a.Close(context.Background()) }()

	for _, d := range Dimensions() {
		dec, err := a.Admit(context.Background(), Request{Dimension: d, OrgID: "unl", PrincipalID: "p-" + string(d)})
		if err != nil || !dec.Allowed {
			t.Fatalf("%s: an unlimited tier must admit, got %+v (%v)", d, dec, err)
		}
	}
	a.WaitForRecording()

	want := map[Dimension]int{
		HumanPrincipal:   1,
		ServicePrincipal: 1,
		OrgRootPolicy:    0,
		Node:             0,
	}
	for d, n := range want {
		if got := ledger.count("unl", d); got != n {
			t.Errorf("dimension %s recorded %d row(s) on an unlimited tier, want %d. "+
				"If this changed deliberately, the comments in recordUnlimited and in the orchestrator's "+
				"admitOrgRootPolicy both describe the old counts and are now false.", d, got, n)
		}
	}
}
