// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
)

const (
	fixtureOrg      = "acme"
	fixtureOtherOrg = "globex"
	fixturePolicy   = "sys_pii_ssn"
	fixtureStamp    = "2026-01-01T00:00:00.000000000Z"
)

// col renders a value as a captured column.
func col(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling fixture column: %v", err)
	}
	return b
}

// staticFixtureRow builds a COMPLETE static_policies capture row and then
// applies the overrides.
//
// Building from a complete row is deliberate: a fixture listing only the
// columns a case cares about trips the compiler's capture-incomplete arm, and
// every test would then assert the same thing about a malformed capture rather
// than about the case it was written for.
func staticFixtureRow(t *testing.T, policyID, orgScope string, overrides map[string]any) legacycompile.RawRow {
	t.Helper()
	base := map[string]any{
		"id":              "00000000-0000-0000-0000-00000000000" + policyID[len(policyID)-1:],
		"policy_id":       policyID,
		"name":            policyID,
		"category":        "pii-us",
		"pattern":         `\d{3}-\d{2}-\d{4}`,
		"severity":        "high",
		"tier":            "system",
		"tenant_id":       orgScope,
		"org_id":          orgScope,
		"priority":        100,
		"enabled":         true,
		"phase":           "both",
		"action_request":  "block",
		"action_response": "redact",
		"action":          "block",
		"segment_id":      nil,
		"version":         1,
		"metadata":        map[string]any{},
		"deleted_at":      nil,
		"created_at":      "2026-01-01T00:00:00Z",
		"updated_at":      "2026-01-01T00:00:00Z",
	}
	for k, v := range overrides {
		base[k] = v
	}
	cols := map[string]json.RawMessage{}
	for k, v := range base {
		cols[k] = col(t, v)
	}
	return legacycompile.RawRow{Table: "static_policies", OrgScope: orgScope, Columns: cols}
}

// staticRows is the fixture row source's content for one org scope.
func staticRows(t *testing.T, orgScope string) []legacycompile.RawRow {
	t.Helper()
	return []legacycompile.RawRow{staticFixtureRow(t, fixturePolicy, orgScope, nil)}
}

// fixtureRowSource serves canned raw rows and counts its reads, so a test can
// tell a cache hit from a miss.
type fixtureRowSource struct {
	mu    sync.Mutex
	byOrg map[string][]legacycompile.RawRow
	reads int
	err   error
}

func (s *fixtureRowSource) RawRows(_ context.Context, orgScope string) ([]legacycompile.RawRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.err != nil {
		return nil, s.err
	}
	return s.byOrg[orgScope], nil
}

func (s *fixtureRowSource) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// capturingRecorder collects every comparison, so a test can assert on the
// classification rather than on a log line.
type capturingRecorder struct {
	mu   sync.Mutex
	got  []Comparison
	done chan struct{}
	want int
}

func newCapturingRecorder(want int) *capturingRecorder {
	return &capturingRecorder{done: make(chan struct{}), want: want}
}

func (r *capturingRecorder) RecordComparison(_ context.Context, c Comparison) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, c)
	if r.want > 0 && len(r.got) == r.want {
		close(r.done)
	}
}

// wait blocks until the expected number of comparisons arrived, or fails.
//
// It waits on a CHANNEL rather than sleeping, because the evaluation is
// asynchronous by design and a sleep long enough to be reliable is a sleep long
// enough to slow every run - and a sleep short enough not to would make this
// suite flaky in exactly the direction that hides a regression: a shadow that
// records nothing looks identical to one that has not finished.
func (r *capturingRecorder) wait(t *testing.T) []Comparison {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(30 * time.Second):
		r.mu.Lock()
		n := len(r.got)
		r.mu.Unlock()
		t.Fatalf("waited 30s for %d comparison(s) and got %d", r.want, n)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Comparison(nil), r.got...)
}

// fixtureOrgModes answers a recorded mode per organization. An org absent from
// the map has NO record, which is the ordinary state.
type fixtureOrgModes struct {
	modes map[string]identity.CompatMode
	err   error
}

func (f fixtureOrgModes) OrgDecisionShadowMode(_ context.Context, orgID string) (identity.CompatMode, bool, error) {
	if f.err != nil {
		return identity.CompatModeUnspecified, false, f.err
	}
	m, ok := f.modes[orgID]
	if !ok {
		return identity.CompatModeUnspecified, false, nil
	}
	return m, true, nil
}

// fixtureConfig is a usable configuration with the queue and pool sized so a
// test never races the workers.
func fixtureConfig(mode Mode) Config {
	return Config{Mode: mode, SampleRate: 1, QueueDepth: 64, Workers: 2}
}

// fixtureObservation is a complete, valid observation on the gateway plane.
func fixtureObservation(matched bool, executable bool) Observation {
	return Observation{
		Plane:     legacycompile.PlaneGatewayRequest,
		OrgScope:  fixtureOrg,
		OrgID:     fixtureOrg,
		Principal: "alice",
		Action:    "postgres.query",
		Legacy:    LegacyOutcome{Executable: executable},
		Rows: []RowFact{{
			Table:     "static_policies",
			PolicyID:  fixturePolicy,
			Category:  "pii-us",
			UpdatedAt: fixtureStamp,
			Ran:       true,
			Matched:   matched,
			Action:    matchedAction(matched),
		}},
	}
}

func matchedAction(matched bool) string {
	if matched {
		return "block"
	}
	return ""
}

// newFixtureObserver wires an observer over the fixture row source, and stops
// it when the test ends.
func newFixtureObserver(t *testing.T, cfg Config, rec Recorder, opts ...Option) (*Observer, *fixtureRowSource) {
	t.Helper()
	src := &fixtureRowSource{byOrg: map[string][]legacycompile.RawRow{
		fixtureOrg:      staticRows(t, fixtureOrg),
		fixtureOtherOrg: staticRows(t, fixtureOtherOrg),
	}}
	o, err := NewObserver(cfg, src, rec, append([]Option{WithComponent("test")}, opts...)...)
	if err != nil {
		t.Fatalf("building the observer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = o.Shutdown(ctx)
	})
	return o, src
}
