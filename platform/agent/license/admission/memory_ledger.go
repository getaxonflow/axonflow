// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"sync"
	"time"
)

// MemoryLedger is an in-memory Ledger and NodeLeases for tests in OTHER
// packages (the agent's and the orchestrator's unit tests wire an Admitter
// over it to exercise a refusal without a database). It is not a production
// store and nothing in run.go constructs it: the census in
// callsite_census_test.go would not notice, so the guard is the constructor's
// name and this comment. The package's own tests use the richer private
// fakes in admission_test.go.
type MemoryLedger struct {
	mu     sync.Mutex
	rows   map[Key]bool
	leases map[string]map[string]time.Time
	// down makes every call fail, to model an outage. Set it with SetDown:
	// the package spawns background work, so an unsynchronised field write
	// races those goroutines under -race.
	down bool
}

// SetDown makes every call fail (or stop failing), to model an outage.
func (m *MemoryLedger) SetDown(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.down = v
}

// NewMemoryLedger returns an empty in-memory ledger.
func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{rows: map[Key]bool{}, leases: map[string]map[string]time.Time{}}
}

func (m *MemoryLedger) fail() error {
	if m.down {
		return errDown
	}
	return nil
}

// Exists implements Ledger.
func (m *MemoryLedger) Exists(_ context.Context, k Key) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	return m.rows[k], nil
}

// AdmitUnderLimit implements Ledger.
func (m *MemoryLedger) AdmitUnderLimit(_ context.Context, k Key, limit int, _ string) (Outcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return Outcome{}, err
	}
	out := Outcome{}
	for row := range m.rows {
		if row.OrgID == k.OrgID && row.Dimension == k.Dimension {
			out.Count++
		}
	}
	if m.rows[k] {
		out.Existing = true
		return out, nil
	}
	if limit < 0 || out.Count >= limit {
		return out, nil
	}
	m.rows[k] = true
	out.Admitted = true
	return out, nil
}

// Record implements Ledger.
func (m *MemoryLedger) Record(_ context.Context, k Key, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	m.rows[k] = true
	return nil
}

// Recent implements Ledger.
func (m *MemoryLedger) Recent(_ context.Context, orgID string, n int) ([]Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var keys []Key
	for k := range m.rows {
		if k.OrgID == orgID && len(keys) < n {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// Renew implements NodeLeases.
func (m *MemoryLedger) Renew(_ context.Context, orgID, nodeID string, ttl time.Duration, limit int) (Outcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return Outcome{}, err
	}
	now := time.Now()
	leases := m.leases[orgID]
	if leases == nil {
		leases = map[string]time.Time{}
		m.leases[orgID] = leases
	}
	out := Outcome{}
	for id, seen := range leases {
		if id != nodeID && !seen.Before(now.Add(-ttl)) {
			out.Count++
		}
	}
	// HELD = holds an UNEXPIRED lease, mirroring PostgresNodeLeases. See the
	// comment there for why a bare existence check bypasses the ceiling.
	if seen, held := leases[nodeID]; held && !seen.Before(now.Add(-ttl)) {
		leases[nodeID] = now
		out.Existing = true
		return out, nil
	}
	if limit < 0 || out.Count >= limit {
		return out, nil
	}
	leases[nodeID] = now
	out.Admitted = true
	return out, nil
}

// Rows reports how many ledger rows the org holds on a dimension.
func (m *MemoryLedger) Rows(orgID string, d Dimension) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k := range m.rows {
		if k.OrgID == orgID && k.Dimension == d {
			n++
		}
	}
	return n
}

type downError struct{}

func (downError) Error() string { return "admission memory ledger: down" }

var errDown error = downError{}
