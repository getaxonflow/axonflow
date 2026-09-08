// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"time"

	"axonflow/platform/agent/rls"
)

// NodeLeaseTTL is how long a lease counts after its last renewal. The wiring
// renews every NodeHeartbeatInterval, so a node is over-counted for at most
// the TTL after it dies, and a genuinely new replica that replaces a dead one
// waits at most the TTL before it is admitted on a single-node tier.
const (
	NodeLeaseTTL          = 3 * time.Minute
	NodeHeartbeatInterval = 30 * time.Second
	// nodeLeaseRetention is how long an expired lease row is kept before the
	// renewal path prunes it. Long enough to read a recent history, short
	// enough that ephemeral replica ids do not accumulate without bound.
	nodeLeaseRetention = 7 * 24 * time.Hour
)

// NodeLeases is the concurrency store for the node dimension (master ruling,
// 2026-09-08): a node is counted while its lease is unexpired, not forever.
type NodeLeases interface {
	// Renew admits nodeID for org under limit, atomically with respect to
	// other nodes of the same org:
	//   - a node that already holds a lease renews it and reports Existing,
	//     whatever the count (the same node restarting inside the TTL is one
	//     node, and an existing node is never refused);
	//   - a node with no lease is admitted (Admitted) when fewer than limit
	//     OTHER leases are unexpired, else refused with Count = that number.
	Renew(ctx context.Context, orgID, nodeID string, ttl time.Duration, limit int) (Outcome, error)
}

// PostgresNodeLeases is NodeLeases over migrations/core/171's node_leases.
type PostgresNodeLeases struct {
	db *sql.DB
}

// NewPostgresNodeLeases wraps an application-role pool.
func NewPostgresNodeLeases(db *sql.DB) *PostgresNodeLeases { return &PostgresNodeLeases{db: db} }

// Renew implements NodeLeases. The per-org advisory lock serializes two new
// nodes racing for the last slot, exactly as the ledger does per (org,
// dimension). Expired rows older than the retention are pruned on the way,
// so the table cannot grow without bound under rolling replica ids.
func (l *PostgresNodeLeases) Renew(ctx context.Context, orgID, nodeID string, ttl time.Duration, limit int) (Outcome, error) {
	if l == nil || l.db == nil {
		return Outcome{}, fmt.Errorf("node leases: no database")
	}
	if limit < 0 {
		return Outcome{}, fmt.Errorf("node leases: Renew called with the unlimited sentinel %d; Admit must short-circuit before the store", limit)
	}
	if ttl <= 0 {
		return Outcome{}, fmt.Errorf("node leases: non-positive ttl %v", ttl)
	}
	ttlInterval := fmt.Sprintf("%d seconds", int(ttl.Seconds()))
	var out Outcome
	err := rls.WithOrgScope(ctx, l.db, orgID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, nodeLockKey(orgID)); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM node_leases WHERE org_id = $1 AND last_seen < now() - $2::interval`,
			orgID, fmt.Sprintf("%d seconds", int(nodeLeaseRetention.Seconds()))); err != nil {
			return fmt.Errorf("prune: %w", err)
		}
		// HELD MEANS "HOLDS AN UNEXPIRED LEASE", AND THE TTL PREDICATE IS THE
		// WHOLE POINT OF THE CHECK. Without it a row that merely EXISTS renews
		// unconditionally, and rows survive nodeLeaseRetention (7 days) - so a
		// node that held the lease at any point in the last week would renew
		// past the ceiling forever. Concretely, on Community: A takes the
		// lease and dies; four minutes later B is admitted because A's lease
		// expired; A restarts under the same id, finds its own stale row, and
		// both renew for ever with no refusal, no metric and no audit row.
		// Found by R3 round 1 on #3593.
		var held bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM node_leases
			                 WHERE org_id = $1 AND node_id = $2
			                   AND last_seen >= now() - $3::interval)`,
			orgID, nodeID, ttlInterval).Scan(&held); err != nil {
			return fmt.Errorf("held: %w", err)
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM node_leases
			  WHERE org_id = $1 AND node_id <> $2 AND last_seen >= now() - $3::interval`,
			orgID, nodeID, ttlInterval).Scan(&out.Count); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		if held {
			if _, err := tx.ExecContext(ctx,
				`UPDATE node_leases SET last_seen = now() WHERE org_id = $1 AND node_id = $2`,
				orgID, nodeID); err != nil {
				return fmt.Errorf("renew: %w", err)
			}
			out.Existing = true
			return nil
		}
		if out.Count >= limit {
			return nil // refused
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_leases (org_id, node_id) VALUES ($1, $2)
			 ON CONFLICT (org_id, node_id) DO UPDATE SET last_seen = now()`,
			orgID, nodeID); err != nil {
			return fmt.Errorf("lease: %w", err)
		}
		out.Admitted = true
		return nil
	})
	if err != nil {
		return Outcome{}, fmt.Errorf("node leases: renew: %w", err)
	}
	return out, nil
}

func nodeLockKey(orgID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("node_leases\x00"))
	_, _ = h.Write([]byte(orgID))
	return int64(h.Sum64())
}
