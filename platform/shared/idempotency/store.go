// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package idempotency provides HTTP Idempotency-Key dedup for handlers that
// must be safe under client-side Retry on Fail. A small Postgres-backed store
// caches the original response envelope keyed by (key, tenant_id, endpoint);
// a retry within TTL gets back the cached response byte-for-byte so no double
// row creation, no double audit record, no double policy-engine work happens.
//
// Wired into the agent's /api/v1/mcp/check-input + /api/v1/hitl/queue and the
// orchestrator's /api/v1/audit/tool-call per Issue #2420. Backing table is
// migrations/core/115_idempotency_keys.sql.
package idempotency

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"axonflow/platform/agent/rls"
)

// DefaultTTL is the cache lifetime for a stored response. n8n's Retry-on-Fail
// pattern wraps short bursts; ADK plugin idempotency keys also recycle within
// a single workflow execution. 24h covers both with margin.
const DefaultTTL = 24 * time.Hour

// MaxKeyLength caps the Idempotency-Key header value. 256 chars matches the
// IETF draft (https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/)
// and is generous for typical workflow IDs.
const MaxKeyLength = 256

// keyPattern restricts to URL-safe characters; rejects whitespace, control
// chars, and shell metachars. Workflow IDs from n8n / ADK / generic SDKs
// all fall inside this set.
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:\-/]+$`)

// ErrKeyTooLong is returned when an Idempotency-Key exceeds MaxKeyLength.
var ErrKeyTooLong = errors.New("idempotency: key exceeds max length")

// ErrKeyInvalid is returned when the key contains disallowed characters.
var ErrKeyInvalid = errors.New("idempotency: key contains invalid characters")

// ErrKeyEmpty is returned when the header is present but empty after trim.
var ErrKeyEmpty = errors.New("idempotency: key is empty")

// CachedResponse is the stored envelope returned on a cache hit.
type CachedResponse struct {
	StatusCode int
	Body       []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Store provides Postgres-backed idempotency dedup. Constructed once per
// process with two pools: appDB runs per-tenant Lookup/Store wrapped in
// WithOrgAndTenantScope (axonflow_app_role under FORCE RLS); adminDB runs
// the cross-tenant Sweep (axonflow_platform_admin / BYPASSRLS). Either pool
// may be nil — Lookup/Store no-op if appDB is nil; Sweep no-ops if adminDB
// is nil (e.g. dev/community deployments without a separate admin pool).
type Store struct {
	appDB   *sql.DB
	adminDB *sql.DB
}

// NewStore wires a Store around the given pools. See the Store doc for the
// appDB vs adminDB split.
func NewStore(appDB, adminDB *sql.DB) *Store {
	return &Store{appDB: appDB, adminDB: adminDB}
}

// ValidateKey runs the syntactic checks the middleware applies before any
// DB roundtrip. Exposed so handlers can fail fast on bad keys without
// touching the store.
func ValidateKey(key string) error {
	if key == "" {
		return ErrKeyEmpty
	}
	if len(key) > MaxKeyLength {
		return ErrKeyTooLong
	}
	if !keyPattern.MatchString(key) {
		return ErrKeyInvalid
	}
	return nil
}

// Enabled reports whether per-tenant lookup/store will operate. False when
// the appDB pool was not wired (community boot path with no DB). Handlers
// can short-circuit the Idempotency-Key code path on false rather than
// paying the validate+log cost.
func (s *Store) Enabled() bool {
	return s != nil && s.appDB != nil
}

// Lookup checks for a non-expired cached response. Returns (nil, nil) on miss
// and (response, nil) on hit; an error means the lookup itself failed and the
// caller should fall through to normal processing (a cache lookup failure
// must never block the request).
//
// orgID + tenantID are used to scope the read under FORCE RLS via
// rls.WithOrgAndTenantScope. The PK constraint already pins the read to a
// single row but the RLS wrap is required by the v9 Phase 8 policy.
func (s *Store) Lookup(ctx context.Context, orgID, tenantID, key, endpoint string) (*CachedResponse, error) {
	if s == nil || s.appDB == nil {
		return nil, errors.New("idempotency: appDB is nil")
	}
	if orgID == "" || tenantID == "" || key == "" || endpoint == "" {
		return nil, errors.New("idempotency: orgID, tenantID, key, and endpoint must be non-empty")
	}

	var cached *CachedResponse
	err := rls.WithOrgAndTenantScope(ctx, s.appDB, orgID, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT status_code, response_body, created_at, expires_at
			FROM idempotency_keys
			WHERE key = $1 AND tenant_id = $2 AND endpoint = $3
			  AND expires_at > CURRENT_TIMESTAMP
		`, key, tenantID, endpoint)

		var statusCode int
		var body []byte
		var createdAt, expiresAt time.Time
		if err := row.Scan(&statusCode, &body, &createdAt, &expiresAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		cached = &CachedResponse{
			StatusCode: statusCode,
			Body:       body,
			CreatedAt:  createdAt,
			ExpiresAt:  expiresAt,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("idempotency lookup: %w", err)
	}
	return cached, nil
}

// Store writes a response envelope. On PK collision (race between two
// concurrent retries) the second writer is a no-op — the first writer's
// response is what subsequent readers get. The race is impossible to
// observe by the caller: both writers return nil, both subsequent reads
// return the same row.
//
// ttl <= 0 falls back to DefaultTTL. Callers can pass a shorter TTL if
// the endpoint's natural staleness window is shorter (e.g. policy
// decisions that depend on hot-reloaded config).
func (s *Store) Store(ctx context.Context, orgID, tenantID, key, endpoint string, statusCode int, body []byte, ttl time.Duration) error {
	if s == nil || s.appDB == nil {
		return errors.New("idempotency: appDB is nil")
	}
	if orgID == "" || tenantID == "" || key == "" || endpoint == "" {
		return errors.New("idempotency: orgID, tenantID, key, and endpoint must be non-empty")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	expiresAt := time.Now().Add(ttl)

	return rls.WithOrgAndTenantScope(ctx, s.appDB, orgID, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO idempotency_keys (key, tenant_id, endpoint, status_code, response_body, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (key, tenant_id, endpoint) DO NOTHING
		`, key, tenantID, endpoint, statusCode, body, expiresAt)
		return err
	})
}

// Sweep deletes expired rows across all tenants using the admin pool
// (BYPASSRLS). Returns the number of rows removed. Safe to call
// concurrently with reads/writes — DELETE on expired rows races
// harmlessly with INSERT on new keys (different PKs).
//
// No-op when adminDB is nil (community boot path with no separate admin
// pool). Production agent + orchestrator deployments always wire one via
// OpenPlatformAdminConnection.
func (s *Store) Sweep(ctx context.Context) (int64, error) {
	if s == nil || s.adminDB == nil {
		return 0, nil
	}
	res, err := s.adminDB.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE expires_at <= CURRENT_TIMESTAMP`)
	if err != nil {
		return 0, fmt.Errorf("idempotency sweep: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
