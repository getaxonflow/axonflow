// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"axonflow/platform/shared/tenantscope"
)

// Repository defines the webhook storage interface.
type Repository interface {
	CreateSubscription(ctx context.Context, sub *Subscription) error
	// GetSubscription is org/tenant-bound (#3065 F6). It deliberately does
	// NOT project the `secret` column — the HMAC signing key is needed only
	// on the delivery path (GetActiveSubscriptionsForEvent).
	GetSubscription(ctx context.Context, id, tenantID, orgID string) (*Subscription, error)
	UpdateSubscription(ctx context.Context, sub *Subscription, tenantID, orgID string) error
	DeleteSubscription(ctx context.Context, id, tenantID, orgID string) error
	ListSubscriptions(ctx context.Context, tenantID, orgID string) ([]Subscription, error)
	GetActiveSubscriptionsForEvent(ctx context.Context, eventType, tenantID, orgID string) ([]Subscription, error)
	RecordDelivery(ctx context.Context, delivery *Delivery) error
}

// PostgresRepository implements Repository with PostgreSQL.
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL-backed webhook repository.
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateSubscription(ctx context.Context, sub *Subscription) error {
	// #3065: webhook_subscriptions.tenant_id/org_id are NOT NULL DEFAULT '' —
	// the constraint exists and the default recreates the exploit value.
	// Refuse the write rather than persist a subscription owned by nobody.
	if err := requireSubscriptionScope(sub.ID, sub.TenantID, sub.OrgID); err != nil {
		return err
	}

	query := `INSERT INTO webhook_subscriptions (id, url, events, secret, active, tenant_id, org_id, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	now := time.Now()
	sub.CreatedAt = now
	sub.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, query,
		sub.ID, sub.URL, pq.Array(sub.Events), sub.Secret, sub.Active,
		sub.TenantID, sub.OrgID, sub.Description, sub.CreatedAt, sub.UpdatedAt)
	return err
}

// GetSubscription retrieves a subscription by id, bound to the caller's
// org/tenant.
//
// #3065 (F6): this was `WHERE id = $1` with no predicate and no post-fetch
// guard — while its siblings UpdateSubscription and DeleteSubscription both
// carried `AND tenant_id = $n AND org_id = $n`, which is what makes the
// omission an oversight rather than a design. The projection also included
// `secret`, the HMAC signing key a subscriber uses to authenticate our
// callbacks; the column is dropped here because only the delivery path needs
// it. webhook_subscriptions has no RLS, so this predicate is the only
// boundary.
//
// The tenancy columns are NOT NULL DEFAULT empty-string (migrations/core/048),
// so rows written before the headers existed carry the empty string.
// requireSubscriptionScope refuses an empty caller value, and migration
// core/156 drops that default and stamps those rows with the unowned
// sentinel, so an empty key cannot match anything.
func (r *PostgresRepository) GetSubscription(ctx context.Context, id, tenantID, orgID string) (*Subscription, error) {
	if err := requireSubscriptionScope(id, tenantID, orgID); err != nil {
		return nil, err
	}

	query := `SELECT id, url, events, active, tenant_id, org_id, description, created_at, updated_at
		FROM webhook_subscriptions WHERE id = $1 AND tenant_id = $2 AND org_id = $3`

	var sub Subscription
	err := r.db.QueryRowContext(ctx, query, id, tenantID, orgID).Scan(
		&sub.ID, &sub.URL, pq.Array(&sub.Events), &sub.Active,
		&sub.TenantID, &sub.OrgID, &sub.Description, &sub.CreatedAt, &sub.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("webhook subscription not found: %s", id)
	}
	return &sub, err
}

// requireSubscriptionScope is the fail-closed precondition for the by-id
// webhook statements. An empty caller org or tenant is a denial, reported as
// the same not-found error a genuinely missing id yields.
func requireSubscriptionScope(id, tenantID, orgID string) error {
	if err := tenantscope.ValidateRowKeys(orgID, tenantID); err != nil {
		return fmt.Errorf("webhook subscription not found: %s", id)
	}
	return nil
}

func (r *PostgresRepository) UpdateSubscription(ctx context.Context, sub *Subscription, tenantID, orgID string) error {
	if err := requireSubscriptionScope(sub.ID, tenantID, orgID); err != nil {
		return err
	}

	query := `UPDATE webhook_subscriptions SET url = $1, events = $2, active = $3, description = $4, updated_at = NOW()
		WHERE id = $5 AND tenant_id = $6 AND org_id = $7`

	result, err := r.db.ExecContext(ctx, query, sub.URL, pq.Array(sub.Events), sub.Active, sub.Description, sub.ID, tenantID, orgID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("webhook subscription not found: %s", sub.ID)
	}
	return nil
}

func (r *PostgresRepository) DeleteSubscription(ctx context.Context, id, tenantID, orgID string) error {
	if err := requireSubscriptionScope(id, tenantID, orgID); err != nil {
		return err
	}

	result, err := r.db.ExecContext(ctx, `DELETE FROM webhook_subscriptions WHERE id = $1 AND tenant_id = $2 AND org_id = $3`, id, tenantID, orgID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("webhook subscription not found: %s", id)
	}
	return nil
}

func (r *PostgresRepository) ListSubscriptions(ctx context.Context, tenantID, orgID string) ([]Subscription, error) {
	if err := requireSubscriptionScope("*", tenantID, orgID); err != nil {
		return nil, err
	}

	query := `SELECT id, url, events, active, tenant_id, org_id, description, created_at, updated_at
		FROM webhook_subscriptions WHERE tenant_id = $1 AND org_id = $2 ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, tenantID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.ID, &sub.URL, pq.Array(&sub.Events), &sub.Active,
			&sub.TenantID, &sub.OrgID, &sub.Description, &sub.CreatedAt, &sub.UpdatedAt); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

func (r *PostgresRepository) GetActiveSubscriptionsForEvent(ctx context.Context, eventType, tenantID, orgID string) ([]Subscription, error) {
	// #3065: the delivery path is the one place the HMAC secret is projected.
	// An unscoped call would fan a tenant's event out to every tenant's
	// endpoints, secret included.
	if err := requireSubscriptionScope(eventType, tenantID, orgID); err != nil {
		return nil, err
	}

	query := `SELECT id, url, events, secret, active, tenant_id, org_id, description, created_at, updated_at
		FROM webhook_subscriptions
		WHERE active = true AND tenant_id = $1 AND org_id = $2 AND $3 = ANY(events)
		ORDER BY created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, tenantID, orgID, eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.ID, &sub.URL, pq.Array(&sub.Events), &sub.Secret, &sub.Active,
			&sub.TenantID, &sub.OrgID, &sub.Description, &sub.CreatedAt, &sub.UpdatedAt); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

func (r *PostgresRepository) RecordDelivery(ctx context.Context, delivery *Delivery) error {
	query := `INSERT INTO webhook_deliveries (subscription_id, event_type, payload, status, attempts, last_attempt_at, response_status, response_body, error, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.db.ExecContext(ctx, query,
		delivery.SubscriptionID, delivery.EventType, delivery.Payload, delivery.Status,
		delivery.Attempts, delivery.LastAttemptAt, delivery.ResponseStatus, delivery.ResponseBody,
		delivery.Error, delivery.CreatedAt)
	return err
}
