// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// Repository defines the webhook storage interface.
type Repository interface {
	CreateSubscription(ctx context.Context, sub *Subscription) error
	GetSubscription(ctx context.Context, id string) (*Subscription, error)
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

func (r *PostgresRepository) GetSubscription(ctx context.Context, id string) (*Subscription, error) {
	query := `SELECT id, url, events, secret, active, tenant_id, org_id, description, created_at, updated_at
		FROM webhook_subscriptions WHERE id = $1`

	var sub Subscription
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&sub.ID, &sub.URL, pq.Array(&sub.Events), &sub.Secret, &sub.Active,
		&sub.TenantID, &sub.OrgID, &sub.Description, &sub.CreatedAt, &sub.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("webhook subscription not found: %s", id)
	}
	return &sub, err
}

func (r *PostgresRepository) UpdateSubscription(ctx context.Context, sub *Subscription, tenantID, orgID string) error {
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
