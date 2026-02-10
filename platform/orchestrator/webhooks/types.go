// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package webhooks

import "time"

// Webhook event types
const (
	EventStepApprovalRequired = "step.approval_required"
	EventStepApproved         = "step.approved"
	EventStepRejected         = "step.rejected"
	EventStepCompleted        = "step.completed"
	EventWorkflowCompleted    = "workflow.completed"
	EventWorkflowAborted      = "workflow.aborted"
	EventWorkflowFailed       = "workflow.failed"
)

// AllEvents lists all supported event types.
var AllEvents = []string{
	EventStepApprovalRequired,
	EventStepApproved,
	EventStepRejected,
	EventStepCompleted,
	EventWorkflowCompleted,
	EventWorkflowAborted,
	EventWorkflowFailed,
}

// Subscription represents a webhook subscription.
type Subscription struct {
	ID          string    `json:"id" db:"id"`
	URL         string    `json:"url" db:"url"`
	Events      []string  `json:"events" db:"events"`
	Secret      string    `json:"-" db:"secret"` // Never exposed in API responses
	Active      bool      `json:"active" db:"active"`
	TenantID    string    `json:"tenant_id,omitempty" db:"tenant_id"`
	OrgID       string    `json:"org_id,omitempty" db:"org_id"`
	Description string    `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Delivery represents a webhook delivery attempt.
type Delivery struct {
	ID             int64      `json:"id" db:"id"`
	SubscriptionID string     `json:"subscription_id" db:"subscription_id"`
	EventType      string     `json:"event_type" db:"event_type"`
	Payload        []byte     `json:"payload" db:"payload"`
	Status         string     `json:"status" db:"status"` // pending, delivered, failed
	Attempts       int        `json:"attempts" db:"attempts"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty" db:"last_attempt_at"`
	ResponseStatus *int       `json:"response_status,omitempty" db:"response_status"`
	ResponseBody   string     `json:"response_body,omitempty" db:"response_body"`
	Error          string     `json:"error,omitempty" db:"error"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
}

// WebhookPayload is the payload sent to webhook endpoints.
type WebhookPayload struct {
	Event     string                 `json:"event"`
	Timestamp string                 `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// CreateSubscriptionRequest is the request to create a webhook subscription.
type CreateSubscriptionRequest struct {
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Secret      string   `json:"secret,omitempty"`
	Active      bool     `json:"active"`
	Description string   `json:"description,omitempty"`
}

// UpdateSubscriptionRequest is the request to update a webhook subscription.
type UpdateSubscriptionRequest struct {
	URL         *string  `json:"url,omitempty"`
	Events      []string `json:"events,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	Description *string  `json:"description,omitempty"`
}

// ListSubscriptionsResponse is the response for listing webhook subscriptions.
type ListSubscriptionsResponse struct {
	Webhooks []Subscription `json:"webhooks"`
	Total    int            `json:"total"`
}
