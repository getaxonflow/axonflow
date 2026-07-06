// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

// Package usage provides usage metering and billing support for AxonFlow.
//
// This is the Community Edition stub - Usage metering is an Enterprise feature.
// Upgrade to Enterprise at https://getaxonflow.com/enterprise for:
//   - API call usage tracking and analytics
//   - LLM token usage and cost tracking
//   - Usage-based billing support
//   - Usage dashboards and reporting
package usage

import (
	"context"
	"database/sql"
)

// NewUsageRecorder creates a new usage recorder.
// Community Edition: Returns a no-op recorder.
func NewUsageRecorder(db *sql.DB) *UsageRecorder {
	return &UsageRecorder{}
}

// RecordAPICall records an API call event to the database.
// Community Edition: No-op implementation.
func (r *UsageRecorder) RecordAPICall(event APICallEvent) error {
	return nil
}

// RecordLLMRequest records an LLM API call event with token usage and cost.
// Community Edition: No-op implementation.
func (r *UsageRecorder) RecordLLMRequest(event LLMRequestEvent) error {
	return nil
}

// RecordOTELMetrics persists OTLP metric datapoints as usage rows.
// Community Edition: No-op implementation (the /v1/metrics ingest is an
// Enterprise feature; the community agent mounts a 501 stub).
func (r *UsageRecorder) RecordOTELMetrics(ctx context.Context, orgID string, events []OTELMetricEvent) (int, error) {
	return 0, nil
}
