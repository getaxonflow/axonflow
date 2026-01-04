// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"axonflow/platform/orchestrator/replay"
)

// ReplayServiceAdapter adapts the replay.Service to the ReplayRecorder interface
type ReplayServiceAdapter struct {
	service *replay.Service
}

// NewReplayServiceAdapter creates a new adapter wrapping the replay service
func NewReplayServiceAdapter(service *replay.Service) *ReplayServiceAdapter {
	return &ReplayServiceAdapter{service: service}
}

// StartExecution starts tracking a new workflow execution
func (a *ReplayServiceAdapter) StartExecution(ctx context.Context, requestID, workflowName string, totalSteps int, orgID, tenantID, userID string) error {
	return a.service.StartExecution(ctx, requestID, workflowName, totalSteps, orgID, tenantID, userID)
}

// RecordStep records a step execution snapshot
func (a *ReplayServiceAdapter) RecordStep(ctx context.Context, snapshot *ReplaySnapshotInput) error {
	if snapshot == nil {
		return nil
	}

	// Convert to replay package's ExecutionSnapshot type
	execSnapshot := &replay.ExecutionSnapshot{
		RequestID:         snapshot.RequestID,
		StepIndex:         snapshot.StepIndex,
		StepName:          snapshot.StepName,
		Status:            replay.StepStatus(snapshot.Status),
		StartedAt:         snapshot.StartedAt,
		CompletedAt:       snapshot.CompletedAt,
		DurationMs:        snapshot.DurationMs,
		Input:             snapshot.Input,
		Output:            snapshot.Output,
		Provider:          snapshot.Provider,
		Model:             snapshot.Model,
		TokensIn:          snapshot.TokensIn,
		TokensOut:         snapshot.TokensOut,
		CostUSD:           snapshot.CostUSD,
		ErrorMessage:      snapshot.Error,
		PoliciesChecked:   []string{},
		PoliciesTriggered: []replay.PolicyEvent{},
	}

	return a.service.RecordStep(ctx, execSnapshot)
}

// CompleteExecution marks an execution as completed
func (a *ReplayServiceAdapter) CompleteExecution(ctx context.Context, requestID string, outputSummary json.RawMessage) error {
	return a.service.CompleteExecution(ctx, requestID, outputSummary)
}

// FailExecution marks an execution as failed
func (a *ReplayServiceAdapter) FailExecution(ctx context.Context, requestID string, errorMessage string) error {
	return a.service.FailExecution(ctx, requestID, errorMessage)
}
