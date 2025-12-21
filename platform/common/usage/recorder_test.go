// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

package usage

import (
	"testing"
)

// TestNewUsageRecorder tests recorder creation
func TestNewUsageRecorder(t *testing.T) {
	recorder := NewUsageRecorder(nil)
	if recorder == nil {
		t.Error("NewUsageRecorder() returned nil")
	}
}

// TestAPICallEvent_Fields tests that APICallEvent has all required fields
func TestAPICallEvent_Fields(t *testing.T) {
	event := APICallEvent{
		OrgID:          "test-org",
		ClientID:       "test-client",
		InstanceID:     "agent-1",
		InstanceType:   "agent",
		HTTPMethod:     "POST",
		HTTPPath:       "/api/request",
		HTTPStatusCode: 200,
		LatencyMs:      15,
	}

	if event.OrgID == "" {
		t.Error("OrgID should not be empty")
	}
	if event.InstanceType != "agent" && event.InstanceType != "orchestrator" {
		t.Error("InstanceType should be 'agent' or 'orchestrator'")
	}
	if event.HTTPStatusCode < 100 || event.HTTPStatusCode > 599 {
		t.Error("HTTPStatusCode should be valid HTTP status code")
	}
	if event.LatencyMs < 0 {
		t.Error("LatencyMs should not be negative")
	}
}

// TestLLMRequestEvent_Fields tests that LLMRequestEvent has all required fields
func TestLLMRequestEvent_Fields(t *testing.T) {
	event := LLMRequestEvent{
		OrgID:            "test-org",
		ClientID:         "test-client",
		InstanceID:       "orchestrator-1",
		InstanceType:     "orchestrator",
		LLMProvider:      "openai",
		LLMModel:         "gpt-4",
		PromptTokens:     150,
		CompletionTokens: 300,
		TotalTokens:      450,
		LatencyMs:        2500,
		HTTPStatusCode:   200,
	}

	if event.OrgID == "" {
		t.Error("OrgID should not be empty")
	}
	if event.LLMProvider == "" {
		t.Error("LLMProvider should not be empty")
	}
	if event.LLMModel == "" {
		t.Error("LLMModel should not be empty")
	}
	if event.TotalTokens != event.PromptTokens+event.CompletionTokens {
		t.Error("TotalTokens should equal PromptTokens + CompletionTokens")
	}
}

// TestRecordAPICall_NoOp tests that RecordAPICall returns nil (no-op in community)
func TestRecordAPICall_NoOp(t *testing.T) {
	recorder := NewUsageRecorder(nil)
	err := recorder.RecordAPICall(APICallEvent{
		OrgID:      "test-org",
		InstanceID: "agent-1",
	})
	if err != nil {
		t.Errorf("RecordAPICall() should return nil, got: %v", err)
	}
}

// TestRecordLLMRequest_NoOp tests that RecordLLMRequest returns nil (no-op in community)
func TestRecordLLMRequest_NoOp(t *testing.T) {
	recorder := NewUsageRecorder(nil)
	err := recorder.RecordLLMRequest(LLMRequestEvent{
		OrgID:       "test-org",
		LLMProvider: "openai",
		LLMModel:    "gpt-4",
	})
	if err != nil {
		t.Errorf("RecordLLMRequest() should return nil, got: %v", err)
	}
}
