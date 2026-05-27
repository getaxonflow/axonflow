// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"testing"
)

func TestExtractPolicyNames_EmptyInput(t *testing.T) {
	result := extractPolicyNames(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestExtractPolicyNames_InvalidJSON(t *testing.T) {
	result := extractPolicyNames(json.RawMessage(`{invalid}`))
	if result != nil {
		t.Errorf("expected nil for invalid JSON, got %v", result)
	}
}

func TestExtractPolicyNames_ValidPolicies(t *testing.T) {
	raw := json.RawMessage(`[{"policy_id":"pol1","policy_name":"SQL Injection"},{"policy_id":"pol2","policy_name":""}]`)
	result := extractPolicyNames(raw)
	if len(result) != 2 {
		t.Errorf("expected 2 names, got %d", len(result))
	}
	if result[0] != "SQL Injection" {
		t.Errorf("expected 'SQL Injection', got %s", result[0])
	}
	if result[1] != "pol2" {
		t.Errorf("expected fallback to pol2, got %s", result[1])
	}
}

func TestExtractPolicyNames_EmptyArray(t *testing.T) {
	result := extractPolicyNames(json.RawMessage(`[]`))
	if result != nil {
		t.Errorf("expected nil for empty array, got %v", result)
	}
}

func TestExtractPolicyNames_AllEmpty(t *testing.T) {
	raw := json.RawMessage(`[{"policy_id":"","policy_name":""}]`)
	result := extractPolicyNames(raw)
	if result != nil {
		t.Errorf("expected nil when all names empty, got %v", result)
	}
}

func TestLoadLLMConfig_Defaults(t *testing.T) {
	cfg := LoadLLMConfig()
	// LoadLLMConfig reads env vars for API keys; without them set, keys are empty
	if cfg.OpenAIKey != "" {
		t.Log("OpenAI key set via env")
	}
}
