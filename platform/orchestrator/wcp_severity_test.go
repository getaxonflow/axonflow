// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
)

func TestDeriveSeverityFromResult_ExplicitSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		risk     float64
		want     string
	}{
		{"explicit critical", "critical", 0.0, "critical"},
		{"explicit high", "high", 0.0, "high"},
		{"explicit medium", "medium", 0.0, "medium"},
		{"explicit low", "low", 0.0, "low"},
		// Explicit severity overrides risk score
		{"explicit low overrides high risk", "low", 0.9, "low"},
		{"explicit critical overrides low risk", "critical", 0.1, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &PolicyEvaluationResult{
				RiskScore: tt.risk,
				Severity:  tt.severity,
			}
			got := deriveSeverityFromResult(result)
			if got != tt.want {
				t.Errorf("deriveSeverityFromResult() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDeriveSeverityFromResult_RiskScoreFallback(t *testing.T) {
	tests := []struct {
		name string
		risk float64
		want string
	}{
		{"zero risk → low", 0.0, "low"},
		{"0.1 → low", 0.1, "low"},
		{"0.29 → low", 0.29, "low"},
		{"0.3 → medium", 0.3, "medium"},
		{"0.4 → medium", 0.4, "medium"},
		{"0.49 → medium", 0.49, "medium"},
		{"0.5 → high", 0.5, "high"},
		{"0.7 → high", 0.7, "high"},
		{"0.79 → high", 0.79, "high"},
		{"0.8 → critical", 0.8, "critical"},
		{"0.9 → critical", 0.9, "critical"},
		{"1.0 → critical", 1.0, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &PolicyEvaluationResult{
				RiskScore: tt.risk,
				// Severity empty → use risk score fallback
			}
			got := deriveSeverityFromResult(result)
			if got != tt.want {
				t.Errorf("deriveSeverityFromResult(risk=%.2f) = %q, want %q", tt.risk, got, tt.want)
			}
		})
	}
}

func TestDeriveSeverityFromResult_EmptyResult(t *testing.T) {
	result := &PolicyEvaluationResult{}
	got := deriveSeverityFromResult(result)
	if got != "low" {
		t.Errorf("empty result should default to low, got %q", got)
	}
}

func TestSeverityOrdinal(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"low", 0},
		{"medium", 1},
		{"high", 2},
		{"critical", 3},
		{"banana", -1},
		{"", -1},
	}
	for _, tt := range tests {
		got := severityOrdinal(tt.severity)
		if got != tt.want {
			t.Errorf("severityOrdinal(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestSeverityOrdinal_HighestWins(t *testing.T) {
	// Simulates two policies matching: first sets "medium", second sets "critical"
	result := &PolicyEvaluationResult{}

	// First policy: medium severity
	severity1 := "medium"
	if result.Severity == "" || severityOrdinal(severity1) > severityOrdinal(result.Severity) {
		result.Severity = severity1
	}
	if result.Severity != "medium" {
		t.Errorf("after first policy: expected medium, got %q", result.Severity)
	}

	// Second policy: critical severity (should win)
	severity2 := "critical"
	if result.Severity == "" || severityOrdinal(severity2) > severityOrdinal(result.Severity) {
		result.Severity = severity2
	}
	if result.Severity != "critical" {
		t.Errorf("after second policy: expected critical, got %q", result.Severity)
	}

	// Third policy: low severity (should NOT override critical)
	severity3 := "low"
	if result.Severity == "" || severityOrdinal(severity3) > severityOrdinal(result.Severity) {
		result.Severity = severity3
	}
	if result.Severity != "critical" {
		t.Errorf("after third policy: expected critical (highest wins), got %q", result.Severity)
	}
}
