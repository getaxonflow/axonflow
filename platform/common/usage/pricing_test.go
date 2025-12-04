// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package usage

import (
	"testing"
)

func TestCalculateCost(t *testing.T) {
	tests := []struct {
		name             string
		provider         string
		model            string
		promptTokens     int
		completionTokens int
		expectedCents    int
	}{
		{
			name:             "OpenAI GPT-4 basic",
			provider:         "openai",
			model:            "gpt-4",
			promptTokens:     100,
			completionTokens: 200,
			expectedCents:    (100 * 3000 / 1000) + (200 * 6000 / 1000), // 300 + 1200 = 1500 cents
		},
		{
			name:             "OpenAI GPT-3.5 Turbo",
			provider:         "openai",
			model:            "gpt-3.5-turbo",
			promptTokens:     1000,
			completionTokens: 500,
			expectedCents:    (1000 * 50 / 1000) + (500 * 150 / 1000), // 50 + 75 = 125 cents
		},
		{
			name:             "Anthropic Claude 3 Sonnet",
			provider:         "anthropic",
			model:            "claude-3-sonnet",
			promptTokens:     500,
			completionTokens: 300,
			expectedCents:    (500 * 300 / 1000) + (300 * 1500 / 1000), // 150 + 450 = 600 cents
		},
		{
			name:             "Anthropic Claude 3 Haiku",
			provider:         "anthropic",
			model:            "claude-3-haiku",
			promptTokens:     1000,
			completionTokens: 1000,
			expectedCents:    (1000 * 25 / 1000) + (1000 * 125 / 1000), // 25 + 125 = 150 cents
		},
		{
			name:             "Unknown provider defaults to fallback pricing",
			provider:         "unknown",
			model:            "unknown-model",
			promptTokens:     100,
			completionTokens: 100,
			expectedCents:    (100 * 1000 / 1000) + (100 * 3000 / 1000), // 100 + 300 = 400 cents
		},
		{
			name:             "Zero tokens",
			provider:         "openai",
			model:            "gpt-4",
			promptTokens:     0,
			completionTokens: 0,
			expectedCents:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := CalculateCost(tt.provider, tt.model, tt.promptTokens, tt.completionTokens)
			if cost != tt.expectedCents {
				t.Errorf("CalculateCost() = %d cents, want %d cents", cost, tt.expectedCents)
			}
		})
	}
}

func TestGetProviderPricing(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		model    string
		wantOk   bool
	}{
		{"OpenAI GPT-4", "openai", "gpt-4", true},
		{"Anthropic Claude 3 Opus", "anthropic", "claude-3-opus", true},
		{"Unknown provider", "unknown", "model", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := GetProviderPricing(tt.provider, tt.model)
			if ok != tt.wantOk {
				t.Errorf("GetProviderPricing() ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}

func TestFormatCostToDollars(t *testing.T) {
	tests := []struct {
		name  string
		cents int
		want  string
	}{
		{"Zero cents", 0, "$0.00"},
		{"One dollar", 100, "$1.00"},
		{"One cent", 1, "$0.01"},
		{"Complex amount", 1234, "$12.34"},
		{"Large amount", 123456, "$1234.56"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatCostToDollars(tt.cents)
			if got != tt.want {
				t.Errorf("FormatCostToDollars(%d) = %q, want %q", tt.cents, got, tt.want)
			}
		})
	}
}

// Benchmark tests
func BenchmarkCalculateCost(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CalculateCost("openai", "gpt-4", 150, 300)
	}
}
