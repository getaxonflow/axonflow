package orchestrator

import (
	"testing"
	"time"
)

func TestCalculatePercentile(t *testing.T) {
	collector := NewMetricsCollector()

	tests := []struct {
		name       string
		times      []time.Duration
		percentile int
		want       time.Duration
	}{
		{
			name:       "empty slice",
			times:      []time.Duration{},
			percentile: 50,
			want:       0,
		},
		{
			name:       "single value - p50",
			times:      []time.Duration{100 * time.Millisecond},
			percentile: 50,
			want:       100 * time.Millisecond,
		},
		{
			name:       "multiple values - p50",
			times:      []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond},
			percentile: 50,
			want:       30 * time.Millisecond,
		},
		{
			name:       "multiple values - p95",
			times:      []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond},
			percentile: 95,
			want:       50 * time.Millisecond,
		},
		{
			name:       "multiple values - p99",
			times:      []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond},
			percentile: 99,
			want:       50 * time.Millisecond,
		},
		{
			name:       "percentile beyond array bounds",
			times:      []time.Duration{10 * time.Millisecond, 20 * time.Millisecond},
			percentile: 100,
			want:       20 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collector.calculatePercentile(tt.times, tt.percentile)

			if result != tt.want {
				t.Errorf("Expected %v, got %v", tt.want, result)
			}
		})
	}
}

func TestGetRiskScoreBucket(t *testing.T) {
	collector := NewMetricsCollector()

	tests := []struct {
		name  string
		score float64
		want  string
	}{
		{
			name:  "very low - 0.0",
			score: 0.0,
			want:  "very_low",
		},
		{
			name:  "very low - 0.1",
			score: 0.1,
			want:  "very_low",
		},
		{
			name:  "low - 0.2",
			score: 0.2,
			want:  "low",
		},
		{
			name:  "low - 0.3",
			score: 0.3,
			want:  "low",
		},
		{
			name:  "medium - 0.4",
			score: 0.4,
			want:  "medium",
		},
		{
			name:  "medium - 0.5",
			score: 0.5,
			want:  "medium",
		},
		{
			name:  "high - 0.6",
			score: 0.6,
			want:  "high",
		},
		{
			name:  "high - 0.7",
			score: 0.7,
			want:  "high",
		},
		{
			name:  "very high - 0.8",
			score: 0.8,
			want:  "very_high",
		},
		{
			name:  "very high - 0.9",
			score: 0.9,
			want:  "very_high",
		},
		{
			name:  "very high - 1.0",
			score: 1.0,
			want:  "very_high",
		},
		{
			name:  "very high - above 1.0",
			score: 1.5,
			want:  "very_high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collector.getRiskScoreBucket(tt.score)

			if result != tt.want {
				t.Errorf("For score %.1f, expected bucket '%s', got '%s'", tt.score, tt.want, result)
			}
		})
	}
}
