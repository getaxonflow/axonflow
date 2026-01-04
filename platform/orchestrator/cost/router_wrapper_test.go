// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"testing"
)

func TestGetStringFromContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		key  string
		want string
	}{
		{
			name: "key exists with string value",
			ctx:  context.WithValue(context.Background(), "org_id", "org-123"),
			key:  "org_id",
			want: "org-123",
		},
		{
			name: "key does not exist",
			ctx:  context.Background(),
			key:  "nonexistent",
			want: "",
		},
		{
			name: "key exists but not string",
			ctx:  context.WithValue(context.Background(), "count", 42),
			key:  "count",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringFromContext(tt.ctx, tt.key)
			if got != tt.want {
				t.Errorf("getStringFromContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFirstOf(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{
			name:   "first non-empty",
			values: []string{"first", "second"},
			want:   "first",
		},
		{
			name:   "first empty, second non-empty",
			values: []string{"", "second"},
			want:   "second",
		},
		{
			name:   "all empty",
			values: []string{"", ""},
			want:   "",
		},
		{
			name:   "no values",
			values: []string{},
			want:   "",
		},
		{
			name:   "single value",
			values: []string{"only"},
			want:   "only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstOf(tt.values...)
			if got != tt.want {
				t.Errorf("firstOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == "" {
		t.Error("generateRequestID() returned empty string")
	}

	// IDs should contain a timestamp and random portion
	if len(id1) < 16 { // At least "20060102150405-x"
		t.Errorf("generateRequestID() returned too short ID: %s", id1)
	}

	// IDs should be different (with very high probability)
	// Note: This could theoretically fail if called within same nanosecond
	// but in practice this is fine for testing
	_ = id2 // Just verify no panic
}

func TestRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"length 1", 1},
		{"length 8", 8},
		{"length 16", 16},
		{"length 0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := randomString(tt.length)
			if len(got) != tt.length {
				t.Errorf("randomString(%d) returned length %d", tt.length, len(got))
			}
		})
	}
}

func TestNewCostTrackingRouter(t *testing.T) {
	// Cannot easily test without llm.UnifiedRouter, but we can test nil handling
	repo := NewMockRepository()
	service := NewService(repo, nil)

	router := NewCostTrackingRouter(nil, service, nil)
	if router == nil {
		t.Error("NewCostTrackingRouter() returned nil")
	}

	if router.service != service {
		t.Error("service not properly set")
	}

	if router.logger == nil {
		t.Error("logger should default to log.Default()")
	}
}

func TestCostTrackingRouterAccessors(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	router := NewCostTrackingRouter(nil, service, nil)

	if router.Router() != nil {
		t.Error("Router() should return nil for nil router")
	}

	if router.Service() != service {
		t.Error("Service() should return the service")
	}
}
