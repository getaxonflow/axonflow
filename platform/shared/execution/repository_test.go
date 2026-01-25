// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"database/sql"
	"testing"
)

// These tests verify the repository logic without a real database.
// Integration tests with a real PostgreSQL database should be in a separate _integration_test.go file.

func TestNullableString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValid bool
		wantValue string
	}{
		{
			name:      "empty string",
			input:     "",
			wantValid: false,
			wantValue: "",
		},
		{
			name:      "non-empty string",
			input:     "test",
			wantValid: true,
			wantValue: "test",
		},
		{
			name:      "string with spaces",
			input:     "  ",
			wantValid: true,
			wantValue: "  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nullableString(tt.input)
			if result.Valid != tt.wantValid {
				t.Errorf("nullableString(%q).Valid = %v, want %v", tt.input, result.Valid, tt.wantValid)
			}
			if result.Valid && result.String != tt.wantValue {
				t.Errorf("nullableString(%q).String = %v, want %v", tt.input, result.String, tt.wantValue)
			}
		})
	}
}

func TestNewPostgresRepository(t *testing.T) {
	// Test that NewPostgresRepository returns a valid repository
	var db *sql.DB // nil is fine for this test
	repo := NewPostgresRepository(db)

	if repo == nil {
		t.Fatal("NewPostgresRepository returned nil")
	}
	if repo.db != db {
		t.Error("Repository db field not set correctly")
	}
}

func TestPostgresRepository_CreateValidation(t *testing.T) {
	repo := NewPostgresRepository(nil)

	// Test nil execution
	err := repo.Create(nil, nil)
	if err != ErrInvalidExecution {
		t.Errorf("Create(nil) error = %v, want %v", err, ErrInvalidExecution)
	}
}

func TestPostgresRepository_UpdateValidation(t *testing.T) {
	repo := NewPostgresRepository(nil)

	// Test nil execution
	err := repo.Update(nil, nil)
	if err != ErrInvalidExecution {
		t.Errorf("Update(nil) error = %v, want %v", err, ErrInvalidExecution)
	}
}

// TestListExecutionsRequest validates the request structure
func TestListExecutionsRequest(t *testing.T) {
	mapType := ExecutionTypeMAP
	pendingStatus := StatusPending

	req := ListExecutionsRequest{
		ExecutionType: &mapType,
		Status:        &pendingStatus,
		TenantID:      "tenant-123",
		OrgID:         "org-456",
		Limit:         10,
		Offset:        5,
	}

	// Validate fields can be set correctly
	if *req.ExecutionType != ExecutionTypeMAP {
		t.Errorf("ExecutionType = %v, want %v", *req.ExecutionType, ExecutionTypeMAP)
	}
	if *req.Status != StatusPending {
		t.Errorf("Status = %v, want %v", *req.Status, StatusPending)
	}
	if req.TenantID != "tenant-123" {
		t.Errorf("TenantID = %v, want %v", req.TenantID, "tenant-123")
	}
	if req.OrgID != "org-456" {
		t.Errorf("OrgID = %v, want %v", req.OrgID, "org-456")
	}
	if req.Limit != 10 {
		t.Errorf("Limit = %v, want %v", req.Limit, 10)
	}
	if req.Offset != 5 {
		t.Errorf("Offset = %v, want %v", req.Offset, 5)
	}
}
