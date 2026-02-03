// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestNewAuditManager_CreatesQueue(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create temp fallback file
	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "audit_test.jsonl")

	am, err := NewAuditManager(db, AuditModeCompliance, 100, 1, fallbackPath)
	if err != nil {
		t.Fatalf("NewAuditManager failed: %v", err)
	}

	if am == nil {
		t.Fatal("Expected non-nil AuditManager")
	}

	if am.GetQueue() == nil {
		t.Fatal("Expected non-nil queue from AuditManager")
	}

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = am.Shutdown(ctx)
}

func TestNewAuditManager_InvalidFallbackPath(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Use an invalid path that can't be created
	_, err = NewAuditManager(db, AuditModeCompliance, 100, 1, "/nonexistent/deep/path/audit.jsonl")
	if err == nil {
		t.Fatal("Expected error for invalid fallback path")
	}
}

func TestAuditManager_GetQueue_NilManager(t *testing.T) {
	var am *AuditManager
	if am.GetQueue() != nil {
		t.Error("Expected nil queue from nil AuditManager")
	}
}

func TestAuditManager_RecoverEntries_NilManager(t *testing.T) {
	var am *AuditManager
	recovered, err := am.RecoverEntries()
	if err != nil {
		t.Errorf("Expected no error from nil AuditManager, got: %v", err)
	}
	if recovered != 0 {
		t.Errorf("Expected 0 recovered from nil AuditManager, got: %d", recovered)
	}
}

func TestAuditManager_RecoverEntries_EmptyFallback(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "audit_test.jsonl")

	am, err := NewAuditManager(db, AuditModePerformance, 100, 1, fallbackPath)
	if err != nil {
		t.Fatalf("NewAuditManager failed: %v", err)
	}

	recovered, err := am.RecoverEntries()
	if err != nil {
		t.Errorf("Expected no error for empty fallback, got: %v", err)
	}
	if recovered != 0 {
		t.Errorf("Expected 0 recovered for empty fallback, got: %d", recovered)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = am.Shutdown(ctx)
}

func TestAuditManager_Shutdown_NilManager(t *testing.T) {
	var am *AuditManager
	err := am.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Expected no error from nil AuditManager shutdown, got: %v", err)
	}
}

func TestAuditManager_Shutdown_Graceful(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "audit_test.jsonl")

	am, err := NewAuditManager(db, AuditModeCompliance, 100, 1, fallbackPath)
	if err != nil {
		t.Fatalf("NewAuditManager failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = am.Shutdown(ctx)
	if err != nil {
		t.Errorf("Expected graceful shutdown, got: %v", err)
	}
}

func TestInitAuditManager_SetsGlobal(t *testing.T) {
	// Save and restore global
	prevAM := auditManager
	defer func() { auditManager = prevAM }()

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Set env vars
	tmpDir := t.TempDir()
	fallbackPath := filepath.Join(tmpDir, "audit_test.jsonl")
	os.Setenv("AUDIT_FALLBACK_PATH", fallbackPath)
	defer os.Unsetenv("AUDIT_FALLBACK_PATH")

	auditManager = nil
	initAuditManager(db)

	if auditManager == nil {
		t.Fatal("Expected auditManager to be initialized")
	}
	if auditManager.GetQueue() == nil {
		t.Fatal("Expected auditManager queue to be non-nil")
	}

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = auditManager.Shutdown(ctx)
}
