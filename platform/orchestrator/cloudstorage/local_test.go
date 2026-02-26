// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalBackend_FullLifecycle(t *testing.T) {
	dir := t.TempDir()
	backend, err := NewLocalBackend(LocalConfig{BasePath: dir})
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}

	ctx := context.Background()

	// Upload
	content := []byte(`{"export_id": "test-123", "records": []}`)
	result, err := backend.Upload(ctx, &UploadRequest{
		Key:         "org1/export-2026.json",
		Body:        bytes.NewReader(content),
		ContentType: "application/json",
		Metadata:    map[string]string{"org_id": "org1"},
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if result.Key != "org1/export-2026.json" {
		t.Errorf("Upload key = %q, want %q", result.Key, "org1/export-2026.json")
	}
	if result.SizeBytes != int64(len(content)) {
		t.Errorf("Upload size = %d, want %d", result.SizeBytes, len(content))
	}

	// Verify file on disk
	diskContent, err := os.ReadFile(filepath.Join(dir, "org1/export-2026.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(diskContent, content) {
		t.Errorf("disk content mismatch")
	}

	// Download
	reader, err := backend.Download(ctx, "org1/export-2026.json")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	downloaded, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(downloaded, content) {
		t.Errorf("downloaded content mismatch")
	}

	// GeneratePresignedURL
	url, err := backend.GeneratePresignedURL(ctx, "org1/export-2026.json", 0)
	if err != nil {
		t.Fatalf("GeneratePresignedURL: %v", err)
	}
	if !strings.HasPrefix(url, "file://") {
		t.Errorf("presigned URL = %q, want file:// prefix", url)
	}

	// List
	objects, err := backend.List(ctx, "org1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("List returned %d objects, want 1", len(objects))
	}
	if objects[0].Key != "org1/export-2026.json" {
		t.Errorf("List key = %q, want %q", objects[0].Key, "org1/export-2026.json")
	}
	if objects[0].SizeBytes != int64(len(content)) {
		t.Errorf("List size = %d, want %d", objects[0].SizeBytes, len(content))
	}

	// HealthCheck
	if err := backend.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}

	// Delete
	if err := backend.Delete(ctx, "org1/export-2026.json"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify deleted
	_, err = backend.Download(ctx, "org1/export-2026.json")
	if err == nil {
		t.Error("Download after delete: expected error")
	}
}

func TestLocalBackend_UploadCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	backend, _ := NewLocalBackend(LocalConfig{BasePath: dir})
	ctx := context.Background()

	_, err := backend.Upload(ctx, &UploadRequest{
		Key:  "deep/nested/path/file.json",
		Body: strings.NewReader("test"),
	})
	if err != nil {
		t.Fatalf("Upload nested: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "deep/nested/path/file.json")); err != nil {
		t.Errorf("nested file not created: %v", err)
	}
}

func TestLocalBackend_DeleteNonExistent(t *testing.T) {
	dir := t.TempDir()
	backend, _ := NewLocalBackend(LocalConfig{BasePath: dir})
	ctx := context.Background()

	// Should not error on deleting non-existent file
	if err := backend.Delete(ctx, "nonexistent.json"); err != nil {
		t.Errorf("Delete nonexistent: %v", err)
	}
}

func TestLocalBackend_PresignNonExistent(t *testing.T) {
	dir := t.TempDir()
	backend, _ := NewLocalBackend(LocalConfig{BasePath: dir})
	ctx := context.Background()

	_, err := backend.GeneratePresignedURL(ctx, "nonexistent.json", 0)
	if err == nil {
		t.Error("GeneratePresignedURL for nonexistent: expected error")
	}
}

func TestLocalBackend_DefaultBasePath(t *testing.T) {
	backend, err := NewLocalBackend(LocalConfig{})
	if err != nil {
		t.Fatalf("NewLocalBackend with default: %v", err)
	}
	if backend.cfg.BasePath != "/tmp/axonflow-audit-exports" {
		t.Errorf("default base path = %q", backend.cfg.BasePath)
	}
}

func TestLocalBackend_HealthCheckInvalidPath(t *testing.T) {
	backend := &LocalBackend{cfg: LocalConfig{BasePath: "/nonexistent/path/12345"}}
	if err := backend.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck on nonexistent path: expected error")
	}
}

func TestLocalBackend_ListEmptyDir(t *testing.T) {
	dir := t.TempDir()
	backend, _ := NewLocalBackend(LocalConfig{BasePath: dir})
	ctx := context.Background()

	objects, err := backend.List(ctx, "nonexistent/")
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(objects) != 0 {
		t.Errorf("List empty returned %d objects, want 0", len(objects))
	}
}

func TestLocalBackend_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	backend, _ := NewLocalBackend(LocalConfig{BasePath: dir})
	ctx := context.Background()

	files := []string{"org1/a.json", "org1/b.json", "org2/c.json"}
	for _, f := range files {
		_, err := backend.Upload(ctx, &UploadRequest{
			Key:  f,
			Body: strings.NewReader("data-" + f),
		})
		if err != nil {
			t.Fatalf("Upload %s: %v", f, err)
		}
	}

	// List org1
	org1Objects, err := backend.List(ctx, "org1/")
	if err != nil {
		t.Fatalf("List org1: %v", err)
	}
	if len(org1Objects) != 2 {
		t.Errorf("List org1 returned %d, want 2", len(org1Objects))
	}
}
