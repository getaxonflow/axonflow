//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"context"
	"testing"
)

func TestNewStorageBackend_Local(t *testing.T) {
	dir := t.TempDir()
	backend, err := NewStorageBackend(context.Background(), StorageConfig{
		Type:  StorageTypeLocal,
		Local: LocalConfig{BasePath: dir},
	})
	if err != nil {
		t.Fatalf("NewStorageBackend(local): %v", err)
	}
	if _, ok := backend.(*LocalBackend); !ok {
		t.Errorf("expected *LocalBackend, got %T", backend)
	}
}

func TestNewStorageBackend_DefaultLocal(t *testing.T) {
	backend, err := NewStorageBackend(context.Background(), StorageConfig{
		Type: "",
	})
	if err != nil {
		t.Fatalf("NewStorageBackend(default): %v", err)
	}
	if _, ok := backend.(*LocalBackend); !ok {
		t.Errorf("expected *LocalBackend for empty type, got %T", backend)
	}
}

func TestNewStorageBackend_UnknownType(t *testing.T) {
	_, err := NewStorageBackend(context.Background(), StorageConfig{
		Type: "ftp",
	})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestNewStorageBackend_S3MissingBucket(t *testing.T) {
	_, err := NewStorageBackend(context.Background(), StorageConfig{
		Type: StorageTypeS3,
		S3:   S3Config{},
	})
	if err == nil {
		t.Fatal("expected error for S3 without bucket")
	}
}

func TestNewStorageBackend_AzureMissingContainer(t *testing.T) {
	_, err := NewStorageBackend(context.Background(), StorageConfig{
		Type:  StorageTypeAzure,
		Azure: AzureConfig{},
	})
	if err == nil {
		t.Fatal("expected error for Azure without container")
	}
}

func TestNewStorageBackend_GCSMissingBucket(t *testing.T) {
	_, err := NewStorageBackend(context.Background(), StorageConfig{
		Type: StorageTypeGCS,
		GCS:  GCSConfig{},
	})
	if err == nil {
		t.Fatal("expected error for GCS without bucket")
	}
}

func TestStorageType_Constants(t *testing.T) {
	if StorageTypeS3 != "s3" {
		t.Errorf("StorageTypeS3 = %q", StorageTypeS3)
	}
	if StorageTypeAzure != "azure" {
		t.Errorf("StorageTypeAzure = %q", StorageTypeAzure)
	}
	if StorageTypeGCS != "gcs" {
		t.Errorf("StorageTypeGCS = %q", StorageTypeGCS)
	}
	if StorageTypeLocal != "local" {
		t.Errorf("StorageTypeLocal = %q", StorageTypeLocal)
	}
}
