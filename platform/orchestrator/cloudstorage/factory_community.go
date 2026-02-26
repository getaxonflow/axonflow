//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"context"
	"fmt"
)

// NewStorageBackend creates a StorageBackend from configuration.
// Community edition only supports local filesystem storage.
func NewStorageBackend(ctx context.Context, cfg StorageConfig) (StorageBackend, error) {
	switch cfg.Type {
	case StorageTypeLocal, "":
		return NewLocalBackend(cfg.Local)
	case StorageTypeS3, StorageTypeAzure, StorageTypeGCS:
		return nil, fmt.Errorf("cloud storage backend %q requires Enterprise edition", cfg.Type)
	default:
		return nil, fmt.Errorf("unsupported storage type: %q", cfg.Type)
	}
}
