//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"context"
	"fmt"
)

// NewStorageBackend creates a StorageBackend from configuration.
func NewStorageBackend(ctx context.Context, cfg StorageConfig) (StorageBackend, error) {
	switch cfg.Type {
	case StorageTypeS3:
		return NewS3Backend(ctx, cfg.S3)
	case StorageTypeAzure:
		return NewAzureBackend(cfg.Azure)
	case StorageTypeGCS:
		return NewGCSBackend(ctx, cfg.GCS)
	case StorageTypeLocal, "":
		return NewLocalBackend(cfg.Local)
	default:
		return nil, fmt.Errorf("unsupported storage type: %q", cfg.Type)
	}
}
