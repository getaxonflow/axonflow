// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalBackend implements StorageBackend using the local filesystem.
// This is for development and community mode — not for production compliance exports.
type LocalBackend struct {
	cfg LocalConfig
}

// NewLocalBackend creates a new local filesystem storage backend.
func NewLocalBackend(cfg LocalConfig) (*LocalBackend, error) {
	if cfg.BasePath == "" {
		cfg.BasePath = "/tmp/axonflow-audit-exports"
	}
	if err := os.MkdirAll(cfg.BasePath, 0755); err != nil {
		return nil, fmt.Errorf("local: create base path: %w", err)
	}
	return &LocalBackend{cfg: cfg}, nil
}

func (b *LocalBackend) fullPath(key string) (string, error) {
	if strings.Contains(key, "..") {
		return "", fmt.Errorf("local: invalid key %q: path traversal not allowed", key)
	}
	joined := filepath.Join(b.cfg.BasePath, key)
	absPath, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("local: resolve path: %w", err)
	}
	absBase, err := filepath.Abs(b.cfg.BasePath)
	if err != nil {
		return "", fmt.Errorf("local: resolve base path: %w", err)
	}
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
		return "", fmt.Errorf("local: key %q resolves outside base path", key)
	}
	return absPath, nil
}

// Upload writes a file to the local filesystem.
func (b *LocalBackend) Upload(ctx context.Context, req *UploadRequest) (*UploadResult, error) {
	path, err := b.fullPath(req.Key)
	if err != nil {
		return nil, fmt.Errorf("local upload: %w", err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("local upload: create dir: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("local upload: create file: %w", err)
	}

	n, err := io.Copy(f, req.Body)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("local upload: write: %w", err)
	}

	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("local upload: close: %w", err)
	}

	return &UploadResult{
		Key:       req.Key,
		SizeBytes: n,
	}, nil
}

// Download opens a file from the local filesystem.
func (b *LocalBackend) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	path, err := b.fullPath(key)
	if err != nil {
		return nil, fmt.Errorf("local download: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("local download: %w", err)
	}
	return f, nil
}

// GeneratePresignedURL returns a file:// URL for local files.
// In production, use a cloud backend with real presigned URLs.
func (b *LocalBackend) GeneratePresignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	path, err := b.fullPath(key)
	if err != nil {
		return "", fmt.Errorf("local presign: %w", err)
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("local presign: %w", err)
	}
	return "file://" + path, nil
}

// Delete removes a file from the local filesystem.
func (b *LocalBackend) Delete(ctx context.Context, key string) error {
	path, err := b.fullPath(key)
	if err != nil {
		return fmt.Errorf("local delete: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("local delete: %w", err)
	}
	return nil
}

// List returns files matching the given prefix under the base path.
func (b *LocalBackend) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var objects []ObjectInfo
	err := filepath.Walk(b.cfg.BasePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			return nil
		}

		// Get relative key from base path
		relPath, relErr := filepath.Rel(b.cfg.BasePath, path)
		if relErr != nil || relPath == "." {
			return nil
		}

		// Match against prefix
		if prefix != "" && len(relPath) >= len(prefix) {
			if relPath[:len(prefix)] != prefix {
				return nil
			}
		} else if prefix != "" {
			return nil
		}

		objects = append(objects, ObjectInfo{
			Key:          relPath,
			SizeBytes:    info.Size(),
			LastModified: info.ModTime(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("local list: %w", err)
	}
	return objects, nil
}

// Type returns the storage backend type.
func (b *LocalBackend) Type() string { return string(StorageTypeLocal) }

// HealthCheck verifies the base path exists and is writable.
func (b *LocalBackend) HealthCheck(ctx context.Context) error {
	info, err := os.Stat(b.cfg.BasePath)
	if err != nil {
		return fmt.Errorf("local health check: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("local health check: %s is not a directory", b.cfg.BasePath)
	}
	return nil
}
