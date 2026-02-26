//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"context"
	"fmt"
	"io"
	"time"

	gcsstorage "cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// gcsObjectHandle abstracts a GCS object for testing.
type gcsObjectHandle interface {
	NewWriter(ctx context.Context) io.WriteCloser
	NewReader(ctx context.Context) (io.ReadCloser, error)
	Delete(ctx context.Context) error
	Attrs(ctx context.Context) (*gcsstorage.ObjectAttrs, error)
}

// gcsBucketHandle abstracts a GCS bucket for testing.
type gcsBucketHandle interface {
	Object(name string) gcsObjectHandle
	Objects(ctx context.Context, q *gcsstorage.Query) gcsObjectIterator
	Attrs(ctx context.Context) (*gcsstorage.BucketAttrs, error)
	SignedURL(object string, opts *gcsstorage.SignedURLOptions) (string, error)
}

// gcsObjectIterator abstracts the GCS object iterator.
type gcsObjectIterator interface {
	Next() (*gcsstorage.ObjectAttrs, error)
}

// GCSBackend implements StorageBackend for Google Cloud Storage.
type GCSBackend struct {
	client *gcsstorage.Client
	bucket gcsBucketHandle
	cfg    GCSConfig
}

// NewGCSBackend creates a new GCS storage backend.
func NewGCSBackend(ctx context.Context, cfg GCSConfig) (*GCSBackend, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("gcs: bucket is required")
	}

	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	} else if len(cfg.CredentialsJSON) > 0 {
		opts = append(opts, option.WithCredentialsJSON(cfg.CredentialsJSON))
	}

	client, err := gcsstorage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcs: create client: %w", err)
	}

	return &GCSBackend{
		client: client,
		bucket: &gcsBucketAdapter{bucket: client.Bucket(cfg.Bucket)},
		cfg:    cfg,
	}, nil
}

// newGCSBackendWithBucket creates a GCSBackend with an injected bucket (for testing).
func newGCSBackendWithBucket(bucket gcsBucketHandle, cfg GCSConfig) *GCSBackend {
	return &GCSBackend{bucket: bucket, cfg: cfg}
}

func (b *GCSBackend) fullKey(key string) string {
	if b.cfg.Prefix != "" {
		return b.cfg.Prefix + key
	}
	return key
}

// Upload stores an object in GCS.
func (b *GCSBackend) Upload(ctx context.Context, req *UploadRequest) (*UploadResult, error) {
	obj := b.bucket.Object(b.fullKey(req.Key))
	w := obj.NewWriter(ctx)

	n, err := io.Copy(w, req.Body)
	if err != nil {
		return nil, fmt.Errorf("gcs upload: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gcs upload: close: %w", err)
	}

	return &UploadResult{
		Key:       req.Key,
		SizeBytes: n,
	}, nil
}

// Download retrieves an object from GCS.
func (b *GCSBackend) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	obj := b.bucket.Object(b.fullKey(key))
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs download: %w", err)
	}
	return reader, nil
}

// GeneratePresignedURL creates a signed URL for the object.
func (b *GCSBackend) GeneratePresignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	url, err := b.bucket.SignedURL(b.fullKey(key), &gcsstorage.SignedURLOptions{
		Method:  "GET",
		Expires: time.Now().Add(expiry),
	})
	if err != nil {
		return "", fmt.Errorf("gcs presign: %w", err)
	}
	return url, nil
}

// Delete removes an object from GCS.
func (b *GCSBackend) Delete(ctx context.Context, key string) error {
	obj := b.bucket.Object(b.fullKey(key))
	if err := obj.Delete(ctx); err != nil {
		return fmt.Errorf("gcs delete: %w", err)
	}
	return nil
}

// List returns objects with the given prefix.
func (b *GCSBackend) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	it := b.bucket.Objects(ctx, &gcsstorage.Query{Prefix: b.fullKey(prefix)})

	var objects []ObjectInfo
	for {
		attrs, err := it.Next()
		if err != nil {
			if err == iterator.Done {
				break
			}
			return nil, fmt.Errorf("gcs list: %w", err)
		}
		objects = append(objects, ObjectInfo{
			Key:          attrs.Name,
			SizeBytes:    attrs.Size,
			LastModified: attrs.Updated,
			ETag:         attrs.Etag,
		})
	}
	return objects, nil
}

// Type returns the storage backend type.
func (b *GCSBackend) Type() string { return string(StorageTypeGCS) }

// HealthCheck verifies the GCS bucket is accessible.
func (b *GCSBackend) HealthCheck(ctx context.Context) error {
	_, err := b.bucket.Attrs(ctx)
	if err != nil {
		return fmt.Errorf("gcs health check: %w", err)
	}
	return nil
}

// Close releases the underlying GCS client resources.
func (b *GCSBackend) Close() error {
	if b.client != nil {
		return b.client.Close()
	}
	return nil
}

// Adapters to wrap real GCS types behind our interfaces.

type gcsBucketAdapter struct {
	bucket *gcsstorage.BucketHandle
}

func (a *gcsBucketAdapter) Object(name string) gcsObjectHandle {
	return &gcsObjectAdapter{obj: a.bucket.Object(name)}
}

func (a *gcsBucketAdapter) Objects(ctx context.Context, q *gcsstorage.Query) gcsObjectIterator {
	return a.bucket.Objects(ctx, q)
}

func (a *gcsBucketAdapter) Attrs(ctx context.Context) (*gcsstorage.BucketAttrs, error) {
	return a.bucket.Attrs(ctx)
}

func (a *gcsBucketAdapter) SignedURL(object string, opts *gcsstorage.SignedURLOptions) (string, error) {
	return a.bucket.SignedURL(object, opts)
}

type gcsObjectAdapter struct {
	obj *gcsstorage.ObjectHandle
}

func (a *gcsObjectAdapter) NewWriter(ctx context.Context) io.WriteCloser {
	return a.obj.NewWriter(ctx)
}

func (a *gcsObjectAdapter) NewReader(ctx context.Context) (io.ReadCloser, error) {
	return a.obj.NewReader(ctx)
}

func (a *gcsObjectAdapter) Delete(ctx context.Context) error {
	return a.obj.Delete(ctx)
}

func (a *gcsObjectAdapter) Attrs(ctx context.Context) (*gcsstorage.ObjectAttrs, error) {
	return a.obj.Attrs(ctx)
}
