//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	gcsstorage "cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// mockGCSBucket implements gcsBucketHandle for testing.
type mockGCSBucket struct {
	objects   map[string][]byte
	signedURL string
	signErr   error
	attrsErr  error
}

func newMockGCSBucket() *mockGCSBucket {
	return &mockGCSBucket{objects: make(map[string][]byte)}
}

func (m *mockGCSBucket) Object(name string) gcsObjectHandle {
	return &mockGCSObject{bucket: m, name: name}
}

func (m *mockGCSBucket) Objects(ctx context.Context, q *gcsstorage.Query) gcsObjectIterator {
	prefix := ""
	if q != nil {
		prefix = q.Prefix
	}
	var items []*gcsstorage.ObjectAttrs
	for key, data := range m.objects {
		if strings.HasPrefix(key, prefix) {
			items = append(items, &gcsstorage.ObjectAttrs{
				Name:    key,
				Size:    int64(len(data)),
				Updated: time.Now(),
				Etag:    "etag123",
			})
		}
	}
	return &mockGCSIterator{items: items}
}

func (m *mockGCSBucket) Attrs(ctx context.Context) (*gcsstorage.BucketAttrs, error) {
	if m.attrsErr != nil {
		return nil, m.attrsErr
	}
	return &gcsstorage.BucketAttrs{Name: "test-bucket"}, nil
}

func (m *mockGCSBucket) SignedURL(object string, opts *gcsstorage.SignedURLOptions) (string, error) {
	if m.signErr != nil {
		return "", m.signErr
	}
	if m.signedURL != "" {
		return m.signedURL, nil
	}
	return "https://storage.googleapis.com/test-bucket/" + object + "?signature=abc", nil
}

// mockGCSObject implements gcsObjectHandle for testing.
type mockGCSObject struct {
	bucket *mockGCSBucket
	name   string
}

func (o *mockGCSObject) NewWriter(ctx context.Context) io.WriteCloser {
	return &mockGCSWriter{bucket: o.bucket, name: o.name}
}

func (o *mockGCSObject) NewReader(ctx context.Context) (io.ReadCloser, error) {
	data, ok := o.bucket.objects[o.name]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", o.name)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (o *mockGCSObject) Delete(ctx context.Context) error {
	if _, ok := o.bucket.objects[o.name]; !ok {
		return fmt.Errorf("object not found: %s", o.name)
	}
	delete(o.bucket.objects, o.name)
	return nil
}

func (o *mockGCSObject) Attrs(ctx context.Context) (*gcsstorage.ObjectAttrs, error) {
	data, ok := o.bucket.objects[o.name]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", o.name)
	}
	return &gcsstorage.ObjectAttrs{
		Name: o.name,
		Size: int64(len(data)),
	}, nil
}

// mockGCSWriter implements io.WriteCloser for testing.
type mockGCSWriter struct {
	bucket *mockGCSBucket
	name   string
	buf    bytes.Buffer
}

func (w *mockGCSWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w *mockGCSWriter) Close() error {
	w.bucket.objects[w.name] = w.buf.Bytes()
	return nil
}

// mockGCSIterator implements gcsObjectIterator for testing.
type mockGCSIterator struct {
	items []*gcsstorage.ObjectAttrs
	idx   int
}

func (it *mockGCSIterator) Next() (*gcsstorage.ObjectAttrs, error) {
	if it.idx >= len(it.items) {
		// GCS callers (see GCSBackend.List) break on iterator.Done — using a
		// generic error here short-circuits List with "gcs list: no more items".
		return nil, iterator.Done
	}
	item := it.items[it.idx]
	it.idx++
	return item, nil
}

func TestGCSBackend_Upload(t *testing.T) {
	bucket := newMockGCSBucket()
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	result, err := backend.Upload(ctx, &UploadRequest{
		Key:  "org1/export.json",
		Body: strings.NewReader(`{"data": true}`),
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if result.Key != "org1/export.json" {
		t.Errorf("key = %q", result.Key)
	}
	if _, ok := bucket.objects["org1/export.json"]; !ok {
		t.Error("object not stored")
	}
}

func TestGCSBackend_UploadWithPrefix(t *testing.T) {
	bucket := newMockGCSBucket()
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test", Prefix: "compliance/"})
	ctx := context.Background()

	_, err := backend.Upload(ctx, &UploadRequest{
		Key:  "export.json",
		Body: strings.NewReader("data"),
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, ok := bucket.objects["compliance/export.json"]; !ok {
		t.Error("object not stored with prefix")
	}
}

func TestGCSBackend_Download(t *testing.T) {
	bucket := newMockGCSBucket()
	bucket.objects["test.json"] = []byte("hello")
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	reader, err := backend.Download(ctx, "test.json")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer reader.Close()
	data, _ := io.ReadAll(reader)
	if string(data) != "hello" {
		t.Errorf("data = %q", string(data))
	}
}

func TestGCSBackend_DownloadNotFound(t *testing.T) {
	bucket := newMockGCSBucket()
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	_, err := backend.Download(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGCSBackend_GeneratePresignedURL(t *testing.T) {
	bucket := newMockGCSBucket()
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	url, err := backend.GeneratePresignedURL(ctx, "test.json", time.Hour)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	if !strings.Contains(url, "signature") {
		t.Errorf("url = %q", url)
	}
}

func TestGCSBackend_PresignError(t *testing.T) {
	bucket := newMockGCSBucket()
	bucket.signErr = fmt.Errorf("sign error")
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	_, err := backend.GeneratePresignedURL(ctx, "test.json", time.Hour)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGCSBackend_Delete(t *testing.T) {
	bucket := newMockGCSBucket()
	bucket.objects["test.json"] = []byte("data")
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	if err := backend.Delete(ctx, "test.json"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := bucket.objects["test.json"]; ok {
		t.Error("object still exists")
	}
}

func TestGCSBackend_DeleteNotFound(t *testing.T) {
	bucket := newMockGCSBucket()
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	err := backend.Delete(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGCSBackend_List(t *testing.T) {
	bucket := newMockGCSBucket()
	bucket.objects["org1/a.json"] = []byte("a")
	bucket.objects["org1/b.json"] = []byte("bb")
	bucket.objects["org2/c.json"] = []byte("ccc")
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	objects, err := backend.List(ctx, "org1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objects) != 2 {
		t.Errorf("List returned %d objects, want 2", len(objects))
	}
}

func TestGCSBackend_HealthCheck(t *testing.T) {
	bucket := newMockGCSBucket()
	backend := newGCSBackendWithBucket(bucket, GCSConfig{Bucket: "test"})
	ctx := context.Background()

	if err := backend.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}

	bucket.attrsErr = fmt.Errorf("bucket not found")
	if err := backend.HealthCheck(ctx); err == nil {
		t.Error("expected error")
	}
}
