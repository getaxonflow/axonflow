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

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// mockS3Client implements s3Client for testing.
type mockS3Client struct {
	objects map[string][]byte
	putErr  error
	getErr  error
	delErr  error
	listErr error
	headErr error
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{objects: make(map[string][]byte)}
}

func (m *mockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	data, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	m.objects[*params.Key] = data
	return &s3.PutObjectOutput{
		ETag:      aws.String(`"abc123"`),
		VersionId: aws.String("v1"),
	}, nil
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	data, ok := m.objects[*params.Key]
	if !ok {
		return nil, fmt.Errorf("NoSuchKey: %s", *params.Key)
	}
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: aws.Int64(int64(len(data))),
	}, nil
}

func (m *mockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if m.delErr != nil {
		return nil, m.delErr
	}
	delete(m.objects, *params.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var contents []s3types.Object
	prefix := ""
	if params.Prefix != nil {
		prefix = *params.Prefix
	}
	for key, data := range m.objects {
		if strings.HasPrefix(key, prefix) {
			now := time.Now()
			contents = append(contents, s3types.Object{
				Key:          aws.String(key),
				Size:         aws.Int64(int64(len(data))),
				LastModified: &now,
				ETag:         aws.String(`"abc"`),
			})
		}
	}
	return &s3.ListObjectsV2Output{Contents: contents}, nil
}

func (m *mockS3Client) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.headErr != nil {
		return nil, m.headErr
	}
	return &s3.HeadBucketOutput{}, nil
}

// mockS3PresignClient implements s3PresignClient for testing.
type mockS3PresignClient struct {
	url string
	err error
}

func (m *mockS3PresignClient) PresignGetObject(ctx context.Context, params *s3.GetObjectInput, _ ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &v4.PresignedHTTPRequest{URL: m.url}, nil
}

func TestS3Backend_Upload(t *testing.T) {
	mock := newMockS3Client()
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	result, err := backend.Upload(ctx, &UploadRequest{
		Key:         "org1/export.json",
		Body:        strings.NewReader(`{"data": true}`),
		ContentType: "application/json",
		Metadata:    map[string]string{"org_id": "org1"},
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if result.Key != "org1/export.json" {
		t.Errorf("key = %q", result.Key)
	}
	if result.ETag != `"abc123"` {
		t.Errorf("etag = %q", result.ETag)
	}
	if result.VersionID != "v1" {
		t.Errorf("version = %q", result.VersionID)
	}

	// Verify stored
	if _, ok := mock.objects["org1/export.json"]; !ok {
		t.Error("object not stored")
	}
}

func TestS3Backend_UploadWithPrefix(t *testing.T) {
	mock := newMockS3Client()
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{
		Bucket: "test-bucket",
		Prefix: "compliance/",
	})
	ctx := context.Background()

	_, err := backend.Upload(ctx, &UploadRequest{
		Key:  "export.json",
		Body: strings.NewReader("data"),
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, ok := mock.objects["compliance/export.json"]; !ok {
		t.Error("object not stored with prefix")
	}
}

func TestS3Backend_UploadError(t *testing.T) {
	mock := newMockS3Client()
	mock.putErr = fmt.Errorf("access denied")
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	_, err := backend.Upload(ctx, &UploadRequest{
		Key:  "test.json",
		Body: strings.NewReader("data"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("error = %q", err)
	}
}

func TestS3Backend_Download(t *testing.T) {
	mock := newMockS3Client()
	mock.objects["org1/export.json"] = []byte("test-data")
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	reader, err := backend.Download(ctx, "org1/export.json")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer reader.Close()

	data, _ := io.ReadAll(reader)
	if string(data) != "test-data" {
		t.Errorf("data = %q", string(data))
	}
}

func TestS3Backend_DownloadNotFound(t *testing.T) {
	mock := newMockS3Client()
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	_, err := backend.Download(ctx, "nonexistent.json")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3Backend_GeneratePresignedURL(t *testing.T) {
	presign := &mockS3PresignClient{url: "https://bucket.s3.amazonaws.com/key?X-Amz-Signature=abc"}
	backend := newS3BackendWithClient(newMockS3Client(), presign, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	url, err := backend.GeneratePresignedURL(ctx, "org1/export.json", time.Hour)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	if !strings.Contains(url, "X-Amz-Signature") {
		t.Errorf("url = %q", url)
	}
}

func TestS3Backend_PresignError(t *testing.T) {
	presign := &mockS3PresignClient{err: fmt.Errorf("presign failed")}
	backend := newS3BackendWithClient(newMockS3Client(), presign, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	_, err := backend.GeneratePresignedURL(ctx, "key", time.Hour)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3Backend_Delete(t *testing.T) {
	mock := newMockS3Client()
	mock.objects["key"] = []byte("data")
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	if err := backend.Delete(ctx, "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := mock.objects["key"]; ok {
		t.Error("object still exists after delete")
	}
}

func TestS3Backend_List(t *testing.T) {
	mock := newMockS3Client()
	mock.objects["org1/a.json"] = []byte("a")
	mock.objects["org1/b.json"] = []byte("bb")
	mock.objects["org2/c.json"] = []byte("ccc")
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	objects, err := backend.List(ctx, "org1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objects) != 2 {
		t.Errorf("List returned %d objects, want 2", len(objects))
	}
}

func TestS3Backend_HealthCheck(t *testing.T) {
	mock := newMockS3Client()
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{Bucket: "test-bucket"})
	ctx := context.Background()

	if err := backend.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}

	mock.headErr = fmt.Errorf("bucket not found")
	if err := backend.HealthCheck(ctx); err == nil {
		t.Error("HealthCheck with error: expected error")
	}
}

func TestS3Backend_UploadWithEncryption(t *testing.T) {
	mock := newMockS3Client()
	backend := newS3BackendWithClient(mock, &mockS3PresignClient{}, S3Config{
		Bucket:         "test-bucket",
		EncryptionType: "SSE-KMS",
		KMSKeyID:       "alias/audit",
	})
	ctx := context.Background()

	_, err := backend.Upload(ctx, &UploadRequest{
		Key:  "test.json",
		Body: strings.NewReader("data"),
	})
	if err != nil {
		t.Fatalf("Upload with encryption: %v", err)
	}
}
