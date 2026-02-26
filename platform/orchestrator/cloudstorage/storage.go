// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package cloudstorage provides a unified interface for cloud object storage
// backends used by compliance audit export services. It supports S3, Azure Blob,
// GCS, and local filesystem for development.
package cloudstorage

import (
	"context"
	"io"
	"os"
	"time"
)

// StorageBackend abstracts cloud object storage for audit exports.
type StorageBackend interface {
	// Upload stores an object in the backend.
	Upload(ctx context.Context, req *UploadRequest) (*UploadResult, error)

	// Download retrieves an object by key.
	Download(ctx context.Context, key string) (io.ReadCloser, error)

	// GeneratePresignedURL creates a time-limited download URL.
	GeneratePresignedURL(ctx context.Context, key string, expiry time.Duration) (string, error)

	// Delete removes an object by key.
	Delete(ctx context.Context, key string) error

	// List returns objects matching the given prefix.
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)

	// HealthCheck verifies the backend is accessible.
	HealthCheck(ctx context.Context) error

	// Type returns the storage backend type (s3, azure, gcs, local).
	Type() string
}

// UploadRequest contains parameters for uploading an object.
type UploadRequest struct {
	Key         string
	Body        io.Reader
	ContentType string
	Metadata    map[string]string // custom metadata (export_id, org_id, framework, checksum)
	Encryption  *EncryptionConfig
}

// UploadResult contains the result of an upload operation.
type UploadResult struct {
	Key       string
	VersionID string
	ETag      string
	SizeBytes int64
}

// EncryptionConfig specifies server-side encryption settings.
type EncryptionConfig struct {
	Type     string // "SSE-S3", "SSE-KMS", "AES256"
	KMSKeyID string // for SSE-KMS
}

// ObjectInfo describes a stored object.
type ObjectInfo struct {
	Key          string
	SizeBytes    int64
	LastModified time.Time
	ETag         string
}

// StorageType identifies the storage backend type.
type StorageType string

const (
	StorageTypeS3    StorageType = "s3"
	StorageTypeAzure StorageType = "azure"
	StorageTypeGCS   StorageType = "gcs"
	StorageTypeLocal StorageType = "local"
)

// StorageConfig holds the top-level storage configuration.
type StorageConfig struct {
	Type  StorageType
	S3    S3Config
	Azure AzureConfig
	GCS   GCSConfig
	Local LocalConfig
}

// S3Config configures the S3 storage backend.
type S3Config struct {
	Bucket          string
	Region          string
	Prefix          string // key prefix for all objects
	Endpoint        string // custom endpoint for data operations (e.g. http://minio:9000)
	PublicEndpoint  string // public endpoint for presigned URLs (e.g. http://localhost:9000)
	ForcePathStyle  bool   // required for MinIO
	AccessKeyID     string // explicit credentials (optional — IAM role is preferred)
	SecretAccessKey string
	EncryptionType  string // "SSE-S3", "SSE-KMS", "AES256"
	KMSKeyID        string
	ObjectLock      bool // enable WORM compliance mode
	RetentionDays   int  // object lock retention period
}

// AzureConfig configures the Azure Blob storage backend.
type AzureConfig struct {
	ContainerName    string
	AccountName      string
	AccountKey       string
	ConnectionString string
}

// GCSConfig configures the Google Cloud Storage backend.
type GCSConfig struct {
	Bucket          string
	Prefix          string // key prefix for all objects
	CredentialsFile string // path to service account JSON
	CredentialsJSON []byte // inline service account JSON
}

// LocalConfig configures the local filesystem storage backend.
type LocalConfig struct {
	BasePath string // root directory for stored files
}

// NewStorageConfigFromEnv builds a StorageConfig from AUDIT_EXPORT_* environment variables.
// This centralises the env-to-config mapping so that both platform/orchestrator/run.go
// and ee/platform/orchestrator/compliance_init.go use the same logic.
func NewStorageConfigFromEnv() StorageConfig {
	var gcsCredentialsJSON []byte
	if v := os.Getenv("AUDIT_EXPORT_GCS_CREDENTIALS_JSON"); v != "" {
		gcsCredentialsJSON = []byte(v)
	}

	return StorageConfig{
		Type: StorageType(os.Getenv("AUDIT_EXPORT_STORAGE_TYPE")),
		S3: S3Config{
			Bucket:         os.Getenv("AUDIT_EXPORT_S3_BUCKET"),
			Region:         os.Getenv("AUDIT_EXPORT_S3_REGION"),
			Prefix:         os.Getenv("AUDIT_EXPORT_S3_PREFIX"),
			Endpoint:       os.Getenv("AUDIT_EXPORT_S3_ENDPOINT"),
			PublicEndpoint: os.Getenv("AUDIT_EXPORT_S3_PUBLIC_ENDPOINT"),
			ForcePathStyle: os.Getenv("AUDIT_EXPORT_S3_FORCE_PATH_STYLE") == "true",
			AccessKeyID:    os.Getenv("AUDIT_EXPORT_S3_ACCESS_KEY"),
			SecretAccessKey: os.Getenv("AUDIT_EXPORT_S3_SECRET_KEY"),
			EncryptionType: os.Getenv("AUDIT_EXPORT_S3_ENCRYPTION"),
			KMSKeyID:       os.Getenv("AUDIT_EXPORT_S3_KMS_KEY_ID"),
		},
		Azure: AzureConfig{
			ContainerName:    os.Getenv("AUDIT_EXPORT_AZURE_CONTAINER"),
			AccountName:      os.Getenv("AUDIT_EXPORT_AZURE_ACCOUNT_NAME"),
			AccountKey:       os.Getenv("AUDIT_EXPORT_AZURE_ACCOUNT_KEY"),
			ConnectionString: os.Getenv("AUDIT_EXPORT_AZURE_CONNECTION_STRING"),
		},
		GCS: GCSConfig{
			Bucket:          os.Getenv("AUDIT_EXPORT_GCS_BUCKET"),
			Prefix:          os.Getenv("AUDIT_EXPORT_GCS_PREFIX"),
			CredentialsFile: os.Getenv("AUDIT_EXPORT_GCS_CREDENTIALS_FILE"),
			CredentialsJSON: gcsCredentialsJSON,
		},
	}
}
