//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// s3Client is the subset of the S3 client API we use, enabling mock injection.
type s3Client interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// s3PresignClient is the subset of the presign client API we use.
type s3PresignClient interface {
	PresignGetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

// S3Backend implements StorageBackend for Amazon S3 (and S3-compatible stores like MinIO).
type S3Backend struct {
	client  s3Client
	presign s3PresignClient
	cfg     S3Config
}

// NewS3Backend creates a new S3 storage backend.
func NewS3Backend(ctx context.Context, cfg S3Config) (*S3Backend, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3: bucket is required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(cfg.Region))

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("s3: load aws config: %w", err)
	}

	var s3Opts []func(*s3.Options)
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = cfg.ForcePathStyle
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Opts...)

	// Use a separate client for presigned URLs if PublicEndpoint is set.
	// This is needed when the data endpoint is internal (e.g. minio:9000)
	// but presigned URLs must use a public address (e.g. localhost:9000).
	var presignClient s3PresignClient
	if cfg.PublicEndpoint != "" && cfg.PublicEndpoint != cfg.Endpoint {
		publicClient := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.PublicEndpoint)
			o.UsePathStyle = cfg.ForcePathStyle
		})
		presignClient = s3.NewPresignClient(publicClient)
	} else {
		presignClient = s3.NewPresignClient(client)
	}

	return &S3Backend{
		client:  client,
		presign: presignClient,
		cfg:     cfg,
	}, nil
}

// newS3BackendWithClient creates an S3Backend with injected clients (for testing).
func newS3BackendWithClient(client s3Client, presign s3PresignClient, cfg S3Config) *S3Backend {
	return &S3Backend{client: client, presign: presign, cfg: cfg}
}

func (b *S3Backend) fullKey(key string) string {
	if b.cfg.Prefix != "" {
		return b.cfg.Prefix + key
	}
	return key
}

// Upload stores an object in S3.
func (b *S3Backend) Upload(ctx context.Context, req *UploadRequest) (*UploadResult, error) {
	// Buffer the body to determine size
	var buf bytes.Buffer
	n, err := io.Copy(&buf, req.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 upload: read body: %w", err)
	}

	input := &s3.PutObjectInput{
		Bucket:      aws.String(b.cfg.Bucket),
		Key:         aws.String(b.fullKey(req.Key)),
		Body:        bytes.NewReader(buf.Bytes()),
		ContentType: aws.String(req.ContentType),
	}

	// Set metadata
	if len(req.Metadata) > 0 {
		input.Metadata = req.Metadata
	}

	// Server-side encryption
	encType := b.cfg.EncryptionType
	kmsKey := b.cfg.KMSKeyID
	if req.Encryption != nil {
		encType = req.Encryption.Type
		kmsKey = req.Encryption.KMSKeyID
	}
	switch encType {
	case "SSE-KMS", "aws:kms":
		input.ServerSideEncryption = s3types.ServerSideEncryptionAwsKms
		if kmsKey != "" {
			input.SSEKMSKeyId = aws.String(kmsKey)
		}
	case "SSE-S3":
		input.ServerSideEncryption = s3types.ServerSideEncryptionAes256
	case "AES256":
		input.ServerSideEncryption = s3types.ServerSideEncryptionAes256
	}

	// Object Lock for WORM compliance
	if b.cfg.ObjectLock && b.cfg.RetentionDays > 0 {
		input.ObjectLockMode = s3types.ObjectLockModeCompliance
		retainUntil := time.Now().UTC().AddDate(0, 0, b.cfg.RetentionDays)
		input.ObjectLockRetainUntilDate = &retainUntil
	}

	out, err := b.client.PutObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("s3 upload: %w", err)
	}

	result := &UploadResult{
		Key:       req.Key,
		SizeBytes: n,
	}
	if out.VersionId != nil {
		result.VersionID = *out.VersionId
	}
	if out.ETag != nil {
		result.ETag = *out.ETag
	}

	return result, nil
}

// Download retrieves an object from S3.
func (b *S3Backend) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.cfg.Bucket),
		Key:    aws.String(b.fullKey(key)),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 download: %w", err)
	}
	return out.Body, nil
}

// GeneratePresignedURL creates a presigned GET URL for the object.
func (b *S3Backend) GeneratePresignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	presigned, err := b.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.cfg.Bucket),
		Key:    aws.String(b.fullKey(key)),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiry
	})
	if err != nil {
		return "", fmt.Errorf("s3 presign: %w", err)
	}
	return presigned.URL, nil
}

// Delete removes an object from S3.
func (b *S3Backend) Delete(ctx context.Context, key string) error {
	_, err := b.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(b.cfg.Bucket),
		Key:    aws.String(b.fullKey(key)),
	})
	if err != nil {
		return fmt.Errorf("s3 delete: %w", err)
	}
	return nil
}

// List returns objects with the given prefix.
func (b *S3Backend) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var objects []ObjectInfo
	var continuationToken *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(b.cfg.Bucket),
			Prefix:            aws.String(b.fullKey(prefix)),
			ContinuationToken: continuationToken,
		}

		out, err := b.client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("s3 list: %w", err)
		}

		for _, obj := range out.Contents {
			info := ObjectInfo{}
			if obj.Key != nil {
				info.Key = *obj.Key
			}
			if obj.Size != nil {
				info.SizeBytes = *obj.Size
			}
			if obj.LastModified != nil {
				info.LastModified = *obj.LastModified
			}
			if obj.ETag != nil {
				info.ETag = *obj.ETag
			}
			objects = append(objects, info)
		}

		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		continuationToken = out.NextContinuationToken
	}

	return objects, nil
}

// Type returns the storage backend type.
func (b *S3Backend) Type() string { return string(StorageTypeS3) }

// HealthCheck verifies the S3 bucket is accessible.
func (b *S3Backend) HealthCheck(ctx context.Context) error {
	_, err := b.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(b.cfg.Bucket),
	})
	if err != nil {
		return fmt.Errorf("s3 health check: %w", err)
	}
	return nil
}
