// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Env vars consumed by newS3SinkFromEnv (in addition to the standard AWS SDK
// chain: AWS_REGION, AWS_ACCESS_KEY_ID, instance/role creds, etc.).
const (
	// envS3Bucket is the destination bucket. Required for the s3 sink.
	envS3Bucket = "AXONFLOW_AUDIT_S3_BUCKET"

	// envS3Prefix is the key prefix decisions land under (default
	// "axonflow/decisions"). A date partition + decision_id is appended.
	envS3Prefix = "AXONFLOW_AUDIT_S3_PREFIX"

	// envS3Region overrides the SDK's region resolution for this sink only.
	envS3Region = "AXONFLOW_AUDIT_S3_REGION"

	// envS3Endpoint points the sink at an S3-compatible store (MinIO,
	// LocalStack, on-prem). Empty uses the real AWS endpoint. No URL is ever
	// hardcoded; an operator opts in explicitly.
	envS3Endpoint = "AXONFLOW_AUDIT_S3_ENDPOINT"

	// envS3PathStyle ("true") forces path-style addressing, required by most
	// S3-compatible stores.
	envS3PathStyle = "AXONFLOW_AUDIT_S3_PATH_STYLE"

	defaultS3Prefix = "axonflow/decisions"
	defaultS3Region = "us-east-1"
)

// s3PutAPI is the one-method subset of the S3 client the sink uses, so tests
// inject a fake PutObject without a live AWS environment.
type s3PutAPI interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// s3Sink ships each decision record as one S3 object: an NDJSON line keyed by a
// date partition + decision_id. One object per decision keeps writes idempotent
// (a re-shipped decision_id overwrites in place) and lets a BigQuery / Athena /
// Snowflake external table read the prefix directly.
type s3Sink struct {
	client s3PutAPI
	bucket string
	prefix string
}

// newS3SinkFromEnv builds the S3 sink from env. Returns an error (which the
// exporter turns into a WARN + disabled export) when the bucket is unset or the
// AWS config cannot load. Never panics, never blocks boot.
func newS3SinkFromEnv(ctx context.Context) (*s3Sink, error) {
	bucket := strings.TrimSpace(os.Getenv(envS3Bucket))
	if bucket == "" {
		return nil, fmt.Errorf("%s is required for the s3 audit sink", envS3Bucket)
	}

	region := strings.TrimSpace(os.Getenv(envS3Region))
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_REGION"))
	}
	if region == "" {
		region = defaultS3Region
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	// Static creds are opt-in; the default SDK chain (env / shared config /
	// instance role / web identity) covers the common managed case.
	if ak, sk := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); ak != "" && sk != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(ak, sk, os.Getenv("AWS_SESSION_TOKEN")),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var s3Opts []func(*s3.Options)
	if endpoint := strings.TrimSpace(os.Getenv(envS3Endpoint)); endpoint != "" {
		pathStyle := strings.EqualFold(strings.TrimSpace(os.Getenv(envS3PathStyle)), "true")
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = pathStyle
		})
	}

	return newS3Sink(s3.NewFromConfig(awsCfg, s3Opts...), bucket, os.Getenv(envS3Prefix)), nil
}

// newS3Sink wires a sink around an explicit client (test seam) and normalizes
// the prefix.
func newS3Sink(client s3PutAPI, bucket, prefix string) *s3Sink {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		prefix = defaultS3Prefix
	}
	return &s3Sink{client: client, bucket: bucket, prefix: prefix}
}

func (s *s3Sink) Name() string { return "s3" }

// objectKey builds the S3 key for a record: <prefix>/<YYYY>/<MM>/<DD>/<id>.json.
// The date partition comes from the record's own Timestamp (parsed back from
// RFC 3339); an unparseable/empty timestamp falls back to "unpartitioned" so a
// record is never silently dropped on a bad clock. A missing decision_id falls
// back to "unknown", keeping the write valid rather than producing a key that
// ends in a bare slash.
func (s *s3Sink) objectKey(record DecisionRecord) string {
	partition := "unpartitioned"
	if t, err := time.Parse(time.RFC3339Nano, record.Timestamp); err == nil {
		partition = t.UTC().Format("2006/01/02")
	}
	id := strings.TrimSpace(record.DecisionID)
	if id == "" {
		id = "unknown"
	}
	return fmt.Sprintf("%s/%s/%s.json", s.prefix, partition, id)
}

// Ship writes one record as an NDJSON object. Honors ctx (the exporter passes a
// per-call timeout); the AWS SDK aborts the request when ctx is done.
func (s *s3Sink) Ship(ctx context.Context, record DecisionRecord) error {
	body, err := marshalRecord(record)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.objectKey(record)),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/x-ndjson"),
	})
	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}
	return nil
}

// Close is a no-op: the S3 client holds no persistent connection that needs an
// explicit teardown.
func (s *s3Sink) Close(context.Context) error { return nil }
