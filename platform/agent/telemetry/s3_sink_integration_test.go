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

//go:build integration

// Integration proof that the S3 sink + exporter ship a decision record through
// the real AWS SDK to a real S3-compatible server (MinIO), then read it back.
// This exercises the actual network path the unit tests stub out.
//
// Off by default (the `integration` build tag). Run against a live MinIO:
//
//	AXONFLOW_TEST_S3_ENDPOINT=http://127.0.0.1:19000 \
//	AXONFLOW_TEST_S3_BUCKET=axonflow-it \
//	AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
//	go test -tags integration -run TestS3Sink_Integration ./agent/telemetry/ -v
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func itS3Client(t *testing.T, endpoint string) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), "")),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

// TestS3Sink_Integration ships a record through the real s3Sink and verifies the
// object lands at the date-partitioned key with the correlatable JSON body.
func TestS3Sink_Integration(t *testing.T) {
	endpoint := os.Getenv("AXONFLOW_TEST_S3_ENDPOINT")
	bucket := os.Getenv("AXONFLOW_TEST_S3_BUCKET")
	if endpoint == "" || bucket == "" {
		t.Skip("set AXONFLOW_TEST_S3_ENDPOINT + AXONFLOW_TEST_S3_BUCKET to run")
	}
	client := itS3Client(t, endpoint)

	// Ensure the bucket exists (ignore "already owned").
	_, _ = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})

	sink := newS3Sink(client, bucket, "it/decisions")
	rec := DecisionRecord{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		DecisionID: "it-dec-" + time.Now().UTC().Format("150405.000000"),
		Stage:      "tool",
		Verdict:    "allow",
		PolicyIDs:  []string{"indonesia_pii_protection"},
		Context:    map[string]string{"x_session_id": "it-sess-1"},
	}

	// Ship through the exporter so the full guard path (breaker + timeout) runs.
	exp := newExporterWithSink(sink, exporterConfig{timeout: 5 * time.Second, breakerThreshold: 3, breakerCooldown: time.Second, buffer: 8})
	exp.Export(rec)
	if err := exp.Close(context.Background()); err != nil {
		t.Fatalf("exporter close: %v", err)
	}
	if s := exp.Stats(); s.Shipped != 1 || s.Failed != 0 {
		t.Fatalf("exporter stats: %+v (want 1 shipped, 0 failed)", s)
	}

	// Read the object back at the expected key and validate the round-tripped body.
	key := sink.objectKey(rec)
	out, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("get shipped object %q: %v", key, err)
	}
	defer out.Body.Close()
	body, _ := io.ReadAll(out.Body)
	if !bytes.HasSuffix(body, []byte("\n")) {
		t.Fatal("shipped object must be newline-terminated NDJSON")
	}
	var back DecisionRecord
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("round-tripped body not valid JSON: %v", err)
	}
	if back.DecisionID != rec.DecisionID || back.Context["x_session_id"] != "it-sess-1" {
		t.Fatalf("round-tripped record mismatch: %+v", back)
	}
	if !strings.HasPrefix(key, "it/decisions/") {
		t.Fatalf("unexpected key layout: %q", key)
	}
	t.Logf("OK: shipped + read back %q (decision_id=%s)", key, back.DecisionID)
}
