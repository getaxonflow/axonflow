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
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakePutAPI captures the last PutObject call and can be made to fail.
type fakePutAPI struct {
	err    error
	bucket string
	key    string
	body   []byte
	ctype  string
	calls  int
}

func (f *fakePutAPI) PutObject(ctx context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if in.Bucket != nil {
		f.bucket = *in.Bucket
	}
	if in.Key != nil {
		f.key = *in.Key
	}
	if in.ContentType != nil {
		f.ctype = *in.ContentType
	}
	if in.Body != nil {
		b, _ := io.ReadAll(in.Body)
		f.body = b
	}
	return &s3.PutObjectOutput{}, nil
}

func newTestRecord() DecisionRecord {
	return DecisionRecord{
		Timestamp:  "2026-06-22T09:15:30Z",
		DecisionID: "dec-abc-123",
		Stage:      "tool",
		Verdict:    "allow",
		Context:    map[string]string{"x_session_id": "sess-7"},
	}
}

func TestS3Sink_ShipWritesNDJSONObject(t *testing.T) {
	put := &fakePutAPI{}
	sink := newS3Sink(put, "audit-bucket", "axonflow/decisions")

	if err := sink.Ship(context.Background(), newTestRecord()); err != nil {
		t.Fatalf("Ship error: %v", err)
	}
	if put.bucket != "audit-bucket" {
		t.Fatalf("bucket = %q", put.bucket)
	}
	if put.key != "axonflow/decisions/2026/06/22/dec-abc-123.json" {
		t.Fatalf("key = %q, want date-partitioned by decision_id", put.key)
	}
	if put.ctype != "application/x-ndjson" {
		t.Fatalf("content-type = %q", put.ctype)
	}
	if len(put.body) == 0 || put.body[len(put.body)-1] != '\n' {
		t.Fatal("body must be newline-terminated NDJSON")
	}
	var rec DecisionRecord
	if err := json.Unmarshal(put.body, &rec); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if rec.DecisionID != "dec-abc-123" || rec.Context["x_session_id"] != "sess-7" {
		t.Fatalf("shipped record fields wrong: %+v", rec)
	}
}

func TestS3Sink_ShipPropagatesPutError(t *testing.T) {
	put := &fakePutAPI{err: errors.New("AccessDenied")}
	sink := newS3Sink(put, "b", "")
	err := sink.Ship(context.Background(), newTestRecord())
	if err == nil {
		t.Fatal("Ship must return the PutObject error")
	}
	if !strings.Contains(err.Error(), "s3 put") {
		t.Fatalf("error should be wrapped with context, got %v", err)
	}
}

func TestS3Sink_ObjectKeyPartitions(t *testing.T) {
	sink := newS3Sink(&fakePutAPI{}, "b", "p")
	cases := []struct {
		name    string
		record  DecisionRecord
		wantKey string
	}{
		{
			name:    "normal",
			record:  DecisionRecord{Timestamp: "2026-01-05T00:00:00Z", DecisionID: "d1"},
			wantKey: "p/2026/01/05/d1.json",
		},
		{
			name:    "bad timestamp falls back to unpartitioned",
			record:  DecisionRecord{Timestamp: "not-a-time", DecisionID: "d2"},
			wantKey: "p/unpartitioned/d2.json",
		},
		{
			name:    "empty decision id falls back to unknown",
			record:  DecisionRecord{Timestamp: "2026-01-05T00:00:00Z", DecisionID: ""},
			wantKey: "p/2026/01/05/unknown.json",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sink.objectKey(tc.record); got != tc.wantKey {
				t.Fatalf("objectKey = %q, want %q", got, tc.wantKey)
			}
		})
	}
}

func TestNewS3Sink_NormalizesPrefix(t *testing.T) {
	cases := map[string]string{
		"":                   defaultS3Prefix,
		"   ":                defaultS3Prefix,
		"/leading/":          "leading",
		"trailing/":          "trailing",
		"a/b/c":              "a/b/c",
		"axonflow/decisions": "axonflow/decisions",
	}
	for in, want := range cases {
		s := newS3Sink(&fakePutAPI{}, "b", in)
		if s.prefix != want {
			t.Fatalf("prefix %q normalized to %q, want %q", in, s.prefix, want)
		}
	}
}

func TestS3Sink_NameAndClose(t *testing.T) {
	sink := newS3Sink(&fakePutAPI{}, "b", "p")
	if sink.Name() != "s3" {
		t.Fatalf("Name = %q, want s3", sink.Name())
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Fatalf("Close error: %v", err)
	}
}

func TestNewS3SinkFromEnv_RequiresBucket(t *testing.T) {
	t.Setenv(envS3Bucket, "")
	if _, err := newS3SinkFromEnv(context.Background()); err == nil {
		t.Fatal("newS3SinkFromEnv must error when the bucket is unset")
	}
}

func TestNewS3SinkFromEnv_BuildsWithBucket(t *testing.T) {
	t.Setenv(envS3Bucket, "my-audit-bucket")
	t.Setenv(envS3Region, "us-west-2")
	t.Setenv(envS3Prefix, "custom/prefix")
	// No endpoint / static creds: exercises the default SDK config path.
	sink, err := newS3SinkFromEnv(context.Background())
	if err != nil {
		t.Fatalf("newS3SinkFromEnv error: %v", err)
	}
	if sink.bucket != "my-audit-bucket" || sink.prefix != "custom/prefix" {
		t.Fatalf("sink built with wrong config: %+v", sink)
	}
}

func TestNewS3SinkFromEnv_RespectsEndpointOverride(t *testing.T) {
	t.Setenv(envS3Bucket, "b")
	t.Setenv(envS3Endpoint, "http://localhost:9000") // MinIO-style
	t.Setenv(envS3PathStyle, "true")
	sink, err := newS3SinkFromEnv(context.Background())
	if err != nil {
		t.Fatalf("newS3SinkFromEnv with endpoint override errored: %v", err)
	}
	if sink == nil {
		t.Fatal("expected a sink")
	}
	// A live Ship is not attempted (no server); construction success is enough
	// to prove the endpoint path doesn't error.
	_ = time.Now
}
