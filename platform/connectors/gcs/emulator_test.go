// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gcs

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

// gcsEmulatorEndpointEnv names a running fake-gcs-server (fsouza/fake-gcs-server)
// JSON endpoint, e.g. http://localhost:4443/storage/v1/. Unset, this test is
// SKIPPED and says so; `Unit Tests: Connectors` in .github/workflows/test.yml
// starts the emulator and sets it, so the skip never happens in CI (#3645).
const gcsEmulatorEndpointEnv = "TEST_GCS_EMULATOR_ENDPOINT"

// TestGCSConnectorAgainstTheEmulator drives the connector's real client path -
// Connect with the `endpoint` option, then upload, get, list and delete -
// against a live emulator. It is what proves the credential migration did not
// break the client that the credentials feed: clientOptions is unit-tested
// beside it, and this is the half a unit test cannot cover.
//
// The emulator authenticates nothing, so the storage client's
// STORAGE_EMULATOR_HOST convention is used (it disables authentication for
// the client); the connector's `endpoint` option is still exercised because it
// is what routes the JSON API calls.
func TestGCSConnectorAgainstTheEmulator(t *testing.T) {
	endpoint := os.Getenv(gcsEmulatorEndpointEnv)
	if endpoint == "" {
		t.Skipf("%s is not set; run fsouza/fake-gcs-server and point it here (CI does)", gcsEmulatorEndpointEnv)
	}
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	host = strings.SplitN(host, "/", 2)[0]
	t.Setenv("STORAGE_EMULATOR_HOST", host)

	bucket := fmt.Sprintf("axonflow-3645-%d", time.Now().UnixNano())
	conn := NewGCSConnector()
	cfg := &base.ConnectorConfig{
		Name: "gcs-emulator", Type: "gcs", Timeout: 30 * time.Second,
		Options: map[string]interface{}{"endpoint": endpoint, "project_id": "axonflow-test"},
	}
	ctx := t.Context()
	if err := conn.Connect(ctx, cfg); err != nil {
		t.Fatalf("Connect against the emulator: %v", err)
	}
	t.Cleanup(func() { _ = conn.Disconnect(ctx) })

	exec := func(action string, params map[string]interface{}) *base.CommandResult {
		t.Helper()
		res, err := conn.Execute(ctx, &base.Command{Action: action, Parameters: params})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !res.Success {
			t.Fatalf("%s: not successful: %+v", action, res)
		}
		return res
	}
	query := func(statement string, params map[string]interface{}) *base.QueryResult {
		t.Helper()
		res, err := conn.Query(ctx, &base.Query{Statement: statement, Parameters: params})
		if err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
		return res
	}

	exec("create_bucket", map[string]interface{}{"bucket": bucket})
	exec("put_object", map[string]interface{}{"bucket": bucket, "key": "hello.txt", "content": "hello from #3645", "content_type": "text/plain"})

	got := query("get_object", map[string]interface{}{"bucket": bucket, "key": "hello.txt"})
	if got.RowCount != 1 || len(got.Rows) != 1 {
		t.Fatalf("get_object returned %d row(s), want 1: %+v", got.RowCount, got.Rows)
	}
	if got.Rows[0]["key"] != "hello.txt" || fmt.Sprint(got.Rows[0]["content"]) != "hello from #3645" {
		t.Fatalf("get_object row = %+v, want key hello.txt with the uploaded content", got.Rows[0])
	}
	listed := query("list_objects", map[string]interface{}{"bucket": bucket})
	if !strings.Contains(fmt.Sprint(listed.Rows), "hello.txt") {
		t.Fatalf("list_objects returned %+v, want hello.txt", listed.Rows)
	}
	exec("delete_object", map[string]interface{}{"bucket": bucket, "key": "hello.txt"})
	exec("delete_bucket", map[string]interface{}{"bucket": bucket})

	health, err := conn.HealthCheck(ctx)
	if err != nil || health == nil || !health.Healthy {
		t.Fatalf("HealthCheck after the round trip: healthy=%v err=%v", health != nil && health.Healthy, err)
	}
}
