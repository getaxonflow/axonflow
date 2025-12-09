// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdk

import (
	"context"
	"fmt"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

func TestMockConnector(t *testing.T) {
	t.Run("basic operations", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")

		if mock.Type() != "mock" {
			t.Errorf("expected type mock, got %s", mock.Type())
		}

		if mock.Name() != "test" {
			t.Errorf("expected name test, got %s", mock.Name())
		}

		if mock.Version() != "1.0.0-mock" {
			t.Errorf("expected version 1.0.0-mock, got %s", mock.Version())
		}

		caps := mock.Capabilities()
		if len(caps) != 2 {
			t.Errorf("expected 2 capabilities, got %d", len(caps))
		}
	})

	t.Run("connect and disconnect", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		config := &base.ConnectorConfig{
			Name: "my-connector",
			Type: "mock",
		}

		err := mock.Connect(ctx, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !mock.IsConnected() {
			t.Error("expected connected after Connect")
		}

		if mock.Name() != "my-connector" {
			t.Errorf("expected name to be updated, got %s", mock.Name())
		}

		calls := mock.GetConnectCalls()
		if len(calls) != 1 {
			t.Errorf("expected 1 connect call, got %d", len(calls))
		}

		err = mock.Disconnect(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.IsConnected() {
			t.Error("expected disconnected after Disconnect")
		}

		if mock.GetDisconnectCalls() != 1 {
			t.Errorf("expected 1 disconnect call, got %d", mock.GetDisconnectCalls())
		}
	})

	t.Run("query with mock result", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		mock.SetQueryResult(&base.QueryResult{
			Rows: []map[string]interface{}{
				{"id": 1, "name": "Alice"},
				{"id": 2, "name": "Bob"},
			},
			RowCount:  2,
			Connector: "test",
		})

		query := &base.Query{Statement: "SELECT * FROM users"}
		result, err := mock.Query(ctx, query)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.RowCount != 2 {
			t.Errorf("expected 2 rows, got %d", result.RowCount)
		}

		calls := mock.GetQueryCalls()
		if len(calls) != 1 {
			t.Errorf("expected 1 query call, got %d", len(calls))
		}

		if calls[0].Query.Statement != "SELECT * FROM users" {
			t.Error("query statement not recorded correctly")
		}
	})

	t.Run("query with error", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		mock.SetQueryError(fmt.Errorf("query failed"))

		_, err := mock.Query(ctx, &base.Query{})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("execute with mock result", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		mock.SetExecuteResult(&base.CommandResult{
			Success:      true,
			RowsAffected: 5,
			Message:      "deleted 5 rows",
		})

		cmd := &base.Command{Action: "DELETE", Statement: "DELETE FROM users"}
		result, err := mock.Execute(ctx, cmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.RowsAffected != 5 {
			t.Errorf("expected 5 rows affected, got %d", result.RowsAffected)
		}

		calls := mock.GetExecuteCalls()
		if len(calls) != 1 {
			t.Errorf("expected 1 execute call, got %d", len(calls))
		}
	})

	t.Run("health check", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		status, err := mock.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !status.Healthy {
			t.Error("expected healthy status")
		}

		if mock.GetHealthCalls() != 1 {
			t.Errorf("expected 1 health call, got %d", mock.GetHealthCalls())
		}

		// Set unhealthy
		mock.SetHealthStatus(&base.HealthStatus{Healthy: false, Error: "down"})
		status, _ = mock.HealthCheck(ctx)

		if status.Healthy {
			t.Error("expected unhealthy status")
		}

		// Set error
		mock.SetHealthError(fmt.Errorf("check failed"))
		_, err = mock.HealthCheck(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("connect error", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		mock.SetConnectError(fmt.Errorf("connection refused"))

		err := mock.Connect(ctx, &base.ConnectorConfig{})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("disconnect error", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		mock.SetDisconnectError(fmt.Errorf("disconnect failed"))

		err := mock.Disconnect(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("custom query handler", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		mock.SetOnQuery(func(ctx context.Context, q *base.Query) (*base.QueryResult, error) {
			if q.Statement == "SELECT 1" {
				return &base.QueryResult{RowCount: 1}, nil
			}
			return nil, fmt.Errorf("unknown query")
		})

		result, err := mock.Query(ctx, &base.Query{Statement: "SELECT 1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.RowCount != 1 {
			t.Error("expected 1 row")
		}

		_, err = mock.Query(ctx, &base.Query{Statement: "SELECT 2"})
		if err == nil {
			t.Error("expected error for unknown query")
		}
	})

	t.Run("reset", func(t *testing.T) {
		mock := NewMockConnector("test", "mock")
		ctx := context.Background()

		mock.Connect(ctx, &base.ConnectorConfig{})
		mock.Query(ctx, &base.Query{})
		mock.Execute(ctx, &base.Command{})
		mock.Disconnect(ctx)
		mock.HealthCheck(ctx)

		mock.Reset()

		if len(mock.GetConnectCalls()) != 0 {
			t.Error("expected connect calls to be reset")
		}
		if len(mock.GetQueryCalls()) != 0 {
			t.Error("expected query calls to be reset")
		}
		if len(mock.GetExecuteCalls()) != 0 {
			t.Error("expected execute calls to be reset")
		}
		if mock.GetDisconnectCalls() != 0 {
			t.Error("expected disconnect calls to be reset")
		}
		if mock.GetHealthCalls() != 0 {
			t.Error("expected health calls to be reset")
		}
	})
}

func TestTestHarness(t *testing.T) {
	t.Run("create and cleanup", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		ctx := harness.Context()
		if ctx == nil {
			t.Error("expected context")
		}
	})

	t.Run("with timeout", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		harness.WithTimeout(100 * time.Millisecond)

		ctx := harness.Context()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("expected deadline to be set")
		}

		if time.Until(deadline) > 200*time.Millisecond {
			t.Error("expected short deadline")
		}
	})

	t.Run("new config", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		config := harness.NewConfig("my-conn", "my-type")

		if config.Name != "my-conn" {
			t.Errorf("expected name my-conn, got %s", config.Name)
		}

		if config.Type != "my-type" {
			t.Errorf("expected type my-type, got %s", config.Type)
		}
	})

	t.Run("new mock connector", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		mock := harness.NewMockConnector()

		if mock == nil {
			t.Error("expected mock connector")
		}
	})
}

func TestTestHarnessAssertions(t *testing.T) {
	// These tests use a sub-test pattern to verify assertions fail correctly
	// without failing the main test

	t.Run("assert row count", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		result := &base.QueryResult{RowCount: 5}
		harness.AssertRowCount(result, 5)
	})

	t.Run("assert success", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		result := &base.CommandResult{Success: true}
		harness.AssertSuccess(result)
	})

	t.Run("assert healthy", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		status := &base.HealthStatus{Healthy: true}
		harness.AssertHealthy(status)
	})

	t.Run("assert unhealthy", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		status := &base.HealthStatus{Healthy: false}
		harness.AssertUnhealthy(status)
	})

	t.Run("assert equal", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		harness.AssertEqual(42, 42)
		harness.AssertEqual("hello", "hello")
	})

	t.Run("assert true", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		harness.AssertTrue(true, "should be true")
	})

	t.Run("assert false", func(t *testing.T) {
		harness := NewTestHarness(t)
		defer harness.Cleanup()

		harness.AssertFalse(false, "should be false")
	})
}

func TestConnectAndTest(t *testing.T) {
	harness := NewTestHarness(t)
	defer harness.Cleanup()

	mock := harness.NewMockConnector()
	config := harness.NewConfig("test", "mock")

	executed := false

	harness.ConnectAndTest(mock, config, func() {
		executed = true
		if !mock.IsConnected() {
			t.Error("expected connected during test")
		}
	})

	if !executed {
		t.Error("test function not executed")
	}

	if mock.IsConnected() {
		t.Error("expected disconnected after test")
	}
}

func TestFailingConnector(t *testing.T) {
	t.Run("always fails", func(t *testing.T) {
		failing := NewFailingConnector(nil)
		ctx := context.Background()

		if err := failing.Connect(ctx, nil); err == nil {
			t.Error("expected error")
		}

		if err := failing.Disconnect(ctx); err == nil {
			t.Error("expected error")
		}

		if _, err := failing.HealthCheck(ctx); err == nil {
			t.Error("expected error")
		}

		if _, err := failing.Query(ctx, nil); err == nil {
			t.Error("expected error")
		}

		if _, err := failing.Execute(ctx, nil); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("custom error", func(t *testing.T) {
		expectedErr := fmt.Errorf("custom error")
		failing := NewFailingConnector(expectedErr)
		ctx := context.Background()

		err := failing.Connect(ctx, nil)
		if err != expectedErr {
			t.Errorf("expected custom error, got %v", err)
		}
	})

	t.Run("metadata", func(t *testing.T) {
		failing := NewFailingConnector(nil)

		if failing.Name() != "failing" {
			t.Error("expected name failing")
		}

		if failing.Type() != "failing" {
			t.Error("expected type failing")
		}

		if failing.Version() != "1.0.0" {
			t.Error("expected version 1.0.0")
		}

		if failing.Capabilities() != nil {
			t.Error("expected nil capabilities")
		}
	})
}

func TestTableDrivenTests(t *testing.T) {
	mock := NewMockConnector("test", "mock")
	config := &base.ConnectorConfig{Name: "test", Type: "mock", Timeout: time.Second}

	tests := []TableDrivenTest{
		{
			Name:  "simple query",
			Query: &base.Query{Statement: "SELECT 1"},
		},
		{
			Name:    "simple command",
			Command: &base.Command{Action: "INSERT"},
		},
	}

	RunTableTests(t, mock, config, tests)
}
