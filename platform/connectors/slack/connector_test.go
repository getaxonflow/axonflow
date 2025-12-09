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

package slack

import (
	"context"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewSlackConnector(t *testing.T) {
	conn := NewSlackConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestSlackConnector_Connect(t *testing.T) {
	conn := NewSlackConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name: "test-slack",
		Type: "slack",
	}

	err := conn.Connect(ctx, config)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSlackConnector_Disconnect(t *testing.T) {
	conn := NewSlackConnector()
	ctx := context.Background()

	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSlackConnector_HealthCheck(t *testing.T) {
	conn := NewSlackConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status for OSS stub")
	}
}

func TestSlackConnector_Query(t *testing.T) {
	conn := NewSlackConnector()
	ctx := context.Background()
	query := &base.Query{Statement: "list"}

	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSlackConnector_Execute(t *testing.T) {
	conn := NewSlackConnector()
	ctx := context.Background()
	cmd := &base.Command{Action: "send"}

	_, err := conn.Execute(ctx, cmd)
	if err == nil {
		t.Error("expected error for OSS stub")
	}
}

func TestSlackConnector_Name(t *testing.T) {
	conn := NewSlackConnector()

	// Without config
	if got := conn.Name(); got != "slack" {
		t.Errorf("Name() = %q, want %q", got, "slack")
	}

	// With config
	conn.config = &base.ConnectorConfig{Name: "my-slack"}
	if got := conn.Name(); got != "my-slack" {
		t.Errorf("Name() = %q, want %q", got, "my-slack")
	}
}

func TestSlackConnector_Type(t *testing.T) {
	conn := NewSlackConnector()
	if got := conn.Type(); got != "slack" {
		t.Errorf("Type() = %q, want %q", got, "slack")
	}
}

func TestSlackConnector_Version(t *testing.T) {
	conn := NewSlackConnector()
	if got := conn.Version(); got != "oss-stub" {
		t.Errorf("Version() = %q, want %q", got, "oss-stub")
	}
}

func TestSlackConnector_Capabilities(t *testing.T) {
	conn := NewSlackConnector()
	caps := conn.Capabilities()
	if len(caps) != 0 {
		t.Errorf("expected empty capabilities for OSS stub, got %v", caps)
	}
}
