package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"axonctl/internal/axonflow"
)

// setupTestEnv sets AXONFLOW env vars pointing to the given server URL.
func setupTestEnv(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv("AXONFLOW_ENDPOINT", serverURL)
	t.Setenv("AXONFLOW_CLIENT_ID", "test-org")
	t.Setenv("AXONFLOW_CLIENT_SECRET", "test-secret")
}

func TestExecutionsListCmd_Table(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dur := 1500
	resp := axonflow.ListExecutionsResponse{
		Executions: []axonflow.ExecutionSummary{
			{
				RequestID:      "exec-001",
				WorkflowName:   "map-workflow",
				Status:         axonflow.ExecutionStatusCompleted,
				TotalSteps:     3,
				CompletedSteps: 3,
				StartedAt:      now,
				DurationMs:     &dur,
				TotalCostUSD:   0.0523,
			},
		},
		Total:  1,
		Limit:  20,
		Offset: 0,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	setupTestEnv(t, srv.URL)

	cmd := executionsListCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var output bytes.Buffer
	output.ReadFrom(r)
	out := output.String()

	if !containsAll(out, "exec-001", "map-workflow", "3/3", "$0.0523") {
		t.Errorf("table output missing expected fields:\n%s", out)
	}
}

func TestExecutionsListCmd_JSON(t *testing.T) {
	resp := axonflow.ListExecutionsResponse{
		Executions: []axonflow.ExecutionSummary{},
		Total:      0,
		Limit:      20,
		Offset:     0,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	setupTestEnv(t, srv.URL)

	cmd := executionsListCmd()
	cmd.SetArgs([]string{"--format", "json"})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var output bytes.Buffer
	output.ReadFrom(r)

	var parsed axonflow.ListExecutionsResponse
	if err := json.Unmarshal(output.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, output.String())
	}
}

func TestExecutionsListCmd_Empty(t *testing.T) {
	resp := axonflow.ListExecutionsResponse{
		Executions: []axonflow.ExecutionSummary{},
		Total:      0,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	setupTestEnv(t, srv.URL)

	cmd := executionsListCmd()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var output bytes.Buffer
	output.ReadFrom(r)
	if !containsAll(output.String(), "No executions found") {
		t.Errorf("expected empty state message, got:\n%s", output.String())
	}
}

func TestExecutionsGetCmd(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exec := axonflow.Execution{
		Summary: &axonflow.ExecutionSummary{
			RequestID:    "exec-001",
			WorkflowName: "test-wf",
			Status:       axonflow.ExecutionStatusCompleted,
			TotalSteps:   1,
			StartedAt:    now,
		},
		Steps: []axonflow.ExecutionSnapshot{
			{
				RequestID: "exec-001",
				StepIndex: 0,
				StepName:  "llm-call",
				Status:    axonflow.StepStatusCompleted,
				StartedAt: now,
				Provider:  "openai",
				Model:     "gpt-4",
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exec)
	}))
	defer srv.Close()

	setupTestEnv(t, srv.URL)

	cmd := executionsGetCmd()
	cmd.SetArgs([]string{"exec-001"})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var output bytes.Buffer
	output.ReadFrom(r)
	out := output.String()

	if !containsAll(out, "exec-001", "test-wf", "llm-call", "openai") {
		t.Errorf("get output missing expected fields:\n%s", out)
	}
}

func TestExecutionsGetCmd_MissingArg(t *testing.T) {
	cmd := executionsGetCmd()
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing argument")
	}
}

func TestExecutionsExportCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"request_id":"exec-001","steps":[]}`))
	}))
	defer srv.Close()

	setupTestEnv(t, srv.URL)

	tmpFile := t.TempDir() + "/export.json"

	cmd := executionsExportCmd()
	cmd.SetArgs([]string{"exec-001", "--output", tmpFile})

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read export file: %v", err)
	}
	if !json.Valid(data) {
		t.Error("exported file is not valid JSON")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		ms       int
		expected string
	}{
		{500, "500ms"},
		{1500, "1.5s"},
		{65000, "1.1m"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.ms)
		if result != tt.expected {
			t.Errorf("formatDuration(%d) = %s, want %s", tt.ms, result, tt.expected)
		}
	}
}

func TestTruncateID(t *testing.T) {
	short := "abc-123"
	if truncateID(short) != short {
		t.Errorf("short ID should not be truncated")
	}

	long := "abcdefghijklmnopqrstuvwxyz-1234567890-extra"
	result := truncateID(long)
	if len(result) > 36 {
		t.Errorf("long ID should be truncated, got len=%d", len(result))
	}
}

func TestColorStatus(t *testing.T) {
	// Just verify no panics and returns non-empty strings
	statuses := []string{"completed", "failed", "running", "paused", "pending"}
	for _, s := range statuses {
		result := colorStatus(s)
		if result == "" {
			t.Errorf("colorStatus(%s) returned empty string", s)
		}
	}
}

func TestMissingEnvVars(t *testing.T) {
	t.Setenv("AXONFLOW_CLIENT_ID", "")
	t.Setenv("AXONFLOW_CLIENT_SECRET", "")

	_, err := getAxonFlowClient()
	if err == nil {
		t.Fatal("expected error for missing env vars")
	}
}

// containsAll checks if s contains all substrings.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
