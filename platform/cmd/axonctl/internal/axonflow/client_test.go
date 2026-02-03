package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-org", "test-secret")
}

func TestListExecutions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	resp := ListExecutionsResponse{
		Executions: []ExecutionSummary{
			{
				RequestID:    "exec-001",
				WorkflowName: "test-workflow",
				Status:       ExecutionStatusCompleted,
				TotalSteps:   3,
				StartedAt:    now,
				TotalCostUSD: 0.05,
			},
		},
		Total:  1,
		Limit:  10,
		Offset: 0,
	}

	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/executions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Client-ID") != "test-org" {
			t.Errorf("missing X-Client-ID header")
		}
		if r.Header.Get("X-Client-Secret") != "test-secret" {
			t.Errorf("missing X-Client-Secret header")
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("expected limit=10, got %s", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	result, err := client.ListExecutions(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(result.Executions))
	}
	if result.Executions[0].RequestID != "exec-001" {
		t.Errorf("expected request_id exec-001, got %s", result.Executions[0].RequestID)
	}
}

func TestListExecutionsWithFilters(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("status") != "completed" {
			t.Errorf("expected status=completed, got %s", q.Get("status"))
		}
		if q.Get("workflow_id") != "wf-1" {
			t.Errorf("expected workflow_id=wf-1, got %s", q.Get("workflow_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ListExecutionsResponse{})
	})

	_, err := client.ListExecutions(ListOptions{
		Status:     "completed",
		WorkflowID: "wf-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetExecution(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exec := Execution{
		Summary: &ExecutionSummary{
			RequestID:    "exec-001",
			WorkflowName: "test-workflow",
			Status:       ExecutionStatusCompleted,
			TotalSteps:   2,
			StartedAt:    now,
		},
		Steps: []ExecutionSnapshot{
			{
				RequestID: "exec-001",
				StepIndex: 0,
				StepName:  "step-1",
				Status:    StepStatusCompleted,
				StartedAt: now,
			},
			{
				RequestID: "exec-001",
				StepIndex: 1,
				StepName:  "step-2",
				Status:    StepStatusCompleted,
				StartedAt: now,
			},
		},
	}

	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/executions/exec-001" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exec)
	})

	result, err := client.GetExecution("exec-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary.RequestID != "exec-001" {
		t.Errorf("expected exec-001, got %s", result.Summary.RequestID)
	}
	if len(result.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(result.Steps))
	}
}

func TestGetExecutionTimeline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	timeline := []TimelineEntry{
		{StepIndex: 0, StepName: "step-1", Status: StepStatusCompleted, StartedAt: now},
		{StepIndex: 1, StepName: "step-2", Status: StepStatusFailed, StartedAt: now, HasError: true},
	}

	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/executions/exec-001/timeline" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(timeline)
	})

	result, err := client.GetExecutionTimeline("exec-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result[1].HasError != true {
		t.Error("expected step-2 to have error")
	}
}

func TestExportExecution(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/executions/exec-001/export" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("include_input") != "true" {
			t.Error("expected include_input=true")
		}
		if q.Get("include_output") != "true" {
			t.Error("expected include_output=true")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"request_id":"exec-001","steps":[]}`))
	})

	data, err := client.ExportExecution("exec-001", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty export data")
	}
}

func TestAPIError(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "not_found",
			Code:    "not_found",
			Message: "Execution not found",
		})
	})

	_, err := client.GetExecution("nonexistent")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestNetworkError(t *testing.T) {
	client := NewClient("http://localhost:1", "test", "test")
	_, err := client.ListExecutions(ListOptions{})
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestGetExecutionSteps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	steps := []ExecutionSnapshot{
		{RequestID: "exec-001", StepIndex: 0, StepName: "step-1", Status: StepStatusCompleted, StartedAt: now},
	}

	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/executions/exec-001/steps" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(steps)
	})

	result, err := client.GetExecutionSteps("exec-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 step, got %d", len(result))
	}
}
