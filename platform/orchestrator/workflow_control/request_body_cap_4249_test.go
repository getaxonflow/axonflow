// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// #4249 row 5666236540: the step gate's body is its content, so it is bounded,
// and a body over the bound is refused whole before it is decoded.

// capTailMarker is the last value in a gate body built to a size: a body cut
// anywhere before its end loses it.
const capTailMarker = "tail-marker-past-any-cut"

// gateBodyOfSize is a valid step-gate body exactly size bytes long, whose last
// step_input value is capTailMarker, padded inside a leading string value.
func gateBodyOfSize(t *testing.T, size int64) []byte {
	t.Helper()
	shape := func(pad string) []byte {
		body, err := json.Marshal(map[string]interface{}{
			"step_name": "generate",
			"step_type": StepTypeLLMCall,
			"step_input": map[string]interface{}{
				"a_padding": pad,
				"z_tail":    capTailMarker,
			},
		})
		if err != nil {
			t.Fatalf("marshal gate body: %v", err)
		}
		return body
	}
	fixed := int64(len(shape("")))
	if size < fixed {
		t.Fatalf("size %d is under the body's fixed %d bytes", size, fixed)
	}
	body := shape(strings.Repeat("p", int(size-fixed)))
	if int64(len(body)) != size {
		t.Fatalf("built a %d-byte body, want %d", len(body), size)
	}
	return body
}

// gateWithBody drives the handler's gate with body, declaring its length only
// when declared is true (a chunked body otherwise), and counts the refusals the
// handler records.
func gateWithBody(t *testing.T, body []byte, declared bool) (*httptest.ResponseRecorder, *MockRepository, string, int) {
	t.Helper()
	handler, svc, repo := setupTestHandlerWith(allowingPolicyEvaluator{})
	refused := 0
	handler.SetOversizedBodyRecorder(func() { refused++ })
	workflow, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "capped"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	var reader io.Reader = bytes.NewReader(body)
	if !declared {
		reader = io.MultiReader(reader) // hides the length: httptest declares none
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/gate", reader)
	if declared && req.ContentLength != int64(len(body)) {
		t.Fatalf("declared length %d, want %d", req.ContentLength, len(body))
	}
	if !declared && req.ContentLength != -1 {
		t.Fatalf("a chunked body declared length %d, want -1", req.ContentLength)
	}
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)
	return rr, repo, workflow.WorkflowID, refused
}

func TestTheStepGateBoundIsOneMebibyte(t *testing.T) {
	if MaxStepRequestBody != 1<<20 {
		t.Fatalf("MaxStepRequestBody = %d, want 1 MiB (the agent's mcpMaxRequestBody)", MaxStepRequestBody)
	}
}

func TestAStepGateBodyAtTheBoundIsGatedWhole(t *testing.T) {
	for _, declared := range []bool{true, false} {
		rr, repo, workflowID, refused := gateWithBody(t, gateBodyOfSize(t, MaxStepRequestBody), declared)
		if rr.Code != http.StatusOK {
			t.Fatalf("declared=%v: status %d at the bound, want 200; body %.300s", declared, rr.Code, rr.Body.String())
		}
		if refused != 0 {
			t.Errorf("declared=%v: %d refusal(s) recorded for a body at the bound, want none", declared, refused)
		}
		step, err := repo.GetStep(context.Background(), workflowID, "step-1")
		if err != nil {
			t.Fatalf("declared=%v: the gated step was not recorded: %v", declared, err)
		}
		if !bytes.Contains(step.StepInput, []byte(capTailMarker)) {
			t.Errorf("declared=%v: the recorded step input lost its last value: the body was cut", declared)
		}
	}
}

func TestAStepGateBodyOneByteOverTheBoundIsRefusedBeforeDecode(t *testing.T) {
	for _, declared := range []bool{true, false} {
		rr, repo, workflowID, refused := gateWithBody(t, gateBodyOfSize(t, MaxStepRequestBody+1), declared)
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("declared=%v: status %d one byte over the bound, want 413; body %.300s", declared, rr.Code, rr.Body.String())
		}
		var got RequestTooLargeResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("declared=%v: the 413 body does not decode: %v", declared, err)
		}
		if got.Error != RequestTooLarge || got.Limit != MaxStepRequestBody {
			t.Errorf("declared=%v: 413 body %+v, want error %q limit %d", declared, got, RequestTooLarge, MaxStepRequestBody)
		}
		if refused != 1 {
			t.Errorf("declared=%v: %d refusal(s) recorded, want 1", declared, refused)
		}
		if _, err := repo.GetStep(context.Background(), workflowID, "step-1"); err == nil {
			t.Errorf("declared=%v: a step was gated for a refused body", declared)
		}
	}
}

func TestADeclaredLengthOverTheBoundIsRefusedWithoutReadingTheBody(t *testing.T) {
	body := &countingReader{r: bytes.NewReader(gateBodyOfSize(t, 512))}
	req := httptest.NewRequest(http.MethodPost, "/gate", body)
	req.ContentLength = MaxStepRequestBody + 1
	rr := httptest.NewRecorder()
	if err := ReadBoundedBody(rr, req); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("err %v; want ErrRequestTooLarge for a declared length over the bound", err)
	}
	if body.read != 0 {
		t.Errorf("%d byte(s) read from a body refused on its declared length, want 0", body.read)
	}
}

type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}
