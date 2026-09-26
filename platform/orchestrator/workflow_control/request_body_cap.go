// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// THE STEP PLANES' BODIES ARE BOUNDED, AND A BODY OVER THE BOUND IS REFUSED
// WHOLE (#4249 row 5666236540).
//
// The step gate and the multi-agent routes present a step's input to the
// anchored engine as content, so the content a detector scans is the body the
// caller sent. A body that does not fit is never cut to fit: a slice would let a
// pattern past the cut through undetected. It is answered 413 before anything
// decodes it, so the step is neither gated nor run.
//
// The bound mirrors the agent's MCP body cap (mcpMaxRequestBody, 1 MiB). The
// largest workflow or plan body a runtime-e2e fixture sends is far under it.

// MaxStepRequestBody is the largest request body a step-plane route accepts.
const MaxStepRequestBody int64 = 1 << 20

// RequestTooLarge is the error and refusal reason a body over the bound is
// answered with.
const RequestTooLarge = "request_too_large"

// RequestTooLargeResponse is the 413 body every step-plane route answers with.
type RequestTooLargeResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Limit   int64  `json:"limit_bytes"`
}

// ErrRequestTooLarge is ReadBoundedBody's refusal of a body over the bound.
var ErrRequestTooLarge = errors.New("request body exceeds the step-plane bound")

// ReadBoundedBody reads the request body whole when it fits MaxStepRequestBody
// and puts it back for the handler to decode. A body over the bound returns
// ErrRequestTooLarge - a declared Content-Length over it without reading, a
// chunked body once reading passes it - and any other read failure its error.
// The caller answers in its own error family: the step gate with
// WriteRequestTooLarge, run.go's multi-agent routes with their flat envelope.
func ReadBoundedBody(w http.ResponseWriter, r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if r.ContentLength > MaxStepRequestBody {
		return ErrRequestTooLarge
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxStepRequestBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return ErrRequestTooLarge
		}
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// RequestTooLargeMessage is the refusal's message on every step-plane route.
var RequestTooLargeMessage = fmt.Sprintf("request body exceeds %d bytes; nothing was gated or run", MaxStepRequestBody)

// boundGateBody is the step gate's use of the bound: its 413 is the triplet
// family the gate's other errors are, with the bound beside it.
func (h *Handler) boundGateBody(w http.ResponseWriter, r *http.Request) bool {
	err := ReadBoundedBody(w, r)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrRequestTooLarge):
		if h.oversizedBodyRecorder != nil {
			h.oversizedBodyRecorder()
		}
		writeBodyError(w, http.StatusRequestEntityTooLarge, RequestTooLargeResponse{
			Error:   RequestTooLarge,
			Code:    "REQUEST_TOO_LARGE",
			Message: RequestTooLargeMessage,
			Limit:   MaxStepRequestBody,
		})
	default:
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
	}
	return false
}

// writeBodyError writes a JSON error and nothing else: the routes this bound
// serves set their own CORS headers, so it adds none.
func writeBodyError(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
