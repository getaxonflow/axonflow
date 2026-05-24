// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// Mock MCP server that simulates a Payments MCP service. Supports tools/call
// for payments.lookup_transaction and payments.process_refund, and tools/list
// for discovery. Logs all received requests for PoC test assertions (the test
// checks that denied requests never reach this server).

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
)

var requestCount atomic.Int64

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

func main() {
	addr := envOr("MOCK_MCP_LISTEN", ":9091")
	log.Printf("Mock MCP Server (Payments) starting on %s", addr)

	http.HandleFunc("/", handleRPC)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/request-count", handleRequestCount)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "mock-payments-mcp"})
}

func handleRequestCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"count": requestCount.Load()})
}

func handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestCount.Add(1)
	count := requestCount.Load()

	var req jsonrpcRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&req); err != nil {
		writeError(w, nil, -32700, "parse error")
		return
	}

	log.Printf("[req #%d] method=%s traceparent=%s", count, req.Method, r.Header.Get("Traceparent"))

	switch req.Method {
	case "tools/list":
		handleToolsList(w, &req)
	case "tools/call":
		handleToolsCall(w, &req)
	default:
		writeError(w, req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func handleToolsList(w http.ResponseWriter, req *jsonrpcRequest) {
	tools := map[string]interface{}{
		"tools": []map[string]interface{}{
			{
				"name":        "payments.lookup_transaction",
				"description": "Look up a transaction by customer ID",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"customer_id": map[string]string{"type": "string"},
						"last":        map[string]string{"type": "boolean"},
					},
					"required": []string{"customer_id"},
				},
			},
			{
				"name":        "payments.process_refund",
				"description": "Process a refund for a transaction",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"transaction_id": map[string]string{"type": "string"},
						"amount":         map[string]string{"type": "number"},
						"reason":         map[string]string{"type": "string"},
					},
					"required": []string{"transaction_id", "amount"},
				},
			},
		},
	}
	resultBytes, _ := json.Marshal(tools)
	writeResult(w, req.ID, resultBytes)
}

func handleToolsCall(w http.ResponseWriter, req *jsonrpcRequest) {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, -32602, "invalid params")
		return
	}

	log.Printf("  tool=%s arguments=%v", params.Name, params.Arguments)

	switch params.Name {
	case "payments.lookup_transaction":
		result := map[string]interface{}{
			"transaction_id": "TXN-20260524-001",
			"customer_id":    params.Arguments["customer_id"],
			"amount":         149.99,
			"currency":       "USD",
			"status":         "completed",
			"timestamp":      "2026-05-24T10:30:00Z",
			"merchant":       "Example Store",
		}
		resultBytes, _ := json.Marshal(map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": mustJSON(result)}}})
		writeResult(w, req.ID, resultBytes)

	case "payments.process_refund":
		result := map[string]interface{}{
			"refund_id":      "REF-20260524-001",
			"transaction_id": params.Arguments["transaction_id"],
			"amount":         params.Arguments["amount"],
			"status":         "processed",
			"timestamp":      "2026-05-24T10:31:00Z",
		}
		resultBytes, _ := json.Marshal(map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": mustJSON(result)}}})
		writeResult(w, req.ID, resultBytes)

	default:
		writeError(w, req.ID, -32602, fmt.Sprintf("unknown tool: %s", params.Name))
	}
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result json.RawMessage) {
	resp := jsonrpcResponse{JSONRPC: "2.0", ID: id, Result: result}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	resp := jsonrpcResponse{JSONRPC: "2.0", ID: id, Error: &jsonrpcError{Code: code, Message: msg}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func mustJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
