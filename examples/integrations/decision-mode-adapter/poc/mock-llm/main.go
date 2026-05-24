// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Minimal mock LLM/agent backend that returns a static OpenAI-shaped response.
// Exposes /stats for request-count verification and /stats/reset to zero it.
// Used by the Decision Mode PoC harness; not a production artifact.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

var requestCount atomic.Int64

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		traceparent := r.Header.Get("traceparent")
		log.Printf("Mock backend received request #%d (traceparent: %s)", requestCount.Load(), traceparent)

		w.Header().Set("Content-Type", "application/json")
		if traceparent != "" {
			w.Header().Set("X-Received-Traceparent", traceparent)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-mock-poc",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4o-mini",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]string{
						"role":    "assistant",
						"content": "Mock LLM response for Decision Mode PoC.",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int{
				"prompt_tokens":     10,
				"completion_tokens": 12,
				"total_tokens":      22,
			},
		})
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"request_count": requestCount.Load(),
		})
	})

	mux.HandleFunc("/stats/reset", func(w http.ResponseWriter, r *http.Request) {
		requestCount.Store(0)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"request_count": 0,
		})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := ":9090"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v
	}
	log.Printf("Mock backend listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
