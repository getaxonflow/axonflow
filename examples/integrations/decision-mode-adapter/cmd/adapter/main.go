// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Decision Mode adapter demo. Starts an HTTP server that wraps the
// configured downstream (LLM endpoint or mock) with the AxonFlow
// Decision Mode middleware. Every OpenAI-shaped POST is policy-checked
// via POST /api/v1/decide before forwarding.
//
// VALIDATION: use poc/test.sh for end-to-end assertions.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	adapter "github.com/getaxonflow/axonflow/examples/integrations/decision-mode-adapter"
)

func main() {
	cfg := adapter.Config{
		AxonFlowEndpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		GatewayID:        getEnv("AXONFLOW_GATEWAY_ID", "llm-gateway-poc"),
		Stage:            getEnv("AXONFLOW_STAGE", "llm"),
		OrgID:            getEnv("AXONFLOW_ORG_ID", ""),
		TenantID:         getEnv("AXONFLOW_TENANT_ID", ""),
		ClientID:         getEnv("AXONFLOW_CLIENT_ID", ""),
		ClientSecret:     getEnv("AXONFLOW_CLIENT_SECRET", ""),
		FailOpen:         getEnv("AXONFLOW_FAIL_OPEN", "false") == "true",
		Timeout:          5 * time.Second,
	}

	downstreamURL := getEnv("DOWNSTREAM_URL", "http://localhost:9090")
	listenAddr := getEnv("LISTEN_ADDR", ":8888")

	downstream, err := buildDownstream(downstreamURL)
	if err != nil {
		log.Fatalf("Failed to configure downstream: %v", err)
	}

	handler := adapter.Middleware(cfg, downstream)

	log.Printf("Decision Mode adapter listening on %s", listenAddr)
	log.Printf("  AxonFlow endpoint: %s", cfg.AxonFlowEndpoint)
	log.Printf("  Downstream: %s", downstreamURL)
	log.Printf("  Gateway ID: %s", cfg.GatewayID)
	log.Printf("  Stage: %s", cfg.Stage)
	log.Printf("  Fail-open: %v", cfg.FailOpen)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func buildDownstream(rawURL string) (http.Handler, error) {
	if rawURL == "mock" {
		return http.HandlerFunc(mockLLMHandler), nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse downstream URL: %w", err)
	}
	return httputil.NewSingleHostReverseProxy(u), nil
}

func mockLLMHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":      "chatcmpl-mock",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "gpt-4o-mini",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": "This is a mock response from the LLM gateway.",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     10,
			"completion_tokens": 15,
			"total_tokens":      25,
		},
	})
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
