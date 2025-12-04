// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestNewHTTPConnector(t *testing.T) {
	conn := NewHTTPConnector()
	if conn == nil {
		t.Fatal("expected non-nil connector")
	}
	if conn.logger == nil {
		t.Error("expected logger to be initialized")
	}
	if conn.httpClient == nil {
		t.Error("expected httpClient to be initialized")
	}
}

func TestHTTPConnector_Name(t *testing.T) {
	conn := NewHTTPConnector()

	// Without config
	if got := conn.Name(); got != "http-connector" {
		t.Errorf("Name() = %q, want %q", got, "http-connector")
	}

	// With config
	conn.config = &base.ConnectorConfig{Name: "my-api"}
	if got := conn.Name(); got != "my-api" {
		t.Errorf("Name() = %q, want %q", got, "my-api")
	}
}

func TestHTTPConnector_Type(t *testing.T) {
	conn := NewHTTPConnector()
	if got := conn.Type(); got != "http" {
		t.Errorf("Type() = %q, want %q", got, "http")
	}
}

func TestHTTPConnector_Version(t *testing.T) {
	conn := NewHTTPConnector()
	if got := conn.Version(); got != "0.2.0" {
		t.Errorf("Version() = %q, want %q", got, "0.2.0")
	}
}

func TestHTTPConnector_Capabilities(t *testing.T) {
	conn := NewHTTPConnector()
	caps := conn.Capabilities()

	expected := []string{"query", "execute", "rest-api"}
	if len(caps) != len(expected) {
		t.Errorf("expected %d capabilities, got %d", len(expected), len(caps))
	}
	for i, c := range caps {
		if c != expected[i] {
			t.Errorf("capability %d: got %q, want %q", i, c, expected[i])
		}
	}
}

func TestHTTPConnector_HealthCheck_NoBaseURL(t *testing.T) {
	conn := NewHTTPConnector()
	ctx := context.Background()

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Healthy {
		t.Error("expected unhealthy status with no base URL")
	}
	if status.Error != "base_url not configured" {
		t.Errorf("expected error 'base_url not configured', got %q", status.Error)
	}
}

func TestHTTPConnector_Connect_MissingBaseURL(t *testing.T) {
	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name:    "test",
		Type:    "http",
		Options: map[string]interface{}{},
	}

	err := conn.Connect(ctx, config)
	if err == nil {
		t.Error("expected error for missing base_url")
	}
}

func TestHTTPConnector_Connect_Success(t *testing.T) {
	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name: "test-api",
		Type: "http",
		Options: map[string]interface{}{
			"base_url":  "http://example.com/api",
			"auth_type": "bearer",
			"timeout":   float64(60),
			"headers": map[string]interface{}{
				"X-Custom": "value",
			},
		},
		Credentials: map[string]string{
			"token": "secret-token",
		},
	}

	err := conn.Connect(ctx, config)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if conn.baseURL != "http://example.com/api" {
		t.Errorf("baseURL = %q, want %q", conn.baseURL, "http://example.com/api")
	}
	if conn.authType != "bearer" {
		t.Errorf("authType = %q, want %q", conn.authType, "bearer")
	}
	if conn.headers["X-Custom"] != "value" {
		t.Errorf("header X-Custom = %q, want %q", conn.headers["X-Custom"], "value")
	}
}

func TestHTTPConnector_Disconnect(t *testing.T) {
	conn := NewHTTPConnector()
	conn.config = &base.ConnectorConfig{Name: "test"}
	ctx := context.Background()

	err := conn.Disconnect(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHTTPConnector_applyAuth(t *testing.T) {
	tests := []struct {
		name       string
		authType   string
		authConfig map[string]string
		checkFn    func(r *http.Request) bool
	}{
		{
			name:     "bearer token",
			authType: "bearer",
			authConfig: map[string]string{
				"token": "my-token",
			},
			checkFn: func(r *http.Request) bool {
				return r.Header.Get("Authorization") == "Bearer my-token"
			},
		},
		{
			name:     "basic auth",
			authType: "basic",
			authConfig: map[string]string{
				"username": "user",
				"password": "pass",
			},
			checkFn: func(r *http.Request) bool {
				user, pass, ok := r.BasicAuth()
				return ok && user == "user" && pass == "pass"
			},
		},
		{
			name:     "api-key default header",
			authType: "api-key",
			authConfig: map[string]string{
				"api_key": "secret-key",
			},
			checkFn: func(r *http.Request) bool {
				return r.Header.Get("X-API-Key") == "secret-key"
			},
		},
		{
			name:     "api-key custom header",
			authType: "api-key",
			authConfig: map[string]string{
				"api_key":     "secret-key",
				"header_name": "X-Auth-Token",
			},
			checkFn: func(r *http.Request) bool {
				return r.Header.Get("X-Auth-Token") == "secret-key"
			},
		},
		{
			name:       "no auth",
			authType:   "none",
			authConfig: map[string]string{},
			checkFn: func(r *http.Request) bool {
				return r.Header.Get("Authorization") == ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := NewHTTPConnector()
			conn.authType = tt.authType
			conn.authConfig = tt.authConfig

			req, _ := http.NewRequest("GET", "http://example.com", nil)
			conn.applyAuth(req)

			if !tt.checkFn(req) {
				t.Errorf("auth check failed for %s", tt.name)
			}
		})
	}
}

func TestHTTPConnector_applyHeaders(t *testing.T) {
	conn := NewHTTPConnector()
	conn.headers = map[string]string{
		"X-Custom-1": "value1",
		"X-Custom-2": "value2",
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	conn.applyHeaders(req)

	if req.Header.Get("X-Custom-1") != "value1" {
		t.Errorf("X-Custom-1 = %q, want %q", req.Header.Get("X-Custom-1"), "value1")
	}
	if req.Header.Get("X-Custom-2") != "value2" {
		t.Errorf("X-Custom-2 = %q, want %q", req.Header.Get("X-Custom-2"), "value2")
	}
}

func TestHTTPConnector_convertToRows(t *testing.T) {
	conn := NewHTTPConnector()

	tests := []struct {
		name     string
		input    interface{}
		expected int // number of rows
	}{
		{
			name:     "array of objects",
			input:    []interface{}{map[string]interface{}{"id": 1}, map[string]interface{}{"id": 2}},
			expected: 2,
		},
		{
			name:     "array of primitives",
			input:    []interface{}{"a", "b", "c"},
			expected: 3,
		},
		{
			name:     "single object",
			input:    map[string]interface{}{"id": 1, "name": "test"},
			expected: 1,
		},
		{
			name:     "primitive value",
			input:    "just a string",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := conn.convertToRows(tt.input)
			if len(rows) != tt.expected {
				t.Errorf("got %d rows, want %d", len(rows), tt.expected)
			}
		})
	}
}

func TestHTTPConnector_Query_WithMockServer(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn := NewHTTPConnector()
	ctx := context.Background()

	// Connect
	config := &base.ConnectorConfig{
		Name: "test",
		Options: map[string]interface{}{
			"base_url": server.URL,
		},
	}
	err := conn.Connect(ctx, config)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Query
	query := &base.Query{Statement: "/users"}
	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.RowCount != 2 {
		t.Errorf("RowCount = %d, want 2", result.RowCount)
	}
}

func TestHTTPConnector_Query_WithParameters(t *testing.T) {
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name:    "test",
		Options: map[string]interface{}{"base_url": server.URL},
	}
	conn.Connect(ctx, config)

	query := &base.Query{
		Statement: "search",
		Parameters: map[string]interface{}{
			"q": "test",
		},
	}
	_, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if capturedURL != "/search?q=test" {
		t.Errorf("URL = %q, want /search?q=test", capturedURL)
	}
}

func TestHTTPConnector_Query_NonJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("plain text response"))
	}))
	defer server.Close()

	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name:    "test",
		Options: map[string]interface{}{"base_url": server.URL},
	}
	conn.Connect(ctx, config)

	query := &base.Query{Statement: "/text"}
	result, err := conn.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if result.RowCount != 1 {
		t.Errorf("RowCount = %d, want 1", result.RowCount)
	}
	if result.Rows[0]["response"] != "plain text response" {
		t.Errorf("response = %v, want 'plain text response'", result.Rows[0]["response"])
	}
}

func TestHTTPConnector_Query_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name:    "test",
		Options: map[string]interface{}{"base_url": server.URL},
	}
	conn.Connect(ctx, config)

	query := &base.Query{Statement: "/missing"}
	_, err := conn.Query(ctx, query)
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestHTTPConnector_Execute_POST(t *testing.T) {
	var capturedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":123}`))
	}))
	defer server.Close()

	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name:    "test",
		Options: map[string]interface{}{"base_url": server.URL},
	}
	conn.Connect(ctx, config)

	cmd := &base.Command{
		Action:    "POST",
		Statement: "/users",
		Parameters: map[string]interface{}{
			"name": "Alice",
		},
	}
	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if capturedMethod != "POST" {
		t.Errorf("method = %q, want POST", capturedMethod)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestHTTPConnector_Execute_RequestError(t *testing.T) {
	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name:    "test",
		Options: map[string]interface{}{"base_url": "http://invalid-host-12345.local"},
	}
	conn.Connect(ctx, config)

	cmd := &base.Command{
		Action:    "POST",
		Statement: "/test",
	}
	result, err := conn.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute returned error instead of result with Success=false: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false for network error")
	}
}

func TestHTTPConnector_HealthCheck_WithServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	conn := NewHTTPConnector()
	ctx := context.Background()
	config := &base.ConnectorConfig{
		Name: "test",
		Options: map[string]interface{}{
			"base_url":    server.URL,
			"health_path": "/health",
		},
	}
	conn.Connect(ctx, config)

	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Healthy {
		t.Error("expected healthy status")
	}
}
