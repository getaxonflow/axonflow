// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestHTTPConnector_ExecuteRetryableStatuses(t *testing.T) {
	for _, tt := range []struct {
		name         string
		method       string
		statuses     []int
		wantAttempts int32
		wantSuccess  bool
	}{
		{"PUT recovers from 503", "PUT", []int{503, 200}, 2, true},
		{"DELETE recovers from 429", "DELETE", []int{429, 204}, 2, true},
		{"PUT exhausts retry budget", "PUT", []int{500}, 3, false},
		{"PUT does not retry 404", "PUT", []int{404}, 1, false},
		{"POST does not retry HTTP failure", "POST", []int{503}, 1, false},
		{"PATCH does not retry HTTP failure", "PATCH", []int{429}, 1, false},
		{"PUT succeeds immediately", "PUT", []int{200}, 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			bodies := make(chan string, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				bodies <- string(body)
				i := int(attempts.Add(1)) - 1
				if i >= len(tt.statuses) {
					i = len(tt.statuses) - 1
				}
				w.WriteHeader(tt.statuses[i])
			}))
			defer server.Close()
			ctx := context.Background()
			connector := NewHTTPConnector()
			if err := connector.Connect(ctx, &base.ConnectorConfig{
				Name: "execute-status-retry",
				Options: map[string]interface{}{
					"base_url": server.URL, "allow_private_ips": true,
					"max_retries": float64(2), "retry_delay": "1ms",
				},
			}); err != nil {
				t.Fatal(err)
			}
			defer connector.Disconnect(ctx)
			result, err := connector.Execute(ctx, &base.Command{
				Action: tt.method, Statement: "/items/1",
				Parameters: map[string]interface{}{"value": "retained"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := attempts.Load(); got != tt.wantAttempts {
				t.Errorf("upstream received %d requests; want %d", got, tt.wantAttempts)
			}
			if result.Success != tt.wantSuccess {
				t.Errorf("Success = %v; want %v (message: %s)", result.Success, tt.wantSuccess, result.Message)
			}
			for range attempts.Load() {
				if got := <-bodies; got != `{"value":"retained"}` {
					t.Errorf("request body = %q; want complete original JSON", got)
				}
			}
		})
	}
}
