// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"axonflow/platform/connectors/base"
)

func TestHTTPConnector_QueryPreservesURLParameters(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]interface{}
		want       url.Values
	}{
		{
			name: "URL parameters without additional parameters",
			want: url.Values{"status": {"active"}, "tag": {"first", "second"}},
		},
		{
			name:       "internal parameters do not erase URL filters",
			parameters: map[string]interface{}{"_trace_id": "trace-123"},
			want:       url.Values{"status": {"active"}, "tag": {"first", "second"}},
		},
		{
			name:       "additional parameters preserve unrelated URL filters",
			parameters: map[string]interface{}{"page": 2, "_trace_id": "trace-123"},
			want:       url.Values{"status": {"active"}, "tag": {"first", "second"}, "page": {"2"}},
		},
		{
			name:       "explicit parameters override matching URL keys",
			parameters: map[string]interface{}{"status": "pending review", "tag": "replacement"},
			want:       url.Values{"status": {"pending review"}, "tag": {"replacement"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := make(chan url.Values, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.URL.Query()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
			}))
			defer server.Close()

			connector := NewHTTPConnector()
			ctx := context.Background()
			if err := connector.Connect(ctx, &base.ConnectorConfig{
				Name: "query-parameters",
				Options: map[string]interface{}{
					"base_url": server.URL, "allow_private_ips": true,
				},
			}); err != nil {
				t.Fatal(err)
			}
			defer connector.Disconnect(ctx)
			result, err := connector.Query(ctx, &base.Query{
				Statement: "/records?status=active&tag=first&tag=second", Parameters: tt.parameters,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.RowCount != 1 {
				t.Fatalf("expected a parsed response row, got %d", result.RowCount)
			}
			received := <-requests
			if !reflect.DeepEqual(received, tt.want) {
				t.Fatalf("server received parameters %v; want %v", received, tt.want)
			}
		})
	}
}
