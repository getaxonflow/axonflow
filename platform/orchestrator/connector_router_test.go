// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
)

// TestNewConnectorRouter verifies a freshly created router has empty state.
func TestNewConnectorRouter(t *testing.T) {
	router := NewConnectorRouter()

	if router == nil {
		t.Fatal("NewConnectorRouter returned nil")
	}
	if !router.IsEmpty() {
		t.Error("New router should be empty")
	}
	if caps := router.ListCapabilities(); len(caps) != 0 {
		t.Errorf("ListCapabilities = %d, want 0", len(caps))
	}
	if len(router.keywords) != 0 {
		t.Errorf("keywords map has %d entries, want 0", len(router.keywords))
	}
}

// TestRegisterCapability verifies registration adds the capability and builds
// the keyword index from operations.
func TestRegisterCapability(t *testing.T) {
	router := NewConnectorRouter()

	cap := ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights", "search_hotels"},
		Connector:  "amadeus-travel",
		Priority:   1,
	}

	router.RegisterCapability(cap)

	if router.IsEmpty() {
		t.Error("Router should not be empty after RegisterCapability")
	}

	caps := router.ListCapabilities()
	if len(caps) != 1 {
		t.Fatalf("ListCapabilities = %d, want 1", len(caps))
	}
	if caps[0].Domain != "travel" {
		t.Errorf("Domain = %q, want %q", caps[0].Domain, "travel")
	}
	if caps[0].Connector != "amadeus-travel" {
		t.Errorf("Connector = %q, want %q", caps[0].Connector, "amadeus-travel")
	}
	if caps[0].Priority != 1 {
		t.Errorf("Priority = %d, want 1", caps[0].Priority)
	}

	// Verify keyword index was built — "flight" should map to "search_flights"
	if op, ok := router.keywords["flight"]; !ok {
		t.Error("keyword 'flight' not indexed")
	} else if op != "search_flights" {
		t.Errorf("keywords['flight'] = %q, want %q", op, "search_flights")
	}

	// "hotel" should map to "search_hotels"
	if op, ok := router.keywords["hotel"]; !ok {
		t.Error("keyword 'hotel' not indexed")
	} else if op != "search_hotels" {
		t.Errorf("keywords['hotel'] = %q, want %q", op, "search_hotels")
	}
}

// TestFindBestMatch verifies matching by step name, by query, and no match cases.
func TestFindBestMatch(t *testing.T) {
	router := NewConnectorRouter()
	router.RegisterCapability(ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights", "search_hotels"},
		Connector:  "amadeus-travel",
		Priority:   1,
	})

	t.Run("match by step name", func(t *testing.T) {
		match := router.FindBestMatch("find_flight_options", "")
		if match == nil {
			t.Fatal("Expected match, got nil")
		}
		if match.Connector != "amadeus-travel" {
			t.Errorf("Connector = %q, want %q", match.Connector, "amadeus-travel")
		}
		if match.Operation != "search_flights" {
			t.Errorf("Operation = %q, want %q", match.Operation, "search_flights")
		}
		if match.Domain != "travel" {
			t.Errorf("Domain = %q, want %q", match.Domain, "travel")
		}
	})

	t.Run("match by query", func(t *testing.T) {
		match := router.FindBestMatch("generic_step", "I need hotel recommendations")
		if match == nil {
			t.Fatal("Expected match, got nil")
		}
		if match.Connector != "amadeus-travel" {
			t.Errorf("Connector = %q, want %q", match.Connector, "amadeus-travel")
		}
		if match.Operation != "search_hotels" {
			t.Errorf("Operation = %q, want %q", match.Operation, "search_hotels")
		}
	})

	t.Run("no match", func(t *testing.T) {
		match := router.FindBestMatch("analyze_data", "run database query")
		if match != nil {
			t.Errorf("Expected nil, got match: %+v", match)
		}
	})

	t.Run("case insensitive step name", func(t *testing.T) {
		match := router.FindBestMatch("SEARCH_FLIGHT_OPTIONS", "")
		if match == nil {
			t.Fatal("Expected case-insensitive match, got nil")
		}
		if match.Operation != "search_flights" {
			t.Errorf("Operation = %q, want %q", match.Operation, "search_flights")
		}
	})

	t.Run("case insensitive query", func(t *testing.T) {
		match := router.FindBestMatch("step", "Book a HOTEL in Paris")
		if match == nil {
			t.Fatal("Expected case-insensitive match, got nil")
		}
		if match.Operation != "search_hotels" {
			t.Errorf("Operation = %q, want %q", match.Operation, "search_hotels")
		}
	})
}

// TestFindAllMatches verifies multiple connectors and enterprise fallback ordering.
func TestFindAllMatches(t *testing.T) {
	router := NewConnectorRouter()
	router.RegisterCapability(ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights"},
		Connector:  "amadeus-travel",
		Priority:   1,
	})
	router.RegisterCapability(ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights"},
		Connector:  "sabre-travel",
		Priority:   2,
	})

	t.Run("multiple connectors for same operation", func(t *testing.T) {
		matches := router.FindAllMatches("book_flight", "")
		if len(matches) != 2 {
			t.Fatalf("FindAllMatches = %d matches, want 2", len(matches))
		}
		// Both connectors should be returned
		connectors := make(map[string]bool)
		for _, m := range matches {
			connectors[m.Connector] = true
			if m.Operation != "search_flights" {
				t.Errorf("Operation = %q, want %q", m.Operation, "search_flights")
			}
			if m.Domain != "travel" {
				t.Errorf("Domain = %q, want %q", m.Domain, "travel")
			}
		}
		if !connectors["amadeus-travel"] {
			t.Error("Missing amadeus-travel in matches")
		}
		if !connectors["sabre-travel"] {
			t.Error("Missing sabre-travel in matches")
		}
	})

	t.Run("no matches", func(t *testing.T) {
		matches := router.FindAllMatches("process_payment", "credit card")
		if len(matches) != 0 {
			t.Errorf("FindAllMatches = %d matches, want 0", len(matches))
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		// A step name and query both matching the same keyword should not duplicate
		matches := router.FindAllMatches("flight_search", "find flights to NYC")
		seen := make(map[string]int)
		for _, m := range matches {
			seen[m.Connector+":"+m.Operation]++
		}
		for key, count := range seen {
			if count > 1 {
				t.Errorf("Duplicate match: %s appeared %d times", key, count)
			}
		}
	})
}

// TestListCapabilities verifies listing returns a copy of all registered capabilities.
func TestListCapabilities(t *testing.T) {
	router := NewConnectorRouter()

	t.Run("empty", func(t *testing.T) {
		caps := router.ListCapabilities()
		if len(caps) != 0 {
			t.Errorf("ListCapabilities = %d, want 0", len(caps))
		}
	})

	router.RegisterCapability(ConnectorCapability{
		Domain:     "finance",
		Operations: []string{"get_stock_price"},
		Connector:  "alpha-vantage",
		Priority:   1,
	})
	router.RegisterCapability(ConnectorCapability{
		Domain:     "weather",
		Operations: []string{"get_forecast"},
		Connector:  "openweather",
		Priority:   1,
	})

	t.Run("multiple capabilities", func(t *testing.T) {
		caps := router.ListCapabilities()
		if len(caps) != 2 {
			t.Fatalf("ListCapabilities = %d, want 2", len(caps))
		}
	})

	t.Run("returns copy", func(t *testing.T) {
		caps := router.ListCapabilities()
		caps[0].Domain = "mutated"
		original := router.ListCapabilities()
		if original[0].Domain == "mutated" {
			t.Error("ListCapabilities should return a copy, not a reference")
		}
	})
}

// TestIsEmpty verifies the emptiness check.
func TestIsEmpty(t *testing.T) {
	router := NewConnectorRouter()

	if !router.IsEmpty() {
		t.Error("New router should be empty")
	}

	router.RegisterCapability(ConnectorCapability{
		Domain:     "test",
		Operations: []string{"test_op"},
		Connector:  "test-connector",
		Priority:   1,
	})

	if router.IsEmpty() {
		t.Error("Router with registered capability should not be empty")
	}
}

// TestOperationKeywords verifies keyword extraction including plural
// singularization and generic verb skipping.
func TestOperationKeywords(t *testing.T) {
	tests := []struct {
		operation string
		want      []string
		notWant   []string
	}{
		{
			operation: "search_flights",
			want:      []string{"flight", "flights"},
			notWant:   []string{"search"},
		},
		{
			operation: "get_hotels",
			want:      []string{"hotel", "hotels"},
			notWant:   []string{"get"},
		},
		{
			operation: "list_payments",
			want:      []string{"payment", "payments"},
			notWant:   []string{"list"},
		},
		{
			operation: "find_results",
			want:      []string{"result", "results"},
			notWant:   []string{"find"},
		},
		{
			operation: "query_logs",
			want:      []string{"log", "logs"},
			notWant:   []string{"query"},
		},
		{
			operation: "analyze_data",
			// "data" is 4 chars and ends in 'a', not 's' — should not be singularized
			want:    []string{"analyze", "data"},
			notWant: []string{},
		},
		{
			operation: "run-checks",
			// Hyphen-separated
			want:    []string{"run", "check", "checks"},
			notWant: []string{},
		},
		{
			operation: "do",
			// Short words (len <= 3) that end in 's' should NOT be singularized
			want:    []string{"do"},
			notWant: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			keywords := operationKeywords(tt.operation)
			keywordSet := make(map[string]bool)
			for _, k := range keywords {
				keywordSet[k] = true
			}

			for _, w := range tt.want {
				if !keywordSet[w] {
					t.Errorf("operationKeywords(%q) missing %q, got %v", tt.operation, w, keywords)
				}
			}
			for _, nw := range tt.notWant {
				if keywordSet[nw] {
					t.Errorf("operationKeywords(%q) should not contain %q, got %v", tt.operation, nw, keywords)
				}
			}
		})
	}
}

// TestInitDefaultConnectorRouter verifies default router initialization
// based on environment variables.
func TestInitDefaultConnectorRouter(t *testing.T) {
	t.Run("without Amadeus env vars", func(t *testing.T) {
		t.Setenv("AMADEUS_API_KEY", "")
		t.Setenv("AMADEUS_API_SECRET", "")

		router := InitDefaultConnectorRouter()
		if !router.IsEmpty() {
			t.Error("Router should be empty without AMADEUS env vars")
		}
	})

	t.Run("with Amadeus env vars", func(t *testing.T) {
		t.Setenv("AMADEUS_API_KEY", "test-key")
		t.Setenv("AMADEUS_API_SECRET", "test-secret")

		router := InitDefaultConnectorRouter()
		if router.IsEmpty() {
			t.Error("Router should not be empty with AMADEUS env vars set")
		}

		caps := router.ListCapabilities()
		if len(caps) != 1 {
			t.Fatalf("ListCapabilities = %d, want 1", len(caps))
		}
		if caps[0].Domain != "travel" {
			t.Errorf("Domain = %q, want %q", caps[0].Domain, "travel")
		}
		if caps[0].Connector != "amadeus-travel" {
			t.Errorf("Connector = %q, want %q", caps[0].Connector, "amadeus-travel")
		}
	})

	t.Run("with only API key set", func(t *testing.T) {
		t.Setenv("AMADEUS_API_KEY", "test-key")
		t.Setenv("AMADEUS_API_SECRET", "")

		router := InitDefaultConnectorRouter()
		if !router.IsEmpty() {
			t.Error("Router should be empty when only API key is set (secret missing)")
		}
	})

	t.Run("with only API secret set", func(t *testing.T) {
		t.Setenv("AMADEUS_API_KEY", "")
		t.Setenv("AMADEUS_API_SECRET", "test-secret")

		router := InitDefaultConnectorRouter()
		if !router.IsEmpty() {
			t.Error("Router should be empty when only API secret is set (key missing)")
		}
	})
}
