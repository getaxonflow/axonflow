// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"strings"
	"sync"
)

// ConnectorCapability describes a connector's domain and supported operations.
type ConnectorCapability struct {
	Domain     string   // e.g., "travel", "finance", "healthcare"
	Operations []string // e.g., ["search_flights", "search_hotels"]
	Connector  string   // connector name
	Priority   int      // for fallback ordering (enterprise only)
}

// ConnectorMatch represents a successful match from the router.
type ConnectorMatch struct {
	Connector string
	Operation string
	Domain    string
}

// ConnectorRouter maintains a registry of connector capabilities and
// routes workflow steps to the best matching connector.
type ConnectorRouter struct {
	mu           sync.RWMutex
	capabilities []ConnectorCapability
	// keyword → operation mapping for matching step names
	keywords map[string]string
}

// NewConnectorRouter creates a new generic connector router.
func NewConnectorRouter() *ConnectorRouter {
	return &ConnectorRouter{
		capabilities: make([]ConnectorCapability, 0),
		keywords:     make(map[string]string),
	}
}

// RegisterCapability adds a connector capability to the registry.
func (r *ConnectorRouter) RegisterCapability(cap ConnectorCapability) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.capabilities = append(r.capabilities, cap)

	// Build keyword index from operations
	for _, op := range cap.Operations {
		// Extract keywords from operation name: "search_flights" → "flight"
		for _, keyword := range operationKeywords(op) {
			r.keywords[keyword] = op
		}
	}
}

// FindBestMatch finds the best connector match for a step name and query.
// Returns nil if no match is found.
func (r *ConnectorRouter) FindBestMatch(stepName, query string) *ConnectorMatch {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stepNameLower := strings.ToLower(stepName)
	queryLower := strings.ToLower(query)

	// Try to match step name against known keywords
	for keyword, operation := range r.keywords {
		if strings.Contains(stepNameLower, keyword) || strings.Contains(queryLower, keyword) {
			// Find the capability that owns this operation
			for _, cap := range r.capabilities {
				for _, op := range cap.Operations {
					if op == operation {
						return &ConnectorMatch{
							Connector: cap.Connector,
							Operation: operation,
							Domain:    cap.Domain,
						}
					}
				}
			}
		}
	}

	return nil
}

// FindAllMatches returns all matching connectors for a step, ordered by priority.
// This is used for enterprise fallback chains.
func (r *ConnectorRouter) FindAllMatches(stepName, query string) []ConnectorMatch {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stepNameLower := strings.ToLower(stepName)
	queryLower := strings.ToLower(query)
	var matches []ConnectorMatch
	seen := make(map[string]bool)

	for keyword, operation := range r.keywords {
		if strings.Contains(stepNameLower, keyword) || strings.Contains(queryLower, keyword) {
			for _, cap := range r.capabilities {
				for _, op := range cap.Operations {
					if op == operation && !seen[cap.Connector+":"+op] {
						seen[cap.Connector+":"+op] = true
						matches = append(matches, ConnectorMatch{
							Connector: cap.Connector,
							Operation: operation,
							Domain:    cap.Domain,
						})
					}
				}
			}
		}
	}

	return matches
}

// ListCapabilities returns all registered capabilities.
func (r *ConnectorRouter) ListCapabilities() []ConnectorCapability {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ConnectorCapability, len(r.capabilities))
	copy(result, r.capabilities)
	return result
}

// IsEmpty returns true if no capabilities are registered.
func (r *ConnectorRouter) IsEmpty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.capabilities) == 0
}

// Words that should not be singularized by simple -s removal
var irregularWords = map[string]bool{
	"analysis": true, "address": true, "status": true, "process": true,
	"access": true, "business": true, "class": true, "loss": true,
	"success": true, "progress": true, "bonus": true, "basis": true,
}

// operationKeywords extracts searchable keywords from an operation name.
// e.g., "search_flights" → ["flight"], "search_hotels" → ["hotel"]
func operationKeywords(operation string) []string {
	var keywords []string

	// Split on underscores and hyphens
	parts := strings.FieldsFunc(operation, func(r rune) bool {
		return r == '_' || r == '-'
	})

	for _, part := range parts {
		part = strings.ToLower(part)
		// Skip generic verbs
		if part == "search" || part == "get" || part == "list" || part == "find" || part == "query" {
			continue
		}
		// Singularize common plurals, but skip known irregular words
		if strings.HasSuffix(part, "s") && len(part) > 3 && !irregularWords[part] {
			keywords = append(keywords, part[:len(part)-1])
		}
		keywords = append(keywords, part)
	}

	return keywords
}

// InitDefaultConnectorRouter creates a connector router with default capabilities
// based on environment configuration.
func InitDefaultConnectorRouter() *ConnectorRouter {
	router := NewConnectorRouter()

	// Register Amadeus travel capability if configured
	if os.Getenv("AMADEUS_API_KEY") != "" && os.Getenv("AMADEUS_API_SECRET") != "" {
		router.RegisterCapability(ConnectorCapability{
			Domain:     "travel",
			Operations: []string{"search_flights", "search_hotels"},
			Connector:  "amadeus-travel",
			Priority:   1,
		})
	}

	return router
}
