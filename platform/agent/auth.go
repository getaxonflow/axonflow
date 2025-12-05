// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"axonflow/platform/agent/license"
)

// ClientAuth represents authentication configuration for a known client.
// This structure holds the client's credentials, permissions, and rate limits.
// In production, client configurations should be loaded from the database
// via db_auth.go rather than using the in-memory whitelist.
//
// Fields:
//   - ClientID: Unique identifier for the client
//   - LicenseKey: V2 format license key (AXON-V2-...)
//   - Name: Human-readable client name
//   - TenantID: Tenant for multi-tenant isolation
//   - Permissions: List of allowed operations (query, llm, connectors, planning)
//   - RateLimit: Maximum requests per minute
//   - Enabled: Whether the client is active
type ClientAuth struct {
	ClientID    string
	LicenseKey  string
	Name        string
	TenantID    string
	Permissions []string
	RateLimit   int // requests per minute
	Enabled     bool
}

// RateLimitEntry tracks request counts for in-memory rate limiting.
// Each client has an entry that tracks requests within a sliding window.
// When the window expires (1 minute), the counter resets.
type RateLimitEntry struct {
	Count     int
	ResetTime time.Time
	mu        sync.Mutex
}

// Known clients whitelist with their license keys (V2 format)
// In production, this should be loaded from database or config file
var knownClients = map[string]*ClientAuth{
	"healthcare-demo": {
		ClientID:    "healthcare-demo",
		LicenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6ImhlYWx0aGNhcmUiLCJzZXJ2aWNlX25hbWUiOiJoZWFsdGhjYXJlLWRlbW8iLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSIsImNvbm5lY3RvcnMiLCJwbGFubmluZyJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-b9870d1f",
		Name:        "Healthcare Demo",
		TenantID:    "healthcare_tenant",
		Permissions: []string{"query", "llm", "connectors", "planning"},
		RateLimit:   1000, // 1000 req/min (PLUS tier)
		Enabled:     true,
	},
	"ecommerce-demo": {
		ClientID:    "ecommerce-demo",
		LicenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6ImVjb21tZXJjZSIsInNlcnZpY2VfbmFtZSI6ImVjb21tZXJjZS1kZW1vIiwic2VydmljZV90eXBlIjoiY2xpZW50LWFwcGxpY2F0aW9uIiwicGVybWlzc2lvbnMiOlsicXVlcnkiLCJsbG0iLCJjb25uZWN0b3JzIl0sImV4cGlyZXNfYXQiOiIyMDM1MTEyNyJ9-e40f5f5d",
		Name:        "E-commerce Demo",
		TenantID:    "ecommerce_tenant",
		Permissions: []string{"query", "llm", "connectors"},
		RateLimit:   1000, // 1000 req/min (PLUS tier)
		Enabled:     true,
	},
	"client_1": {
		ClientID:    "client_1",
		LicenseKey:  "AXON-V2-eyJ0aWVyIjoiRU5UIiwidGVuYW50X2lkIjoiY2xpZW50MSIsInNlcnZpY2VfbmFtZSI6ImNsaWVudDEiLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-22b4e980",
		Name:        "Client 1 (Legacy)",
		TenantID:    "tenant_1",
		Permissions: []string{"query", "llm"},
		RateLimit:   500, // 500 req/min (ENT tier)
		Enabled:     true,
	},
	"client_2": {
		ClientID:    "client_2",
		LicenseKey:  "AXON-V2-eyJ0aWVyIjoiRU5UIiwidGVuYW50X2lkIjoiY2xpZW50MiIsInNlcnZpY2VfbmFtZSI6ImNsaWVudDIiLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-2fa74e5a",
		Name:        "Client 2 (Legacy)",
		TenantID:    "tenant_2",
		Permissions: []string{"query", "llm"},
		RateLimit:   500, // 500 req/min (ENT tier)
		Enabled:     true,
	},
	"loadtest": {
		ClientID:    "loadtest",
		LicenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6ImxvYWR0ZXN0Iiwic2VydmljZV9uYW1lIjoibG9hZHRlc3QiLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-8cc4ef10",
		Name:        "Load Testing Client",
		TenantID:    "loadtest_tenant",
		Permissions: []string{"query", "llm"},
		RateLimit:   10000, // 10000 req/min for load testing
		Enabled:     true,
	},
}

// In-memory rate limiting (simple implementation for Option 2)
var rateLimitMap = make(map[string]*RateLimitEntry)
var rateLimitMu sync.RWMutex

// validateClientLicense validates a client using their license key
// This replaces the old validateClient() function
func validateClientLicense(ctx context.Context, clientID, licenseKey string) (*Client, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID required")
	}

	if licenseKey == "" {
		return nil, fmt.Errorf("license key required")
	}

	// Look up client in whitelist
	clientAuth, exists := knownClients[clientID]
	if !exists {
		return nil, fmt.Errorf("client '%s' not found in whitelist", clientID)
	}

	if !clientAuth.Enabled {
		return nil, fmt.Errorf("client '%s' is disabled", clientID)
	}

	// Verify license key matches (simple string comparison for now)
	// In Option 3, we'll do database lookup
	if licenseKey != clientAuth.LicenseKey {
		return nil, fmt.Errorf("invalid license key for client '%s'", clientID)
	}

	// Validate license key with license validation system
	validationResult, err := license.ValidateLicense(ctx, licenseKey)
	if err != nil {
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("license invalid or expired: %s", validationResult.Error)
	}

	// Check rate limit
	if err := checkRateLimit(clientID, clientAuth.RateLimit); err != nil {
		return nil, err
	}

	// Return authenticated client
	return &Client{
		ID:          clientAuth.ClientID,
		Name:        clientAuth.Name,
		OrgID:       validationResult.OrgID, // From license validation
		TenantID:    clientAuth.TenantID,
		Permissions: clientAuth.Permissions,
		RateLimit:   clientAuth.RateLimit,
		Enabled:     true,
		LicenseTier: string(validationResult.Tier),
		LicenseExpiry: validationResult.ExpiresAt,
	}, nil
}

// checkRateLimit implements simple in-memory rate limiting
// Returns error if rate limit exceeded
func checkRateLimit(clientID string, limitPerMinute int) error {
	now := time.Now()

	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	entry, exists := rateLimitMap[clientID]
	if !exists {
		// First request from this client
		rateLimitMap[clientID] = &RateLimitEntry{
			Count:     1,
			ResetTime: now.Add(time.Minute),
		}
		return nil
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Check if rate limit window has reset
	if now.After(entry.ResetTime) {
		entry.Count = 1
		entry.ResetTime = now.Add(time.Minute)
		return nil
	}

	// Increment counter
	entry.Count++

	// Check if limit exceeded
	if entry.Count > limitPerMinute {
		return fmt.Errorf("rate limit exceeded: %d requests/minute (limit: %d)", entry.Count, limitPerMinute)
	}

	return nil
}

// getRateLimitStatus returns current rate limit status for a client
//
//nolint:unused // Used in tests
func getRateLimitStatus(clientID string) (count int, limit int, resetTime time.Time) {
	rateLimitMu.RLock()
	defer rateLimitMu.RUnlock()

	entry, exists := rateLimitMap[clientID]
	if !exists {
		return 0, 0, time.Time{}
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	clientAuth, exists := knownClients[clientID]
	if !exists {
		return entry.Count, 0, entry.ResetTime
	}

	return entry.Count, clientAuth.RateLimit, entry.ResetTime
}
