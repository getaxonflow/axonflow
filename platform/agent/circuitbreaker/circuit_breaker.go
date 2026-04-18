// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Emergency Circuit Breaker
// EU AI Act Article 14: Human Oversight - Interrupt/Stop capability
//
// Provides emergency halt capability for AI system operations.
// Implements "stop button" functionality for Article 14 compliance.

//go:build enterprise

package circuitbreaker

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// State represents the circuit breaker state
type State string

const (
	// StateClosed means normal operation - requests pass through
	StateClosed State = "closed"
	// StateOpen means circuit is tripped - all requests are blocked
	StateOpen State = "open"
	// StateHalfOpen means testing recovery - limited requests allowed
	StateHalfOpen State = "half_open"
)

// TripReason categorizes why the circuit was tripped
type TripReason string

const (
	// ReasonManual is for human-initiated emergency stop (Article 14)
	ReasonManual TripReason = "manual"
	// ReasonAutomatic is for automated threshold-based tripping
	ReasonAutomatic TripReason = "automatic"
	// ReasonPolicy is for policy violation threshold
	ReasonPolicy TripReason = "policy_violation"
	// ReasonRiskLevel is for risk threshold exceeded
	ReasonRiskLevel TripReason = "risk_level"
	// ReasonError is for error rate threshold
	ReasonError TripReason = "error_rate"
)

// Scope defines what the circuit breaker affects
type Scope string

const (
	// ScopeGlobal affects all operations in the org
	ScopeGlobal Scope = "global"
	// ScopeTenant affects a specific tenant
	ScopeTenant Scope = "tenant"
	// ScopeClient affects a specific client
	ScopeClient Scope = "client"
	// ScopePolicy affects operations triggering a specific policy
	ScopePolicy Scope = "policy"
)

// TenantConfig holds per-tenant circuit breaker threshold overrides.
// All fields are pointers; nil means "use global default".
type TenantConfig struct {
	ID                    string     `json:"id"`
	OrgID                 string     `json:"org_id"`
	TenantID              string     `json:"tenant_id"`
	ErrorThreshold        *int       `json:"error_threshold,omitempty"`
	ViolationThreshold    *int       `json:"violation_threshold,omitempty"`
	WindowSeconds         *int       `json:"window_seconds,omitempty"`
	DefaultTimeoutSeconds *int       `json:"default_timeout_seconds,omitempty"`
	MaxTimeoutSeconds     *int       `json:"max_timeout_seconds,omitempty"`
	EnableAutoRecovery    *bool      `json:"enable_auto_recovery,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// tenantConfigCache caches resolved tenant configs with TTL
type tenantConfigCache struct {
	configs map[string]*tenantConfigEntry
	mu      sync.RWMutex
}

type tenantConfigEntry struct {
	config    *TenantConfig
	expiresAt time.Time
}

const tenantConfigCacheTTL = 1 * time.Minute

// CircuitBreaker manages emergency stop functionality
type CircuitBreaker struct {
	mu               sync.RWMutex
	repo             *Repository
	state            State
	circuits         map[string]*Circuit // Key: scope+id
	config           Config
	tripCallback     func(trip *TripEvent)
	errorWindows     map[string]*eventWindow
	violationWindows map[string]*eventWindow
	configCache      *tenantConfigCache
}

// eventWindow tracks timestamped events for sliding window counting.
// Only events within the configured window duration are counted toward thresholds.
type eventWindow struct {
	timestamps []time.Time
	maxSize    int // prevents unbounded growth; 2x threshold
}

// record adds a new event timestamp and compacts old entries if maxSize exceeded.
func (w *eventWindow) record(now time.Time) {
	w.timestamps = append(w.timestamps, now)
	// Compact if we've exceeded maxSize — remove oldest entries beyond what we need
	if len(w.timestamps) > w.maxSize {
		w.timestamps = w.timestamps[len(w.timestamps)-w.maxSize:]
	}
}

// countInWindow returns the number of events within the given window duration,
// and compacts expired entries.
func (w *eventWindow) countInWindow(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	// Find first index within window
	start := 0
	for start < len(w.timestamps) && w.timestamps[start].Before(cutoff) {
		start++
	}
	// Compact expired entries
	if start > 0 {
		w.timestamps = w.timestamps[start:]
	}
	return len(w.timestamps)
}

// Config contains circuit breaker configuration
type Config struct {
	// DefaultTimeout is how long a circuit stays open before auto-recovery
	DefaultTimeout time.Duration
	// MaxTimeout is the maximum allowed timeout
	MaxTimeout time.Duration
	// ErrorThreshold triggers automatic trip after N consecutive errors
	ErrorThreshold int
	// PolicyViolationThreshold triggers trip after N violations in window
	PolicyViolationThreshold int
	// PolicyViolationWindow is the time window for violation counting
	PolicyViolationWindow time.Duration
	// EnableAutoRecovery allows automatic transition from open to half-open
	EnableAutoRecovery bool
}

// Circuit represents an individual circuit state
type Circuit struct {
	ID             string     `json:"id"`
	Scope          Scope      `json:"scope"`
	ScopeID        string     `json:"scope_id"`
	OrgID          string     `json:"org_id"`
	State          State      `json:"state"`
	TripReason     TripReason `json:"trip_reason,omitempty"`
	TrippedBy      string     `json:"tripped_by,omitempty"`
	TrippedByEmail string     `json:"tripped_by_email,omitempty"`
	TripComment    string     `json:"trip_comment,omitempty"`
	TrippedAt      *time.Time `json:"tripped_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	ResetBy        string     `json:"reset_by,omitempty"`
	ResetAt        *time.Time `json:"reset_at,omitempty"`
	ErrorCount     int        `json:"error_count"`
	ViolationCount int        `json:"violation_count"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// TripEvent is emitted when a circuit is tripped
type TripEvent struct {
	CircuitID  string
	OrgID      string
	TenantID   string
	Scope      Scope
	ScopeID    string
	Reason     TripReason
	TrippedBy  string
	Comment    string
	Timestamp  time.Time
}

// Prometheus metrics
var (
	circuitTripsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_circuit_trips_total",
			Help: "Total number of circuit breaker trips",
		},
		[]string{"org_id", "scope", "reason"},
	)
	circuitResetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_circuit_resets_total",
			Help: "Total number of circuit breaker resets",
		},
		[]string{"org_id", "scope"},
	)
	circuitBlockedRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_circuit_blocked_requests_total",
			Help: "Total requests blocked by circuit breaker",
		},
		[]string{"org_id", "scope"},
	)
	circuitState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "axonflow_circuit_state",
			Help: "Current circuit state (0=closed, 1=open, 2=half_open)",
		},
		[]string{"org_id", "scope", "scope_id"},
	)
)

func init() {
	prometheus.MustRegister(circuitTripsTotal)
	prometheus.MustRegister(circuitResetsTotal)
	prometheus.MustRegister(circuitBlockedRequests)
	prometheus.MustRegister(circuitState)
}

// New creates a new circuit breaker
func New(repo *Repository, config Config) *CircuitBreaker {
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Minute
	}
	if config.MaxTimeout == 0 {
		config.MaxTimeout = 24 * time.Hour
	}
	if config.ErrorThreshold == 0 {
		config.ErrorThreshold = 10
	}
	if config.PolicyViolationThreshold == 0 {
		config.PolicyViolationThreshold = 5
	}
	if config.PolicyViolationWindow == 0 {
		config.PolicyViolationWindow = 5 * time.Minute
	}

	return &CircuitBreaker{
		repo:             repo,
		state:            StateClosed,
		circuits:         make(map[string]*Circuit),
		config:           config,
		errorWindows:     make(map[string]*eventWindow),
		violationWindows: make(map[string]*eventWindow),
		configCache: &tenantConfigCache{
			configs: make(map[string]*tenantConfigEntry),
		},
	}
}

// SetTripCallback sets a callback function called when circuits trip
func (cb *CircuitBreaker) SetTripCallback(fn func(trip *TripEvent)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tripCallback = fn
}

// TripInput contains input for tripping a circuit
type TripInput struct {
	OrgID          string
	Scope          Scope
	ScopeID        string // tenant_id, client_id, or policy_id (optional for global)
	Reason         TripReason
	TrippedBy      string
	TrippedByEmail string
	Comment        string
	Duration       time.Duration // 0 = indefinite (manual reset required)
}

// Trip opens a circuit, blocking all matching requests
func (cb *CircuitBreaker) Trip(ctx context.Context, input TripInput) (*Circuit, error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Validate
	if input.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	if input.Scope == "" {
		input.Scope = ScopeGlobal
	}
	if input.Reason == "" {
		input.Reason = ReasonManual
	}
	if input.TrippedBy == "" {
		return nil, fmt.Errorf("tripped_by is required for audit trail")
	}

	// Enforce max timeout
	if input.Duration > cb.config.MaxTimeout {
		input.Duration = cb.config.MaxTimeout
	}

	// Create circuit
	now := time.Now().UTC()
	circuit := &Circuit{
		ID:             uuid.New().String(),
		Scope:          input.Scope,
		ScopeID:        input.ScopeID,
		OrgID:          input.OrgID,
		State:          StateOpen,
		TripReason:     input.Reason,
		TrippedBy:      input.TrippedBy,
		TrippedByEmail: input.TrippedByEmail,
		TripComment:    input.Comment,
		TrippedAt:      &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if input.Duration > 0 {
		expiresAt := now.Add(input.Duration)
		circuit.ExpiresAt = &expiresAt
	}

	// Persist
	if err := cb.repo.CreateCircuit(ctx, circuit); err != nil {
		return nil, fmt.Errorf("persist circuit: %w", err)
	}

	// Cache
	key := cb.circuitKey(input.OrgID, input.Scope, input.ScopeID)
	cb.circuits[key] = circuit

	// Metrics
	circuitTripsTotal.WithLabelValues(input.OrgID, string(input.Scope), string(input.Reason)).Inc()
	circuitState.WithLabelValues(input.OrgID, string(input.Scope), input.ScopeID).Set(1) // open

	// Callback
	if cb.tripCallback != nil {
		go cb.tripCallback(&TripEvent{
			CircuitID: circuit.ID,
			OrgID:     input.OrgID,
			Scope:     input.Scope,
			ScopeID:   input.ScopeID,
			Reason:    input.Reason,
			TrippedBy: input.TrippedBy,
			Comment:   input.Comment,
			Timestamp: now,
		})
	}

	return circuit, nil
}

// ResetInput contains input for resetting a circuit
type ResetInput struct {
	OrgID   string
	Scope   Scope
	ScopeID string
	ResetBy string
	Comment string
}

// Reset closes a circuit, resuming normal operation
func (cb *CircuitBreaker) Reset(ctx context.Context, input ResetInput) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if input.OrgID == "" {
		return fmt.Errorf("org_id is required")
	}
	if input.ResetBy == "" {
		return fmt.Errorf("reset_by is required for audit trail")
	}

	key := cb.circuitKey(input.OrgID, input.Scope, input.ScopeID)

	// Update in DB
	if err := cb.repo.ResetCircuit(ctx, input.OrgID, input.Scope, input.ScopeID, input.ResetBy); err != nil {
		return fmt.Errorf("reset circuit: %w", err)
	}

	// Update cache
	if circuit, ok := cb.circuits[key]; ok {
		now := time.Now().UTC()
		circuit.State = StateClosed
		circuit.ResetBy = input.ResetBy
		circuit.ResetAt = &now
		circuit.UpdatedAt = now
	}

	// Clear sliding window entries so stale events don't re-trigger after reset
	delete(cb.errorWindows, key)
	delete(cb.violationWindows, key)

	// Metrics
	circuitResetsTotal.WithLabelValues(input.OrgID, string(input.Scope)).Inc()
	circuitState.WithLabelValues(input.OrgID, string(input.Scope), input.ScopeID).Set(0) // closed

	return nil
}

// CheckResult is the result of checking if a request should proceed
type CheckResult struct {
	Allowed    bool
	CircuitID  string
	Scope      Scope
	ScopeID    string
	Reason     TripReason
	TrippedBy  string
	TrippedAt  *time.Time
	ExpiresAt  *time.Time
	Comment    string
}

// CheckInput contains input for checking circuit state
type CheckInput struct {
	OrgID    string
	TenantID string
	ClientID string
	PolicyID string
}

// Check determines if a request should be allowed based on circuit state
func (cb *CircuitBreaker) Check(ctx context.Context, input CheckInput) (*CheckResult, error) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Check circuits from most specific to least specific
	scopes := []struct {
		scope   Scope
		scopeID string
	}{
		{ScopeClient, input.ClientID},
		{ScopePolicy, input.PolicyID},
		{ScopeTenant, input.TenantID},
		{ScopeGlobal, ""},
	}

	for _, s := range scopes {
		if s.scopeID == "" && s.scope != ScopeGlobal {
			continue
		}

		key := cb.circuitKey(input.OrgID, s.scope, s.scopeID)
		if circuit, ok := cb.circuits[key]; ok {
			if circuit.State == StateOpen {
				// Check if expired
				if circuit.ExpiresAt != nil && time.Now().After(*circuit.ExpiresAt) {
					continue // Expired, don't block
				}

				circuitBlockedRequests.WithLabelValues(input.OrgID, string(s.scope)).Inc()
				return &CheckResult{
					Allowed:   false,
					CircuitID: circuit.ID,
					Scope:     s.scope,
					ScopeID:   s.scopeID,
					Reason:    circuit.TripReason,
					TrippedBy: circuit.TrippedBy,
					TrippedAt: circuit.TrippedAt,
					ExpiresAt: circuit.ExpiresAt,
					Comment:   circuit.TripComment,
				}, nil
			}
		}
	}

	return &CheckResult{Allowed: true}, nil
}

// IsAllowed is a convenience method for quick checks
func (cb *CircuitBreaker) IsAllowed(ctx context.Context, orgID, tenantID, clientID string) bool {
	result, _ := cb.Check(ctx, CheckInput{
		OrgID:    orgID,
		TenantID: tenantID,
		ClientID: clientID,
	})
	return result != nil && result.Allowed
}

// GetActiveCircuits returns all active (open) circuits for an org
func (cb *CircuitBreaker) GetActiveCircuits(ctx context.Context, orgID string) ([]*Circuit, error) {
	return cb.repo.GetActiveCircuits(ctx, orgID)
}

// GetCircuitHistory returns circuit history for an org
func (cb *CircuitBreaker) GetCircuitHistory(ctx context.Context, orgID string, limit int) ([]*Circuit, error) {
	return cb.repo.GetCircuitHistory(ctx, orgID, limit)
}

// LoadCircuits loads active circuits from the database into memory.
// If orgID is empty, loads active circuits across all orgs (used at startup).
func (cb *CircuitBreaker) LoadCircuits(ctx context.Context, orgID string) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	var circuits []*Circuit
	var err error
	if orgID == "" {
		circuits, err = cb.repo.GetAllActiveCircuits(ctx)
	} else {
		circuits, err = cb.repo.GetActiveCircuits(ctx, orgID)
	}
	if err != nil {
		return fmt.Errorf("load circuits: %w", err)
	}

	for _, circuit := range circuits {
		key := cb.circuitKey(circuit.OrgID, circuit.Scope, circuit.ScopeID)
		cb.circuits[key] = circuit

		// Update metrics
		stateVal := 0.0
		if circuit.State == StateOpen {
			stateVal = 1.0
		} else if circuit.State == StateHalfOpen {
			stateVal = 2.0
		}
		circuitState.WithLabelValues(circuit.OrgID, string(circuit.Scope), circuit.ScopeID).Set(stateVal)
	}

	return nil
}

// RecordError records an error for automatic circuit tripping.
// Uses a sliding window: only errors within PolicyViolationWindow are counted.
func (cb *CircuitBreaker) RecordError(ctx context.Context, orgID, tenantID, clientID string) error {
	// Resolve effective config before acquiring main lock (uses separate cache lock)
	effectiveConfig := cb.getEffectiveConfig(ctx, orgID, tenantID)

	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now().UTC()
	key := cb.circuitKey(orgID, ScopeClient, clientID)

	// Record in sliding window
	w, ok := cb.errorWindows[key]
	if !ok {
		w = &eventWindow{maxSize: effectiveConfig.ErrorThreshold * 2}
		cb.errorWindows[key] = w
	}
	w.record(now)

	// Ensure circuit exists in cache
	circuit, ok := cb.circuits[key]
	if !ok {
		circuit = &Circuit{
			ID:        uuid.New().String(),
			Scope:     ScopeClient,
			ScopeID:   clientID,
			OrgID:     orgID,
			State:     StateClosed,
			CreatedAt: now,
		}
		cb.circuits[key] = circuit
	}

	circuit.ErrorCount = w.countInWindow(now, effectiveConfig.PolicyViolationWindow)
	circuit.UpdatedAt = now

	// Auto-trip if windowed count exceeds threshold
	if circuit.ErrorCount >= effectiveConfig.ErrorThreshold && circuit.State == StateClosed {
		circuit.State = StateOpen
		circuit.TripReason = ReasonError
		circuit.TrippedBy = "system"
		circuit.TrippedAt = &now

		if effectiveConfig.EnableAutoRecovery {
			expiresAt := now.Add(effectiveConfig.DefaultTimeout)
			circuit.ExpiresAt = &expiresAt
		}

		if err := cb.repo.CreateCircuit(ctx, circuit); err != nil {
			return fmt.Errorf("persist auto-tripped circuit: %w", err)
		}

		circuitTripsTotal.WithLabelValues(orgID, string(ScopeClient), string(ReasonError)).Inc()
		circuitState.WithLabelValues(orgID, string(ScopeClient), clientID).Set(1)

		// Fire trip callback for notifications
		if cb.tripCallback != nil {
			go cb.tripCallback(&TripEvent{
				CircuitID: circuit.ID,
				OrgID:     orgID,
				TenantID:  tenantID,
				Scope:     ScopeClient,
				ScopeID:   clientID,
				Reason:    ReasonError,
				TrippedBy: "system",
				Comment:   fmt.Sprintf("Auto-tripped after %d errors in %v window", circuit.ErrorCount, effectiveConfig.PolicyViolationWindow),
				Timestamp: now,
			})
		}
	}

	return nil
}

// RecordPolicyViolation records a policy violation for automatic tripping.
// Tracks violations at both policy scope (audit trail) and client scope (pipeline blocking).
// Uses a sliding window: only violations within PolicyViolationWindow are counted.
func (cb *CircuitBreaker) RecordPolicyViolation(ctx context.Context, orgID, tenantID, clientID, policyID string) error {
	// Resolve effective config before acquiring main lock
	effectiveConfig := cb.getEffectiveConfig(ctx, orgID, tenantID)

	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now().UTC()

	// Track at policy scope for audit visibility
	policyKey := cb.circuitKey(orgID, ScopePolicy, policyID)
	policyCircuit, ok := cb.circuits[policyKey]
	if !ok {
		policyCircuit = &Circuit{
			ID:        uuid.New().String(),
			Scope:     ScopePolicy,
			ScopeID:   policyID,
			OrgID:     orgID,
			State:     StateClosed,
			CreatedAt: now,
		}
		cb.circuits[policyKey] = policyCircuit
	}
	// Record in policy violation window (for audit count)
	policyVW, ok := cb.violationWindows[policyKey]
	if !ok {
		policyVW = &eventWindow{maxSize: effectiveConfig.PolicyViolationThreshold * 2}
		cb.violationWindows[policyKey] = policyVW
	}
	policyVW.record(now)
	policyCircuit.ViolationCount = policyVW.countInWindow(now, effectiveConfig.PolicyViolationWindow)
	policyCircuit.UpdatedAt = now

	// Track at client scope for pipeline blocking
	clientKey := cb.circuitKey(orgID, ScopeClient, clientID)
	clientCircuit, ok := cb.circuits[clientKey]
	if !ok {
		clientCircuit = &Circuit{
			ID:        uuid.New().String(),
			Scope:     ScopeClient,
			ScopeID:   clientID,
			OrgID:     orgID,
			State:     StateClosed,
			CreatedAt: now,
		}
		cb.circuits[clientKey] = clientCircuit
	}
	// Record in client violation window
	clientVW, ok := cb.violationWindows[clientKey]
	if !ok {
		clientVW = &eventWindow{maxSize: effectiveConfig.PolicyViolationThreshold * 2}
		cb.violationWindows[clientKey] = clientVW
	}
	clientVW.record(now)
	clientCircuit.ViolationCount = clientVW.countInWindow(now, effectiveConfig.PolicyViolationWindow)
	clientCircuit.UpdatedAt = now

	// Auto-trip at client scope if threshold exceeded — this is what actually blocks requests
	if clientCircuit.ViolationCount >= effectiveConfig.PolicyViolationThreshold && clientCircuit.State == StateClosed {
		clientCircuit.State = StateOpen
		clientCircuit.TripReason = ReasonPolicy
		clientCircuit.TrippedBy = "system"
		clientCircuit.TripComment = fmt.Sprintf("Auto-tripped after %d policy violations in %v window (last policy: %s)", clientCircuit.ViolationCount, effectiveConfig.PolicyViolationWindow, policyID)
		clientCircuit.TrippedAt = &now

		if effectiveConfig.EnableAutoRecovery {
			expiresAt := now.Add(effectiveConfig.DefaultTimeout)
			clientCircuit.ExpiresAt = &expiresAt
		}

		if err := cb.repo.CreateCircuit(ctx, clientCircuit); err != nil {
			return fmt.Errorf("persist auto-tripped client circuit: %w", err)
		}

		// Also persist the policy-scoped circuit for audit trail
		policyCircuit.State = StateOpen
		policyCircuit.TripReason = ReasonPolicy
		policyCircuit.TrippedBy = "system"
		policyCircuit.TripComment = fmt.Sprintf("Auto-tripped after %d policy violations in %v window", policyCircuit.ViolationCount, effectiveConfig.PolicyViolationWindow)
		policyCircuit.TrippedAt = &now
		if effectiveConfig.EnableAutoRecovery {
			expiresAt := now.Add(effectiveConfig.DefaultTimeout)
			policyCircuit.ExpiresAt = &expiresAt
		}
		if err := cb.repo.CreateCircuit(ctx, policyCircuit); err != nil {
			fmt.Printf("[CircuitBreaker] Failed to persist policy audit circuit: %v\n", err)
		}

		circuitTripsTotal.WithLabelValues(orgID, string(ScopeClient), string(ReasonPolicy)).Inc()
		circuitState.WithLabelValues(orgID, string(ScopeClient), clientID).Set(1)
		circuitState.WithLabelValues(orgID, string(ScopePolicy), policyID).Set(1)

		// Fire trip callback for notifications
		if cb.tripCallback != nil {
			go cb.tripCallback(&TripEvent{
				CircuitID: clientCircuit.ID,
				OrgID:     orgID,
				TenantID:  tenantID,
				Scope:     ScopeClient,
				ScopeID:   clientID,
				Reason:    ReasonPolicy,
				TrippedBy: "system",
				Comment:   clientCircuit.TripComment,
				Timestamp: now,
			})
		}
	}

	return nil
}

// getEffectiveConfig resolves the effective config for a tenant, merging
// tenant overrides onto global defaults. Results are cached for 1 minute.
func (cb *CircuitBreaker) getEffectiveConfig(ctx context.Context, orgID, tenantID string) Config {
	if tenantID == "" {
		return cb.config
	}

	cacheKey := orgID + ":" + tenantID

	// Check cache first (read lock)
	cb.configCache.mu.RLock()
	if entry, ok := cb.configCache.configs[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		tc := entry.config
		cb.configCache.mu.RUnlock()
		if tc == nil {
			return cb.config
		}
		return cb.mergeConfig(tc)
	}
	cb.configCache.mu.RUnlock()

	// Cache miss or expired — fetch from DB
	tc, err := cb.repo.GetTenantConfig(ctx, orgID, tenantID)
	if err != nil {
		// On error, fall back to global config
		return cb.config
	}

	// Cache the result (even if nil — means no tenant override)
	cb.configCache.mu.Lock()
	cb.configCache.configs[cacheKey] = &tenantConfigEntry{
		config:    tc,
		expiresAt: time.Now().Add(tenantConfigCacheTTL),
	}
	cb.configCache.mu.Unlock()

	if tc == nil {
		return cb.config
	}
	return cb.mergeConfig(tc)
}

// mergeConfig merges tenant overrides onto global defaults
func (cb *CircuitBreaker) mergeConfig(tc *TenantConfig) Config {
	cfg := cb.config // copy global
	if tc.ErrorThreshold != nil {
		cfg.ErrorThreshold = *tc.ErrorThreshold
	}
	if tc.ViolationThreshold != nil {
		cfg.PolicyViolationThreshold = *tc.ViolationThreshold
	}
	if tc.WindowSeconds != nil {
		cfg.PolicyViolationWindow = time.Duration(*tc.WindowSeconds) * time.Second
	}
	if tc.DefaultTimeoutSeconds != nil {
		cfg.DefaultTimeout = time.Duration(*tc.DefaultTimeoutSeconds) * time.Second
	}
	if tc.MaxTimeoutSeconds != nil {
		cfg.MaxTimeout = time.Duration(*tc.MaxTimeoutSeconds) * time.Second
	}
	if tc.EnableAutoRecovery != nil {
		cfg.EnableAutoRecovery = *tc.EnableAutoRecovery
	}
	return cfg
}

// GetConfig returns the global config (exposed for handler)
func (cb *CircuitBreaker) GetConfig() Config {
	return cb.config
}

// GetTenantConfig returns tenant config from repo (exposed for handler)
func (cb *CircuitBreaker) GetTenantConfig(ctx context.Context, orgID, tenantID string) (*TenantConfig, error) {
	return cb.repo.GetTenantConfig(ctx, orgID, tenantID)
}

// UpsertTenantConfig saves a tenant config override (exposed for handler)
func (cb *CircuitBreaker) UpsertTenantConfig(ctx context.Context, config *TenantConfig) error {
	err := cb.repo.UpsertTenantConfig(ctx, config)
	if err != nil {
		return err
	}
	// Invalidate cache for this tenant
	cacheKey := config.OrgID + ":" + config.TenantID
	cb.configCache.mu.Lock()
	delete(cb.configCache.configs, cacheKey)
	cb.configCache.mu.Unlock()
	return nil
}

// ExpireCircuits closes circuits that have passed their expiry time
func (cb *CircuitBreaker) ExpireCircuits(ctx context.Context) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	for key, circuit := range cb.circuits {
		if circuit.State == StateOpen && circuit.ExpiresAt != nil && now.After(*circuit.ExpiresAt) {
			circuit.State = StateClosed
			circuit.UpdatedAt = now

			if err := cb.repo.ResetCircuit(ctx, circuit.OrgID, circuit.Scope, circuit.ScopeID, "system"); err != nil {
				// Log but continue
				continue
			}

			circuitResetsTotal.WithLabelValues(circuit.OrgID, string(circuit.Scope)).Inc()
			circuitState.WithLabelValues(circuit.OrgID, string(circuit.Scope), circuit.ScopeID).Set(0)

			delete(cb.circuits, key)
		}
	}

	return nil
}

// circuitKey generates a cache key for a circuit
func (cb *CircuitBreaker) circuitKey(orgID string, scope Scope, scopeID string) string {
	return fmt.Sprintf("%s:%s:%s", orgID, scope, scopeID)
}

// Repository provides persistence for circuit breaker state
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new repository
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// CreateCircuit persists a new circuit
func (r *Repository) CreateCircuit(ctx context.Context, circuit *Circuit) error {
	query := `
		INSERT INTO circuit_breaker (
			id, org_id, scope, scope_id, state,
			trip_reason, tripped_by, tripped_by_email, trip_comment,
			tripped_at, expires_at, error_count, violation_count
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13
		)
		ON CONFLICT (org_id, scope, scope_id) DO UPDATE SET
			state = EXCLUDED.state,
			trip_reason = EXCLUDED.trip_reason,
			tripped_by = EXCLUDED.tripped_by,
			tripped_by_email = EXCLUDED.tripped_by_email,
			trip_comment = EXCLUDED.trip_comment,
			tripped_at = EXCLUDED.tripped_at,
			expires_at = EXCLUDED.expires_at,
			error_count = EXCLUDED.error_count,
			violation_count = EXCLUDED.violation_count,
			updated_at = CURRENT_TIMESTAMP`

	_, err := r.db.ExecContext(ctx, query,
		circuit.ID, circuit.OrgID, circuit.Scope, circuit.ScopeID, circuit.State,
		circuit.TripReason, circuit.TrippedBy, nullString(circuit.TrippedByEmail), nullString(circuit.TripComment),
		circuit.TrippedAt, circuit.ExpiresAt, circuit.ErrorCount, circuit.ViolationCount,
	)
	return err
}

// ResetCircuit closes an open circuit
func (r *Repository) ResetCircuit(ctx context.Context, orgID string, scope Scope, scopeID string, resetBy string) error {
	query := `
		UPDATE circuit_breaker
		SET state = 'closed',
			reset_by = $1,
			reset_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE org_id = $2 AND scope = $3 AND scope_id = $4 AND state = 'open'`

	_, err := r.db.ExecContext(ctx, query, resetBy, orgID, scope, scopeID)
	return err
}

// GetAllActiveCircuits retrieves all open circuits across all orgs.
// Used at startup to restore circuit state after agent restart.
func (r *Repository) GetAllActiveCircuits(ctx context.Context) ([]*Circuit, error) {
	query := `
		SELECT
			id, org_id, scope, scope_id, state,
			trip_reason, tripped_by, tripped_by_email, trip_comment,
			tripped_at, expires_at, reset_by, reset_at,
			error_count, violation_count, created_at, updated_at
		FROM circuit_breaker
		WHERE state = 'open'
		ORDER BY tripped_at DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanCircuits(rows)
}

// GetActiveCircuits retrieves all open circuits for an org
func (r *Repository) GetActiveCircuits(ctx context.Context, orgID string) ([]*Circuit, error) {
	query := `
		SELECT
			id, org_id, scope, scope_id, state,
			trip_reason, tripped_by, tripped_by_email, trip_comment,
			tripped_at, expires_at, reset_by, reset_at,
			error_count, violation_count, created_at, updated_at
		FROM circuit_breaker
		WHERE org_id = $1 AND state = 'open'
		ORDER BY tripped_at DESC`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanCircuits(rows)
}

// GetCircuitHistory retrieves circuit history for an org
func (r *Repository) GetCircuitHistory(ctx context.Context, orgID string, limit int) ([]*Circuit, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	query := `
		SELECT
			id, org_id, scope, scope_id, state,
			trip_reason, tripped_by, tripped_by_email, trip_comment,
			tripped_at, expires_at, reset_by, reset_at,
			error_count, violation_count, created_at, updated_at
		FROM circuit_breaker
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.db.QueryContext(ctx, query, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanCircuits(rows)
}

func scanCircuits(rows *sql.Rows) ([]*Circuit, error) {
	var circuits []*Circuit
	for rows.Next() {
		c := &Circuit{}
		var trippedByEmail, tripComment sql.NullString
		var trippedAt, expiresAt, resetAt sql.NullTime
		var resetBy sql.NullString

		err := rows.Scan(
			&c.ID, &c.OrgID, &c.Scope, &c.ScopeID, &c.State,
			&c.TripReason, &c.TrippedBy, &trippedByEmail, &tripComment,
			&trippedAt, &expiresAt, &resetBy, &resetAt,
			&c.ErrorCount, &c.ViolationCount, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		c.TrippedByEmail = trippedByEmail.String
		c.TripComment = tripComment.String
		c.ResetBy = resetBy.String
		if trippedAt.Valid {
			c.TrippedAt = &trippedAt.Time
		}
		if expiresAt.Valid {
			c.ExpiresAt = &expiresAt.Time
		}
		if resetAt.Valid {
			c.ResetAt = &resetAt.Time
		}

		circuits = append(circuits, c)
	}
	return circuits, nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// GetTenantConfig retrieves per-tenant circuit breaker config overrides.
// Returns nil if no tenant-specific config exists.
func (r *Repository) GetTenantConfig(ctx context.Context, orgID, tenantID string) (*TenantConfig, error) {
	query := `
		SELECT id, org_id, tenant_id,
			error_threshold, violation_threshold, window_seconds,
			default_timeout_seconds, max_timeout_seconds, enable_auto_recovery,
			created_at, updated_at
		FROM circuit_breaker_config
		WHERE org_id = $1 AND tenant_id = $2`

	var tc TenantConfig
	var errorThreshold, violationThreshold, windowSeconds sql.NullInt32
	var defaultTimeoutSeconds, maxTimeoutSeconds sql.NullInt32
	var enableAutoRecovery sql.NullBool

	err := r.db.QueryRowContext(ctx, query, orgID, tenantID).Scan(
		&tc.ID, &tc.OrgID, &tc.TenantID,
		&errorThreshold, &violationThreshold, &windowSeconds,
		&defaultTimeoutSeconds, &maxTimeoutSeconds, &enableAutoRecovery,
		&tc.CreatedAt, &tc.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if errorThreshold.Valid {
		v := int(errorThreshold.Int32)
		tc.ErrorThreshold = &v
	}
	if violationThreshold.Valid {
		v := int(violationThreshold.Int32)
		tc.ViolationThreshold = &v
	}
	if windowSeconds.Valid {
		v := int(windowSeconds.Int32)
		tc.WindowSeconds = &v
	}
	if defaultTimeoutSeconds.Valid {
		v := int(defaultTimeoutSeconds.Int32)
		tc.DefaultTimeoutSeconds = &v
	}
	if maxTimeoutSeconds.Valid {
		v := int(maxTimeoutSeconds.Int32)
		tc.MaxTimeoutSeconds = &v
	}
	if enableAutoRecovery.Valid {
		tc.EnableAutoRecovery = &enableAutoRecovery.Bool
	}

	return &tc, nil
}

// UpsertTenantConfig creates or updates per-tenant circuit breaker config.
func (r *Repository) UpsertTenantConfig(ctx context.Context, config *TenantConfig) error {
	query := `
		INSERT INTO circuit_breaker_config (
			id, org_id, tenant_id,
			error_threshold, violation_threshold, window_seconds,
			default_timeout_seconds, max_timeout_seconds, enable_auto_recovery
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (org_id, tenant_id) DO UPDATE SET
			error_threshold = EXCLUDED.error_threshold,
			violation_threshold = EXCLUDED.violation_threshold,
			window_seconds = EXCLUDED.window_seconds,
			default_timeout_seconds = EXCLUDED.default_timeout_seconds,
			max_timeout_seconds = EXCLUDED.max_timeout_seconds,
			enable_auto_recovery = EXCLUDED.enable_auto_recovery,
			updated_at = CURRENT_TIMESTAMP`

	id := config.ID
	if id == "" {
		id = uuid.New().String()
	}

	_, err := r.db.ExecContext(ctx, query,
		id, config.OrgID, config.TenantID,
		config.ErrorThreshold, config.ViolationThreshold, config.WindowSeconds,
		config.DefaultTimeoutSeconds, config.MaxTimeoutSeconds, config.EnableAutoRecovery,
	)
	return err
}
