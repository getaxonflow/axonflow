// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"fmt"
	"sync"
)

// Event type constants for execution lifecycle events.
const (
	EventExecutionStarted   = "execution.started"
	EventExecutionCompleted = "execution.completed"
	EventExecutionFailed    = "execution.failed"
	EventExecutionCancelled = "execution.cancelled"
	EventStepStarted        = "step.started"
	EventStepCompleted      = "step.completed"
	EventStepFailed         = "step.failed"
	EventStepDecision       = "step.decision"
)

// ExecutionEvent represents an event published when execution state changes.
type ExecutionEvent struct {
	EventType   string           `json:"event_type"`
	ExecutionID string           `json:"execution_id"`
	Data        *ExecutionStatus `json:"data,omitempty"`
}

// EventHub provides pub-sub for execution events, enabling SSE streaming.
// Subscribers receive events for a specific execution ID.
// Pattern follows audit_queue.go: buffered channels, non-blocking publish.
type EventHub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan ExecutionEvent]struct{}
}

// NewEventHub creates a new EventHub.
func NewEventHub() *EventHub {
	return &EventHub{
		subscribers: make(map[string]map[chan ExecutionEvent]struct{}),
	}
}

// Subscribe creates a buffered channel to receive events for the given execution ID.
// The caller must call Unsubscribe when done to prevent resource leaks.
func (h *EventHub) Subscribe(executionID string) chan ExecutionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan ExecutionEvent, 16)
	if h.subscribers[executionID] == nil {
		h.subscribers[executionID] = make(map[chan ExecutionEvent]struct{})
	}
	h.subscribers[executionID][ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscriber channel and closes it.
func (h *EventHub) Unsubscribe(executionID string, ch chan ExecutionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	subs, ok := h.subscribers[executionID]
	if !ok {
		return
	}
	if _, exists := subs[ch]; exists {
		delete(subs, ch)
		close(ch)
	}
	if len(subs) == 0 {
		delete(h.subscribers, executionID)
	}
}

// Publish sends an event to all subscribers of the given execution ID.
// Non-blocking: if a subscriber's channel is full, the event is dropped
// for that subscriber (slow subscriber protection).
func (h *EventHub) Publish(event ExecutionEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	subs, ok := h.subscribers[event.ExecutionID]
	if !ok {
		return
	}

	for ch := range subs {
		select {
		case ch <- event:
		default:
			// Drop event for slow subscriber
		}
	}
}

// SubscriberCount returns the number of active subscribers for an execution ID.
func (h *EventHub) SubscriberCount(executionID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.subscribers[executionID])
}

// --- Connection Tracker for SSE tenant-level limits ---

// ErrConnectionLimitReached is returned when a tenant exceeds the maximum concurrent SSE connections.
var ErrConnectionLimitReached = fmt.Errorf("concurrent SSE connection limit reached")

// DefaultCommunityMaxConnections is the max concurrent SSE connections per tenant in community mode.
// This MUST be 5 (not 10) — kept consistent across ConnectionTracker and unified_execution_handler.
const DefaultCommunityMaxConnections = 5

// ConnectionTracker enforces per-tenant concurrent SSE connection limits.
// Limits are set via SetMaxConnections (typically from tier/license system).
// A limit of -1 means unlimited connections.
type ConnectionTracker struct {
	mu          sync.RWMutex
	connections map[string]int // tenantID → active connection count
	maxPerTenant int           // max connections per tenant; -1 = unlimited
}

// NewConnectionTracker creates a new ConnectionTracker with the default community limit.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections:  make(map[string]int),
		maxPerTenant: DefaultCommunityMaxConnections,
	}
}

// NewConnectionTrackerWithLimit creates a ConnectionTracker with a custom limit.
// Use -1 for unlimited connections.
func NewConnectionTrackerWithLimit(max int) *ConnectionTracker {
	if max == 0 {
		max = DefaultCommunityMaxConnections
	}
	return &ConnectionTracker{
		connections:  make(map[string]int),
		maxPerTenant: max,
	}
}

// SetMaxConnections updates the per-tenant connection limit.
// Use -1 for unlimited. Thread-safe.
func (ct *ConnectionTracker) SetMaxConnections(max int) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.maxPerTenant = max
}

// TryConnect attempts to register a new connection for the given tenant.
// Returns ErrConnectionLimitReached if the tenant is at the limit.
// When maxPerTenant is -1 (unlimited), always succeeds.
func (ct *ConnectionTracker) TryConnect(tenantID string) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// -1 means unlimited
	if ct.maxPerTenant < 0 {
		ct.connections[tenantID]++
		return nil
	}

	current := ct.connections[tenantID]
	if current >= ct.maxPerTenant {
		return ErrConnectionLimitReached
	}

	ct.connections[tenantID] = current + 1
	return nil
}

// Disconnect decrements the connection count for the given tenant.
func (ct *ConnectionTracker) Disconnect(tenantID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.connections[tenantID] > 0 {
		ct.connections[tenantID]--
	}
	if ct.connections[tenantID] == 0 {
		delete(ct.connections, tenantID)
	}
}

// ActiveConnections returns the current connection count for a tenant.
func (ct *ConnectionTracker) ActiveConnections(tenantID string) int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.connections[tenantID]
}

// MaxConnections returns the per-tenant connection limit.
func (ct *ConnectionTracker) MaxConnections() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.maxPerTenant
}
