// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
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
