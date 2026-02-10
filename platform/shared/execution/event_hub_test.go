// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"sync"
	"testing"
	"time"
)

func TestEventHub_SubscribeAndPublish(t *testing.T) {
	hub := NewEventHub()
	ch := hub.Subscribe("exec-1")
	defer hub.Unsubscribe("exec-1", ch)

	event := ExecutionEvent{
		EventType:   EventExecutionStarted,
		ExecutionID: "exec-1",
		Data: &ExecutionStatus{
			ExecutionID: "exec-1",
			Status:      StatusRunning,
		},
	}

	hub.Publish(event)

	select {
	case received := <-ch:
		if received.EventType != EventExecutionStarted {
			t.Errorf("EventType = %q, want %q", received.EventType, EventExecutionStarted)
		}
		if received.ExecutionID != "exec-1" {
			t.Errorf("ExecutionID = %q, want %q", received.ExecutionID, "exec-1")
		}
		if received.Data.Status != StatusRunning {
			t.Errorf("Data.Status = %q, want %q", received.Data.Status, StatusRunning)
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestEventHub_Unsubscribe(t *testing.T) {
	hub := NewEventHub()
	ch := hub.Subscribe("exec-1")

	if hub.SubscriberCount("exec-1") != 1 {
		t.Fatalf("SubscriberCount = %d, want 1", hub.SubscriberCount("exec-1"))
	}

	hub.Unsubscribe("exec-1", ch)

	if hub.SubscriberCount("exec-1") != 0 {
		t.Fatalf("SubscriberCount = %d, want 0 after unsubscribe", hub.SubscriberCount("exec-1"))
	}

	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("Channel should be closed after Unsubscribe")
	}
}

func TestEventHub_SlowSubscriber(t *testing.T) {
	hub := NewEventHub()
	ch := hub.Subscribe("exec-1")
	defer hub.Unsubscribe("exec-1", ch)

	// Fill the buffer (cap 16) + extras
	for i := 0; i < 20; i++ {
		hub.Publish(ExecutionEvent{
			EventType:   EventStepCompleted,
			ExecutionID: "exec-1",
		})
	}

	// Should not block — extras are dropped
	received := 0
	for {
		select {
		case <-ch:
			received++
		default:
			goto done
		}
	}
done:
	if received != 16 {
		t.Errorf("Received %d events, want 16 (buffer capacity)", received)
	}
}

func TestEventHub_MultipleSubscribers(t *testing.T) {
	hub := NewEventHub()
	ch1 := hub.Subscribe("exec-1")
	ch2 := hub.Subscribe("exec-1")
	defer hub.Unsubscribe("exec-1", ch1)
	defer hub.Unsubscribe("exec-1", ch2)

	if hub.SubscriberCount("exec-1") != 2 {
		t.Fatalf("SubscriberCount = %d, want 2", hub.SubscriberCount("exec-1"))
	}

	hub.Publish(ExecutionEvent{
		EventType:   EventExecutionCompleted,
		ExecutionID: "exec-1",
	})

	// Both should receive
	for i, ch := range []chan ExecutionEvent{ch1, ch2} {
		select {
		case event := <-ch:
			if event.EventType != EventExecutionCompleted {
				t.Errorf("Subscriber %d: EventType = %q, want %q", i, event.EventType, EventExecutionCompleted)
			}
		case <-time.After(time.Second):
			t.Fatalf("Subscriber %d: timeout", i)
		}
	}
}

func TestEventHub_DifferentExecutions(t *testing.T) {
	hub := NewEventHub()
	ch1 := hub.Subscribe("exec-1")
	ch2 := hub.Subscribe("exec-2")
	defer hub.Unsubscribe("exec-1", ch1)
	defer hub.Unsubscribe("exec-2", ch2)

	// Publish to exec-1 only
	hub.Publish(ExecutionEvent{
		EventType:   EventExecutionStarted,
		ExecutionID: "exec-1",
	})

	select {
	case <-ch1:
		// expected
	case <-time.After(time.Second):
		t.Fatal("ch1 should receive event")
	}

	select {
	case <-ch2:
		t.Fatal("ch2 should not receive event for exec-1")
	case <-time.After(50 * time.Millisecond):
		// expected — no event for exec-2
	}
}

func TestEventHub_Concurrent(t *testing.T) {
	hub := NewEventHub()
	const goroutines = 20
	const eventsPerGoroutine = 50

	var wg sync.WaitGroup

	// Concurrent subscribe/publish/unsubscribe
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			execID := "exec-concurrent"
			ch := hub.Subscribe(execID)

			for j := 0; j < eventsPerGoroutine; j++ {
				hub.Publish(ExecutionEvent{
					EventType:   EventStepStarted,
					ExecutionID: execID,
				})
			}

			hub.Unsubscribe(execID, ch)
		}(i)
	}

	wg.Wait()

	// After all goroutines done, subscriber count should be 0
	if count := hub.SubscriberCount("exec-concurrent"); count != 0 {
		t.Errorf("SubscriberCount = %d after concurrent test, want 0", count)
	}
}

func TestEventHub_PublishNoSubscribers(t *testing.T) {
	hub := NewEventHub()

	// Should not panic
	hub.Publish(ExecutionEvent{
		EventType:   EventExecutionStarted,
		ExecutionID: "nonexistent",
	})
}

func TestEventHub_UnsubscribeNonexistent(t *testing.T) {
	hub := NewEventHub()
	ch := make(chan ExecutionEvent, 1)

	// Should not panic
	hub.Unsubscribe("nonexistent", ch)
}

func TestEventHub_SubscriberCountEmpty(t *testing.T) {
	hub := NewEventHub()
	if count := hub.SubscriberCount("nonexistent"); count != 0 {
		t.Errorf("SubscriberCount = %d, want 0", count)
	}
}

// =============================================================================
// ConnectionTracker Tests
// =============================================================================

func TestNewConnectionTracker(t *testing.T) {
	ct := NewConnectionTracker()
	if ct == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	if ct.MaxConnections() != DefaultCommunityMaxConnections {
		t.Errorf("MaxConnections = %d, want %d", ct.MaxConnections(), DefaultCommunityMaxConnections)
	}
}

func TestNewConnectionTrackerWithLimit(t *testing.T) {
	t.Run("custom limit", func(t *testing.T) {
		ct := NewConnectionTrackerWithLimit(10)
		if ct.MaxConnections() != 10 {
			t.Errorf("MaxConnections = %d, want 10", ct.MaxConnections())
		}
	})

	t.Run("zero limit uses default", func(t *testing.T) {
		ct := NewConnectionTrackerWithLimit(0)
		if ct.MaxConnections() != DefaultCommunityMaxConnections {
			t.Errorf("MaxConnections = %d, want %d", ct.MaxConnections(), DefaultCommunityMaxConnections)
		}
	})

	t.Run("negative limit means unlimited", func(t *testing.T) {
		ct := NewConnectionTrackerWithLimit(-1)
		if ct.MaxConnections() != -1 {
			t.Errorf("MaxConnections = %d, want -1 (unlimited)", ct.MaxConnections())
		}
		// Unlimited: should allow many connections
		for i := 0; i < 100; i++ {
			if err := ct.TryConnect("tenant"); err != nil {
				t.Fatalf("TryConnect #%d failed with unlimited: %v", i+1, err)
			}
		}
	})
}

func TestTryConnect_DefaultLimit(t *testing.T) {
	ct := NewConnectionTracker()
	tenant := "tenant-default"

	// Default tracker has community limit (5)
	for i := 0; i < DefaultCommunityMaxConnections; i++ {
		if err := ct.TryConnect(tenant); err != nil {
			t.Fatalf("TryConnect #%d failed: %v", i+1, err)
		}
	}

	if ct.ActiveConnections(tenant) != DefaultCommunityMaxConnections {
		t.Errorf("ActiveConnections = %d, want %d", ct.ActiveConnections(tenant), DefaultCommunityMaxConnections)
	}

	// The 6th connection should fail
	err := ct.TryConnect(tenant)
	if err == nil {
		t.Fatal("Expected ErrConnectionLimitReached, got nil")
	}
	if err != ErrConnectionLimitReached {
		t.Errorf("Error = %v, want ErrConnectionLimitReached", err)
	}

	// Disconnect one and retry — should succeed
	ct.Disconnect(tenant)
	if err := ct.TryConnect(tenant); err != nil {
		t.Fatalf("TryConnect after Disconnect failed: %v", err)
	}
}

func TestTryConnect_UnlimitedMode(t *testing.T) {
	ct := NewConnectionTrackerWithLimit(-1)
	tenant := "tenant-unlimited"

	// Unlimited (-1) has no limit — connect many times
	for i := 0; i < 100; i++ {
		if err := ct.TryConnect(tenant); err != nil {
			t.Fatalf("TryConnect #%d failed in unlimited mode: %v", i+1, err)
		}
	}

	if ct.ActiveConnections(tenant) != 100 {
		t.Errorf("ActiveConnections = %d, want 100", ct.ActiveConnections(tenant))
	}
}

func TestSetMaxConnections(t *testing.T) {
	ct := NewConnectionTracker()
	tenant := "tenant-dynamic"

	// Default limit is 5
	if ct.MaxConnections() != DefaultCommunityMaxConnections {
		t.Fatalf("initial MaxConnections = %d, want %d", ct.MaxConnections(), DefaultCommunityMaxConnections)
	}

	// Fill to limit
	for i := 0; i < DefaultCommunityMaxConnections; i++ {
		_ = ct.TryConnect(tenant)
	}
	if err := ct.TryConnect(tenant); err != ErrConnectionLimitReached {
		t.Fatalf("Expected limit at %d, got err=%v", DefaultCommunityMaxConnections, err)
	}

	// Increase limit to 25 (evaluation tier)
	ct.SetMaxConnections(25)
	if ct.MaxConnections() != 25 {
		t.Errorf("MaxConnections after set = %d, want 25", ct.MaxConnections())
	}
	// Now should allow more connections
	if err := ct.TryConnect(tenant); err != nil {
		t.Fatalf("TryConnect after raising limit failed: %v", err)
	}

	// Set to unlimited
	ct.SetMaxConnections(-1)
	for i := 0; i < 100; i++ {
		if err := ct.TryConnect(tenant); err != nil {
			t.Fatalf("TryConnect #%d failed after unlimited: %v", i+1, err)
		}
	}
}

func TestDisconnect(t *testing.T) {
	ct := NewConnectionTrackerWithLimit(-1) // unlimited for this test
	tenant := "tenant-disconnect"

	// Connect 3 times
	for i := 0; i < 3; i++ {
		_ = ct.TryConnect(tenant)
	}
	if ct.ActiveConnections(tenant) != 3 {
		t.Fatalf("ActiveConnections = %d, want 3", ct.ActiveConnections(tenant))
	}

	// Disconnect once
	ct.Disconnect(tenant)
	if ct.ActiveConnections(tenant) != 2 {
		t.Errorf("ActiveConnections after 1 disconnect = %d, want 2", ct.ActiveConnections(tenant))
	}

	// Disconnect all
	ct.Disconnect(tenant)
	ct.Disconnect(tenant)
	if ct.ActiveConnections(tenant) != 0 {
		t.Errorf("ActiveConnections after full disconnect = %d, want 0", ct.ActiveConnections(tenant))
	}

	// Disconnect on already-zero should not go negative
	ct.Disconnect(tenant)
	if ct.ActiveConnections(tenant) != 0 {
		t.Errorf("ActiveConnections after extra disconnect = %d, want 0", ct.ActiveConnections(tenant))
	}
}

func TestActiveConnections(t *testing.T) {
	ct := NewConnectionTrackerWithLimit(-1) // unlimited for this test

	// Unknown tenant should return 0
	if ct.ActiveConnections("unknown") != 0 {
		t.Errorf("ActiveConnections for unknown tenant = %d, want 0", ct.ActiveConnections("unknown"))
	}

	// Connect and verify
	_ = ct.TryConnect("t1")
	_ = ct.TryConnect("t1")
	_ = ct.TryConnect("t2")

	if ct.ActiveConnections("t1") != 2 {
		t.Errorf("ActiveConnections(t1) = %d, want 2", ct.ActiveConnections("t1"))
	}
	if ct.ActiveConnections("t2") != 1 {
		t.Errorf("ActiveConnections(t2) = %d, want 1", ct.ActiveConnections("t2"))
	}
}

func TestMaxConnections(t *testing.T) {
	t.Run("default tracker", func(t *testing.T) {
		ct := NewConnectionTracker()
		if ct.MaxConnections() != DefaultCommunityMaxConnections {
			t.Errorf("MaxConnections = %d, want %d", ct.MaxConnections(), DefaultCommunityMaxConnections)
		}
	})

	t.Run("custom limit tracker", func(t *testing.T) {
		ct := NewConnectionTrackerWithLimit(42)
		if ct.MaxConnections() != 42 {
			t.Errorf("MaxConnections = %d, want 42", ct.MaxConnections())
		}
	})
}
