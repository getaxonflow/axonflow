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
