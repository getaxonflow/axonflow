// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"container/list"
	"sync"
)

// seenSet is the bounded, per-process, least-recently-used set of admitted
// keys. It is a cache in front of the ledger and nothing more: a miss is a
// ledger lookup, never a refusal (see the package documentation).
type seenSet struct {
	mu    sync.Mutex
	cap   int
	order *list.List // front = most recently used
	index map[Key]*list.Element
}

func newSeenSet(capacity int) *seenSet {
	if capacity < 1 {
		capacity = 1
	}
	return &seenSet{cap: capacity, order: list.New(), index: make(map[Key]*list.Element)}
}

// Has reports membership and marks the key most recently used.
func (s *seenSet) Has(k Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.index[k]
	if !ok {
		return false
	}
	s.order.MoveToFront(el)
	return true
}

// Add inserts (or refreshes) the key, evicting the least recently used one
// when the cap is exceeded.
func (s *seenSet) Add(k Key) { s.add(k) }

// add is Add, reporting whether the insert EVICTED a key. Callers that need to
// know - the debt set, where an eviction means a principal stops being retried
// - use this; the admission seen-set does not care, because an eviction there
// costs one ledger lookup and nothing else.
func (s *seenSet) add(k Key) (evicted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.index[k]; ok {
		s.order.MoveToFront(el)
		return false
	}
	s.index[k] = s.order.PushFront(k)
	for s.order.Len() > s.cap {
		last := s.order.Back()
		s.order.Remove(last)
		delete(s.index, last.Value.(Key))
		evicted = true
	}
	return evicted
}

// Remove drops the key. Used when a background write for it never landed, so
// the next request for that principal enqueues it again rather than trusting a
// record that does not exist.
func (s *seenSet) Remove(k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.index[k]; ok {
		s.order.Remove(el)
		delete(s.index, k)
	}
}

// Len is the current size; Cap the bound.
func (s *seenSet) Len() int { s.mu.Lock(); defer s.mu.Unlock(); return s.order.Len() }
func (s *seenSet) Cap() int { return s.cap }
