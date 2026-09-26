// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"sync"
)

// lazyFactSource is a plane's fact source, built once per process on first use
// (#4249 row 5674229604): the route requests, the workflow step gate and the
// multi-agent checker each hold one. build calls the plane's replaceable
// builder (newRouteRequestFactProducer, newWCPFactProducer,
// newMAPFactProducer) at build time, so a test that replaces the builder and
// calls reset gets the next get built from its replacement.
type lazyFactSource[T any] struct {
	once  sync.Once
	value T
	err   error
	build func() (T, error)
}

func (l *lazyFactSource[T]) get() (T, error) {
	l.once.Do(func() { l.value, l.err = l.build() })
	return l.value, l.err
}

// reset forgets the built source, so the next get builds again. Tests only.
func (l *lazyFactSource[T]) reset() {
	var zero T
	l.once = sync.Once{}
	l.value, l.err = zero, nil
}

// wiredDynamicFactProducer builds a fact producer from the dynamic engine this
// process wired. stepPlane wraps it for a step plane (asStepPlane: the step's
// own context is stated, and every content row is evaluated over it); the
// request routes present their query as content and take it unwrapped.
func wiredDynamicFactProducer(stepPlane bool) (*dynamicFactProducer, error) {
	if dynamicPolicyEngine == nil {
		return nil, errors.New("the dynamic policy engine is not wired, so this plane's facts cannot be produced")
	}
	p, err := newDynamicFactProducer(dynamicPolicyEngine)
	if err != nil {
		return nil, err
	}
	if stepPlane {
		return asStepPlane(p), nil
	}
	return p, nil
}
