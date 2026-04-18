// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

/*
Package circuitbreaker provides emergency stop functionality
for EU AI Act Article 14 compliance (Human Oversight - Stop Button).

# Overview

This package implements a circuit breaker pattern that allows immediate
halting of all AI operations within an organization. Features include:

  - One-click emergency stop activation
  - Two-person deactivation for high-risk systems
  - Reason tracking for audit purposes
  - State persistence and recovery

# Usage

Create a circuit breaker with a repository:

	repo := circuitbreaker.NewInMemoryRepository()
	cb := circuitbreaker.NewCircuitBreaker(repo)

Activate emergency stop:

	state, err := cb.Activate(ctx, circuitbreaker.ActivateInput{
		OrgID:       "org-123",
		ActivatedBy: "user-456",
		Reason:      "Bias detected in production model",
	})

Check if operations are blocked:

	isOpen, err := cb.IsOpen(ctx, "org-123")
	if isOpen {
		return errors.New("operations halted - circuit breaker active")
	}

Deactivate (for high-risk, requires two approvals):

	// First approver
	state, err := cb.Deactivate(ctx, circuitbreaker.DeactivateInput{
		OrgID:         "org-123",
		DeactivatedBy: "user-789",
	})
	// state.State == StatePendingDeactivation

	// Second approver (different user)
	state, err = cb.Deactivate(ctx, circuitbreaker.DeactivateInput{
		OrgID:         "org-123",
		DeactivatedBy: "user-012",
	})
	// state.State == StateClosed

# Circuit Breaker States

  - StateClosed: Normal operation, all requests proceed
  - StateOpen: Emergency stop active, all AI requests blocked
  - StatePendingDeactivation: First approver has requested deactivation, waiting for second

# Two-Person Rule

For high-risk systems (as defined by EU AI Act), the circuit breaker requires
two different authorized users to deactivate:

	1. First user calls Deactivate() -> state changes to PendingDeactivation
	2. Second user (different from first) calls Deactivate() -> state changes to Closed

This ensures that emergency stops cannot be accidentally or maliciously
reversed by a single person.

# Configuration

The circuit breaker behavior can be configured per organization through
the organization's risk classification:

  - High-risk systems: Two-person deactivation required
  - Standard systems: Single-person deactivation allowed

# EU AI Act Compliance

This package helps organizations comply with Article 14(4)(e) requirements:

	"High-risk AI systems shall be designed and developed in such a way,
	including with appropriate human-machine interface tools, that they
	can be effectively overseen by natural persons during the period in
	which the AI system is in use, including through the use of a stop
	button or a similar procedure..."

Key compliance features:

  - Immediate halt of all AI operations
  - Two-person control for high-risk systems
  - Full audit trail of activation/deactivation
  - Reason documentation for regulatory reporting

See the EU AI Act compliance documentation for more details.
*/
//go:build enterprise

package circuitbreaker
