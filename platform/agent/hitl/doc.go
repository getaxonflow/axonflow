// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

/*
Package hitl provides Human-in-the-Loop (HITL) queue management
for EU AI Act Article 14 compliance (Human Oversight).

# Overview

This package implements a decision queue that routes high-risk AI decisions
for human review before execution. Features include:

  - Decision queueing with priority levels
  - Approval and rejection workflows
  - Timeout handling for pending decisions
  - Full audit trail of all human oversight actions

# Usage

Create a queue with a repository:

	repo := hitl.NewInMemoryRepository()
	config := hitl.DefaultConfig()
	queue := hitl.NewQueue(repo, config)

Create a decision for review:

	decision, err := queue.CreateDecision(ctx, hitl.CreateDecisionInput{
		OrgID:        "org-123",
		DecisionType: "loan_approval",
		Content:      map[string]interface{}{"amount": 50000, "applicant": "John Doe"},
		Priority:     hitl.PriorityHigh,
	})

Approve or reject a decision:

	err := queue.ApproveDecision(ctx, decisionID, "reviewer-user-id", "Approved after verification")
	// or
	err := queue.RejectDecision(ctx, decisionID, "reviewer-user-id", "Insufficient documentation")

Get pending decisions:

	decisions, err := queue.GetPendingDecisions(ctx, "org-123", 100)

# Decision Status Flow

	Pending -> Approved
	        -> Rejected
	        -> Expired (if timeout reached)

# Priority Levels

  - PriorityLow: Standard processing
  - PriorityNormal: Default priority
  - PriorityHigh: Expedited review required
  - PriorityCritical: Immediate attention required

# Configuration

	config := hitl.Config{
		DefaultTimeout:  60 * time.Minute,  // Time before decision expires
		MaxPending:      1000,               // Max pending decisions per org
		AlertThreshold:  100,                // Alert when pending count exceeds
	}

# EU AI Act Compliance

This package helps organizations comply with Article 14 requirements:

  - Ability to interrupt AI system operation
  - Human review of high-risk decisions
  - Override capability for automated decisions
  - Audit trail of all human oversight actions

High-risk AI systems must be designed to allow effective human oversight,
including the ability to:

  - Fully understand the relevant capacities and limitations of the system
  - Properly monitor operation and detect anomalies
  - Interpret the system's output
  - Decide not to use the system or override decisions
  - Intervene or interrupt the system through a stop button

See the EU AI Act compliance documentation for more details.
*/
//go:build enterprise

package hitl
