//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"errors"
	"fmt"
	"time"
)

// BreachStatus is the lifecycle state of a UU PDP Art. 46 breach notification.
//
// The 72-hour (3x24h) notification window runs from discovery_time. The status
// is the single evidence artifact that distinguishes a breach reported to OJK /
// MOCDA in time from one that is overdue, failed, or never transmitted — so it
// is never a hard-coded literal. Every persisted value is the output of either
// a gated transition (ApplyBreachTransition) or the deadline evaluator
// (EvaluateBreachStatus / EvaluateBreachDeadlines).
type BreachStatus string

const (
	// BreachStatusDraft is the initial state (migration 130 DDL default): the
	// breach is recorded internally but not yet transmitted to the supervisory
	// authority. submitted_at / acknowledged_at are NULL.
	BreachStatusDraft BreachStatus = "draft"
	// BreachStatusSubmitted means the notification was transmitted to the
	// authority. submitted_at is set. A submission is timely iff
	// submitted_at <= notification_deadline.
	BreachStatusSubmitted BreachStatus = "submitted"
	// BreachStatusAcknowledged means the authority confirmed receipt.
	// acknowledged_at is set. Terminal success.
	BreachStatusAcknowledged BreachStatus = "acknowledged"
	// BreachStatusOverdue means the 72h window lapsed without a timely
	// submission — either never transmitted (a draft that lapsed) or transmitted
	// after the deadline. Compliance failure surfaced to auditors.
	BreachStatusOverdue BreachStatus = "overdue"
	// BreachStatusFailed means a transmission attempt failed. Terminal.
	BreachStatusFailed BreachStatus = "failed"
)

// BreachEvent is an operator/system-driven lifecycle transition trigger.
// Note: overdue is reachable ONLY via the deadline evaluator, never via an
// event, so it is not a transition target below.
type BreachEvent string

const (
	BreachEventSubmit      BreachEvent = "submit"
	BreachEventAcknowledge BreachEvent = "acknowledge"
	BreachEventFail        BreachEvent = "fail"
)

// ErrInvalidBreachTransition is returned by ApplyBreachTransition when an event
// is not permitted from the current status. Callers map it to a client error
// (HTTP 409), not a 500.
var ErrInvalidBreachTransition = errors.New("invalid breach status transition")

// AllBreachStatuses is the closed set persisted by migration 131's CHECK
// constraint. Order is stable for deterministic iteration in tests/validators.
func AllBreachStatuses() []BreachStatus {
	return []BreachStatus{
		BreachStatusDraft,
		BreachStatusSubmitted,
		BreachStatusAcknowledged,
		BreachStatusOverdue,
		BreachStatusFailed,
	}
}

// IsValidBreachStatus reports whether s is one of the persisted lifecycle states.
func IsValidBreachStatus(s BreachStatus) bool {
	for _, v := range AllBreachStatuses() {
		if s == v {
			return true
		}
	}
	return false
}

// IsTerminalBreachStatus reports whether s is a terminal state the deadline
// evaluator must never escalate to overdue: acknowledged (authority received it)
// and failed (transmission abandoned).
func IsTerminalBreachStatus(s BreachStatus) bool {
	return s == BreachStatusAcknowledged || s == BreachStatusFailed
}

// breachTransitions is the gated transition table. A transition is permitted iff
// the target appears in the source status's allow-list. acknowledged and failed
// are terminal (absent as keys). overdue allows a late submission/failure but
// NOT a direct acknowledge — an authority can only acknowledge a submission, so
// a never-submitted overdue breach must be submitted first.
var breachTransitions = map[BreachStatus]map[BreachEvent]BreachStatus{
	BreachStatusDraft: {
		BreachEventSubmit: BreachStatusSubmitted,
		BreachEventFail:   BreachStatusFailed,
	},
	BreachStatusSubmitted: {
		BreachEventAcknowledge: BreachStatusAcknowledged,
		BreachEventFail:        BreachStatusFailed,
	},
	BreachStatusOverdue: {
		BreachEventSubmit: BreachStatusSubmitted, // late submission still recorded
		BreachEventFail:   BreachStatusFailed,
	},
}

// ApplyBreachTransition returns the status reached by applying event to from,
// or ErrInvalidBreachTransition (wrapped) if the transition is not permitted.
// It is pure: it never reads the clock and never fabricates a submission.
func ApplyBreachTransition(from BreachStatus, event BreachEvent) (BreachStatus, error) {
	targets, ok := breachTransitions[from]
	if !ok {
		return from, fmt.Errorf("%w: %q is terminal (event %q)", ErrInvalidBreachTransition, from, event)
	}
	to, ok := targets[event]
	if !ok {
		return from, fmt.Errorf("%w: %q under event %q", ErrInvalidBreachTransition, from, event)
	}
	return to, nil
}

// EvaluateBreachStatus returns the EFFECTIVE status of a breach notification at
// time now, given its stored lifecycle status, its 72h deadline, and when (if
// ever) it was submitted. It is the deadline evaluator the readers apply so a
// breach that has silently crossed its window reads as "overdue" without
// requiring a background sweep to have run first.
//
// Rules (in order):
//   - acknowledged / failed are terminal → returned unchanged (never escalated).
//   - a submission on or before the deadline is timely → "submitted".
//   - otherwise, once now is past the deadline → "overdue" (never transmitted,
//     or transmitted late).
//   - otherwise (still inside the window, not yet submitted) → the stored status.
//
// It is pure and total — no DB, no side effects.
func EvaluateBreachStatus(stored BreachStatus, deadline time.Time, submittedAt *time.Time, now time.Time) BreachStatus {
	if IsTerminalBreachStatus(stored) {
		return stored
	}
	if submittedAt != nil && !submittedAt.After(deadline) {
		return BreachStatusSubmitted
	}
	if now.After(deadline) {
		return BreachStatusOverdue
	}
	return stored
}

// IsBreachWithinDeadline reports the UU PDP Art. 46 timeliness verdict for an
// effective status: true while the obligation is still met (timely submission,
// acknowledged, or a draft still inside its window); false once the breach is
// overdue or failed.
func IsBreachWithinDeadline(effective BreachStatus) bool {
	return effective != BreachStatusOverdue && effective != BreachStatusFailed
}
