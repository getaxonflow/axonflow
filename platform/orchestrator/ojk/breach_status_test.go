//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"errors"
	"testing"
	"time"
)

func TestAllBreachStatuses_MatchesMigrationCheckSet(t *testing.T) {
	got := AllBreachStatuses()
	want := []BreachStatus{
		BreachStatusDraft,
		BreachStatusSubmitted,
		BreachStatusAcknowledged,
		BreachStatusOverdue,
		BreachStatusFailed,
	}
	if len(got) != len(want) {
		t.Fatalf("AllBreachStatuses len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllBreachStatuses[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestIsValidBreachStatus(t *testing.T) {
	for _, s := range AllBreachStatuses() {
		if !IsValidBreachStatus(s) {
			t.Errorf("IsValidBreachStatus(%q) = false, want true", s)
		}
	}
	for _, bad := range []BreachStatus{"", "pending", "SUBMITTED", "done"} {
		if IsValidBreachStatus(bad) {
			t.Errorf("IsValidBreachStatus(%q) = true, want false", bad)
		}
	}
}

func TestIsTerminalBreachStatus(t *testing.T) {
	terminal := map[BreachStatus]bool{
		BreachStatusAcknowledged: true,
		BreachStatusFailed:       true,
		BreachStatusDraft:        false,
		BreachStatusSubmitted:    false,
		BreachStatusOverdue:      false,
	}
	for s, want := range terminal {
		if got := IsTerminalBreachStatus(s); got != want {
			t.Errorf("IsTerminalBreachStatus(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestApplyBreachTransition_Valid(t *testing.T) {
	cases := []struct {
		from  BreachStatus
		event BreachEvent
		want  BreachStatus
	}{
		{BreachStatusDraft, BreachEventSubmit, BreachStatusSubmitted},
		{BreachStatusDraft, BreachEventFail, BreachStatusFailed},
		{BreachStatusSubmitted, BreachEventAcknowledge, BreachStatusAcknowledged},
		{BreachStatusSubmitted, BreachEventFail, BreachStatusFailed},
		{BreachStatusOverdue, BreachEventSubmit, BreachStatusSubmitted},
		{BreachStatusOverdue, BreachEventFail, BreachStatusFailed},
	}
	for _, c := range cases {
		got, err := ApplyBreachTransition(c.from, c.event)
		if err != nil {
			t.Errorf("ApplyBreachTransition(%q,%q) unexpected err: %v", c.from, c.event, err)
			continue
		}
		if got != c.want {
			t.Errorf("ApplyBreachTransition(%q,%q) = %q, want %q", c.from, c.event, got, c.want)
		}
	}
}

func TestApplyBreachTransition_Invalid(t *testing.T) {
	cases := []struct {
		from  BreachStatus
		event BreachEvent
	}{
		{BreachStatusDraft, BreachEventAcknowledge},   // cannot acknowledge a never-submitted breach
		{BreachStatusOverdue, BreachEventAcknowledge}, // overdue must be submitted before acknowledge
		{BreachStatusAcknowledged, BreachEventSubmit}, // terminal
		{BreachStatusAcknowledged, BreachEventFail},   // terminal
		{BreachStatusFailed, BreachEventSubmit},       // terminal
		{BreachStatusFailed, BreachEventAcknowledge},  // terminal
		{BreachStatusSubmitted, BreachEventSubmit},    // no self-resubmit
		{BreachStatus("bogus"), BreachEventSubmit},    // unknown source
	}
	for _, c := range cases {
		got, err := ApplyBreachTransition(c.from, c.event)
		if err == nil {
			t.Errorf("ApplyBreachTransition(%q,%q) = %q, want error", c.from, c.event, got)
			continue
		}
		if !errors.Is(err, ErrInvalidBreachTransition) {
			t.Errorf("ApplyBreachTransition(%q,%q) err = %v, want ErrInvalidBreachTransition", c.from, c.event, err)
		}
		if got != c.from {
			t.Errorf("ApplyBreachTransition(%q,%q) returned %q on error, want unchanged source", c.from, c.event, got)
		}
	}
}

// TestEvaluateBreachStatus_OverdueRequiresLapsedDeadline exercises BOTH the
// overdue precondition (deadline passed, never submitted → overdue) AND its
// absence (deadline NOT passed → still draft). The second case is what stops a
// naive "not acknowledged ⇒ overdue" implementation from passing.
func TestEvaluateBreachStatus_OverdueRequiresLapsedDeadline(t *testing.T) {
	discovery := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	deadline := discovery.Add(72 * time.Hour) // 2026-06-04 00:00 UTC

	// Still inside the 72h window, never submitted → draft (NOT overdue).
	within := deadline.Add(-1 * time.Hour)
	if got := EvaluateBreachStatus(BreachStatusDraft, deadline, nil, within); got != BreachStatusDraft {
		t.Errorf("draft within window: got %q, want draft (overdue must NOT fire before the deadline)", got)
	}

	// Past the window, never submitted → overdue.
	past := deadline.Add(1 * time.Hour)
	if got := EvaluateBreachStatus(BreachStatusDraft, deadline, nil, past); got != BreachStatusOverdue {
		t.Errorf("draft past window: got %q, want overdue", got)
	}

	// A stored overdue row stays overdue past the deadline.
	if got := EvaluateBreachStatus(BreachStatusOverdue, deadline, nil, past); got != BreachStatusOverdue {
		t.Errorf("overdue past window: got %q, want overdue", got)
	}
}

// TestEvaluateBreachStatus_TimelySubmissionNotOverdue proves a breach submitted
// ON TIME is never flagged overdue, even long after the deadline — the
// precondition-absent counterpart to the overdue path.
func TestEvaluateBreachStatus_TimelySubmissionNotOverdue(t *testing.T) {
	discovery := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	deadline := discovery.Add(72 * time.Hour)

	submittedOnTime := deadline.Add(-2 * time.Hour) // within the window
	wayLater := deadline.Add(240 * time.Hour)       // 10 days past deadline

	if got := EvaluateBreachStatus(BreachStatusSubmitted, deadline, &submittedOnTime, wayLater); got != BreachStatusSubmitted {
		t.Errorf("timely submission long after deadline: got %q, want submitted", got)
	}
}

func TestEvaluateBreachStatus_LateSubmissionIsOverdue(t *testing.T) {
	discovery := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	deadline := discovery.Add(72 * time.Hour)

	submittedLate := deadline.Add(5 * time.Hour) // after the window
	now := submittedLate.Add(1 * time.Hour)

	if got := EvaluateBreachStatus(BreachStatusSubmitted, deadline, &submittedLate, now); got != BreachStatusOverdue {
		t.Errorf("late submission: got %q, want overdue", got)
	}
}

func TestEvaluateBreachStatus_SubmittedExactlyAtDeadlineIsTimely(t *testing.T) {
	deadline := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	atDeadline := deadline // boundary: <= deadline is timely
	now := deadline.Add(time.Hour)
	if got := EvaluateBreachStatus(BreachStatusSubmitted, deadline, &atDeadline, now); got != BreachStatusSubmitted {
		t.Errorf("submission exactly at deadline: got %q, want submitted (boundary inclusive)", got)
	}
}

func TestEvaluateBreachStatus_TerminalNeverEscalated(t *testing.T) {
	deadline := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	past := deadline.Add(100 * time.Hour)

	// Acknowledged is terminal success — never overdue, even with no submitted_at recorded.
	if got := EvaluateBreachStatus(BreachStatusAcknowledged, deadline, nil, past); got != BreachStatusAcknowledged {
		t.Errorf("acknowledged past deadline: got %q, want acknowledged", got)
	}
	// Failed is terminal — never overdue.
	if got := EvaluateBreachStatus(BreachStatusFailed, deadline, nil, past); got != BreachStatusFailed {
		t.Errorf("failed past deadline: got %q, want failed", got)
	}
}

func TestIsBreachWithinDeadline(t *testing.T) {
	cases := map[BreachStatus]bool{
		BreachStatusDraft:        true,  // still inside its window
		BreachStatusSubmitted:    true,  // timely
		BreachStatusAcknowledged: true,  // received
		BreachStatusOverdue:      false, // missed the window
		BreachStatusFailed:       false, // not transmitted
	}
	for s, want := range cases {
		if got := IsBreachWithinDeadline(s); got != want {
			t.Errorf("IsBreachWithinDeadline(%q) = %v, want %v", s, got, want)
		}
	}
}
