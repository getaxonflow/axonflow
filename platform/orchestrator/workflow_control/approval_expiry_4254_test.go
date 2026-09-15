// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// A TIMED-OUT APPROVAL IS A DENY ON THE APPROVE PATH TOO (#4254, ADR-065).
//
// The step's queue row records when its approval stops being grantable. An
// approval after that is refused before anything is written; a row the queue
// already expired is refused whatever its timestamp says; an expiry that cannot
// be read refuses rather than approving blind; and a step with no row declares
// no expiry, so it is approved as it always was.

// expiryMirror is a mirror resolver whose queue row is described by its fields.
type expiryMirror struct {
	recordingMirrorResolver
	expiresAt time.Time
	expired   bool
	found     bool
	err       error
}

func (m *expiryMirror) StepMirrorExpiry(context.Context, string, string, string, string) (time.Time, bool, bool, error) {
	return m.expiresAt, m.expired, m.found, m.err
}

// approvalOutcome is one approval of a held step, and what it left behind.
type approvalOutcome struct {
	repo    *MockRepository
	wfID    string
	err     error
	capture *captureAuditLogger
	mirror  *expiryMirror
}

// approveUnder approves step-1 of a fresh held workflow with mirror wired.
func approveUnder(t *testing.T, mirror *expiryMirror) approvalOutcome {
	t.Helper()
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	svc.SetHITLMirrorResolver(mirror)
	capture := &captureAuditLogger{}
	svc.SetAuditLogger(capture)
	wfID := approvableWorkflow(t, svc)
	err := svc.ApproveStep(context.Background(), wfID, "step-1", "tenant-1", "org-1", "approver@example.com", "reviewed and approved")
	return approvalOutcome{repo: repo, wfID: wfID, err: err, capture: capture, mirror: mirror}
}

// stillHeld asserts a refused approval left the step pending, resolved no
// mirror and wrote no approval row.
func stillHeld(t *testing.T, o approvalOutcome) {
	t.Helper()
	step, err := o.repo.GetStep(context.Background(), o.wfID, "step-1")
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if step.ApprovalStatus == nil || *step.ApprovalStatus != ApprovalStatusPending {
		t.Errorf("approval status = %v after a refused approval, want pending", step.ApprovalStatus)
	}
	if len(o.mirror.calls) != 0 {
		t.Errorf("a refused approval resolved the mirror %d times", len(o.mirror.calls))
	}
	for _, e := range o.capture.entries {
		if e.Operation == "step_approved" {
			t.Error("a refused approval wrote a step_approved audit row")
		}
	}
}

// approvedOnce asserts the approval landed and resolved the mirror once.
func approvedOnce(t *testing.T, o approvalOutcome) {
	t.Helper()
	step, err := o.repo.GetStep(context.Background(), o.wfID, "step-1")
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if step.ApprovalStatus == nil || *step.ApprovalStatus != ApprovalStatusApproved {
		t.Errorf("approval status = %v, want approved", step.ApprovalStatus)
	}
	if len(o.mirror.calls) != 1 {
		t.Errorf("the mirror was resolved %d times, want once", len(o.mirror.calls))
	}
}

func TestAnApprovalAfterTheQueueRowsExpiryIsRefused(t *testing.T) {
	expiresAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	o := approveUnder(t, &expiryMirror{expiresAt: expiresAt, found: true})
	if !errors.Is(o.err, ErrApprovalExpired) {
		t.Fatalf("an approval after the expiry = %v, want ErrApprovalExpired", o.err)
	}
	if want := expiresAt.UTC().Format(time.RFC3339); !strings.Contains(o.err.Error(), want) {
		t.Errorf("the refusal %q does not name the expiry %s", o.err, want)
	}
	stillHeld(t, o)
}

func TestAnApprovalTheQueueAlreadyExpiredIsRefused(t *testing.T) {
	o := approveUnder(t, &expiryMirror{expiresAt: time.Now().Add(time.Hour), expired: true, found: true})
	if !errors.Is(o.err, ErrApprovalExpired) {
		t.Fatalf("an approval of a row the queue expired = %v, want ErrApprovalExpired", o.err)
	}
	stillHeld(t, o)
}

func TestAnApprovalWhoseExpiryCannotBeReadIsRefused(t *testing.T) {
	o := approveUnder(t, &expiryMirror{err: errors.New(`pq: relation "hitl_approval_queue" does not exist`)})
	if !errors.Is(o.err, ErrApprovalStateUnreadable) {
		t.Fatalf("an approval whose expiry cannot be read = %v, want ErrApprovalStateUnreadable", o.err)
	}
	if strings.Contains(o.err.Error(), "hitl_approval_queue") || strings.Contains(o.err.Error(), "pq:") {
		t.Errorf("the refusal %q carries the read's driver detail", o.err)
	}
	stillHeld(t, o)
}

func TestAnApprovalBeforeTheQueueRowsExpiryIsApproved(t *testing.T) {
	o := approveUnder(t, &expiryMirror{expiresAt: time.Now().Add(time.Hour), found: true})
	if o.err != nil {
		t.Fatalf("an approval before the expiry: %v", o.err)
	}
	approvedOnce(t, o)
}

// No row declares no expiry: no adapter was wired when the gate fired, or the
// enqueue was refused (tier_disabled, cap_reached).
func TestAnApprovalWithNoQueueRowIsApproved(t *testing.T) {
	o := approveUnder(t, &expiryMirror{})
	if o.err != nil {
		t.Fatalf("an approval with no queue row: %v", o.err)
	}
	approvedOnce(t, o)
}

func TestTheApproveRouteNamesAnExpiredOrUnreadableApproval(t *testing.T) {
	cases := []struct {
		name   string
		mirror *expiryMirror
		status int
		code   string
	}{
		{"expired", &expiryMirror{expiresAt: time.Now().Add(-time.Minute), found: true}, http.StatusConflict, "APPROVAL_EXPIRED"},
		{"unreadable", &expiryMirror{err: errors.New("read failed")}, http.StatusServiceUnavailable, "APPROVAL_STATE_UNREADABLE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := NewMockRepository()
			svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
			svc.SetHITLMirrorResolver(c.mirror)
			wfID := approvableWorkflow(t, svc)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+wfID+"/steps/step-1/approve",
				strings.NewReader(`{"comment": "Reviewed and approved for production"}`))
			req.Header.Set("X-Org-ID", "org-1")
			req.Header.Set("X-Tenant-ID", "tenant-1")
			req.Header.Set("X-User-ID", "approver@example.com")
			req = mux.SetURLVars(req, map[string]string{"id": wfID, "step_id": "step-1"})
			rr := httptest.NewRecorder()
			NewHandler(svc).ApproveStep(rr, req)

			if rr.Code != c.status || !strings.Contains(rr.Body.String(), c.code) {
				t.Errorf("status = %d, body = %s; want %d naming %s", rr.Code, rr.Body.String(), c.status, c.code)
			}
		})
	}
}
