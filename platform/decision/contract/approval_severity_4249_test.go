// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

// #4249 row 5667311128: a typed approval states the severity its queue row
// carries, as a parameter of its mandatory approval_challenge obligations.

import (
	"strings"
	"testing"
	"time"
)

func severityApproval(src string, mandatory bool, severity string) Obligation {
	params := map[string]string{"quorum": "1", "eligible": "Group::r:" + src}
	if severity != "" {
		params[ParamApprovalSeverity] = severity
	}
	return gob(ObApprovalChallenge, "", mandatory, src, params)
}

// The param survives composition, and the highest severity among the MANDATORY
// approvals is the one a hold carries; an advisory approval's is ignored.
func TestAnApprovalsSeveritySurvivesCompositionAndTheHighestMandatoryWins(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  []Obligation
		want string
	}{
		{"none stated", []Obligation{severityApproval("a", true, "")}, ""},
		{"one stated", []Obligation{severityApproval("a", true, "critical")}, "critical"},
		{"the highest mandatory wins", []Obligation{severityApproval("a", true, "low"), severityApproval("b", true, "high")}, "high"},
		{"an advisory severity is ignored", []Obligation{severityApproval("a", true, "low"), severityApproval("b", false, "critical")}, "low"},
		{"an advisory severity alone is ignored", []Obligation{severityApproval("a", true, ""), severityApproval("b", false, "critical")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := ComposeObligations(ComposeInput{Obligations: tc.obs, PEP: goldenPEP(), ApprovalExpiry: goldenNow.Add(time.Hour), Now: goldenNow})
			if out.Denied {
				t.Fatalf("composition denied: %s %s", out.Reason, out.Detail)
			}
			if out.Approval == nil {
				t.Fatalf("no approval composed")
			}
			if got := ApprovalSeverity(out.Obligations); got != tc.want {
				t.Errorf("ApprovalSeverity(composed) = %q, want %q", got, tc.want)
			}
		})
	}
}

// A spelling outside the queue's four is refused on the approval family.
func TestAnApprovalSeverityOutsideTheQueuesFourIsRefused(t *testing.T) {
	for _, bad := range []string{"CRITICAL", "urgent", "", " high"} {
		o := severityApproval("a", true, "x")
		o.Params[ParamApprovalSeverity] = bad
		if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "the declared severities are low, medium, high and critical") {
			t.Errorf("severity %q: Validate = %v, want refused naming the declared severities", bad, err)
		}
	}
	for _, good := range []string{"low", "medium", "high", "critical"} {
		if err := severityApproval("a", true, good).Validate(); err != nil {
			t.Errorf("severity %q refused: %v", good, err)
		}
	}
}
