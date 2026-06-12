//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"testing"
)

func TestAcknowledgeBreachNotification_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	if _, err := svc.AcknowledgeBreachNotification(context.Background(), "t", "some-id"); err == nil {
		t.Error("expected error for nil DB")
	}
}

func TestEvaluateBreachDeadlines_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	if _, err := svc.EvaluateBreachDeadlines(context.Background(), "t"); err == nil {
		t.Error("expected error for nil DB")
	}
}

func TestGetDashboard_NilDBZeroBreachCounts(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")
	svc := &ojkAuditExportServiceImpl{}
	resp, err := svc.GetDashboard(context.Background(), "t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.BreachNotifications != 0 || resp.OverdueBreachNotifications != 0 {
		t.Errorf("nil-db dashboard breach counts = %d/%d, want 0/0",
			resp.BreachNotifications, resp.OverdueBreachNotifications)
	}
}

func TestSplitDataTypes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"   ", []string{}},
		{"nik", []string{"nik"}},
		{"nik,npwp", []string{"nik", "npwp"}},
		{"nik, npwp ,", []string{"nik", "npwp"}},
		{",,", []string{}},
	}
	for _, c := range cases {
		got := splitDataTypes(c.in)
		if got == nil {
			t.Errorf("splitDataTypes(%q) = nil, want non-nil slice", c.in)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("splitDataTypes(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("splitDataTypes(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}
