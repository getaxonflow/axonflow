//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #2820: the Cowork / Claude Code OTEL storage redactor is enterprise-only
// (coworkRedactDefault lives behind //go:build enterprise), so its fail-closed
// test carries the same tag. Shared helper installLoadErroringEngine lives in
// the edition-agnostic response_failclosed_test.go.

import (
	"context"
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

func TestCoworkRedact_FailsClosedOnLoadError(t *testing.T) {
	installLoadErroringEngine(t)
	res := coworkRedactDefault(context.Background(), "unseeded-tenant", "u1", "claude_code", "reach me at andi@example.com")
	if res.verdict != sharedaudit.DecisionError {
		t.Errorf("load error must fail closed with verdict=error, got %q", res.verdict)
	}
	if res.text != "[redaction-unavailable: content withheld]" {
		t.Errorf("content must be withheld, got %q", res.text)
	}
}
