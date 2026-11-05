//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package usage

import (
	"context"
	"errors"
	"time"
)

func (r *UsageRecorder) RecordCapabilityEvent(ctx context.Context, event CapabilityEvent) (bool, error) {
	return false, errors.New("capability usage requires Enterprise storage")
}

func (r *UsageRecorder) ReadCapabilityUsage(ctx context.Context, orgID, tenantID, capability string) (CapabilityUsageSummary, error) {
	return CapabilityUsageSummary{BusinessOutcome: "not_measured"}, errors.New("capability usage requires Enterprise storage")
}

func (r *UsageRecorder) ReadCapabilityUsageWindow(ctx context.Context, orgID, tenantID, capability string, start, end time.Time) (CapabilityUsageSummary, error) {
	return CapabilityUsageSummary{BusinessOutcome: "not_measured"}, errors.New("capability usage requires Enterprise storage")
}
