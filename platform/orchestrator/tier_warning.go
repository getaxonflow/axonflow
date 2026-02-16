// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"fmt"
	"net/http"

	"axonflow/platform/agent/license"
)

const (
	// HeaderTierWarning signals the client that a resource is approaching its tier limit.
	// Example: "concurrent_executions: 4/5 (80%)"
	HeaderTierWarning = "X-AxonFlow-Tier-Warning"
	// HeaderTierUpgradeURL provides the URL to upgrade the tier.
	HeaderTierUpgradeURL = "X-AxonFlow-Tier-Upgrade-URL"
)

const warningThreshold = 0.8 // 80%

// addTierWarningIfNeeded checks if usage is at or above 80% of the tier limit.
// If so, it adds X-AxonFlow-Tier-Warning and X-AxonFlow-Tier-Upgrade-URL headers.
// A limit of -1 means unlimited (no warning needed).
func addTierWarningIfNeeded(w http.ResponseWriter, resource string, current, limit int) {
	if limit <= 0 { // unlimited or not configured
		return
	}

	percentage := float64(current) / float64(limit)
	if percentage < warningThreshold {
		return
	}

	pctInt := int(percentage * 100)
	w.Header().Set(HeaderTierWarning, fmt.Sprintf("%s: %d/%d (%d%%)", resource, current, limit, pctInt))

	upgradeURL := "https://getaxonflow.com/evaluation-license"
	if tierChecker != nil && license.IsEvaluationOrHigher(tierChecker.Tier()) {
		upgradeURL = "https://getaxonflow.com/enterprise"
	}
	w.Header().Set(HeaderTierUpgradeURL, upgradeURL)
}
