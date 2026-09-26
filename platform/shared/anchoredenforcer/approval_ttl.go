// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// ApprovalTTLEnv names the deployment's approval window: how long a composed
// approval stays grantable when no policy that raised it carries its own
// expiry_seconds (#4249 row 5774029945). It is read once, here, by every
// process that builds an anchored enforcer, so the agent and the orchestrator
// cannot stamp different windows.
const ApprovalTTLEnv = "AXONFLOW_APPROVAL_TTL_SECONDS"

// DefaultApprovalTTL is the window when ApprovalTTLEnv is unset or empty: the
// engine's own default, re-exported rather than restated, so a deployment that
// sets nothing stamps exactly what it did before the variable existed.
const DefaultApprovalTTL = pdp.DefaultApprovalTTL

// ApprovalTTLFrom reads the deployment's approval window through lookup
// (os.LookupEnv in production). A value that is not a whole number of seconds
// within contract.MinApprovalExpirySeconds..MaxApprovalExpirySeconds is
// REFUSED, never clamped: clamping would enforce a window the operator did not
// write, and the enforcer's constructor returning the error is what refuses
// the process's boot.
func ApprovalTTLFrom(lookup func(string) (string, bool)) (time.Duration, error) {
	raw, set := lookup(ApprovalTTLEnv)
	trimmed := strings.TrimSpace(raw)
	if !set || trimmed == "" {
		return DefaultApprovalTTL, nil
	}
	n, err := strconv.Atoi(trimmed)
	if err != nil || strconv.Itoa(n) != trimmed {
		return 0, fmt.Errorf("%s is %q, which is not a whole number of seconds", ApprovalTTLEnv, raw)
	}
	if n < contract.MinApprovalExpirySeconds || n > contract.MaxApprovalExpirySeconds {
		return 0, fmt.Errorf("%s is %d seconds, outside the approval window's bounds %d..%d; it is refused rather than clamped",
			ApprovalTTLEnv, n, contract.MinApprovalExpirySeconds, contract.MaxApprovalExpirySeconds)
	}
	return time.Duration(n) * time.Second, nil
}
