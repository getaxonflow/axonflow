// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// heldAs rewrites a refused call's reason to code, keeping it refused. The
// policy-bundle drift guard uses this in both editions, while the approval
// queue itself remains Enterprise-only.
func heldAs(enforced requestPassEnforcement, code, detail string) requestPassEnforcement {
	enforced.verdict = VerdictDeny
	enforced.reasonCode = code
	enforced.reasons = []string{code + ": " + detail}
	return enforced
}
