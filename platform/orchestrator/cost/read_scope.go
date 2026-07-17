// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import "context"

// Role-scoped read authorization for the cost/usage domain (#2934, epic #2919).
//
// The cost read surfaces (usage summary/breakdown/records, budget listings,
// budget status/alerts) expose tenant-wide spend, so they are gated on
// tenant-wide read authority by the orchestrator's enforceDomainReadAuthority
// middleware — this package never resolves trust itself. usage_records.user_id
// is not stamped with a per-user identity by any production write path, so
// there is no meaningful "own rows" form for a non-admin caller: the posture
// is deny (403), mirroring tenantWideAuditExportPaths.
//
// POST /api/v1/budgets/check is the one deliberate exception: it is the
// budget-enforcement decision plane (SDK CheckBudget gates LLM spend on it),
// so denying non-admin service callers would break cost governance itself.
// It stays reachable for any authenticated tenant caller, but the middleware
// marks non-tenant-wide requests via WithSpendRedaction and the handler strips
// the absolute spend figures from the decision — the caller learns
// allowed/blocked (what enforcement needs) without the tenant's spend numbers
// (what #2934 closes).

type spendRedactionCtxKey struct{}

// WithSpendRedaction marks the request context so the budget-check handler
// redacts absolute spend figures from its decision. Set by the orchestrator
// read-authority middleware for callers without tenant-wide read scope.
func WithSpendRedaction(ctx context.Context) context.Context {
	return context.WithValue(ctx, spendRedactionCtxKey{}, true)
}

// SpendRedactionRequested reports whether the middleware asked for spend
// redaction on this request.
func SpendRedactionRequested(ctx context.Context) bool {
	v, _ := ctx.Value(spendRedactionCtxKey{}).(bool)
	return v
}

// redactSpend strips the absolute spend figures AND the budget-identity
// metadata from a budget decision while preserving the only thing enforcement
// needs (allowed + action). Budget id/name are removed too so a redacted
// caller cannot use the decision as an oracle for another scope's budget
// existence/name (#2934, R3). The message is reduced to a generic string.
func (d *BudgetDecision) redactSpend() {
	d.UsedUSD = 0
	d.LimitUSD = 0
	d.Percentage = 0
	d.BudgetID = ""
	d.BudgetName = ""
	if d.Message != "" {
		if d.Allowed {
			d.Message = ""
		} else {
			d.Message = "Budget exceeded"
		}
	}
}
