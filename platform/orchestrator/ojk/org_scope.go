//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"net/http"
	"strings"
)

// Header names. Both are Set (not Add) by the agent's proxyAuthMiddleware from
// the cryptographically validated client credential on every proxied route, and
// /api/v1/ojk IS in that proxied prefix list (platform/agent/proxy.go:717) -- so
// on the real plane both are server-derived and a client-supplied value is
// overwritten before the request reaches the orchestrator.
const (
	orgIDHeader    = "X-Org-ID"
	tenantIDHeader = "X-Tenant-ID"
)

// resolveOrgID returns the ORGANISATION this OJK request is scoped to, or ""
// when there is none. Callers MUST treat "" as a refusal and must never pass it
// downstream.
//
// # Why the organisation, and why this changed
//
// Every durable surface this module owns is keyed on the ORGANISATION: the
// ojk_* tables declare `org_id`, their RLS policies read
// `current_setting('app.current_org_id')`, and withOrgScope sets exactly that.
// The handler's previous resolver (getTenantID) returned X-Tenant-ID FIRST and
// fed it into all of them. On the proxied path -- where both headers are
// present and, under a v9 enterprise license, hold DIFFERENT values (#3071,
// platform/shared/tenantscope.go) -- that wrote a TENANT identifier into an
// ORG-labelled column and scoped every read by it.
//
// That is the scope-helper-does-not-match-its-writer class, and it is why the
// new audit_logs reads could not simply keep the old resolver: audit_logs.org_id
// carries the real organisation (writeDecisionAuditRow / the orchestrator
// AuditLogger both stamp req.Client.OrgID), so an org-column predicate fed a
// tenant value returns ZERO rows -- reproducing the silent-empty export this
// workstream exists to remove.
//
// # Precedence, and why it is not a choice the caller makes
//
//  1. X-Org-ID, trimmed. Proxy-Set from the validated credential.
//  2. X-Tenant-ID, trimmed -- ONLY when X-Org-ID is absent. This fallback is
//     unreachable on the proxied path (the proxy always Sets both). It exists
//     for direct-to-orchestrator callers in single-identifier deployments,
//     where the two values are the same, and for the in-tree harnesses that
//     send only X-Tenant-ID. It never lets a caller ENLARGE its scope: when
//     X-Org-ID is present it wins outright, and both headers are proxy-Set.
//
// # Deployments upgrading from the previous behaviour
//
// A deployment that (a) is proxied, (b) has DISTINCT org and tenant values, and
// (c) already wrote ojk_breach_notifications rows will find those rows scoped
// under the tenant value and therefore invisible to the org-scoped read. There
// is no reliable automated mapping -- the stored row records the same value in
// both columns, so the platform cannot tell a mis-keyed row from an intentional
// single-identifier one. The operator-run repair is in
// docs/compliance/ojk-org-scope-upgrade.md.
//
// The audit_logs-backed sections are NOT affected: they carry the real
// organisation, and ojkOrgPredicate additionally reaches rows with no
// organisation attribution by their tenant.
//
// # Trimming
//
// The result is TRIMMED so a whitespace-only header cannot pass a caller's
// `orgID == ""` check and reach the database as a blank scope. A blank org
// predicate aliases every row whose org was written blank, and on an INSERT it
// plants a row nothing can subsequently scope -- the recurring defect
// core/155 and core/156 exist to prevent.
func resolveOrgID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if org := strings.TrimSpace(r.Header.Get(orgIDHeader)); org != "" {
		return org
	}
	return strings.TrimSpace(r.Header.Get(tenantIDHeader))
}
