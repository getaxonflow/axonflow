// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"strings"

	"github.com/lib/pq"
)

// isMissingColumnError reports whether err is a Postgres "column does not
// exist" error (SQLSTATE 42703) naming column — the shape refreshPolicies
// (db_dynamic_policies.go) and loadPoliciesFromDB (dynamic_policy_engine.go)
// see when they boot against a not-yet-migrated dynamic_policies table.
//
// H3 (#3239 round 2, upgrade-ordering): standard Docker Compose is
// reachable, not just k8s — /health is liveness-only
// (readinessAwareHealthHandler returns 200 + status:"starting" BEFORE
// migrations finish), so a `depends_on: agent service_healthy` gate does not
// actually wait for migrations. The orchestrator can boot and start serving
// requests mid-migration, before migration 159 has added
// dynamic_policies.segment_id. Both loaders' unconditional SELECT of that
// column would otherwise fail outright, which (via loadDefaultPolicies /
// the error-return path) can degrade enforcement instead of merely staying
// segment-unaware. Catching 42703 here and retrying with a segment-less
// SELECT keeps enforcement live (correct pre-159: no segment rows can exist
// yet) instead of tripping the fallback. Mirrors the pq.Error 42703 check in
// platform/connectors/config/runtime_config.go (backward-compat retry for a
// missing connector_configs.credentials column).
//
// This is the interim in-code backstop only — the proper root-cause fix
// (honest readiness: IsHealthy() reporting false while degraded, plus a
// genuine 503-until-ready signal separate from the liveness /health check)
// is deferred to #3285.
func isMissingColumnError(err error, column string) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	return pqErr.Code == "42703" && strings.Contains(pqErr.Message, column)
}
