//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "database/sql"

// startPluginLicenseMetricsPoller in community builds is a no-op. The
// plugin_user_licenses table only exists on enterprise / community-saas
// builds (migration 077 — feature-flagged behind the `enterprise` build
// tag). Polling it on a community build would always 42P01 the table.
//
// The Prometheus gauges are NOT registered on community builds, by design:
// metrics that are always zero create false-positive "MRR is 0" alerts on
// self-hosted community deployments. If a self-hosted enterprise install
// disables the paid Pro tier, the gauges still register but the poller
// returns table_missing failures (caught by the absent() alert rule).
func startPluginLicenseMetricsPoller(_ *sql.DB) (cancel func()) {
	return func() {}
}
