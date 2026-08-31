//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "database/sql"

// NewDBOrgIdentitySettingsStore is Enterprise-only. Community builds have no
// organization-management surface, so there is no record to read: the
// process-wide mode is the whole answer there, which is exactly #3582's
// behaviour. Callers skip on ErrEnterpriseOnly, as they do for
// NewOIDCRealmSource.
func NewDBOrgIdentitySettingsStore(_ *sql.DB) (OrgIdentitySettingsSource, error) {
	return nil, ErrEnterpriseOnly
}
