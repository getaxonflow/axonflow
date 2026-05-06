//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import "errors"

// ParseAndVerifyServiceToken — community-build stub. The SaaS Plugin tier is
// enterprise-only and the plugin-claim signing key is not embedded in
// community binaries. Always returns an error so the caller surfaces a 401
// with explicit reason ("plugin-claim tokens require enterprise build").
//
// Community binaries don't run try.getaxonflow.com (which is the SaaS Plugin
// path's only entry point today), so this stub being reachable indicates a
// misconfiguration upstream. Failing closed is the correct posture.
func ParseAndVerifyServiceToken(licenseKey string) (*ServiceLicensePayload, error) {
	_ = licenseKey
	return nil, errors.New("plugin-claim tokens require the enterprise build")
}
