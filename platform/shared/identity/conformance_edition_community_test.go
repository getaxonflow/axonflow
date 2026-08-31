//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// conformanceEnterpriseBuild is false here: the directory graph and the SCIM
// ingestion adapter are not compiled into a community build, so the conformance
// cases that exercise them are not expected to run. See its Enterprise twin.
const conformanceEnterpriseBuild = false
