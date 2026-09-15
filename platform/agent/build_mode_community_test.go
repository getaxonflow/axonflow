//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// isCommunityBuild is true when building without the enterprise tag.
// Used by tests that only apply to community license validation.
const isCommunityBuild = true
