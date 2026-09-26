//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import sharedidentity "axonflow/platform/shared/identity"

// groupClosureResolver is the community resolver: directory ingestion is
// Enterprise, so a realm with no group graph is an authoritative empty closure
// and a realm declaring one is unreachable (sharedidentity.NoGraphOnlyResolver).
func groupClosureResolver() sharedidentity.GroupClosureResolver {
	return sharedidentity.NoGraphOnlyResolver{}
}
