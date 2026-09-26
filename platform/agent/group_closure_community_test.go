//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// Directory ingestion is Enterprise: the community build's group-closure
// resolver is the one that states no directory's groups.
func TestTheCommunityGroupClosureIsNoGraphOnly(t *testing.T) {
	if _, ok := groupClosureResolver().(sharedidentity.NoGraphOnlyResolver); !ok {
		t.Fatalf("the community group-closure resolver is %T; want sharedidentity.NoGraphOnlyResolver", groupClosureResolver())
	}
}
