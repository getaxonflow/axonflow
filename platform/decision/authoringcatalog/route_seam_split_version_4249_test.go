// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringcatalog_test

import (
	"testing"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
)

// THE ROUTE-SEAM SPLIT VERSION IS A DOCUMENTED LITERAL, AND THIS IS THE WELD
// (#4249 row 5706695827).
//
// legacycompile.RouteSeamSplitCatalogVersion names ONE release's vocabulary for
// ever: a document published under a catalog older than it binds the two
// orchestrator request routes wherever it binds `wcp`, because at that version
// `wcp` still meant the step gate AND those routes. BindsOnPinned reads it on
// every activation of every published document.
//
// So it must not be written as a reference to DeploymentCatalogVersion, which
// moves on any content change: the next unrelated bump would silently move
// which documents are read as pre-split, and a control an organization left off
// `wcp` would start binding the routes again (or stop). This test is what the
// constant's own comment cites - it did not exist until this cell was written,
// which is the reason a cited guard is checked and not believed.
func TestTheRouteSeamSplitVersionIsThisCatalogsOrOlder(t *testing.T) {
	// THE LITERAL, restated here so a change to the constant has to be a change
	// to a second file, with this comment in front of it. 7 is the version the
	// split shipped in: DeploymentCatalogVersion 6 was #4259's cowork_ingest,
	// and this lane's split moved it to 7.
	const shipped = 7
	if legacycompile.RouteSeamSplitCatalogVersion != shipped {
		t.Fatalf("RouteSeamSplitCatalogVersion = %d, want the shipped literal %d. It names the release the routes left `wcp` in; moving it re-reads every document published in between",
			legacycompile.RouteSeamSplitCatalogVersion, shipped)
	}
	// A split version AHEAD of the catalog would mean no document this
	// deployment can publish is post-split, so every one of them would bind the
	// routes through `wcp` for ever.
	if authoringcatalog.DeploymentCatalogVersion < legacycompile.RouteSeamSplitCatalogVersion {
		t.Fatalf("DeploymentCatalogVersion = %d is older than the split at %d; a document published by this deployment would be read as pre-split",
			authoringcatalog.DeploymentCatalogVersion, legacycompile.RouteSeamSplitCatalogVersion)
	}
}
