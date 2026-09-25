// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"axonflow/platform/shared/contenttext"
)

// THE CONTENT A STEP PLANE DECIDES OVER IS THE TEXT A STEP CARRIES, UNESCAPED
// (#4249 row 5666236540, R3 round 1 finding 1).
//
// A detector matches text, so a step's input is presented as the projection
// of its keys and string leaves, raw, one per line - never as its JSON
// encoding, which is what it is RECORDED as. The rule lives in
// platform/shared/contenttext, the one statement both binaries read (#4259:
// the agent's cowork ingest storage pass reads it too); its
// TestTheStepPlanesCorpus holds it to the cells #4360 proved here.

// contentProjection is the projection of parts, in order
// (contenttext.Projection).
func contentProjection(parts ...any) (string, error) {
	return contenttext.Projection(parts...)
}
