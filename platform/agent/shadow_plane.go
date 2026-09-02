// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "axonflow/platform/decision/legacycompile"

// shadowPlaneOf reads the ADR-065 enforcement plane out of a variadic
// parameter (#3564).
//
// An ABSENT plane returns the empty plane, which the shadow's own Validate
// refuses and counts under `refused`. It deliberately does NOT fall back to a
// plausible default: a default would attribute an unattributed observation to
// some plane, and that plane's denominator is what an operator reads to decide
// whether it may cut over. A refusal is loud and costs one comparison; a wrong
// attribution is silent and costs the decision.
//
// A SECOND plane is also refused, for the same reason in the other direction:
// a caller that passed two has a bug, and picking the first would hide it.
func shadowPlaneOf(planes []legacycompile.Plane) legacycompile.Plane {
	if len(planes) != 1 {
		return ""
	}
	return planes[0]
}
