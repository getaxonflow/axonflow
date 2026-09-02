// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"fmt"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
)

// AnonymousPrincipal addresses a request whose plane resolved no subject.
//
// It is a DECLARED identifier rather than an empty string because
// contract.ParseID refuses an empty local part, and a translation that refused
// the request instead would drop exactly the population the brief calls a
// first-class case: identity absent, auth missing, auth malformed. Those
// requests are evaluated by the legacy planes and must be evaluated by the
// shadow, or the window measures only the happy path.
const AnonymousPrincipal = "anonymous"

// legacyVerdictFor normalizes what the plane ACTUALLY decided into the
// harness's legacy vocabulary.
//
// It is the whole of the legacy side and it re-runs nothing. Executable and
// the state come off the plane's own result; the effects come off the rows'
// resolved actions. Nothing here consults the compiler, the bundle or the
// classifier, which is what keeps the two sides of the diff two sides.
func legacyVerdictFor(obs Observation, contentTarget string) shadow.Verdict {
	// ApprovalClauses is deliberately left at zero; see observation.go.
	v := shadow.Verdict{Executable: obs.Legacy.Executable}
	// THE STATE IS DERIVED FROM EXECUTABILITY, NOT FROM THE ACTIONS.
	//
	// The offline model has to infer it: it reads require_approval off a row
	// and reports DENY because that is what the legacy engines do. Here the
	// plane has already told us what it did, so the inference is unnecessary
	// and would be actively wrong on a community deployment, where
	// require_approval resolves to ALLOW (shadow.ModelLimitations item 1) and
	// an actions-derived state would report a deny the running system did not
	// issue. Reading the real outcome is what keeps that model error out of
	// the production path entirely.
	if obs.Legacy.Executable {
		v.State = contract.StateAllow
	} else {
		v.State = contract.StateDeny
	}
	for _, r := range obs.Rows {
		if !r.Matched {
			continue
		}
		if r.Shadowed {
			// FIRED, BUT THE COMBINER DISCARDED IT. It is not in the legacy
			// determining set and it contributes no effect, because the running
			// system did neither. Its detector verdict is still TRUE on the
			// ADR-065 side (see caseFor), which is exactly the asymmetry
			// EC6_PROXY_TIER_FIRST_MATCH_SHADOWING exists to classify: the
			// compiled policy will start denying at cutover on a row today's
			// first-match reduction hides.
			continue
		}
		v.Determining = append(v.Determining, r.RowKey())
		if r.Action == "" {
			// A row that fired and resolved to nothing contributes to the
			// determining set and to no effect. That is a real legacy shape -
			// an inert action type the engine's switch has no arm for - and
			// inventing an effect for it would make the correspondence table
			// answer for a control the running system never applied.
			continue
		}
		target := r.Target
		if legacycompile.LegacyAction(r.Action) == legacycompile.ActionRedact && target == "" {
			// static_policies stores no field path for a redaction: the target
			// was whatever span the detector matched. Both sides must be given
			// the SAME configured content root, so it comes from the
			// compilation options rather than from a default written here.
			target = contentTarget
		}
		v.Effects = append(v.Effects, shadow.LegacyEffect(r.RowKey(), r.Action, target))
	}
	return v.Canonical()
}

// caseFor builds the replay case the ADR-065 side is evaluated from.
//
// opts MUST be the options the report in hand was compiled with. Building a
// case against different options is the #3577 round-2 defect verbatim: Realm
// qualifies the group identifiers a segment-scoped policy is scoped to and
// FieldPaths remaps a legacy condition field onto its attribute path, so a
// mismatch silently drops every segment-scoped constraint from the ADR-065
// side while the legacy side still applies it - a fail-open, armed by setting
// the realm the compiler's own documentation tells an operator to set.
func caseFor(obs Observation, id string, opts legacycompile.Options) shadow.Case {
	c := shadow.Case{
		ID:    id,
		Plane: obs.Plane,
		Phase: obs.Phase,
		Org:   obs.OrgScope,
		// THE ACTION IS ALWAYS THE CORPUS'S SINGLE REGISTERED ACTION, NEVER
		// THE PLANE'S TOOL IDENTITY. This is not a simplification; passing the
		// tool identity through makes the whole window unreadable.
		//
		// A compiled world registers exactly ONE action (shadow.ActionID), and
		// shadow's own doc says why: the legacy static substrate is content
		// inspection that applies to every request on its plane
		// (ActionSelector.Any), and the dynamic substrate selects on request
		// attributes rather than on a registered action, so enumerating
		// actions would multiply cases without exercising a single additional
		// policy row. Per-action coverage becomes meaningful when the planes
		// cut over against the REAL action registry, which is #3564's cutover
		// work and not the shadow's.
		//
		// So an ADR-065 request naming anything else hits an UNREGISTERED
		// ACTION and is denied for unknown_action - with an empty determining
		// set, so nothing explains it. MEASURED before this line existed:
		// every observation carrying a tool identity classified UNEXPLAINED,
		// whatever the detectors had done, while the identical observation
		// with no action classified `match` or `expected_change/EC2`
		// correctly. Every production call site passes a tool identity
		// (EvalOptions.ToolIdentity, OrchestratorRequest.RequestType), so the
		// entire production window would have been UNEXPLAINED noise and gate
		// 18 would have been unreadable from it.
		//
		// The tool identity is not discarded: it rides on the Comparison for
		// attribution, so an operator can still see which tool a difference
		// came from. It just does not ADDRESS the request.
		Action:  shadow.ActionID,
		Groups:  obs.Groups,
		Fields:  obs.Fields,
		Posture: posture(obs.Posture),
		Options: opts,
		// ExercisesRows is deliberately EMPTY on a production observation.
		//
		// It is a CLAIM - "this case is meant to reach these rows" - and the
		// runner reports a case that claims a row and misses it. A generated
		// corpus can make that claim because it built the case to fire a
		// specific row. Production traffic makes no such claim: a row that ran
		// and did not match is the ordinary case and is in neither side's
		// determining set, so claiming it would report an unreached claim on
		// almost every request and bury the corpus defects the field exists to
		// surface.
		ExercisesRows: nil,
	}
	c.Principal = strings.TrimSpace(obs.Principal)
	if c.Principal == "" {
		c.Principal = AnonymousPrincipal
	}

	for _, r := range obs.Rows {
		if !r.Ran {
			// NOT RECORDED AT ALL, which is what makes it UNKNOWN.
			//
			// A detector that did not run is absent from the map, and
			// Case.Request fills every detector path the plane's policies
			// reference and the case did not supply with
			// Unknown(resolution_failed). Writing a false here instead would
			// tell the PDP that a skipped detector positively did not match -
			// the one thing ADR-065's tri-state exists to stop, and a
			// fail-open on every request a category filter or capability
			// scoping (#2801) narrowed.
			continue
		}
		switch r.Table {
		case "static_policies":
			if c.DetectorVerdicts == nil {
				c.DetectorVerdicts = map[string]bool{}
			}
			c.DetectorVerdicts[r.PolicyID] = r.Matched
		case "dynamic_policies":
			if c.ContentVerdicts == nil {
				c.ContentVerdicts = map[string]bool{}
			}
			c.ContentVerdicts[legacycompile.DynamicContentDetectorPath(r.PolicyID)] = r.Matched
		}
	}

	if obs.SegmentsUnresolved {
		// A FAILURE to resolve the closure is not an empty closure, and the
		// difference is the fail-open direction. Case.Request maps a nil/empty
		// Groups to a KNOWN empty array - a resolved fact that excludes every
		// segment-scoped policy - which is exactly the wrong answer when the
		// resolver errored. An explicit unknown makes the ADR-065 side
		// Indeterminate instead, which is #3482's class surfacing rather than
		// being papered over.
		c.PrincipalAttributes = map[string]*contract.Attribute{
			"principal.groups": attrPtr(contract.Unknown(contract.ReasonResolutionFailed, contract.ProvDirectory, 1, shadow.Now)),
		}
		c.Groups = nil
	}
	return c
}

func attrPtr(a contract.Attribute) *contract.Attribute { return &a }

// posture converts the plane's EvalOptions.ActionOverrides into the
// compiler's posture type, dropping any entry whose action the compiler does
// not know.
//
// An unknown action is DROPPED rather than carried, and that is the
// conservative direction here: the posture lever DISPLACES a stored action, so
// carrying a value the compiler cannot interpret would replace a known action
// with an uninterpretable one on the legacy side of the diff. Dropping it
// leaves the stored action in place, which is what the row says, and any real
// divergence then shows up as a difference rather than as a translation.
func posture(in map[string]string) legacycompile.Posture {
	if len(in) == 0 {
		return nil
	}
	known := map[legacycompile.LegacyAction]bool{}
	for _, a := range legacycompile.KnownActions() {
		known[a] = true
	}
	var out legacycompile.Posture
	for category, action := range in {
		a := legacycompile.LegacyAction(strings.TrimSpace(action))
		if !known[a] {
			continue
		}
		if out == nil {
			out = legacycompile.Posture{}
		}
		out[category] = a
	}
	return out
}

// caseID renders a stable, content-free identifier for one observation.
//
// It carries the plane, the phase and a monotonic sequence number and NOTHING
// from the request. A case id reaches diff records, log lines and metrics
// labels; putting a request id or a principal in it would put request-linkable
// data into all three, and the whole point of Observation carrying no content
// is that this queue cannot become a leak.
func caseID(plane legacycompile.Plane, phase legacycompile.Phase, seq uint64) string {
	if phase == "" {
		return fmt.Sprintf("rt/%s/%d", plane, seq)
	}
	return fmt.Sprintf("rt/%s/%s/%d", plane, phase, seq)
}
