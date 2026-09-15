// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"testing"
)

// namedPreviewSurfaces are the preview surfaces #3595 names in its scope -
// "simulation, impact analysis, small evidence export, media governance,
// provider, and checkpoint previews" - mapped to the registry rows that carry
// them, with the reason each mapping is the right row.
//
// SIX NAMES, FIVE ROWS. Simulation and impact analysis are one capability, not
// two: policy.simulation is titled "Policy simulation and impact analysis" and
// its license_gate carries both MaxSimulationsPerDay and MaxImpactReportInputs.
// Splitting them here would assert twice about one row and imply a sixth row
// exists.
//
// The mapping is recorded rather than derived because the issue names surfaces
// in prose and the registry names them by id; a keyword match over titles is
// how "checkpoint previews" becomes execution.replay or wcp.workflows, which
// are adjacent preview rows describing replay and lifecycle rather than
// checkpoints. TestTheNamedPreviewSurfacesAreStillApt below is the control that
// keeps each mapping honest.
var namedPreviewSurfaces = map[string]string{
	"policy.simulation": "simulation AND impact analysis: titled \"Policy simulation and impact analysis\"; " +
		"the simulation and impact-report routes run a candidate policy against recorded " +
		"traffic without enforcing it",
	"compliance.evidence_export": "small evidence export: GET /api/v1/evidence/export and /summary produce a " +
		"bounded bundle over the audit trail, capped by MaxEvidenceExportRecords, MaxEvidenceWindowDays " +
		"and MaxEvidenceExportsPerDay",
	"media.governance": "media governance: /api/v1/media-governance with config, status and audit export, " +
		"gated by MediaGovernanceEnabled",
	"llm.providers": "provider previews: CRUD over /api/v1/llm-providers plus the provider-type catalogue, " +
		"bounded by MaxLLMProviders",
	"wcp.checkpoints": "checkpoint previews: titled \"Workflow checkpoints and resume\" - reading a workflow's " +
		"step-gate checkpoints and resuming from one. NOT execution.replay (recording and replay) and NOT " +
		"wcp.workflows (lifecycle), which are adjacent preview rows describing different surfaces",
}

// TestTheNamedPreviewSurfacesAreClassifiedAndCommunityVisible is #3595's
// classification clause, and its "every Evaluation implementation is explicitly
// accepted as Community-visible and bypassable" clause, for the surfaces the
// issue names.
//
// # WHAT IT ASSERTS
//
// Each named surface is classified evaluation_preview, and each is
// community-visible: build_tag none and sync mirrored, so the implementation
// reaches the public mirror and its gate is a runtime one a source user can
// modify. The PRD accepts that explicitly - "Signed-license soft gate and
// finite limits; bypass risk accepted" - which is what makes a preview a
// preview rather than an Enterprise implementation.
//
// # WHAT IT DELIBERATELY DOES NOT ASSERT
//
// That a named surface requires an Evaluation licence. Two of the five -
// llm.providers and wcp.checkpoints - carry minimum_edition community: the
// capability is reachable on Community and the PREVIEW is the higher limit, not
// the feature. Asserting minimum_edition == evaluation would be false on two of
// five rows and would encode a misreading of what "preview" means here.
func TestTheNamedPreviewSurfacesAreClassifiedAndCommunityVisible(t *testing.T) {
	r := Load()
	var checked int
	for id, why := range namedPreviewSurfaces {
		e := r.ByID(id)
		if e == nil {
			t.Errorf("%s is named as a preview surface by #3595 (%s) but is not in the registry; "+
				"either the row was renamed and this mapping is stale, or the surface was removed",
				id, why)
			continue
		}
		checked++
		if e.Classification != ClassEvaluationPreview {
			t.Errorf("%s is classified %q, want %q. #3595 names it as a preview surface: %s",
				id, e.Classification, ClassEvaluationPreview, why)
		}
		// Community-visible and bypassable, which is the clause's own wording.
		if e.BuildTag != TagNone {
			t.Errorf("%s declares build_tag %q; a preview is Community-visible source, so its "+
				"implementation carries no build constraint", id, e.BuildTag)
		}
		if e.Sync != SyncMirrored {
			t.Errorf("%s declares sync %q; a preview reaches the public mirror, so it is %q",
				id, e.Sync, SyncMirrored)
		}
	}
	if checked != len(namedPreviewSurfaces) {
		t.Fatalf("checked %d of %d named surfaces", checked, len(namedPreviewSurfaces))
	}
	t.Logf("checked %d named preview surface(s), all evaluation_preview and community-visible", checked)
}

// TestTheNamedPreviewSurfacesAreStillApt is the control that keeps the mapping
// above from rotting into statements about rows that have moved.
//
// It is the shape TestTheContradictionFixturesAreDistinctAndStillApt uses for
// the contradiction fixtures, and for the same reason: a test aimed at a row
// that no longer carries the property it was chosen for is a test that passes
// while asserting nothing about what it names.
func TestTheNamedPreviewSurfacesAreStillApt(t *testing.T) {
	r := Load()
	seen := map[string]bool{}
	for id := range namedPreviewSurfaces {
		if seen[id] {
			t.Errorf("%s is mapped twice", id)
		}
		seen[id] = true
		if e := r.ByID(id); e == nil {
			t.Errorf("%s is gone from the registry; its mapping names nothing", id)
		}
	}
	if len(seen) < 5 {
		t.Errorf("only %d distinct named surfaces; #3595 names six, which map to five rows "+
			"(simulation and impact analysis are one capability)", len(seen))
	}
	// Every mapping carries a reason. An entry with an empty one is a mapping
	// somebody added without saying why that row is the right one.
	for id, why := range namedPreviewSurfaces {
		if len(why) < 40 {
			t.Errorf("%s has a %d-character reason; the mapping from #3595's prose to a registry "+
				"id is exactly what a later reader cannot reconstruct", id, len(why))
		}
	}
}

// minEvaluationPreviewEntries is an ANTI-VACUITY FLOOR on the preview
// population, not a target.
//
// 23 of the 86 registry entries are classified evaluation_preview at the time
// of writing (26.7%, denominator = registry entries). The floor sits below that
// so ordinary movement does not red it, while a collapse - a reclassification
// pass that empties the preview set, or a registry that stops loading - still
// does. It is deliberately NOT a ceiling: see the header on
// TestThePreviewPopulationIsStatedAndFloored.
const minEvaluationPreviewEntries = 18

// TestThePreviewPopulationIsStatedAndFloored asserts the Evaluation preview
// population cannot silently shrink, and STATES its share.
//
// # WHY A FLOOR AND NOT A CEILING
//
// #3595's acceptance says Evaluation "limits preview coverage to 10 percent".
// That ceiling is not enforced here, deliberately. The measured share is 26.7%
// of registry entries; enforcing 10% would mean reclassifying roughly two
// thirds of the preview set, which is a product decision nobody has made. The
// edition PRD's own target-band table gives Evaluation "Up to 10 percent"
// ADDITIONAL LIMITED PREVIEW COVERAGE and the paragraph beneath it says the
// bands "are direction, not commitments" until #3590 delivers the weighting
// method and the anti-gaming rules, and that "no percentage becomes an
// acceptance criterion" before then. A test that turned stated direction into a
// gate would be asserting a threshold the document defers.
//
// So the guard is the direction that IS safe: the population is floored and its
// share is logged, so the number is visible in CI output and a silent shrink
// reds.
func TestThePreviewPopulationIsStatedAndFloored(t *testing.T) {
	r := Load()
	var preview, total int
	for _, e := range r.Entries {
		total++
		if e.Classification == ClassEvaluationPreview {
			preview++
		}
	}
	if total == 0 {
		t.Fatal("the registry loaded no entries, so every figure below is vacuous")
	}
	if preview < minEvaluationPreviewEntries {
		t.Errorf("%d entries are classified %q, below the floor of %d. The preview population "+
			"collapsed: either a reclassification pass emptied it, or the registry is not the one "+
			"this floor was measured against", preview, ClassEvaluationPreview, minEvaluationPreviewEntries)
	}
	// Every named surface must be inside the population it is counted in.
	for id := range namedPreviewSurfaces {
		e := r.ByID(id)
		if e == nil {
			continue // reported by the aptness control
		}
		if e.Classification != ClassEvaluationPreview {
			t.Errorf("%s is a named preview surface but is classified %q, so it is not in the "+
				"population this floor counts", id, e.Classification)
		}
	}
	t.Logf("evaluation_preview population: %d of %d registry entries = %.1f%% "+
		"(denominator: registry entries)", preview, total, 100*float64(preview)/float64(total))
}

// TestTheEvaluationBandsAreReportedNotAsserted records the four band figures as
// EVIDENCE, and states why none of them is asserted.
//
// # WHY NO ASSERTION
//
// Against the published targets - Community 35-40%, Evaluation 50-55% - three
// of the four measured cells sit outside, and census.go says so in its own
// prose: "The measurement does not land in the targets, and that is a result
// rather than an error to be corrected by re-scoring." An assertion that the
// measured band sits inside its target would be red today on the ByFamily
// weighting; making it green would mean asserting only the flattering
// weighting, which is exactly the spread census.go publishes BOTH numbers to
// prevent.
//
// # THE INSTRUMENT, WHICH IS THE POINT
//
// These figures come from Registry.Score(), the scorer the census itself uses.
// A hand aggregation over the registry gives materially different answers -
// it omits Unscorable exclusion, the Availability weights, and the `limited`
// grade - and the difference is large enough to change the verdict on whether a
// target is met. The official scorer is the instrument; a re-implementation
// that disagrees with it is worth no more than one that agrees.
func TestTheEvaluationBandsAreReportedNotAsserted(t *testing.T) {
	b := Load().Score()
	if b.Scored == 0 {
		t.Fatal("nothing is scored, so the figures below would be vacuous")
	}
	t.Logf("measured bands (Registry.Score(), %d scored / %d unscorable):", b.Scored, b.Unscorable)
	t.Logf("  Community  by capability %.2f%%   by family %.2f%%   (target 35-40%%)",
		b.CommunityByCapability, b.CommunityByFamily)
	t.Logf("  Evaluation by capability %.2f%%   by family %.2f%%   (target 50-55%%)",
		b.EvaluationByCapability, b.EvaluationByFamily)
	t.Log("  not asserted against the targets: the PRD states the bands are direction, not " +
		"commitments, until #3590 delivers the weighting and anti-gaming rules")
}
