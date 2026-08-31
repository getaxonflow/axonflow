package legacycompile

import (
	"sort"
	"strings"
	"testing"
)

// TestPlaneModelMatchesTheCensus is this module's half of the pin that binds
// the plane model to the tree it claims to describe.
//
// The other half is TestLegacyCallSiteCensusIsComplete in the MAIN module,
// which proves legacy_call_sites.tsv names exactly the call sites that exist.
// This one proves the plane model says nothing the census does not support.
//
// Between them: a plane cannot be invented (it would have no census rows), a
// plane cannot go missing (the census rows would belong to no plane), and no
// plane can claim a substrate, a phase or a posture the call sites do not have.
// AllPlanes is the shadow gate's denominator, so each of those is the
// difference between measuring an enforcement surface and reporting coverage of
// one that does not exist.
func TestPlaneModelMatchesTheCensus(t *testing.T) {
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition"})
	if len(rows) == 0 {
		t.Fatal("legacy_call_sites.tsv is empty; an empty census supports any model at all")
	}

	type siteFacts struct {
		evaluators map[string]bool
		overrides  map[string]bool // evaluator -> any call site passes overrides
		files      []string
	}
	byPlane := map[Plane]*siteFacts{}
	for _, r := range rows {
		// The edition column says which build carries the file. Its TRUTH is
		// pinned by platform/shared/policy's TestLegacyCallSiteCensusIsComplete
		// against the file's real build constraint; here only its vocabulary
		// is checked, so a row cannot carry a third value both tests ignore.
		switch r["edition"] {
		case "community", "enterprise":
		default:
			t.Fatalf("legacy_call_sites.tsv: row for %s %s has edition %q, want community or enterprise", r["file"], r["function"], r["edition"])
		}
		p := Plane(r["plane"])
		if byPlane[p] == nil {
			byPlane[p] = &siteFacts{evaluators: map[string]bool{}, overrides: map[string]bool{}}
		}
		f := byPlane[p]
		f.evaluators[r["evaluator"]] = true
		if r["passes_action_overrides"] == "yes" {
			f.overrides[r["evaluator"]] = true
		}
		f.files = append(f.files, r["file"]+" "+r["function"])
	}

	// Every census plane is modelled, and every modelled plane is in the
	// census. Both directions, because the two failures are opposite and both
	// are silent.
	for p := range byPlane {
		if _, ok := planeSpecs[p]; !ok {
			t.Fatalf("the census records call sites for plane %q and planeSpecs has no entry for it: %v",
				p, byPlane[p].files)
		}
	}
	for p := range planeSpecs {
		if _, ok := byPlane[p]; !ok {
			t.Fatalf("planeSpecs models plane %q and the census records no call site for it; "+
				"a plane with no evaluation behind it reads as coverage of something that does not exist", p)
		}
	}

	for _, p := range AllPlanes() {
		spec := MustSpecFor(p)
		f := byPlane[p]

		staticSite := f.evaluators["EvaluateRequest"] || f.evaluators["EvaluateResponse"] || f.evaluators["EvaluatePolicy"]
		dynamicSite := f.evaluators["EvaluateDynamicPolicies"]

		claimsStatic, claimsDynamic := false, false
		for _, s := range spec.Substrates {
			switch s {
			case SubstrateStatic:
				claimsStatic = true
			case SubstrateDynamic:
				claimsDynamic = true
			}
		}
		if claimsStatic != staticSite {
			t.Fatalf("plane %q claims static=%t and the census has a static-engine call site=%t (%v)",
				p, claimsStatic, staticSite, f.files)
		}
		if claimsDynamic != dynamicSite {
			t.Fatalf("plane %q claims dynamic=%t and the census has an EvaluateDynamicPolicies call site=%t (%v)",
				p, claimsDynamic, dynamicSite, f.files)
		}

		// A plane that evaluates a phase must have a call site for it.
		if spec.EvaluatesPhase(PhaseResponse) && !f.evaluators["EvaluateResponse"] {
			t.Fatalf("plane %q claims the response phase and the census has no EvaluateResponse call site (%v)", p, f.files)
		}
		if spec.EvaluatesPhase(PhaseRequest) && !(f.evaluators["EvaluateRequest"] || f.evaluators["EvaluatePolicy"]) {
			t.Fatalf("plane %q claims the request phase and the census has no request-side call site (%v)", p, f.files)
		}
		if f.evaluators["EvaluateResponse"] && !spec.EvaluatesPhase(PhaseResponse) {
			t.Fatalf("plane %q has an EvaluateResponse call site and does not model the response phase (%v)", p, f.files)
		}

		// The effective read path is the tier engine and only the tier engine.
		if spec.StaticReadPath == ReadPathEffectiveAction {
			if !f.evaluators["EvaluatePolicy"] {
				t.Fatalf("plane %q claims the effective read path and has no TierAwarePolicyEngine.EvaluatePolicy call site (%v)", p, f.files)
			}
			if f.evaluators["EvaluateRequest"] || f.evaluators["EvaluateResponse"] {
				t.Fatalf("plane %q claims the effective read path AND has a shared-engine call site; those are two read paths and two planes (%v)", p, f.files)
			}
		}

		// The posture lever. A plane claiming it must have a call site that
		// passes ActionOverrides; a plane denying it must either have none, or
		// declare a ForcedAction - which is the cowork case, where the map
		// passed is the handler's own and not the deployment posture.
		anyOverrides := false
		for _, v := range f.overrides {
			if v {
				anyOverrides = true
			}
		}
		if spec.PostureLever && !anyOverrides {
			t.Fatalf("plane %q claims the detection posture displaces its actions and no census call site passes ActionOverrides (%v)", p, f.files)
		}
		if !spec.PostureLever && anyOverrides && spec.ForcedAction == "" {
			t.Fatalf("plane %q denies the posture lever, passes ActionOverrides at a census call site, and declares no ForcedAction; "+
				"one of the three is wrong and a plane whose actions are displaced by something the model does not name "+
				"attributes the displacement to the compiler (%v)", p, f.files)
		}
	}

	// Anti-vacuity, derived: the census must actually distinguish the axes it
	// is being used to pin. A census in which every plane looked the same would
	// agree with any model.
	var planes []string
	staticPlanes, dynamicPlanes, leverPlanes, effectivePlanes := 0, 0, 0, 0
	for _, p := range AllPlanes() {
		planes = append(planes, string(p))
		spec := MustSpecFor(p)
		for _, s := range spec.Substrates {
			if s == SubstrateStatic {
				staticPlanes++
			} else {
				dynamicPlanes++
			}
		}
		if spec.PostureLever {
			leverPlanes++
		}
		if spec.StaticReadPath == ReadPathEffectiveAction {
			effectivePlanes++
		}
	}
	sort.Strings(planes)
	if staticPlanes == 0 || dynamicPlanes == 0 {
		t.Fatalf("the model has %d static and %d dynamic plane claims; both substrates must appear or the substrate axis is untested",
			staticPlanes, dynamicPlanes)
	}
	if leverPlanes == 0 || leverPlanes == len(planes) {
		t.Fatalf("%d of %d planes claim the posture lever; if every plane or no plane claims it, the axis pins nothing", leverPlanes, len(planes))
	}
	if effectivePlanes != 1 {
		t.Fatalf("%d planes claim the effective read path; exactly one engine reads static_policies.action", effectivePlanes)
	}
	t.Logf("plane model agrees with the census over %d plane(s): %s", len(planes), strings.Join(planes, ", "))
}

// TestUnimplementedPlanesAreRecordedNotModelled pins the third option between
// inventing a plane and omitting one.
func TestUnimplementedPlanesAreRecordedNotModelled(t *testing.T) {
	if len(UnimplementedPlanes) == 0 {
		t.Skip("no plane is currently recorded as unimplemented")
	}
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition"})
	inCensus := map[string]bool{}
	for _, r := range rows {
		inCensus[r["plane"]] = true
	}
	for p, why := range UnimplementedPlanes {
		if _, modelled := planeSpecs[p]; modelled {
			t.Fatalf("plane %q is recorded as unimplemented AND modelled in planeSpecs; it would be compiled for and counted", p)
		}
		if inCensus[string(p)] {
			t.Fatalf("plane %q is recorded as unimplemented and the census has call sites for it; one of the two is stale", p)
		}
		if len(why) < 40 {
			t.Fatalf("plane %q is recorded as unimplemented with a %d-character reason; a bare entry is a claim nobody can check", p, len(why))
		}
	}
}
