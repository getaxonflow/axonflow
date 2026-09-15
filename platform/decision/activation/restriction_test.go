// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// The plane restriction (#3895): which of the shipped corpus's controls bind on
// a plane, why, and the two things that must stay true of the answer - it is a
// SUBSET of what shipped, and it is not empty.

func TestTheRestrictionIsDerivedAndBothArmsFire(t *testing.T) {
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the substrate arm drops the dynamic controls on a static-only plane", func(t *testing.T) {
		doc, reason, err := restrict("decide")
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Policies) == 0 || len(doc.Policies) >= len(shipped.Policies) {
			t.Fatalf("decide activates %d of %d shipped controls; a restriction that keeps everything or nothing is not one",
				len(doc.Policies), len(shipped.Policies))
		}
		for _, p := range doc.Policies {
			if strings.HasPrefix(p.ID, "corpus:dynamic_policies:") {
				t.Fatalf("%s binds on decide, which reads the static substrate only", p.ID)
			}
		}
		if !strings.Contains(reason, "static") {
			t.Fatalf("the reason does not name the substrate it restricted by: %s", reason)
		}
	})

	t.Run("the mirror image: the static scopes together and a dynamic-only plane cover every control once", func(t *testing.T) {
		// Until #4253 one static plane - proxy_tier, whose tier engine applied no
		// category filter - bound the whole static half by itself. No unfiltered
		// static plane is left, so the static half is the UNION of every static
		// scope's restriction, and the disjoint-and-total property is a statement
		// about the SUBSTRATE arm over that union. A static control no scope binds
		// is one no plane evaluates any more - which is how the four sys_admin_*
		// controls would have gone had #4253 not bound their stored block on
		// proxy_request - and it fails the coverage count below.
		inStatic := map[string]bool{}
		staticScopes := 0
		for _, sc := range legacycompile.AllScopes() {
			spec, err := legacycompile.SpecFor(sc.Plane)
			if err != nil {
				t.Fatal(err)
			}
			static := false
			for _, sub := range spec.Substrates {
				if sub == legacycompile.SubstrateStatic {
					static = true
				}
			}
			if !static {
				continue
			}
			staticScopes++
			doc, _, err := activation.RestrictToScope(sc)
			if err != nil {
				t.Fatalf("%s: %v", sc, err)
			}
			for c := range controlsOf(t, doc) {
				inStatic[c] = true
			}
		}
		if staticScopes < 2 {
			t.Fatalf("%d static scopes; the union is not a union", staticScopes)
		}
		dynamic, _, err := restrict("wcp")
		if err != nil {
			t.Fatal(err)
		}
		// ANTI-VACUITY IN BOTH DIRECTIONS, by CONTROL: a split control binds a
		// different variant on each scope (#4046), so the property is that every
		// control binds on exactly one of the two planes and that together they
		// cover every control the corpus ships - or one of them is silently
		// dropping a control for a reason nobody stated.
		inDynamic := controlsOf(t, dynamic)
		for control := range inStatic {
			if inDynamic[control] {
				t.Fatalf("%s binds on both a static-only and a dynamic-only plane", control)
			}
		}
		if shippedControls := controlsOf(t, shipped); len(inStatic)+len(inDynamic) != len(shippedControls) {
			t.Fatalf("the static and dynamic restrictions cover %d controls; the corpus ships %d, so %d bind nowhere",
				len(inStatic)+len(inDynamic), len(shippedControls), len(shippedControls)-len(inStatic)-len(inDynamic))
		}
	})

	t.Run("the detector arm fires on a plane a detector does not list", func(t *testing.T) {
		// DRIVEN, not assumed. If this ever reports zero, the second arm of the
		// restriction is dead code and the test that exercises it is vacuous.
		decide, _, err := restrict("decide")
		if err != nil {
			t.Fatal(err)
		}
		response, reason, err := restrict("orchestrator_response")
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Policies) >= len(decide.Policies) {
			t.Fatalf("orchestrator_response activates %d controls and decide %d; both read the static substrate, so the "+
				"difference is the detector arm and it must be positive", len(response.Policies), len(decide.Policies))
		}
		if strings.Contains(reason, ", 0 whose detector") {
			t.Fatalf("the detector arm reported zero drops on a plane where it must drop some: %s", reason)
		}
	})

	t.Run("every shipped control names a substrate this package can read", func(t *testing.T) {
		// The identifier shape is what the restriction parses. A corpus whose
		// identifiers changed must fail HERE, loudly, rather than classify every
		// control as out-of-plane on every plane.
		for _, plane := range []string{"decide", "wcp"} {
			if _, _, err := restrict(plane); err != nil {
				t.Fatalf("%s: %v", plane, err)
			}
		}
	})

	t.Run("an undeclared plane is refused", func(t *testing.T) {
		if _, _, err := restrict("no-such-plane"); err == nil {
			t.Fatal("a restriction was derived for a plane the model does not declare")
		}
		// A two-phase plane named whole is refused too: its phases bind
		// different controls, so no single answer is right for both.
		if _, _, err := restrict(string(legacycompile.PlaneMCP)); err == nil {
			t.Fatal("a plane-wide restriction was derived for mcp, which evaluates two phases")
		}
		// CONTROL: every declared SCOPE does restrict, so the refusals above are
		// about the name and not about the derivation being broken.
		for _, s := range legacycompile.AllScopes() {
			if _, _, err := activation.RestrictToScope(s); err != nil {
				t.Fatalf("the declared scope %s could not be restricted: %v", s, err)
			}
		}
	})
}

// restrict is RestrictToScope for a plane named alone, the form every
// single-phase plane is enforced in.
func restrict(plane string) (*pdp.Document, string, error) {
	return activation.RestrictToScope(legacycompile.EnforcementScope{Plane: legacycompile.Plane(plane)})
}

func TestTheAnchorRefusesARestrictionThatIsNotOne(t *testing.T) {
	w := newWorld(t)
	restricted, reason, err := restrict(testPlane)
	if err != nil {
		t.Fatal(err)
	}

	// The three cases are driven through Activate itself rather than through a
	// hand-built engine, so what is tested is the path a deployment takes.
	t.Run("the honest restriction activates", func(t *testing.T) {
		if _, err := activation.Activate(context.Background(), w.inputs()); err != nil {
			t.Fatalf("the derived restriction was refused: %v", err)
		}
		if len(restricted.Policies) == 0 || reason == "" {
			t.Fatal("the restriction is empty or unexplained")
		}
	})

	t.Run("an ADDED policy is refused as not a restriction", func(t *testing.T) {
		anchor, err := pdp.AnchorToShippedCorpusRestriction(reason)
		if err != nil {
			t.Fatal(err)
		}
		doc := *restricted
		doc.Policies = append(append([]pdp.Policy(nil), restricted.Policies...), pdp.Policy{
			ID: "invented.ceiling", Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
			Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true}, Where: pdp.True(),
		})
		err = activateWith(t, w, &doc, anchor)
		assertRefusal(t, err, pdp.RefusalNotARestriction, "invented.ceiling")
	})

	t.Run("an EDITED policy is refused, keeping its name", func(t *testing.T) {
		anchor, err := pdp.AnchorToShippedCorpusRestriction(reason)
		if err != nil {
			t.Fatal(err)
		}
		doc := *restricted
		doc.Policies = append([]pdp.Policy(nil), restricted.Policies...)
		// THE SAME IDENTIFIER, THE OPPOSITE MEANING: the constraint now binds
		// when its detector does NOT fire. It is deliberately a mutation that
		// stays schema-valid and compiles - an earlier version of this case
		// read an undeclared path and was refused by the bundle's own authoring
		// validation, several guards before the anchor, so it proved nothing
		// about the anchor.
		edited := false
		for i := range doc.Policies {
			p := &doc.Policies[i]
			if p.Authority != contract.AuthorityConstraint || p.Where.Kind != pdp.CondCompare {
				continue
			}
			if lit, ok := p.Where.Literal.(bool); ok && lit {
				p.Where = pdp.Compare(p.Where.Path, p.Where.Op, false)
				edited = true
				break
			}
		}
		if !edited {
			t.Fatal("no single-comparison boolean constraint to subvert; this case would prove nothing")
		}
		err = activateWith(t, w, &doc, anchor)
		assertRefusal(t, err, pdp.RefusalNotARestriction, "")
	})

	t.Run("an EMPTY restriction is refused", func(t *testing.T) {
		anchor, err := pdp.AnchorToShippedCorpusRestriction(reason)
		if err != nil {
			t.Fatal(err)
		}
		doc := *restricted
		doc.Policies = nil
		doc.Attributes = nil
		err = activateWith(t, w, &doc, anchor)
		assertRefusal(t, err, pdp.RefusalEmptyRestriction, "")
	})

	t.Run("an EDITED ATTRIBUTE cannot reach an engine, and THREE fences say so", func(t *testing.T) {
		// THE HOLE R3 POINTED AT, and what driving it actually showed.
		//
		// The attack: leave every policy byte-identical and flip ONE attribute's
		// Optional flag. Optional decides whether the authoritative ABSENCE of
		// that signal is a NON-MATCH or an UNKNOWN, so flipping it to true turns
		// a fail-closed control into one that silently stops applying - and a
		// subset check over the POLICY LIST ALONE passes it.
		//
		// Driven: it is refused, and NOT first by the anchor. Three fences stand
		// in front of an engine and they catch it in this order:
		//
		//  1. the compiler's own authoring validation - ABSENCE_NOT_HANDLED,
		//     because every shipped condition leaves on_absent unspecified, so
		//     marking its attribute optional makes the document invalid;
		//  2. NewEngine's document-to-bundle digest binding, if a caller
		//     compiled the ORIGINAL document and swapped the modified one in;
		//  3. the anchor's attribute check, which is the one this PR adds and
		//     the only one of the three that is about the SHIPPED corpus rather
		//     than about internal consistency.
		//
		// So this case asserts the property - the edit cannot reach an engine -
		// and records which fence answered, rather than pretending the anchor
		// was first. An assertion that demanded the anchor's code would have
		// been asserting the ORDER of the fences, which is not the property.
		anchor, err := pdp.AnchorToShippedCorpusRestriction(reason)
		if err != nil {
			t.Fatal(err)
		}
		doc := *restricted
		doc.Attributes = append([]pdp.AttributeSchema(nil), restricted.Attributes...)
		flipped := ""
		for i := range doc.Attributes {
			if !doc.Attributes[i].Optional {
				doc.Attributes[i].Optional = true
				flipped = doc.Attributes[i].Path
				break
			}
		}
		if flipped == "" {
			t.Fatal("no required attribute to flip; this case would prove nothing")
		}
		err = activateWith(t, w, &doc, anchor)
		if err == nil {
			t.Fatalf("flipping %s to optional produced a working engine; a control's fail-closed unknown became a "+
				"silent non-match while every policy stayed byte-identical", flipped)
		}
		t.Logf("refused by the first fence that saw it: %v", err)

		// AND THE ANCHOR ITSELF REFUSES IT, asked directly - so fence 3 is real
		// rather than assumed to be behind the other two.
		if err := anchor.CheckSystemRestrictionForTest(&doc); err == nil {
			t.Fatalf("the anchor accepted a document whose attribute %s was edited; the subset rule is "+
				"'leave out, never alter' and it must cover the schema too", flipped)
		} else {
			var refusal *pdp.ActivationRefusal
			if !errors.As(err, &refusal) || refusal.Code != pdp.RefusalNotARestriction {
				t.Fatalf("the anchor refused with %v; want a typed %s", err, pdp.RefusalNotARestriction)
			}
			if !strings.Contains(refusal.Detail, "Optional") {
				t.Fatalf("the anchor's refusal does not name what changed: %s", refusal.Detail)
			}
		}
	})

	t.Run("an ADDED ATTRIBUTE is refused", func(t *testing.T) {
		anchor, err := pdp.AnchorToShippedCorpusRestriction(reason)
		if err != nil {
			t.Fatal(err)
		}
		doc := *restricted
		doc.Attributes = append(append([]pdp.AttributeSchema(nil), restricted.Attributes...),
			pdp.AttributeSchema{Path: "signal.invented", Type: pdp.TypeBoolean})
		err = activateWith(t, w, &doc, anchor)
		assertRefusal(t, err, pdp.RefusalNotARestriction, "signal.invented")
	})

	t.Run("an OMITTED attribute is allowed, because that is what a restriction does", func(t *testing.T) {
		// THE CONTROL for the two above: the rule is "leave out, never alter",
		// so dropping an attribute must NOT be refused - otherwise the check
		// would refuse every real restriction, which drops the attributes of
		// the controls it drops.
		anchor, err := pdp.AnchorToShippedCorpusRestriction(reason)
		if err != nil {
			t.Fatal(err)
		}
		if len(restricted.Attributes) == 0 {
			t.Fatal("the restriction declares no attributes; this control would prove nothing")
		}
		doc := *restricted
		doc.Attributes = append([]pdp.AttributeSchema(nil), restricted.Attributes[1:]...)
		// The remaining policies still reference the dropped path, so the
		// document will not VALIDATE - which is a different guard. What this
		// case asserts is only that the ANCHOR did not refuse it: the failure,
		// if any, must not be a restriction refusal.
		err = activateWith(t, w, &doc, anchor)
		var refusal *pdp.ActivationRefusal
		if errors.As(err, &refusal) && refusal.Code == pdp.RefusalNotARestriction {
			t.Fatalf("omitting an attribute was refused as not-a-restriction; a restriction drops the attributes of "+
				"the controls it drops, so this refusal would reject every real one: %s", refusal.Detail)
		}
	})

	t.Run("a restriction with no reason cannot be declared at all", func(t *testing.T) {
		if _, err := pdp.AnchorToShippedCorpusRestriction("  "); err == nil {
			t.Fatal("an unexplained restriction of the platform's own ceiling was accepted")
		}
	})
}

// activateWith builds an engine over a hand-supplied system document, through
// pdp.NewEngine exactly as Activate does, so the anchor is the thing under
// test rather than a re-implementation of it.
func activateWith(t *testing.T, w *world, system *pdp.Document, anchor pdp.SystemCorpusAnchor) error {
	t.Helper()
	b, err := pdp.BuildBundle(system)
	if err != nil {
		return err
	}
	if err := b.Sign(authoring.SystemKeyID, w.sysPriv); err != nil {
		return err
	}
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootSystem, authoring.SystemKeyID, w.sysPriv.Public().(ed25519.PublicKey))
	reg, err := w.snap.Registry.PDPRegistry()
	if err != nil {
		return err
	}
	pep, _ := w.snap.PEPFor(testPlane)
	_, err = pdp.NewEngine(context.Background(), pdp.EngineConfig{
		Bundles: []*pdp.Bundle{b}, Documents: []*pdp.Document{system}, TrustStore: trust,
		Registry: reg, PEP: pep, SystemCorpus: anchor, ApprovalTTL: time.Minute,
	})
	return err
}

func assertRefusal(t *testing.T, err error, wantCode, wantDetail string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the engine activated; want refusal %s", wantCode)
	}
	var refusal *pdp.ActivationRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("refused with %v; want a typed %s refusal", err, wantCode)
	}
	if refusal.Code != wantCode {
		t.Fatalf("refused with %q; want %q (%s)", refusal.Code, wantCode, refusal.Detail)
	}
	if wantDetail != "" && !strings.Contains(refusal.Detail, wantDetail) {
		t.Fatalf("the refusal does not name %q: %s", wantDetail, refusal.Detail)
	}
}

// TestAShippedControlThatFiresDenies is the assertion the whole cutover rests
// on: the restriction keeps the controls that bind, and one of them, when its
// detector fires, actually refuses the request.
//
// Without it every other assertion here is satisfied by an engine that permits
// everything, which is exactly what a too-wide restriction would produce.
func TestAShippedControlThatFiresDenies(t *testing.T) {
	w := newWorld(t)
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	w.promote(t, w.publish(t, pack, 1, ""))
	act := w.activate(t)

	restricted, _, err := restrict(testPlane)
	if err != nil {
		t.Fatal(err)
	}
	// A CONSTRAINT this plane enforces, chosen from the restriction rather
	// than named here: a hardcoded policy id would go stale the day the corpus
	// is regenerated, and the test would then pass against a control that no
	// longer exists.
	var constraintID, signalPath string
	for _, p := range restricted.Policies {
		if p.Authority != contract.AuthorityConstraint {
			continue
		}
		paths := p.Where.Paths()
		if len(paths) == 1 && strings.HasPrefix(paths[0], "signal.detector.") {
			constraintID, signalPath = p.ID, paths[0]
			break
		}
	}
	if constraintID == "" {
		t.Fatal("the decide restriction carries no single-detector constraint, so this test could not choose one; " +
			"the corpus has changed shape and this assertion is no longer exercising a denial")
	}

	now := time.Date(2026, 9, 10, 12, 5, 0, 0, time.UTC)
	request := func(fired bool) *contract.Request {
		principal := contract.MustParseID(contract.KindPrincipal, testCaller)
		attrs := contract.AttributeSet{
			"action.id":   contract.Known("Action::"+authoringcatalog.ActionLLMCompletion, contract.ProvPlatform, 1, now),
			"action.tags": contract.Known([]any{"stage:llm"}, contract.ProvPlatform, 1, now),
			"args.query":  contract.Known("hello", contract.ProvCaller, 1, now),
		}
		for _, a := range restricted.Attributes {
			if _, ok := attrs[a.Path]; ok {
				continue
			}
			if strings.HasPrefix(a.Path, "signal.") {
				attrs[a.Path] = contract.Known(a.Path == signalPath && fired, contract.ProvDetector, 1, now)
			}
		}
		return &contract.Request{
			RequestID: "fire", Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_1"),
			Principal: principal,
			Action:    contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionLLMCompletion),
			Resource:  contract.MustParseID(contract.KindResource, "Request::self:fire"),
			Context: contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: contract.AttributeSet{
				"principal.id": contract.Known(testCaller, contract.ProvAuthentication, 1, now),
			}}}},
			Snapshot: act.RequestSnapshot(7, 0, 1), Attributes: attrs, EvaluatedAt: now,
		}
	}

	// THE CONTROL, FIRST: with the detector not firing the request is allowed,
	// so the denial below is the detector's doing and not the engine's default.
	clean, err := act.Engine.Decide(context.Background(), request(false))
	if err != nil {
		t.Fatal(err)
	}
	if clean.State != contract.StateAllow {
		t.Fatalf("a clean request on the enforcing engine is %s (%s); the denial below would prove nothing",
			clean.State, clean.Reason)
	}

	fired, err := act.Engine.Decide(context.Background(), request(true))
	if err != nil {
		t.Fatal(err)
	}
	if fired.State != contract.StateDeny {
		t.Fatalf("%s fired and the anchored engine answered %s (%s); the platform's own ceiling did not hold",
			constraintID, fired.State, fired.Reason)
	}
	// THE REASON, NOT ONLY THE REFUSAL: the denial must be attributed to the
	// control that caused it, or a deny for some unrelated cause would satisfy
	// this test.
	found := false
	for _, id := range fired.Determining.MatchedConstraints {
		if id == constraintID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the denial names constraints %v, not %s", fired.Determining.MatchedConstraints, constraintID)
	}
	t.Logf("%d of %d shipped controls bind on %s; %s denied when its detector fired",
		act.SystemPolicies, act.ShippedPolicies, act.Plane, constraintID)
}

// TestNoShippedControlReferencesTwoCensusedDetectors is the trigger named in
// censusFactFor's comment: it is FIRST-MATCH over a policy's signal paths,
// which is unobservable only while no control references two censused
// detectors.
//
// On the day one does, the first-match choice starts deciding whether a control
// binds - and in a direction nobody picked, since ReferencedPaths is sorted and
// the winner is therefore alphabetical. This fails then, and its message says
// what decision is now owed.
func TestNoShippedControlReferencesTwoCensusedDetectors(t *testing.T) {
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	censused := map[string]bool{}
	for _, r := range rows {
		censused[registry.DetectorID(r.PolicyID).SignalPath()] = true
	}
	if len(censused) == 0 {
		t.Fatal("the census produced no signal paths; this test would then find no multi-detector policy for the wrong reason")
	}

	seen := 0
	for _, p := range shipped.Policies {
		var hits []string
		for _, path := range p.ReferencedPaths() {
			if censused[path] {
				hits = append(hits, path)
			}
		}
		if len(hits) > 0 {
			seen++
		}
		if len(hits) > 1 {
			t.Fatalf("%s references %d censused detectors (%v). censusFactFor is FIRST-MATCH, so which of "+
				"them decides whether this control binds on a plane is now alphabetical. Decide explicitly: keep "+
				"the control only if EVERY referenced detector lists the plane (fail-closed), or if ANY does "+
				"(fail-open), and state which in the function's comment.", p.ID, len(hits), hits)
		}
	}
	// ANTI-VACUITY: if no shipped policy referenced a censused detector at all,
	// the loop above would pass having compared nothing.
	if seen == 0 {
		t.Fatal("no shipped control references a censused detector; the census index and the corpus have stopped " +
			"agreeing on signal paths, and the detector arm of the restriction is judging nothing")
	}
	t.Logf("%d of %d shipped controls reference exactly one censused detector; none references two", seen, len(shipped.Policies))
}
