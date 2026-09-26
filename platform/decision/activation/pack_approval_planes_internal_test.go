// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/decision/registry"
)

// approvalHoldingPlanes are the planes of the scopes that HOLD an anchored
// challenge for approval rather than refusing it approval_required (PRD v11
// §1.13), read from the ONE declaration of what each scope does with a
// challenge (legacycompile.HoldingScopes, #4249 row 5768885106): the workflow
// control plane's step gate, and mcp:request and decide on Enterprise (#4375).
// The multi-agent plane holds nothing since #4382: its step gate withholds a
// challenge as approval_requires_durable_record (ApprovalWithheld).
//
// TestEveryChallengeHandlingSiteIsCensused holds these planes to the seams, so
// the declaration is pinned by the files that actually handle a challenge.
func approvalHoldingPlanes() map[legacycompile.Plane]bool {
	out := map[legacycompile.Plane]bool{}
	for _, s := range legacycompile.HoldingScopes() {
		out[s.Plane] = true
	}
	return out
}

// TestEveryShippedPackStepUpBindsOnAPlaneThatHoldsNoApproval pins which pack
// step-ups sit on a plane that HOLDS approvals. Until #4375 no holding plane
// carried a pack step-up, so InstallPacks' pool was named and never resolved
// by construction. Since #4375 (mcp:request and decide hold a challenge as a
// pending approval) the rbi and sebi oversight step-ups sit on holding planes:
// on this release they are held and released by any person the queue admits,
// because no release predicate reads a pool (#4249 row 5670730156); the day
// #4374's eligibility enforcement lands, exactly these bindings start deciding
// who may approve, and a deployment whose directory lacks the pack's group
// would refuse every such call. The set is therefore pinned by value: a new
// pack step-up on a holding plane, or one that leaves, fails this test until
// stepUpsOnHoldingPlanes says so.
var stepUpsOnHoldingPlanes = map[string]bool{
	"fincrime/pack:fincrime:fincrime__cnp__high__value__stepup/decide":          true,
	"fincrime/pack:fincrime:fincrime__cnp__high__value__stepup/mcp:request":     true,
	"fincrime/pack:fincrime:fincrime__cumulative__exposure__stepup/decide":      true,
	"fincrime/pack:fincrime:fincrime__cumulative__exposure__stepup/mcp:request": true,
	"fincrime/pack:fincrime:fincrime__geo__corridor__stepup/decide":             true,
	"fincrime/pack:fincrime:fincrime__geo__corridor__stepup/mcp:request":        true,
	// #3330: the Engine B score step-up, a score control that binds where the
	// pack's fincrime detectors load - exactly the two Enterprise holding planes.
	"fincrime/pack:fincrime:fincrime__ml__risk__stepup/decide":                  true,
	"fincrime/pack:fincrime:fincrime__ml__risk__stepup/mcp:request":             true,
	"fincrime/pack:fincrime:fincrime__payment__execution__stepup/decide":        true,
	"fincrime/pack:fincrime:fincrime__payment__execution__stepup/mcp:request":   true,
	"fincrime/pack:fincrime:fincrime__structuring__pattern__stepup/decide":      true,
	"fincrime/pack:fincrime:fincrime__structuring__pattern__stepup/mcp:request": true,
	"fincrime/pack:fincrime:fincrime__velocity__frequency__stepup/decide":       true,
	"fincrime/pack:fincrime:fincrime__velocity__frequency__stepup/mcp:request":  true,
	"mas-feat/pack:mas-feat:mas__feat__credit__scoring/decide":                  true,
	"mas-feat/pack:mas-feat:mas__feat__credit__scoring/mcp:request":             true,
	"mas-feat/pack:mas-feat:mas__feat__insurance__underwriting/decide":          true,
	"mas-feat/pack:mas-feat:mas__feat__insurance__underwriting/mcp:request":     true,
	"mas-feat/pack:mas-feat:mas__feat__investment__advisory/decide":             true,
	"mas-feat/pack:mas-feat:mas__feat__investment__advisory/mcp:request":        true,
	"rbi/pack:rbi:rbi__board__reporting__trigger/decide":                        true,
	"rbi/pack:rbi:rbi__board__reporting__trigger/mcp:request":                   true,
	"rbi/pack:rbi:rbi__high__risk__ai__oversight/decide":                        true,
	"rbi/pack:rbi:rbi__high__risk__ai__oversight/mcp:request":                   true,
	"sebi/pack:sebi:sebi__cross__border__transfer/decide":                       true,
	"sebi/pack:sebi:sebi__cross__border__transfer/mcp:request":                  true,
	"sebi/pack:sebi:sebi__high__value__trade__oversight/decide":                 true,
	"sebi/pack:sebi:sebi__high__value__trade__oversight/mcp:request":            true,
}

func TestEveryShippedPackStepUpBindsOnAPlaneThatHoldsNoApproval(t *testing.T) {
	root := filepath.Join("..", "..", "..", "ee", "policy-packs")
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no ee/policy-packs in this tree (the community mirror ships no pack)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var packs []*policypack.Pack
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		source, err := os.ReadFile(filepath.Join(root, e.Name(), "pack.json"))
		if err != nil {
			t.Fatal(err)
		}
		committed, err := os.ReadFile(filepath.Join(root, e.Name(), "document.json"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := policypack.Load(source, committed)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		packs = append(packs, p)
	}
	snap, err := authoringcatalog.Resolve("", authoringcatalog.Deployment{
		Edition: registry.EditionEnterprise,
		Realms: map[string]authoring.RealmEntry{
			"axonflow-minted": {Interactive: true, HasGroupGraph: true},
			"oidc":            {Interactive: true, HasGroupGraph: true},
		},
		Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := InstallPacks(snap, packs)
	if err != nil {
		t.Fatal(err)
	}
	bound := 0
	onHolding := map[string]bool{}
	for _, ip := range installed {
		for _, scope := range legacycompile.AllScopes() {
			doc, err := packForScope(scope, ip)
			if err != nil {
				t.Fatalf("%s on %s: %v", ip.Pack.Source.ID, scope, err)
			}
			for _, p := range doc.Policies {
				for _, o := range p.Obligations {
					if o.Params["eligible"] == "" {
						continue
					}
					bound++
					if legacycompile.ApprovalHandlingOf(scope).Holds() {
						key := ip.Pack.Source.ID + "/" + p.ID + "/" + scope.String()
						onHolding[key] = true
						if !stepUpsOnHoldingPlanes[key] {
							t.Errorf("%s's step-up %s binds on %s, a plane that HOLDS approvals, and stepUpsOnHoldingPlanes does not list it: its pool %q is held and released by any admitted person on this release and decides who may approve once #4374 lands",
								ip.Pack.Source.ID, p.ID, scope, o.Params["eligible"])
						}
					}
				}
			}
		}
	}
	if len(installed) == 0 || bound == 0 {
		t.Fatalf("%d packs installed, %d step-up bindings found; the census read nothing", len(installed), bound)
	}
	for key := range stepUpsOnHoldingPlanes {
		if !onHolding[key] {
			t.Errorf("stepUpsOnHoldingPlanes lists %s, which no installed pack binds on a holding plane any more", key)
		}
	}
}

// challengeHandlingSites is every production file that handles an anchored
// decision's challenge, with what it does with it: the planes it HOLDS on, or
// nil when it refuses (approval_required) or only maps the state. A file
// handles a challenge when it names contract.StateChallenge, or
// anchoredenforcer.ClassChallenge: since #4425 the three orchestrator request
// seams switch on the verdict's class (anchoredenforcer.Classify), and each
// still decides in its own ClassChallenge arm whether its plane holds,
// withholds or refuses. anchoredenforcer/classify.go is the shared classifier
// that maps the state to the class; it decides nothing and holds nothing. It is what
// makes the declaration's holding scopes falsifiable: a new file that handles a challenge
// fails TestEveryChallengeHandlingSiteIsCensused until it is listed here, and
// the planes listed as holding must be exactly approvalHoldingPlanes().
var challengeHandlingSites = map[string][]legacycompile.Plane{
	"agent/approval_hold_enterprise.go":            {legacycompile.PlaneMCP, legacycompile.PlaneDecide}, // #4370: the pending approval a retry spends once (mcp:request and decide)
	"agent/decision_enforcing_seam.go":             nil,                                                 // mapAnchoredDecision: approval_required on every agent request plane; the hold is applied after it by approval_hold_enterprise.go
	"agent/mcp_response_enforcing_seam.go":         nil,                                                 // anchoredResponse: approval_required
	"agent/cowork_ingest_enforcing_seam.go":        nil,                                                 // decideCoworkContent: approval_required, the content withheld (#4259)
	"agent/authzen_adapter.go":                     nil,                                                 // maps the state and reason for the AuthZEN wire; holds nothing
	"decision/contract/decision.go":                nil,                                                 // the state's declaration
	"shared/anchoredenforcer/classify.go":          nil,                                                 // Classify maps StateChallenge to ClassChallenge for the three orchestrator seams; it decides and holds nothing (#4425)
	"orchestrator/route_request_enforcing_seam.go": nil,                                                 // its ClassChallenge arm: withheld approval_required, neither route can hold
	"orchestrator/response_enforcing_seam.go":      nil,                                                 // approval_required
	"orchestrator/wcp_enforcing_seam.go":           {legacycompile.PlaneWCP},                            // its ClassChallenge arm holds the step
	"orchestrator/map_enforcing_seam.go":           nil,                                                 // #4382: its ClassChallenge arm makes require_approval, which mapStepGate.decide withholds approval_requires_durable_record
}

// TestEveryChallengeHandlingSiteIsCensused walks every non-test Go file under
// platform/ and ee/ for a reference to StateChallenge or ClassChallenge and fails on a file the
// census does not list, on a census entry no longer referencing it, and when
// the census's holding planes are not approvalHoldingPlanes().
func TestEveryChallengeHandlingSiteIsCensused(t *testing.T) {
	platformRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	scanned := 0
	for i, root := range []string{platformRoot, filepath.Join(platformRoot, "..", "ee")} {
		if _, err := os.Stat(root); err != nil {
			if i > 0 && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			t.Fatal(err)
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "vendor", "testdata", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			if handlesAChallenge(string(raw)) {
				rel, _ := filepath.Rel(platformRoot, path)
				found[filepath.ToSlash(rel)] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files", scanned)
	}
	var unlisted, gone, stripped []string
	for f := range found {
		if _, ok := challengeHandlingSites[f]; !ok {
			unlisted = append(unlisted, f)
		}
	}
	// On a community-mirror checkout (no ee/ beside platform/), the sync also
	// deletes platform/ files that build only for the enterprise edition, so a
	// census entry naming one cannot be found there. It is excused only when
	// the FILE is absent on a mirror: a file that is present and stopped
	// handling a challenge still fails on both trees, and on the enterprise
	// tree every entry must be found as before. The plane comparison below
	// reads the census itself, so it is asserted in full on both trees.
	_, eeErr := os.Stat(filepath.Join(platformRoot, "..", "ee"))
	onMirror := errors.Is(eeErr, fs.ErrNotExist)
	holding := map[legacycompile.Plane]bool{}
	for f, planes := range challengeHandlingSites {
		if !found[f] {
			if _, err := os.Stat(filepath.Join(platformRoot, filepath.FromSlash(f))); onMirror && errors.Is(err, fs.ErrNotExist) {
				stripped = append(stripped, f)
			} else {
				gone = append(gone, f)
			}
		}
		for _, plane := range planes {
			holding[plane] = true
		}
	}
	sort.Strings(unlisted)
	sort.Strings(gone)
	sort.Strings(stripped)
	if len(stripped) > 0 {
		t.Logf("a community-mirror checkout: %d census entries are in files the sync strips, and are asserted on the enterprise tree: %v", len(stripped), stripped)
	}
	if len(unlisted) > 0 {
		t.Errorf("files handling StateChallenge or ClassChallenge not in the census: %v. Say whether each HOLDS an approval, and if it does, declare its scope Held in legacycompile's scopeApprovalHandling: a pack step-up binding there makes the pack's approver pool decide who may approve", unlisted)
	}
	if len(gone) > 0 {
		t.Errorf("census entries that no longer reference StateChallenge or ClassChallenge: %v", gone)
	}
	declared := approvalHoldingPlanes()
	if len(holding) != len(declared) {
		t.Errorf("the census holds on %v and the declaration's holding scopes are on %v", holding, declared)
	}
	for p := range holding {
		if !declared[p] {
			t.Errorf("the census holds on %s, where legacycompile's scopeApprovalHandling declares no holding scope", p)
		}
	}
}

// handlesAChallenge is whether a file's source names the challenge: the
// decision state, or the class the seams switch on (anchoredenforcer.Classify).
func handlesAChallenge(src string) bool {
	return strings.Contains(src, "StateChallenge") || strings.Contains(src, "ClassChallenge")
}
