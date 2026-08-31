package authoring

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

func mustPublish(t *testing.T) (*Artifact, *pdp.TrustStore, ed25519.PrivateKey) {
	t.Helper()
	trust, priv := systemTrust(t)
	d := baseDocument(t)
	art, findings, err := Publish(context.Background(), d, baseCatalog(t), publishOptions(t, priv))
	if err != nil {
		t.Fatalf("the baseline must publish: %v\nfindings: %v", err, findings)
	}
	return art, trust, priv
}

func TestPublishRunsEveryGateAndSigns(t *testing.T) {
	art, trust, _ := mustPublish(t)

	if err := art.Report().Passed(); err != nil {
		t.Fatalf("the signed report does not satisfy its own completeness rule: %v", err)
	}
	seen := map[GateName]GateResult{}
	for _, r := range art.Report().Results {
		seen[r.Gate] = r
	}
	for _, gate := range AllGates() {
		r, ok := seen[gate]
		if !ok {
			t.Fatalf("gate %q is absent from the signed report", gate)
		}
		if !r.Passed || r.Checks <= 0 {
			t.Fatalf("gate %q reports passed=%t checks=%d", gate, r.Passed, r.Checks)
		}
		t.Logf("gate %-12s passed with %d checks", gate, r.Checks)
	}

	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadArtifact(raw, trust)
	if err != nil {
		t.Fatalf("a freshly published artifact did not load: %v", err)
	}
	if loaded.Digest() != art.Digest() {
		t.Fatalf("the artifact digests to %s and reloads as %s", art.Digest(), loaded.Digest())
	}
	if string(loaded.Source()) != string(art.Source()) {
		t.Fatal("the reloaded artifact carries different source bytes")
	}
}

// TestPublishIsTheOnlyPathToASignedArtifact is the structural half of "a
// publication path that skips the gauntlet on trusted input cannot exist".
//
// Artifact carries only unexported fields, so `&Artifact{...}` does not compile
// anywhere outside this package and a zero Artifact carries no signature. The
// assertion below is what stops a future refactor exporting one: an artifact
// that was not produced by Publish must be unusable rather than merely
// unusual.
func TestPublishIsTheOnlyPathToASignedArtifact(t *testing.T) {
	trust, _ := systemTrust(t)
	store, err := NewStore(trust)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Admit(&Artifact{}); err == nil {
		t.Fatal("a hand-built artifact was admitted")
	}
	// And one assembled by hand out of a real bundle, which is the shape a
	// caller who wanted to skip the gauntlet would actually reach for.
	d := baseDocument(t)
	bundle, err := pdp.BuildBundle(&d.Policy)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := testKeys(t)
	if err := bundle.Sign("system-key-1", priv); err != nil {
		t.Fatal(err)
	}
	source, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	forged := &Artifact{
		source: source,
		bundle: bundle,
		// An empty report: no gate ran.
		report:     GauntletReport{},
		provenance: PublicationProvenance{Root: pdp.RootSystem, Author: pid(t, principalAlice)},
	}
	err = store.Admit(forged)
	if err == nil {
		t.Fatal("an artifact whose gauntlet never ran was admitted")
	}
	// The refusal arrives at the authority check, which is the first thing an
	// unsigned artifact fails. That ordering is itself the guarantee: a
	// hand-assembled artifact never reaches the point where a report could be
	// believed, because it never gets past "who signed this".
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("the refusal should name the missing signing authority, got: %v", err)
	}
	// And with a real signature over the forged view, so the refusal below is
	// about the gauntlet rather than about the signature.
	forged.keyID = "system-key-1"
	digest, err := contract.ExactDigest(forged.view())
	if err != nil {
		t.Fatal(err)
	}
	forged.digest = digest
	payload, err := contract.ExactJSON(forged.view())
	if err != nil {
		t.Fatal(err)
	}
	forged.signature = ed25519.Sign(priv, payload)
	err = store.Admit(forged)
	if err == nil {
		t.Fatal("a correctly signed artifact whose gauntlet never ran was admitted")
	}
	if !strings.Contains(err.Error(), "gauntlet") {
		t.Fatalf("the refusal should name the gauntlet, got: %v", err)
	}
}

// TestGauntletRefusesAPublicationWithNoFixtures pins the anti-vacuity rule: a
// document nobody wrote a case for has not been shown to do anything, and a
// signed report saying "fixtures passed" about an empty set is worse than no
// report.
func TestGauntletRefusesAPublicationWithNoFixtures(t *testing.T) {
	_, priv := systemTrust(t)
	opts := publishOptions(t, priv)
	opts.Fixtures = nil
	_, _, err := Publish(context.Background(), baseDocument(t), baseCatalog(t), opts)
	if err == nil {
		t.Fatal("a publication with no fixtures was accepted")
	}
	if !strings.Contains(err.Error(), "fixtures") {
		t.Fatalf("the refusal should name the fixtures gate, got: %v", err)
	}
}

// TestGauntletCatchesAWrongFixtureExpectation proves the fixtures gate can
// fail. A gate that has never been observed failing is a gate nobody knows
// runs.
func TestGauntletCatchesAWrongFixtureExpectation(t *testing.T) {
	_, priv := systemTrust(t)
	opts := publishOptions(t, priv)
	opts.Fixtures = baseFixtures()
	opts.Fixtures[0].Expect["perm.refund"] = pdp.VerdictNoMatch
	_, _, err := Publish(context.Background(), baseDocument(t), baseCatalog(t), opts)
	if err == nil {
		t.Fatal("a publication whose fixture assertion is wrong was accepted")
	}
	if !strings.Contains(err.Error(), "perm.refund") {
		t.Fatalf("the refusal should name the failing policy, got: %v", err)
	}
}

// TestGauntletTriStateGateRefusesAWideningDegradation plants the fail-open the
// gate exists to catch: a policy that MATCHES because an attribute could not be
// resolved.
//
// It is the falsification of the gate. A gate nobody has watched fail is a gate
// nobody knows is connected, and this one is worth watching fail specifically
// because the author's own fixtures still pass under the plant: every baseline
// attribute is known, so the defect is invisible to every case a person would
// write. Degradation is the only thing that reaches it.
func TestGauntletTriStateGateRefusesAWideningDegradation(t *testing.T) {
	ctx := context.Background()
	d := baseDocument(t)

	// The plant is in the platform-owned tri-state HELPER, not in a generated
	// module, and that is the only place it can be. A generated module cannot
	// express this defect: every leaf is a helper call, so "unknown behaves like
	// a match" is a property of the helper or of nothing. Planting it here is
	// therefore a faithful model of the failure the gate exists to catch, a
	// defective bundle whose unresolvable attributes widen rather than narrow.
	original := pdp.HelperSource
	t.Cleanup(func() { pdp.HelperSource = original })
	planted := strings.Replace(original,
		"\ta.state == \"unknown\"\n\tr := unk(path, a.reason)",
		"\ta.state == \"unknown\"\n\tr := ok(MATCH)", 1)
	if planted == original {
		t.Fatal("the plant did not apply, so this test is asserting nothing about the gate")
	}
	pdp.HelperSource = planted

	bundle, err := pdp.BuildBundle(&d.Policy)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := pdp.NewRuntime(ctx, bundle, pdp.DefaultLimits())
	if err != nil {
		t.Fatalf("the planted helper must still compile for this to test the gate rather than the compiler: %v", err)
	}

	// The fixtures still pass, which is the point: every baseline attribute is
	// known, so nothing in the author's own cases touches the planted branch.
	// A publication gated on fixtures alone would ship this bundle.
	if _, err := gateFixtures(ctx, rt, baseFixtures()); err != nil {
		t.Fatalf("the planted bundle must still satisfy the author's fixtures, or the tri-state gate is not the thing catching it: %v", err)
	}

	checks, err := gateTriState(ctx, rt, &d.Policy, baseFixtures())
	if err == nil {
		t.Fatalf("the tri-state gate accepted a bundle that matches on unresolvable data (%d checks)", checks)
	}
	if !strings.Contains(err.Error(), "widening") {
		t.Fatalf("the refusal should name the widening, got: %v", err)
	}
	t.Logf("tri-state gate refused the plant after %d checks: %v", checks, firstClause(err.Error()))
}

func firstClause(s string) string {
	if i := strings.Index(s, ";"); i > 0 {
		return s[:i]
	}
	return s
}

// TestGauntletTriStateGateDirections pins BOTH directions of the gate's
// widening predicate in one table, because the two directions bound each
// other and a fix to either can silently break the other:
//
//   - an UNKNOWN-to-MATCH widening must be REFUSED. Unknown degradations
//     strictly remove information and the Kleene connectives are
//     information-monotone, so with a correct helper no verdict can reach
//     MATCH from a non-MATCH baseline; a gate that flags only NO_MATCH-to-
//     MATCH is blind to a reason-conditional fail-open whose baseline is
//     already UNKNOWN, which is the exact plant in the first row.
//   - a declared-absence flip must be ACCEPTED. Authoritative absence is
//     resolved data under ADR-065's three-state model, so a policy that reads
//     an optional attribute with a declared AbsentIsNoMatch under a negation
//     legitimately flips NO_MATCH to MATCH when the attribute is absent, and
//     a gate that calls that "a widening on unresolvable data" makes a
//     publishable policy shape unpublishable.
func TestGauntletTriStateGateDirections(t *testing.T) {
	ctx := context.Background()
	cat := baseCatalog(t)

	rows := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			// The regression case for the reason-conditional fail-open: the
			// helper resolves unknowns to MATCH only when the reason is
			// "stale". The document's only data-reading condition is over the
			// optional caller note, so the baseline verdict is UNKNOWN
			// (attribute_not_supplied), the author's fixtures pass, no policy
			// ever flips NO_MATCH to MATCH, and only the strict unknown-class
			// predicate can see the widening.
			name: "an unknown-to-MATCH widening is refused even when only one reason widens",
			run: func(t *testing.T) {
				d := documentWith(t, cat, func(_ *Metadata, doc *pdp.Document) {
					doc.Policies = []pdp.Policy{{
						ID:        "perm.note",
						Authority: contract.AuthorityPermission,
						Root:      pdp.RootSystem,
						Scope:     pdp.Scope{Organization: true},
						Actions:   pdp.ActionSelector{Any: true},
						Where:     pdp.Compare("args.note", pdp.OpEq, "expedite").HandlingAbsence(pdp.AbsentIsUnknown),
					}}
				})
				fixtures := []Fixture{{
					Name:       "note not supplied",
					Attributes: contract.AttributeSet{},
					Expect:     map[string]pdp.Verdict{"perm.note": pdp.VerdictUnknown},
				}}

				// The gate accepts this document with an honest helper, so the
				// refusal below is about the plant rather than the document.
				cleanBundle, err := pdp.BuildBundle(&d.Policy)
				if err != nil {
					t.Fatal(err)
				}
				cleanRT, err := pdp.NewRuntime(ctx, cleanBundle, pdp.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := gateTriState(ctx, cleanRT, &d.Policy, fixtures); err != nil {
					t.Fatalf("the gate must accept this document with an honest helper: %v", err)
				}

				original := pdp.HelperSource
				t.Cleanup(func() { pdp.HelperSource = original })
				planted := strings.Replace(original,
					"\ta.state == \"unknown\"\n\tr := unk(path, a.reason)",
					"\ta.state == \"unknown\"\n\ta.reason == \"stale\"\n\tr := ok(MATCH)\n} else := r if {\n\ta.state == \"unknown\"\n\tr := unk(path, a.reason)", 1)
				if planted == original {
					t.Fatal("the plant did not apply, so this test is asserting nothing about the gate")
				}
				pdp.HelperSource = planted

				bundle, err := pdp.BuildBundle(&d.Policy)
				if err != nil {
					t.Fatal(err)
				}
				rt, err := pdp.NewRuntime(ctx, bundle, pdp.DefaultLimits())
				if err != nil {
					t.Fatalf("the planted helper must still compile for this to test the gate rather than the compiler: %v", err)
				}
				// The author's fixtures pass under the plant: the baseline
				// reason is attribute_not_supplied, not stale, so nothing a
				// person would write reaches the planted branch.
				if _, err := gateFixtures(ctx, rt, fixtures); err != nil {
					t.Fatalf("the planted bundle must still satisfy the author's fixtures, or this gate is not the thing catching it: %v", err)
				}
				checks, err := gateTriState(ctx, rt, &d.Policy, fixtures)
				if err == nil {
					t.Fatalf("the tri-state gate accepted a bundle whose stale degradation resolves an UNKNOWN baseline to MATCH (%d checks)", checks)
				}
				if !strings.Contains(err.Error(), "widening on unresolvable data") {
					t.Fatalf("the refusal should name the widening on unresolvable data, got: %v", err)
				}
				if !strings.Contains(err.Error(), "unknown/stale") {
					t.Fatalf("the refusal should name the stale degradation, got: %v", err)
				}
				t.Logf("tri-state gate refused the reason-conditional plant after %d checks: %v", checks, firstClause(err.Error()))
			},
		},
		{
			// The opposite direction, with an UNMODIFIED helper: a permission
			// carrying NOT (env.zone == "restricted") with declared
			// AbsentIsNoMatch is a publishable shape. Degrading env.zone to
			// absent legitimately flips the policy NO_MATCH to MATCH through
			// k_not, and the gate must not call the author's declared
			// semantics a widening.
			name: "declared absence participating as known-no-match under negation is publishable",
			run: func(t *testing.T) {
				_, priv := systemTrust(t)
				d := documentWith(t, cat, func(_ *Metadata, doc *pdp.Document) {
					doc.Attributes = append(doc.Attributes, pdp.AttributeSchema{
						Path: "env.zone", Type: pdp.TypeString, Optional: true,
					})
					doc.Policies = append(doc.Policies, pdp.Policy{
						ID:        "con.zone",
						Authority: contract.AuthorityConstraint,
						Root:      pdp.RootSystem,
						Scope:     pdp.Scope{Organization: true},
						Actions:   pdp.ActionSelector{Actions: []contract.ID{aid(t, actionRefund)}},
						Where:     pdp.Not(pdp.Compare("env.zone", pdp.OpEq, "restricted").HandlingAbsence(pdp.AbsentIsNoMatch)),
					})
				})
				fixtures := baseFixtures()
				for i := range fixtures {
					fixtures[i].Attributes["env.zone"] = known("restricted", contract.ProvPlatform)
					fixtures[i].Expect["con.zone"] = pdp.VerdictNoMatch
				}
				// con.zone matches the export fixture's action selector on
				// nothing, and on the refund fixture the known "restricted"
				// zone makes the negation NO_MATCH.

				// Anti-vacuity: prove the flip this row is about actually
				// occurs. With env.zone absent, the declared handling makes
				// the inner condition NO_MATCH and k_not turns the policy
				// MATCH, so the gate IS looking at a NO_MATCH-to-MATCH flip
				// and accepting it deliberately.
				bundle, err := pdp.BuildBundle(&d.Policy)
				if err != nil {
					t.Fatal(err)
				}
				rt, err := pdp.NewRuntime(ctx, bundle, pdp.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				baseline, err := rt.Eval(ctx, fixtures[0].Attributes)
				if err != nil {
					t.Fatal(err)
				}
				if got := baseline.Outcomes["con.zone"].Verdict; got != pdp.VerdictNoMatch {
					t.Fatalf("baseline con.zone is %s, this row needs NO_MATCH for the flip to exist", got)
				}
				absentAttrs := make(contract.AttributeSet, len(fixtures[0].Attributes))
				for k, v := range fixtures[0].Attributes {
					absentAttrs[k] = v
				}
				absentAttrs["env.zone"] = contract.Absent(contract.ProvPlatform, 1, time.Unix(1_700_000_000, 0).UTC())
				flipped, err := rt.Eval(ctx, absentAttrs)
				if err != nil {
					t.Fatal(err)
				}
				if got := flipped.Outcomes["con.zone"].Verdict; got != pdp.VerdictMatch {
					t.Fatalf("con.zone with env.zone absent is %s, this row needs MATCH for the flip to exist", got)
				}

				if checks, err := gateTriState(ctx, rt, &d.Policy, fixtures); err != nil {
					t.Fatalf("the gate refused the author's declared absence semantics after %d checks: %v", checks, err)
				}

				// And the whole shape publishes, which is the claim the gate's
				// false refusal was denying.
				opts := publishOptions(t, priv)
				opts.Fixtures = fixtures
				if _, findings, err := Publish(ctx, d, cat, opts); err != nil {
					t.Fatalf("a legitimate NOT-over-declared-absence policy did not publish: %v\nfindings: %v", err, findings)
				}
			},
		},
	}
	for _, row := range rows {
		t.Run(row.name, row.run)
	}
}

// TestCrossRootPublicationIsRefused covers both directions of the separate
// authority roots, which is the invariant that stops an organization
// permission from touching a system constraint.
func TestCrossRootPublicationIsRefused(t *testing.T) {
	ctx := context.Background()
	cat := baseCatalog(t)
	_, systemPriv := testKeys(t)
	_, orgPriv := otherKeys(t)

	t.Run("a system document cannot be published under the organization root", func(t *testing.T) {
		opts := publishOptions(t, systemPriv)
		opts.Root = pdp.RootOrganization
		_, _, err := Publish(ctx, baseDocument(t), cat, opts)
		if err == nil {
			t.Fatal("a system document was published under the organization root")
		}
		if !strings.Contains(err.Error(), "separate signing authorities") {
			t.Fatalf("the refusal should name the separation of roots, got: %v", err)
		}
	})

	t.Run("an organization document cannot be published under the system root", func(t *testing.T) {
		d := documentWith(t, cat, func(_ *Metadata, doc *pdp.Document) {
			doc.Root = pdp.RootOrganization
			for i := range doc.Policies {
				doc.Policies[i].Root = pdp.RootOrganization
				doc.Policies[i].PierceableBy = nil
			}
		})
		if err := Validate(d, cat).Error(); err != nil {
			t.Fatalf("the organization fixture must itself be valid: %v", err)
		}
		opts := publishOptions(t, orgPriv)
		opts.Root = pdp.RootSystem
		if _, _, err := Publish(ctx, d, cat, opts); err == nil {
			t.Fatal("an organization document was published under the system root")
		}
	})

	t.Run("an artifact signed for one root does not verify under the other", func(t *testing.T) {
		// Published correctly under the ORGANIZATION root, then presented to a
		// trust store that authorizes the key for the SYSTEM root only. The
		// signature is genuine; the authority is not.
		d := documentWith(t, cat, func(_ *Metadata, doc *pdp.Document) {
			doc.Root = pdp.RootOrganization
			for i := range doc.Policies {
				doc.Policies[i].Root = pdp.RootOrganization
				doc.Policies[i].PierceableBy = nil
			}
		})
		opts := publishOptions(t, orgPriv)
		opts.Root = pdp.RootOrganization
		opts.KeyID = "org-key-1"
		art, _, err := Publish(ctx, d, cat, opts)
		if err != nil {
			t.Fatalf("the organization document must publish under its own root: %v", err)
		}
		orgPub, _ := otherKeys(t)
		wrongRoot := pdp.NewTrustStore()
		wrongRoot.Authorize(pdp.RootSystem, "org-key-1", orgPub)
		raw, err := json.Marshal(art)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadArtifact(raw, wrongRoot); err == nil {
			t.Fatal("an organization artifact verified against a store that authorizes its key for the system root only")
		}

		// And the same artifact against a store that authorizes the key for the
		// right root does load, so the refusal above is about the root and not
		// about the artifact being broken.
		rightRoot := pdp.NewTrustStore()
		rightRoot.Authorize(pdp.RootOrganization, "org-key-1", orgPub)
		if _, err := LoadArtifact(raw, rightRoot); err != nil {
			t.Fatalf("the artifact does not load under its own root either, so the previous refusal proved nothing: %v", err)
		}
	})
}

// TestASwappedSourceIsRefused closes render-back loss on the load path. An
// artifact whose source has been replaced still carries a valid bundle, so
// nothing but recompiling the source can notice that what an operator reads
// back is not what is enforced.
func TestASwappedSourceIsRefused(t *testing.T) {
	art, trust, priv := mustPublish(t)
	cat := baseCatalog(t)

	other := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
		policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.amount_cents", pdp.OpLe, 999999999)
	})
	otherSource, err := Render(other)
	if err != nil {
		t.Fatal(err)
	}

	var w wireArtifact
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	w.Source = string(otherSource)

	t.Run("without re-signing", func(t *testing.T) {
		tampered, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadArtifact(tampered, trust); err == nil {
			t.Fatal("an artifact whose source was swapped verified")
		}
	})

	t.Run("re-signed by the legitimate key", func(t *testing.T) {
		// The stronger case. Somebody who holds the signing key swaps the
		// source and re-signs: the signature is valid, the digest is
		// recomputed, and only recompiling the source catches it.
		resigned := &Artifact{
			source: []byte(w.Source), bundle: w.Bundle, report: w.Report, provenance: w.Provenance,
		}
		digest, err := contract.ExactDigest(resigned.view())
		if err != nil {
			t.Fatal(err)
		}
		resigned.digest = digest
		payload, err := contract.ExactJSON(resigned.view())
		if err != nil {
			t.Fatal(err)
		}
		resigned.keyID = "system-key-1"
		resigned.signature = ed25519.Sign(priv, payload)

		err = resigned.verify(trust)
		if err == nil {
			t.Fatal("an artifact with a swapped and re-signed source verified, so what renders back need not be what is enforced")
		}
		if !strings.Contains(err.Error(), "compiles to a different module") && !strings.Contains(err.Error(), "digests to") {
			t.Fatalf("the refusal should name the source-to-module mismatch, got: %v", err)
		}
	})
}

// TestATamperedReportIsRefused proves the gauntlet evidence is covered by the
// signature rather than carried beside it.
func TestATamperedReportIsRefused(t *testing.T) {
	art, trust, _ := mustPublish(t)
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	var w wireArtifact
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	// Claim a gate passed with more checks than it performed. Nothing about the
	// bundle changes.
	w.Report.Results[0].Checks = 9999
	tampered, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArtifact(tampered, trust); err == nil {
		t.Fatal("an artifact whose gauntlet report was edited verified")
	}
}

// TestUnicodeNormalizationCannotForgeAnArtifact is the #3572 attack shape run
// against the artifact signature rather than against the document digest: the
// signed payload must be the exact bytes, so an NFD twin of an approved
// document must not satisfy the signature over its NFC original.
func TestUnicodeNormalizationCannotForgeAnArtifact(t *testing.T) {
	ctx := context.Background()
	cat := baseCatalog(t)
	trust, priv := systemTrust(t)

	build := func(literal string) *Document {
		return documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
			policyByIDIn(d, "perm.refund").Where = pdp.And(
				pdp.Compare("args.amount_cents", pdp.OpLe, 500000),
				pdp.Compare("args.note", pdp.OpEq, literal).HandlingAbsence(pdp.AbsentIsUnknown),
			)
		})
	}
	approved := build("café")
	twin := build(norm.NFD.String("café"))

	opts := publishOptions(t, priv)
	opts.Fixtures = fixturesWithNote("caf\u00e9")
	art, _, err := Publish(ctx, approved, cat, opts)
	if err != nil {
		t.Fatalf("the approved document must publish: %v", err)
	}
	twinSource, err := Render(twin)
	if err != nil {
		t.Fatal(err)
	}
	if string(twinSource) == string(art.Source()) {
		t.Fatal("the two documents render identically, so the encoder has normalized and this test is asserting nothing")
	}

	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	var w wireArtifact
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	w.Source = string(twinSource)
	forged, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArtifact(forged, trust); err == nil {
		t.Fatal("an NFD twin of the approved source satisfied the signature over its NFC original")
	}
}

func TestActivationLifecycle(t *testing.T) {
	ctx := context.Background()
	cat := baseCatalog(t)
	trust, priv := systemTrust(t)
	api, err := NewAPI(cat, trust)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_200, 0).UTC()

	v1, _, err := api.Publish(ctx, baseDocument(t), publishOptions(t, priv))
	if err != nil {
		t.Fatalf("v1 must publish: %v", err)
	}

	t.Run("the author cannot activate their own version", func(t *testing.T) {
		if _, err := api.Promote(pdp.RootSystem, v1.Digest(), pid(t, principalAlice), now, "self"); err == nil {
			t.Fatal("the author activated their own document")
		}
	})
	t.Run("a stranger cannot activate it either", func(t *testing.T) {
		if _, err := api.Promote(pdp.RootSystem, v1.Digest(), pid(t, principalCarol), now, "stranger"); err == nil {
			t.Fatal("a principal who is not an approver activated the document")
		}
	})

	act, err := api.Promote(pdp.RootSystem, v1.Digest(), pid(t, principalBob), now, "initial rollout")
	if err != nil {
		t.Fatalf("an approver must be able to activate: %v", err)
	}
	if act.Kind != ActivationPromote || act.PreviousDigest != "" {
		t.Fatalf("unexpected first activation: %+v", act)
	}

	// Render back what is active, and prove it is the source that was signed.
	back, err := api.Render(pdp.RootSystem)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(v1.Source()) {
		t.Fatal("the active document does not render back to the published source")
	}

	// A second version that correctly names its parent.
	v2doc := documentWith(t, cat, func(m *Metadata, d *pdp.Document) {
		d.Version = 2
		m.Supersedes = v1.Digest()
		policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.amount_cents", pdp.OpLe, 250000)
	})
	v2, _, err := api.Publish(ctx, v2doc, publishOptions(t, priv))
	if err != nil {
		t.Fatalf("v2 must publish: %v", err)
	}

	t.Run("a version that does not name the active parent is refused", func(t *testing.T) {
		orphan := documentWith(t, cat, func(m *Metadata, d *pdp.Document) {
			d.Version = 3
			m.Supersedes = "sha256:" + strings.Repeat("00", 32)
		})
		art, _, err := api.Publish(ctx, orphan, publishOptions(t, priv))
		if err != nil {
			t.Fatalf("the orphan must publish; it is activation that refuses it: %v", err)
		}
		if _, err := api.Promote(pdp.RootSystem, art.Digest(), pid(t, principalBob), now, "orphan"); err == nil {
			t.Fatal("a version edited from a digest that is not active was promoted over the active one")
		}
	})

	if _, err := api.Promote(pdp.RootSystem, v2.Digest(), pid(t, principalBob), now, "narrow the refund cap"); err != nil {
		t.Fatalf("v2 must promote: %v", err)
	}

	t.Run("promotion cannot go backwards", func(t *testing.T) {
		if _, err := api.Promote(pdp.RootSystem, v1.Digest(), pid(t, principalBob), now, "back"); err == nil {
			t.Fatal("an older version was promoted over a newer one")
		}
	})

	t.Run("rollback restores a previously activated digest", func(t *testing.T) {
		if _, err := api.Rollback(pdp.RootSystem, v1.Digest(), pid(t, principalBob), now, ""); err == nil {
			t.Fatal("an unexplained rollback was accepted")
		}
		act, err := api.Rollback(pdp.RootSystem, v1.Digest(), pid(t, principalBob), now, "the narrower cap blocked legitimate refunds")
		if err != nil {
			t.Fatalf("rollback to a previously activated digest must work: %v", err)
		}
		if act.Kind != ActivationRollback || act.PreviousDigest != v2.Digest() {
			t.Fatalf("unexpected rollback record: %+v", act)
		}
		active, ok := api.Store().Active(pdp.RootSystem)
		if !ok || active.Digest() != v1.Digest() {
			t.Fatal("the rollback did not change what is active")
		}
	})

	t.Run("a rollback that names no actor is refused", func(t *testing.T) {
		// v2 has been activated before and is not currently active, so the
		// only thing wrong with this rollback is the actor. An unattributed
		// activation record (actor "::") would defeat the audited history
		// that makes emergency changes tolerable.
		if _, err := api.Rollback(pdp.RootSystem, v2.Digest(), contract.ID{}, now, "unattributed emergency"); err == nil {
			t.Fatal("a rollback with a zero actor was accepted, so the audit trail can carry an unattributed activation")
		} else if !strings.Contains(err.Error(), "no actor") {
			t.Fatalf("the refusal should name the missing actor, got: %v", err)
		}
	})
	t.Run("the author cannot roll back to their own version either", func(t *testing.T) {
		if _, err := api.Rollback(pdp.RootSystem, v2.Digest(), pid(t, principalAlice), now, "author self-service"); err == nil {
			t.Fatal("the author rolled back to their own version, which is a route to activating their own policy that Promote refuses")
		} else if !strings.Contains(err.Error(), "separation of author and approver duties") {
			t.Fatalf("the refusal should name the separation of duties, got: %v", err)
		}
	})

	t.Run("rollback to a never-activated digest is refused", func(t *testing.T) {
		never := documentWith(t, cat, func(m *Metadata, d *pdp.Document) {
			d.Version = 9
			m.Supersedes = v2.Digest()
		})
		art, _, err := api.Publish(ctx, never, publishOptions(t, priv))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.Rollback(pdp.RootSystem, art.Digest(), pid(t, principalBob), now, "never activated"); err == nil {
			t.Fatal("a digest that was never activated was rolled back to; it is not a verified digest to return to")
		}
	})

	history := api.Store().History(pdp.RootSystem)
	if len(history) != 3 {
		t.Fatalf("expected three activations in the history, got %d: %+v", len(history), history)
	}
	// The history is a chain, not a list: each entry names what it replaced.
	for i := 1; i < len(history); i++ {
		if history[i].PreviousDigest != history[i-1].Digest {
			t.Fatalf("activation %d says it replaced %s, the previous activation activated %s",
				i, history[i].PreviousDigest, history[i-1].Digest)
		}
	}
}

// TestADeauthorizedKeyStopsActivation proves verification at activation is not
// redundant with verification at admission. A key can be withdrawn between the
// two, and that is the moment it matters.
func TestADeauthorizedKeyStopsActivation(t *testing.T) {
	ctx := context.Background()
	cat := baseCatalog(t)
	pub, priv := testKeys(t)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootSystem, "system-key-1", pub)
	store, err := NewStore(trust)
	if err != nil {
		t.Fatal(err)
	}
	art, _, err := Publish(ctx, baseDocument(t), cat, publishOptions(t, priv))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Admit(art); err != nil {
		t.Fatalf("admission must succeed while the key is authorized: %v", err)
	}
	// Withdraw the key by rebuilding the store's trust with a different key
	// under the same identifier, which is what a rotation without re-signing
	// looks like from the verifier's side.
	otherPub, _ := otherKeys(t)
	trust.Authorize(pdp.RootSystem, "system-key-1", otherPub)
	if _, err := store.Promote(pdp.RootSystem, art.Digest(), pid(t, principalBob), time.Now(), "after rotation"); err == nil {
		t.Fatal("an artifact signed by a key that no longer verifies was activated")
	}
}
