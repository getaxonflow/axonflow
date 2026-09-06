// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"axonflow/platform/decision/conformance"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/replay"
)

// The committed replay fixture, and how it is kept honest.
//
// # WHY THE FIXTURE IS GENERATED FROM THE CONFORMANCE WORLD
//
// A replay artifact hand-written for this package would be a second policy set
// that nothing else evaluates, and a replay tool that agreed with it would
// have proved only that it agrees with itself. The fixture is therefore built
// from the ADR-065 conformance corpus - the same documents, registry and
// enforcement profile the gate-4/5/6/14/15 suites run against - so the
// artifact on disk is a projection of a policy set the rest of the module
// already tests.
//
// # THE TWO CHECKS THAT MAKE THE FIXTURE EVIDENCE RATHER THAN DECORATION
//
//  1. CONSISTENCY. TestTheCommittedFixtureIsWhatTheGeneratorProduces
//     regenerates the artifact and compares bytes, so an edit to the corpus
//     that moves a digest fails here rather than being carried silently.
//  2. FIDELITY. A regeneration gate proves the file matches the generator and
//     nothing else - a generator with a bug produces a file that matches its
//     own bug. So TestReplayReproducesEveryLiveDecision decides every sample
//     through the LIVE conformance engine and compares that to what replay
//     produces from the file. The committed expectations are pinned to a
//     running evaluator, not merely to themselves.
//
// # THE SIGNING KEY
//
// Derived from a published constant, in the open, on purpose. It is a fixture
// key and nothing else: it signs one artifact whose only consumer is this
// package's tests, so committing a private half would be pointless secrecy
// while committing NOTHING would make the fixture unregenerable. It is not a
// trust anchor and no deployment authorizes it.

const fixtureKeySeedPhrase = "axonflow/platform/decision/replay fixture signing key v1: "

func fixtureKey(t *testing.T, root pdp.Root) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte(fixtureKeySeedPhrase + string(root)))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

const (
	environmentPath = "testdata/environment.json"
	samplesDir      = "testdata/samples"
)

// sampleSpec names one sampled decision in fixture terms.
type sampleSpec struct {
	caseID      string
	description string
	scenario    conformance.Scenario
}

// fixtureSamples is the sampled population.
//
// Chosen for SPREAD rather than for coverage of the corpus: the point of a
// replay fixture is that the tool reproduces decisions of every operational
// class, and a fixture whose samples all denied would be reproduced perfectly
// by a tool that always returned DENY. The floor that enforces the spread is
// asserted in TestTheSampledPopulationSpansTheDecisionSurface, so a future
// edit that flattened it fails rather than quietly weakening every other test
// in this file.
//
// The two spend samples are a matched pair: identical in every field except
// args.amount_cents, which is what makes "a changed input changes the
// decision" attributable to the change rather than to two unrelated requests.
func fixtureSamples() []sampleSpec {
	return []sampleSpec{
		{
			caseID:      "read-only-has-no-matching-permission",
			description: "a document search nothing grants: not applicable is a refusal, not a constraint",
			scenario: conformance.Scenario{
				RequestID: "req_replay_read_only", Principal: "alice", Action: "T3",
				Args: map[string]any{"query": "invoices"},
			},
		},
		{
			caseID:      "spend-below-threshold",
			description: "a refund under the approval threshold; the matched pair's control arm",
			scenario: conformance.Scenario{
				RequestID: "req_replay_spend_low", Principal: "alice", Action: "T1", Resource: "SUP-42",
				Args: map[string]any{"amount_cents": 1000},
			},
		},
		{
			caseID:      "spend-above-threshold",
			description: "the same refund above the threshold; identical to its pair but for the amount",
			scenario: conformance.Scenario{
				RequestID: "req_replay_spend_high", Principal: "alice", Action: "T1", Resource: "SUP-42",
				Args: map[string]any{"amount_cents": 300000},
			},
		},
		{
			caseID:      "personal-data-egress-denied",
			description: "a personal-data export outside legal and compliance",
			scenario: conformance.Scenario{
				RequestID: "req_replay_pii_egress", Principal: "alice", Action: "T2",
				Args: map[string]any{"segment": "all"},
			},
		},
		{
			caseID:      "unresolvable-attribute-is-indeterminate",
			description: "the risk signal could not be resolved, so a policy that reads it cannot be evaluated",
			scenario: conformance.Scenario{
				RequestID: "req_replay_unknown_signal", Principal: "alice", Action: "T1", Resource: "SUP-42",
				Args: map[string]any{"amount_cents": 300000},
				Overrides: map[string]*contract.Attribute{
					conformance.PathSignalRisk: conformance.UnknownAttr(conformance.PathSignalRisk, contract.ReasonResolutionFailed),
				},
			},
		},
	}
}

// generateEnvironment builds the pinned environment from the conformance
// corpus, through the shipped build-and-sign path.
func generateEnvironment(t *testing.T) *replay.Environment {
	t.Helper()
	env := &replay.Environment{
		SchemaVersion:      replay.EnvironmentSchemaVersion,
		Registry:           conformance.Registry(),
		PEP:                conformance.DefaultPEP(),
		ApprovalTTLSeconds: int64((15 * time.Minute).Seconds()),
	}
	for _, doc := range []*pdp.Document{conformance.SystemDocument(), conformance.OrganizationDocument()} {
		bundle, err := pdp.BuildBundle(doc)
		if err != nil {
			t.Fatalf("building the %s bundle: %v", doc.Root, err)
		}
		pub, priv := fixtureKey(t, doc.Root)
		keyID := string(doc.Root) + "-replay-fixture-key"
		if err := bundle.Sign(keyID, priv); err != nil {
			t.Fatalf("signing the %s bundle: %v", doc.Root, err)
		}
		env.Roots = append(env.Roots, replay.RootArtifact{
			Root: doc.Root, Bundle: bundle, Document: doc,
			TrustedKeyID: keyID, TrustedPublicKey: hex.EncodeToString(pub),
		})
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("the generated environment does not validate: %v", err)
	}
	return env
}

// generateRecords builds one record per sample, with the expected decision
// taken from a LIVE conformance world rather than from anything this file
// asserts by hand.
func generateRecords(t *testing.T, env *replay.Environment) []*replay.Record {
	t.Helper()
	world, err := conformance.NewWorld(context.Background())
	if err != nil {
		t.Fatalf("building the live conformance world: %v", err)
	}
	envDigest, err := env.Digest()
	if err != nil {
		t.Fatalf("digesting the environment: %v", err)
	}

	var out []*replay.Record
	for _, s := range fixtureSamples() {
		req, err := world.Request(s.scenario)
		if err != nil {
			t.Fatalf("building the request for %s: %v", s.caseID, err)
		}
		decision, err := world.Engine.Decide(context.Background(), req)
		if err != nil {
			t.Fatalf("deciding %s on the live world: %v", s.caseID, err)
		}
		out = append(out, &replay.Record{
			SchemaVersion:     replay.RecordSchemaVersion,
			CaseID:            s.caseID,
			Description:       s.description,
			EnvironmentDigest: envDigest,
			BundlePins:        env.BundleDigests(),
			Request:           req,
			Expected:          decision,
		})
	}
	return out
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("encoding the fixture: %v", err)
	}
	return append(raw, '\n')
}

func samplePath(caseID string) string { return filepath.Join(samplesDir, caseID+".json") }

// TestTheCommittedFixtureIsWhatTheGeneratorProduces is the consistency half.
//
// Set AXONFLOW_UPDATE_FIXTURES=1 to rewrite the artifact after a deliberate
// corpus change. Reviewing that diff is the point: a moved bundle digest is a
// compatibility event for every stored artifact digest, exactly as
// conformance/pins_test.go says.
func TestTheCommittedFixtureIsWhatTheGeneratorProduces(t *testing.T) {
	env := generateEnvironment(t)
	records := generateRecords(t, env)

	want := map[string][]byte{environmentPath: encode(t, env)}
	for _, rec := range records {
		want[samplePath(rec.CaseID)] = encode(t, rec)
	}

	if os.Getenv("AXONFLOW_UPDATE_FIXTURES") == "1" {
		if err := os.MkdirAll(samplesDir, 0o755); err != nil {
			t.Fatalf("creating %s: %v", samplesDir, err)
		}
		for path, raw := range want {
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatalf("writing %s: %v", path, err)
			}
		}
		t.Fatalf("fixtures rewritten; re-run without AXONFLOW_UPDATE_FIXTURES and review the diff")
	}

	for path, raw := range want {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v\nRegenerate with AXONFLOW_UPDATE_FIXTURES=1 go test ./replay/", path, err)
		}
		if string(got) != string(raw) {
			t.Errorf("%s is not what the generator produces.\n"+
				"If the conformance corpus was edited deliberately, regenerate with AXONFLOW_UPDATE_FIXTURES=1 and review the diff in the same commit; "+
				"if it was not, the compiler or the encoder moved for unchanged input, which is a compatibility event for every stored artifact digest.", path)
		}
	}

	// The generated set and the committed set must be the same set. Comparing
	// only the files the generator produced would leave a stale sample on disk
	// unnoticed - and a stale sample is a record pinned to an environment that
	// no longer exists, which the pin check would then refuse for a reason
	// nobody could explain.
	entries, err := os.ReadDir(samplesDir)
	if err != nil {
		t.Fatalf("reading %s: %v", samplesDir, err)
	}
	var onDisk []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			onDisk = append(onDisk, filepath.Join(samplesDir, e.Name()))
		}
	}
	var generated []string
	for _, rec := range records {
		generated = append(generated, samplePath(rec.CaseID))
	}
	sort.Strings(onDisk)
	sort.Strings(generated)
	if fmt.Sprint(onDisk) != fmt.Sprint(generated) {
		t.Errorf("the committed samples are %v and the generator produces %v", onDisk, generated)
	}
}
