// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// THE PAYLOAD CORPUS IS A DECISION-PLANE FACT, NOT AN ENTERPRISE ONE (#3859).
//
// # WHY IT LIVES IN A FIXTURE HERE AND NOT IN THE CANARY TEMPLATE
//
// These payloads assert something about DETECTORS: each names a `static_policies`
// row seeded by `migrations/core/031` and `059`, and TestEveryCanaryPayloadFires
// TheRowItNames compiles those seeded patterns and proves the payload trips the
// row it claims. Those migrations reach the community mirror, the engine that
// evaluates them ships in both editions, and so the property is true of the
// community build too.
//
// It used to be read out of `infrastructure/cloudformation/synthetic-monitoring-
// decision-shadow.yaml`, which the sync STRIPS. The result was that
// `platform/decision` failed on the mirror - `go test ./...` there could not
// open the template - while every enterprise board stayed green, because the
// community job only runs on the public repository and nothing publishes until
// a sync. The community edition also could not verify its own detector corpus
// at all, which is the more interesting half.
//
// The PLANE MAP is the opposite kind of fact and stays where it was: which probe
// drives which plane in which posture describes where the canary is DEPLOYED,
// and community has no such deployment. Those tests are enterprise-tagged and
// keep reading the template - see decision_shadow_canary_shapes_test.go.
//
// # THE COPY THIS CREATES, AND WHAT STOPS IT DRIFTING
//
// A fixture is a second copy of the corpus, and two copies can disagree - the
// argument made against packaging in #3694. TestTheCorpusFixtureMatchesThe
// Template (enterprise-tagged, beside the template it reads) fails if they
// diverge. The fixture is what this module tests; the template is what deploys;
// the guard makes shipping a disagreement impossible.
const canaryCorpusFixture = "testdata/canary_payload_corpus.json"

type canaryPayload struct {
	ID       string `json:"id"`
	Row      string `json:"row"`
	Category string `json:"category"`
	Expect   string `json:"expect"`
	Text     string `json:"text"`
}

// canaryPayloads reads the corpus fixture.
//
// Every failure here is FATAL rather than a skip. A corpus that cannot be read
// makes every assertion built on it vacuous, and a test suite that skips when
// its input is missing reports the same green as one that checked.
func canaryPayloads(t *testing.T) []canaryPayload {
	t.Helper()
	raw, err := os.ReadFile(canaryCorpusFixture)
	if err != nil {
		t.Fatalf("reading %s: %v.\n\nThis fixture is the canary's payload corpus and the "+
			"subject of every assertion below; without it they would all pass over nothing "+
			"(#3859).", canaryCorpusFixture, err)
	}
	var out []canaryPayload
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding %s: %v", canaryCorpusFixture, err)
	}
	if len(out) == 0 {
		t.Fatalf("%s decoded to zero payloads; the fixture is present but empty, which is "+
			"indistinguishable from a corpus that passes every check", canaryCorpusFixture)
	}
	return out
}

// sortedStringSet renders a set for a failure message, in a stable order so two
// runs of the same failure read identically.
func sortedStringSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTheCanaryPayloadCorpusIsAdversarial refuses a benign-only corpus.
//
// A canary that sends only well-formed, policy-clean text proves the plumbing
// and NOTHING about the diff: with no row matched, both engines produce an empty
// verdict, the pair classifies `match`, and the plane accumulates a denominator
// made entirely of comparisons that could not have disagreed. The window would
// then be non-vacuous and worthless at the same time, which is the most
// expensive possible outcome - it would satisfy the gate.
//
// So the corpus must name real seeded rows, and it must name rows from more than
// one category: a corpus that fires only `sys_pii_ssn` twelve times measures one
// detector.
func TestTheCanaryPayloadCorpusIsAdversarial(t *testing.T) {
	payloads := canaryPayloads(t)
	if len(payloads) == 0 {
		t.Fatal("the canary declares no payloads; the extraction is broken or the corpus is gone")
	}

	categories := map[string]bool{}
	rows := map[string]bool{}
	denies := 0
	allows := 0
	for _, p := range payloads {
		if p.Row != "" {
			rows[p.Row] = true
		}
		if p.Category != "" {
			categories[p.Category] = true
		}
		switch p.Expect {
		case "deny":
			denies++
		case "allow":
			allows++
		default:
			t.Errorf("payload %q declares expect=%q, which is neither allow nor deny; the "+
				"probe's evidence predicate reads this", p.ID, p.Expect)
		}
	}

	if len(rows) < 6 {
		t.Errorf("the corpus names only %d distinct seeded policy rows (%v). A canary that "+
			"exercises one or two detectors gives every plane a denominator made of one "+
			"question asked repeatedly.", len(rows), sortedStringSet(rows))
	}
	if len(categories) < 3 {
		t.Errorf("the corpus spans only %d policy categories (%v); at least PII, SQL injection "+
			"and dangerous-command should be represented, because the legacy engines resolve "+
			"their actions from different columns",
			len(categories), sortedStringSet(categories))
	}
	if denies == 0 {
		t.Error("no payload expects a DENY. Every comparison would then be on the allow path, " +
			"and a translation that got denial wrong would never be measured.")
	}
	if allows == 0 {
		t.Error("no payload expects an ALLOW. A plane whose every observation is a block is a " +
			"plane whose allow path is unmeasured - and the allow path is where an " +
			"obligation-vocabulary difference shows up, which is what all six UNEXPLAINED " +
			"comparisons on the v10.4.0 gate (b) run turned out to be.")
	}
}
