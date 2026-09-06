// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package heartbeat_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"axonflow/platform/shared/deploymode"
	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/heartbeat"
)

// THE PLATFORM SIDE OF THE CROSS-MODULE VOCABULARY PIN.
//
// # WHAT THIS CLOSES
//
// The checkpoint receiver validates `component` against a closed allowlist and
// answers HTTP 400 on anything else — and the emitter contract is to SWALLOW a
// non-2xx, so the symptom of a mismatch is a binary that silently never appears
// in any analytics, with no error anywhere. Before this test, the checkpoint
// package pinned its own copy against a Go literal and nothing pinned the
// EMITTER's copy at all: renaming heartbeat.ComponentGatewayAdapters to
// "gateway_adapters" passed every test in the tree while the gateway-adapters
// binary would have 400'd on every ping it ever sent.
//
// # WHY IT GOES THROUGH THE DOC AND NOT THROUGH A GO IMPORT
//
// ee/platform/checkpoint-service is a separate Go module and this one cannot
// import it. Adding a `replace` would drag the whole platform dependency tree
// into a Lambda AND break that Lambda's image build, which resolves a
// filesystem replace by reading a path the dependency layer does not have.
//
// docs/TELEMETRY_CONTRACT.md's vocab blocks are already held equal to the
// checkpoint Go source by TestDocsVocabularyTablesMatchTheGoSource in
// ee/platform/checkpoint-service/pkg/telemetry. Reading the same blocks here
// makes the doc the meeting point of two modules that cannot see each other,
// and BOTH links are enforced tests — so a rename on either side reddens
// something.
//
// # ANTI-VACUITY
//
// A missing file, a missing marker, an unparseable line and an empty parse are
// all FATAL. A pin that reads nothing, compares nothing and reports success is
// the exact failure mode a pin exists to prevent.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// .../platform/shared/heartbeat/vocabulary_pin_test.go
	root := filepath.Dir(thisFile)
	for i := 0; i < 3; i++ {
		root = filepath.Dir(root)
	}
	return root
}

// readVocabBlock extracts one `<!-- vocab:<name>:begin -->` block from the
// contract doc as a sorted-as-written list.
func readVocabBlock(t *testing.T, marker string) []string {
	t.Helper()
	const path = "docs/TELEMETRY_CONTRACT.md"
	data, err := os.ReadFile(filepath.Join(repoRoot(t), path))
	if err != nil {
		t.Fatalf("read %s: %v — the file this vocabulary is pinned against is gone, "+
			"which is itself the drift this test exists to catch", path, err)
	}
	body := string(data)

	open := "<!-- vocab:" + marker + ":begin -->"
	close := "<!-- vocab:" + marker + ":end -->"
	start := strings.Index(body, open)
	if start < 0 {
		t.Fatalf("%s has no %s marker — the table moved or was renamed, and this test "+
			"would otherwise check nothing and report success", path, open)
	}
	rest := body[start+len(open):]
	end := strings.Index(rest, close)
	if end < 0 {
		t.Fatalf("%s: %s is never closed by %s", path, open, close)
	}

	var out []string
	for _, line := range strings.Split(rest[:end], "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "- `") || !strings.HasSuffix(line, "`") {
			t.Fatalf("%s: unparseable line %q inside the %s block; the expected shape is \"- `value`\"",
				path, line, marker)
		}
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(line, "- `"), "`"))
	}
	if len(out) == 0 {
		t.Fatalf("%s: the %s block is empty; an empty list compares equal to an empty "+
			"vocabulary and this check would be vacuous", path, marker)
	}
	return out
}

// TestComponentVocabularyMatchesTheContract pins every Component* constant the
// three emitters bind to against the component list the receiver validates.
//
// Mutation: rename heartbeat.ComponentGatewayAdapters to "gateway_adapters" —
// this fails, where before the change it passed everywhere.
func TestComponentVocabularyMatchesTheContract(t *testing.T) {
	documented := readVocabBlock(t, "component")

	// A CENSUS, not a list retyped here. AllComponents() is built from the
	// constants themselves, so a fourth emitter added to that package lands in
	// this comparison automatically and the pin fails until the receiving
	// contract knows about it. Enumerating them by hand would have gone on
	// passing while the new component's pings were answered HTTP 400 — which
	// this emitter swallows, so nothing else would have said so.
	emitted := heartbeat.AllComponents()
	if len(emitted) == 0 {
		t.Fatal("heartbeat.AllComponents() is empty; the census has nothing to compare")
	}

	if strings.Join(documented, ",") != strings.Join(emitted, ",") {
		t.Errorf("component vocabulary drift between the emitter and the receiving contract.\n"+
			"  emitter (platform/shared/heartbeat): %v\n"+
			"  contract (docs/TELEMETRY_CONTRACT.md, pinned to the checkpoint Go): %v\n"+
			"A component the receiver does not know is answered with HTTP 400, and the emitter "+
			"contract is to swallow a non-2xx — so the symptom of this drift is a binary that "+
			"silently never appears in any analytics.", emitted, documented)
	}
}

// TestEditionVocabularyMatchesTheContract pins the two edition values the
// platform emits against the two the receiver recognises. A typo on either side
// ("enterprize") compiles, ships, and turns every enterprise deployment into
// the receiver's "unknown" bucket with no other symptom.
func TestEditionVocabularyMatchesTheContract(t *testing.T) {
	documented := readVocabBlock(t, "edition")
	emitted := edition.All()

	if strings.Join(documented, ",") != strings.Join(emitted, ",") {
		t.Errorf("edition vocabulary drift.\n"+
			"  emitter (platform/shared/edition): %v\n"+
			"  contract (docs/TELEMETRY_CONTRACT.md, pinned to the checkpoint Go): %v",
			emitted, documented)
	}

	// The build-tagged constant must be one of them, in whichever build this
	// test is running.
	found := false
	for _, v := range emitted {
		if edition.Current == v {
			found = true
		}
	}
	if !found {
		t.Errorf("edition.Current = %q is not in the vocabulary %v", edition.Current, emitted)
	}
}

// TestPlatformDeploymentModeVocabularyMatchesTheContract pins what the emitter
// can put on the wire against what the receiver accepts.
//
// It compares the emitter's REACHABLE OUTPUTS, not a literal: for every
// spelling deploymode recognises, PlatformDeploymentMode() must produce a value
// the contract documents. That is the property that matters — a canonical
// spelling the receiver does not list would silently bucket a real deployment
// as "unknown".
func TestPlatformDeploymentModeVocabularyMatchesTheContract(t *testing.T) {
	documented := map[string]bool{}
	for _, m := range readVocabBlock(t, "platform_deployment_mode") {
		documented[m] = true
	}

	// The emitter folds aliases, so its outputs are the CANONICAL subset. Every
	// one of those must be documented; the doc additionally lists the aliases
	// it accepts on the wire, which the emitter never sends.
	checked := 0
	for _, raw := range recognisedModesForTest(t) {
		t.Setenv("DEPLOYMENT_MODE", raw)
		got := heartbeat.PlatformDeploymentMode()
		if got == "" {
			t.Errorf("DEPLOYMENT_MODE=%q produced an empty wire value; only an UNSET variable may omit the field", raw)
			continue
		}
		if !documented[got] {
			t.Errorf("DEPLOYMENT_MODE=%q makes the emitter send %q, which the receiving contract "+
				"does not list — that value would bucket as \"unknown\" at ingest", raw, got)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no modes were checked; the vocabulary source returned nothing and this test was vacuous")
	}
}

// recognisedModesForTest returns every DEPLOYMENT_MODE spelling the platform
// recognises, from the package that ENFORCES it rather than from a list typed
// here — deriving the input set from a literal would make the test agree with
// whatever it was written against instead of with the system.
func recognisedModesForTest(t *testing.T) []string {
	t.Helper()
	modes := deploymode.RecognisedModes()
	if len(modes) == 0 {
		t.Fatal("deploymode.RecognisedModes() is empty")
	}
	return modes
}
