// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package sdkcompat

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"axonflow/platform/shared/plugincompat"
)

// The Go detector beside this file closes the class in Go, and #3712's own text
// is about two Go literals. But the SAME values are restated in the two
// published OpenAPI specs, as the `example:` blocks on `SDKCompatInfo` -- and
// when R3 looked, both had drifted:
//
//   - docs/api/agent-api.yaml advertised a MINIMUM of python 6.0.0,
//     typescript 5.0.0, go 5.0.0, java 5.0.0. The real floor is 8.0.0 for all
//     four. Its schema description enumerated four languages and omitted rust
//     entirely, which has been in the map since the 9.7.0 train.
//   - docs/api/orchestrator-api.yaml gave a single-key example, and its
//     recommended version was 9.0.0 against a real 9.2.0.
//
// That is the same defect as #3712 in a different file format, and it is the
// copy a CUSTOMER reads: the spec is published, the Go literal is not. So
// correcting the values would have been the smaller half of the job. This test
// is the other half.
//
// PLUGINCOMPAT WAS ADDED TO THE SUBJECT ON THE v10.4.0 PREP TRAIN, and the
// reason is the measurement that adding it produced. Scoped to SDKCompatInfo,
// this test watched two of the four example blocks that /health's compat
// section restates. The other two were `PluginCompatInfo`, and with nothing
// watching them the agent spec had sat at openclaw 2.0.0 / claude-code 1.0.0 /
// cursor 1.0.0 / codex 1.0.0 -- all four BELOW THE FLOOR the platform actually
// enforces, by four minors each (the floors are 2.4.0 and 1.4.0), and missing
// claude-desktop, which joined the map on the 9.7.0 train -- while the
// orchestrator spec carried no example at all. A
// published contract that names a version below the floor tells a reader their
// client is supported at a version that receives a downgrade warning on every
// governed call.
//
// It is one traversal over both schemas rather than a second copy of this
// parser in plugincompat's own package: a second copy is the shape both
// sdkcompat and plugincompat exist to end, and it would have the same blind
// spot -- whichever schema its author did not think of. The import is
// test-only, so no production dependency is created between the two packages.
//
// Both specs reach the community mirror (docs/ is synced except for a short
// list of subdirectories, none of which is docs/api), so this runs in both
// trees. The paths are located from the repository root the sibling test
// derives, not from a relative path that breaks if the package moves.
//
// RUN IT WITH `-count=1` LOCALLY. The specs live outside this Go module, so the
// toolchain does not record them as inputs to this test and the result cache
// does not notice when one changes: populate the cache, break a value in
// docs/api/agent-api.yaml, re-run `go test ./shared/sdkcompat/`, and it answers
// `ok (cached)`. CI is unaffected -- test.yml's platform-packages lane already
// passes `-count=1` -- but a developer checking the claim two lines above, that
// a stale example fails rather than misleading a reader, gets a false pass the
// obvious way. Stated here rather than in a review comment because this comment
// is what that developer is reading.
func TestOpenAPIExamplesMatchTheSourceOfTruth(t *testing.T) {
	root := repoRoot(t)

	specs := []string{
		filepath.Join("docs", "api", "agent-api.yaml"),
		filepath.Join("docs", "api", "orchestrator-api.yaml"),
	}

	// schema name -> property name -> the canonical map /health serves.
	want := map[string]map[string]map[string]string{
		"SDKCompatInfo": {
			"min_sdk_version":         MinVersions(),
			"recommended_sdk_version": RecommendedVersions(),
		},
		"PluginCompatInfo": {
			"min_plugin_version":         plugincompat.MinVersions(),
			"recommended_plugin_version": plugincompat.RecommendedVersions(),
		},
	}
	fields := 0
	for schema, byField := range want {
		for field, m := range byField {
			if len(m) == 0 {
				t.Fatalf("%s.%s: the canonical map is empty, so every comparison below would be vacuous", schema, field)
			}
			fields++
		}
	}

	checked := 0
	for _, rel := range specs {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			// Not a skip. A spec that cannot be read is a spec nobody is
			// checking, which is how both of these drifted in the first place.
			t.Errorf("%s: %v", rel, err)
			continue
		}

		// `Example` is decoded as a yaml.Node and type-checked only for the
		// properties this test is about. Decoding every sibling property as
		// map[string]string made the WHOLE spec unparseable the moment anyone
		// added an ordinary property with a scalar example - `example: "see the
		// runbook"` - and the resulting error blamed the parser for a change
		// that has nothing to do with the compat maps.
		//
		// `schemas` is a map rather than a struct with one named field per
		// schema, because a struct is the census-bounded-by-its-author shape
		// this test just had to be widened out of.
		var doc struct {
			Components struct {
				Schemas map[string]struct {
					Properties map[string]struct {
						Example yaml.Node `yaml:"example"`
					} `yaml:"properties"`
				} `yaml:"schemas"`
			} `yaml:"components"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s: parsing: %v", rel, err)
			continue
		}

		for schemaName, byField := range want {
			schema, ok := doc.Components.Schemas[schemaName]
			if !ok {
				t.Errorf("%s: no components.schemas.%s found; either the schema was renamed or this "+
					"test is reading the wrong path, and in both cases it is asserting nothing", rel, schemaName)
				continue
			}
			if len(schema.Properties) == 0 {
				t.Errorf("%s: components.schemas.%s carries no properties", rel, schemaName)
				continue
			}

			for field, canonical := range byField {
				prop, ok := schema.Properties[field]
				if !ok {
					t.Errorf("%s: %s has no %q property", rel, schemaName, field)
					continue
				}
				if prop.Example.IsZero() {
					t.Errorf("%s: %s.%s carries no example block. An absent example is not a stale one, but it is "+
						"also not a checked one -- give it the real map so a reader gets the values this platform serves",
						rel, schemaName, field)
					continue
				}
				example := map[string]string{}
				if err := prop.Example.Decode(&example); err != nil {
					t.Errorf("%s: %s.%s example is not a map of strings (%v); it is the block a client copies, so it "+
						"must carry the per-client map this platform serves", rel, schemaName, field, err)
					continue
				}
				checked++
				if len(example) != len(canonical) {
					t.Errorf("%s: %s.%s example has %d entries, the canonical map holds %d (example=%v canonical=%v)",
						rel, schemaName, field, len(example), len(canonical), example, canonical)
				}
				for id, w := range canonical {
					if got, ok := example[id]; !ok {
						t.Errorf("%s: %s.%s example is missing %q (canonical holds %q); a published spec that omits a "+
							"client tells its readers that client is not supported", rel, schemaName, field, id, w)
					} else if got != w {
						t.Errorf("%s: %s.%s example[%q] = %q; canonical holds %q -- the published contract disagrees with "+
							"what /health serves", rel, schemaName, field, id, got, w)
					}
				}
				for id := range example {
					if _, ok := canonical[id]; !ok {
						t.Errorf("%s: %s.%s example has key %q that the canonical map does not", rel, schemaName, field, id)
					}
				}
			}
		}
	}

	// Anti-vacuity: two specs times four fields. Anything less means a spec was
	// unreadable, renamed, or lost its example block, and the loop above passed
	// by not comparing.
	if checked != len(specs)*fields {
		t.Errorf("compared %d example blocks, expected %d (one per field per spec); the rest were skipped, "+
			"and a skipped comparison is not a passing one", checked, len(specs)*fields)
	}
}
