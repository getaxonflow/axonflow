// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llmdefaults

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot resolves the repository root from this file's location
// (platform/shared/llmdefaults → three levels up).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// communitySynced reports whether this checkout is the product of
// .github/workflows/sync-community-repo.yml (the PUBLIC community mirror)
// rather than the enterprise repo.
//
// Every surface below that the mirror lacks is removed by an rsync --exclude,
// and all of those exclusions are arguments to ONE rsync invocation, so `ee/`
// being gone means the whole exclusion set was applied. That makes this a
// direct observation of the strip mechanism, not a proxy for an edition name,
// which is what keeps a MOVED or RENAMED file from being mistaken for an
// excluded one. (The sync's other mechanism, deletion of `//go:build
// enterprise` .go files, cannot reach any surface here: none of them is a
// build-tagged Go file.)
func communitySynced(t *testing.T, root string) bool {
	t.Helper()
	fi, err := os.Stat(filepath.Join(root, "ee"))
	return err != nil || !fi.IsDir()
}

// configSurface is a non-Go file that carries LLM model defaults and therefore
// drifts independently of the Go constants.
type configSurface struct {
	rel string
	// mirrored records whether the file ships to the public community mirror.
	// A surface the sync strips may be absent, but ONLY on a tree the sync has
	// actually processed. Everywhere else absence still means it was moved or
	// renamed and this list has gone stale.
	mirrored bool
}

// configSurfaces: every entry MUST exist wherever the sync has not removed it
// (a move or rename fails the test so the list stays current) and MUST NOT
// contain a retired model id. Files whose defaults should literally match the
// constants are additionally pinned below.
//
// This test file itself ships to the public mirror, where 5 of these 7 surfaces
// are stripped. It used to t.Errorf unconditionally on an unreadable surface,
// so `go test ./...` from platform/ on a mirror checkout produced 9 hard
// failures. It stayed green in enterprise CI only because test.yml runs the
// whole platform/ tree while the mirror's test-community.yml happens not to
// test this package.
var configSurfaces = []configSurface{
	{"docker-compose.yml", true},
	// --exclude='docker-compose.enterprise.yml'
	{"docker-compose.enterprise.yml", false},
	// --exclude='ee/'
	{"ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml", false},
	// --exclude='infrastructure/'
	{"infrastructure/cloudformation/community-saas-ecs.yaml", false},
	// --exclude='/scripts/deployment/*' (only v9_self_hosted_preflight.sh is re-included)
	{"scripts/deployment/deploy-cloudformation.sh", false},
	// --exclude='/config/*'
	{"config/environments/healthcare.yaml", false},
	// yaml-template string defaults
	{"platform/connectors/config/file_loader.go", true},
}

func TestConfigSurfacesCarryNoRetiredModelIDs(t *testing.T) {
	root := repoRoot(t)
	synced := communitySynced(t, root)

	read, wantRead := 0, 0
	for _, s := range configSurfaces {
		mayBeAbsent := synced && !s.mirrored
		if !mayBeAbsent {
			wantRead++
		}
		path := filepath.Join(root, s.rel)
		data, err := os.ReadFile(path)
		if err != nil {
			if mayBeAbsent {
				continue
			}
			t.Errorf("config surface %s unreadable, and this checkout still has everything the "+
				"community sync strips, so it was moved or renamed rather than excluded (update "+
				"configSurfaces): %v", s.rel, err)
			continue
		}
		read++
		content := string(data)
		for _, retired := range RetiredModelIDs {
			if strings.Contains(content, retired) {
				t.Errorf("%s still references retired model id %q — replace with llmdefaults.AnthropicModel/BedrockModel (%s / %s)",
					s.rel, retired, AnthropicModel, BedrockModel)
			}
		}
	}

	// Anti-vacuity, keyed to the edition this is running on: a scan that read
	// nothing would report no retired ids and look identical to a clean pass.
	if read != wantRead {
		t.Fatalf("scanned %d config surfaces but %d are present-by-construction here "+
			"(community-synced=%v)", read, wantRead, synced)
	}
	if synced {
		// docker-compose.yml and platform/connectors/config/file_loader.go both
		// survive the sync, so the mirror still scans a real pair.
		if read < 2 {
			t.Fatalf("community-synced checkout scanned only %d config surface(s); the two mirrored "+
				"surfaces always survive, so this scan is vacuous here", read)
		}
	} else if read != len(configSurfaces) {
		t.Fatalf("this checkout has nothing stripped yet only %d of %d config surfaces were scanned; "+
			"the full scan must run here", read, len(configSurfaces))
	}
}

// TestDefaultBearingSurfacesMatchConstants pins the surfaces whose DEFAULT
// value must equal the shared constants, so a future model bump happens in
// one place (this package) and the test names every file to update.
func TestDefaultBearingSurfacesMatchConstants(t *testing.T) {
	root := repoRoot(t)
	synced := communitySynced(t, root)
	type pin struct {
		file     string
		want     string
		hint     string
		mirrored bool
	}
	pins := []pin{
		{"docker-compose.enterprise.yml", "${ANTHROPIC_MODEL:-" + AnthropicModel + "}", "orchestrator + agent env defaults", false},
		{"platform/connectors/config/file_loader.go", "${ANTHROPIC_MODEL:-" + AnthropicModel + "}", "yaml-template anthropic default", true},
		{"platform/connectors/config/file_loader.go", "${BEDROCK_MODEL:-" + BedrockModel + "}", "yaml-template bedrock default", true},
		{"ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml", "Default: '" + AnthropicModel + "'", "CFN AnthropicModel default", false},
		{"infrastructure/cloudformation/community-saas-ecs.yaml", "Default: '" + AnthropicModel + "'", "CFN AnthropicModel default", false},
		{"scripts/deployment/deploy-cloudformation.sh", `"` + AnthropicModel + `"`, "yq fallback default", false},
	}
	checked, wantChecked := 0, 0
	for _, p := range pins {
		mayBeAbsent := synced && !p.mirrored
		if !mayBeAbsent {
			wantChecked++
		}
		data, err := os.ReadFile(filepath.Join(root, p.file))
		if err != nil {
			if mayBeAbsent {
				continue
			}
			t.Errorf("%s unreadable, and this checkout still has everything the community sync "+
				"strips, so it was moved or renamed rather than excluded: %v", p.file, err)
			continue
		}
		checked++
		if !strings.Contains(string(data), p.want) {
			t.Errorf("%s: expected default %q (%s) — keep in lockstep with llmdefaults", p.file, p.want, p.hint)
		}
	}

	// Anti-vacuity: every pin that is present-by-construction here must have been
	// compared, and the mirrored pins must always be.
	if checked != wantChecked {
		t.Fatalf("compared %d pins but %d are present-by-construction here (community-synced=%v)",
			checked, wantChecked, synced)
	}
	if synced {
		if checked < 2 {
			t.Fatalf("community-synced checkout compared only %d pin(s); the two file_loader.go pins "+
				"always survive the sync, so this check is vacuous here", checked)
		}
	} else if checked != len(pins) {
		t.Fatalf("this checkout has nothing stripped yet only %d of %d pins were compared; "+
			"the full check must run here", checked, len(pins))
	}
}

// TestBedrockDefaultIsRegionPrefixed pins the on-demand-invocation
// requirement: non-region-prefixed Claude 4+ Bedrock ids fail with
// "on-demand throughput isn't supported".
func TestBedrockDefaultIsRegionPrefixed(t *testing.T) {
	for _, prefix := range []string{"us.", "eu.", "apac.", "global."} {
		if strings.HasPrefix(BedrockModel, prefix) {
			return
		}
	}
	t.Errorf("BedrockModel %q must carry a region prefix (us./eu./apac./global.)", BedrockModel)
}
