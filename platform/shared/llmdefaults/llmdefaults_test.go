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

// configSurfaces are the non-Go files that carry LLM model defaults and
// therefore drift independently of the Go constants. Every entry MUST
// exist (a move/rename fails the test so the list stays current) and MUST
// NOT contain a retired model id. Files whose defaults should literally
// match the constants are additionally pinned below.
var configSurfaces = []string{
	"docker-compose.yml",
	"docker-compose.enterprise.yml",
	"ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml",
	"infrastructure/cloudformation/community-saas-ecs.yaml",
	"scripts/deployment/deploy-cloudformation.sh",
	"config/environments/healthcare.yaml",
	"platform/connectors/config/file_loader.go", // yaml-template string defaults
}

func TestConfigSurfacesCarryNoRetiredModelIDs(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range configSurfaces {
		path := filepath.Join(root, rel)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("config surface %s unreadable (moved/renamed? update configSurfaces): %v", rel, err)
			continue
		}
		content := string(data)
		for _, retired := range RetiredModelIDs {
			if strings.Contains(content, retired) {
				t.Errorf("%s still references retired model id %q — replace with llmdefaults.AnthropicModel/BedrockModel (%s / %s)",
					rel, retired, AnthropicModel, BedrockModel)
			}
		}
	}
}

// TestDefaultBearingSurfacesMatchConstants pins the surfaces whose DEFAULT
// value must equal the shared constants, so a future model bump happens in
// one place (this package) and the test names every file to update.
func TestDefaultBearingSurfacesMatchConstants(t *testing.T) {
	root := repoRoot(t)
	type pin struct {
		file string
		want string
		hint string
	}
	pins := []pin{
		{"docker-compose.enterprise.yml", "${ANTHROPIC_MODEL:-" + AnthropicModel + "}", "orchestrator + agent env defaults"},
		{"platform/connectors/config/file_loader.go", "${ANTHROPIC_MODEL:-" + AnthropicModel + "}", "yaml-template anthropic default"},
		{"platform/connectors/config/file_loader.go", "${BEDROCK_MODEL:-" + BedrockModel + "}", "yaml-template bedrock default"},
		{"ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml", "Default: '" + AnthropicModel + "'", "CFN AnthropicModel default"},
		{"infrastructure/cloudformation/community-saas-ecs.yaml", "Default: '" + AnthropicModel + "'", "CFN AnthropicModel default"},
		{"scripts/deployment/deploy-cloudformation.sh", `"` + AnthropicModel + `"`, "yq fallback default"},
	}
	for _, p := range pins {
		data, err := os.ReadFile(filepath.Join(root, p.file))
		if err != nil {
			t.Errorf("%s unreadable: %v", p.file, err)
			continue
		}
		if !strings.Contains(string(data), p.want) {
			t.Errorf("%s: expected default %q (%s) — keep in lockstep with llmdefaults", p.file, p.want, p.hint)
		}
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
