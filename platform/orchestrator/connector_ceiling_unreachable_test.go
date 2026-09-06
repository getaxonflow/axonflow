// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestTheOrchestratorNeverResolvesTheConnectorCeiling pins a NON-reachability
// (#3709 row 1, R3 round 1 from master).
//
// platform/shared/policy resolves the custom-policy connector ceiling through
// a LicenseTierSource that package agent registers at init. A binary that
// links platform/shared/policy WITHOUT package agent and reaches the ceiling
// resolves to Community, counts it on
// axonflow_license_tier_source_unregistered_total and logs a line saying no
// verified source is registered. That line is a finding in an Enterprise
// deployment and NOISE in a binary where Community is the correct answer.
//
// Today no binary emits it: the agent registers, and this package never
// reaches any of the entry points that resolve the ceiling. That is a property
// of the CURRENT tree, and the day an orchestrator change calls
// NewDynamicPolicyEvaluatorFromEnv the line starts firing on every
// orchestrator start with nothing announcing the change. This test is the
// announcement: it scans this package's non-test source for every entry point
// that reaches resolveConnectorLimitTier and fails on the first reference,
// naming the two ways to keep the property (do not call it, or register a
// source first).
//
// ANTI-VACUITY: the same scan over platform/agent must find the agent's own
// call (run.go's InitGlobalDynamicPolicyEvaluator), so a regex that matches
// nothing anywhere cannot pass this test.
func TestTheOrchestratorNeverResolvesTheConnectorCeiling(t *testing.T) {
	// Every exported path into resolveConnectorLimitTier, by name. Adding a
	// fourth entry point to platform/shared/policy means adding it here; the
	// test in that package that would catch the omission is
	// license_tier_source_test.go's unregistered-default assertion, which
	// documents the three.
	entryPoints := regexp.MustCompile(`\b(NewDynamicPolicyEvaluatorFromEnv|InitGlobalDynamicPolicyEvaluator|EnforceCustomPolicyConnectorLimit|ValidateCustomPolicyConnectorLimit)\b`)

	// scan walks dir RECURSIVELY: the orchestrator's sub-packages (llm,
	// media, ...) are part of the same binary, and a call from one of them
	// would fire the line just as surely as one from this package.
	scan := func(dir string) map[string][]string {
		hits := map[string][]string{}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, path)
			for i, line := range strings.Split(string(src), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue // a comment naming the function is not a call
				}
				if m := entryPoints.FindString(line); m != "" {
					hits[m] = append(hits[m], rel+":"+strconv.Itoa(i+1))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
		return hits
	}

	if agentHits := scan(filepath.Join("..", "agent")); len(agentHits["InitGlobalDynamicPolicyEvaluator"]) == 0 {
		t.Fatalf("the scan found no InitGlobalDynamicPolicyEvaluator call in platform/agent (hits: %v); "+
			"the agent's own registration site is the positive control and the regex is not seeing it", agentHits)
	}

	for fn, sites := range scan(".") {
		t.Errorf("platform/orchestrator reaches the connector ceiling through %s at %v.\n"+
			"This binary registers no verified licence tier source, so the ceiling resolves to Community "+
			"and platform/shared/policy logs 'no verified licence tier source is registered' on every "+
			"start - as noise, because Community is the right answer here. Either do not resolve the "+
			"ceiling from the orchestrator, or register a source (policy.SetLicenseTierSource with "+
			"license.GetCurrentTier) before the first call and extend this test to say so.", fn, sites)
	}
}
