// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"encoding/json"
	"os"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/legacycompile"
)

// TestThePublishedPostureListsATemplatePolicyOnlyWhereItBinds reads the
// CHECKED-IN artifact, the file the docs site renders, and holds its
// organization section to where the implicit bundle binds each template policy
// (#4131). Until #4131 the derivation listed every template policy on every
// declared scope, including the MCP response pass, which runs none of the
// template's detectors (TestAScopeThatRunsNoneOfTheTemplatesDetectorsIsNotAskedForThem
// holds that premise); the published table then showed controls on scopes where
// they never decide.
func TestThePublishedPostureListsATemplatePolicyOnlyWhereItBinds(t *testing.T) {
	raw, err := os.ReadFile(shippedPosturePath)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Organization []struct {
			LegacyID string `json:"legacy_id"`
			Policies []struct {
				PolicyID string   `json:"policy_id"`
				Scopes   []string `json:"scopes"`
			} `json:"policies"`
		} `json:"organization"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	if len(artifact.Organization) == 0 {
		t.Fatal("the artifact's organization section is empty, so nothing below is judged")
	}

	keeps := map[string]map[string]bool{}
	for _, s := range legacycompile.AllScopes() {
		doc, err := activation.OrganizationTemplateForScope(s)
		if err != nil {
			t.Fatal(err)
		}
		keeps[s.String()] = map[string]bool{}
		for _, p := range doc.Policies {
			keeps[s.String()][p.ID] = true
		}
	}
	mcpResponse := legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse).String()
	listed := map[string]map[string]bool{}
	for _, e := range artifact.Organization {
		for _, p := range e.Policies {
			for _, s := range p.Scopes {
				if s == mcpResponse {
					t.Errorf("%s (%s) is listed on %s, which runs none of the template's detectors", p.PolicyID, e.LegacyID, s)
				}
				if !keeps[s][p.PolicyID] {
					t.Errorf("%s is listed on %s, where the implicit bundle does not bind it", p.PolicyID, s)
				}
				if listed[s] == nil {
					listed[s] = map[string]bool{}
				}
				listed[s][p.PolicyID] = true
			}
		}
	}
	for s, ids := range keeps {
		for id := range ids {
			if !listed[s][id] {
				t.Errorf("%s binds on %s and the artifact does not list it there", id, s)
			}
		}
	}
}
