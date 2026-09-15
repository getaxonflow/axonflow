// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/policypack"
)

// TestAPackBindsWhereItsDetectorsRun pins where each class of pack control
// binds, derived over every declared scope. The expected sets are the measured
// answer today; a call site whose category filter, phase or evaluator changes
// moves them, and that should be read here rather than discovered on a plane.
func TestAPackBindsWhereItsDetectorsRun(t *testing.T) {
	src := &policypack.Source{
		ID: "archpack", Version: 1,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: "archpack-approvers"},
		Detectors: []policypack.Detector{
			// A FinCrime-shaped request detector: category fincrime is admitted
			// only by the input-policy sites (decide and the MCP request pass).
			{ID: "ap_fincrime_block", Name: "a", Category: "fincrime", Severity: "high", Phase: "request", Action: "block", Pattern: "a"},
			{ID: "ap_fincrime_step", Name: "b", Category: "fincrime", Severity: "high", Phase: "request", Action: "require_approval", Pattern: "b"},
			// A response detector in the PII family: it binds where an agent
			// shared-engine site scans responses and admits PII, and NOT on the
			// orchestrator's response plane, whose engine is not given packs.
			{ID: "ap_pii_response", Name: "c", Category: "pii-global", Severity: "low", Phase: "response", Action: "warn", Pattern: "c"},
			// A detector whose phases take different actions, as a pack that
			// mirrors the shipped PII posture has: warn on requests, redact on
			// responses. Each of its two controls binds on its own phase only.
			{ID: "ap_pii_split", Name: "d", Category: "pii-india", Severity: "high", Phase: "both", Action: "warn", ActionResponse: "redact", Pattern: "d"},
		},
	}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	doc, digest, err := pack.Instantiate([]string{"r"})
	if err != nil {
		t.Fatal(err)
	}
	ip := InstalledPack{Pack: pack, Document: doc, Digest: digest}

	boundOn := map[string][]string{}
	for _, scope := range legacycompile.AllScopes() {
		scoped, err := packForScope(scope, ip)
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		for _, p := range scoped.Policies {
			boundOn[p.ID] = append(boundOn[p.ID], scope.String())
		}
		// The schema is restricted with the policies.
		if len(scoped.Attributes) != len(scoped.Policies) {
			t.Errorf("%s: %d attributes for %d policies", scope, len(scoped.Attributes), len(scoped.Policies))
		}
	}
	want := map[string]string{
		policypack.PolicyID("archpack", "ap_fincrime_block"): "decide mcp:request",
		policypack.PolicyID("archpack", "ap_fincrime_step"):  "decide mcp:request",
		policypack.PolicyID("archpack", "ap_pii_response"):   "cowork_ingest mcp:response",
		// The shipped PII posture's own split, on the scopes whose agent sites
		// load pack detectors: the request variant everywhere the PII family or
		// pii-india is evaluated on a request, the response variant where the
		// agent scans responses. Not policy_test: since #4253 its one site is the
		// orchestrator's dynamic one, which loads no pack. And not
		// orchestrator_response, whose engine is not given packs.
		policypack.PolicyID("archpack", "ap_pii_split") + ":warn":   "decide gateway_request mcp:request openai_compatible proxy_request",
		policypack.PolicyID("archpack", "ap_pii_split") + ":redact": "cowork_ingest mcp:response",
	}
	for id, scopes := range want {
		got := boundOn[id]
		sort.Strings(got)
		if strings.Join(got, " ") != scopes {
			t.Errorf("%s binds on %v, want %s", id, got, scopes)
		}
	}
}
