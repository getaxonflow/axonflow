// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringvocabulary_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/authoringvocabulary"
)

// The two documents runtime-e2e/1431_policy_path_alias posts at the community
// typed-authoring surface are held here to the wire format they claim (#3907).
//
// # Why this test exists at all
//
// They are heredocs in a shell script. Nothing in a shell script parses a
// policy document, so a wire-format change - a renamed condition field, a new
// required member, a stricter decoder - turns them into bodies the route
// refuses, and the first thing anyone learns is a red e2e leg on a booted
// stack, in a suite whose subject is something else.
//
// The first draft of those heredocs was hand-written and WAS wrong: the
// condition carried `left_path`, which the decoder rejects outright
// (`DisallowUnknownFields`). It was caught here rather than on a stack, which
// is the whole argument for the test.
//
// # What it asserts, and what it deliberately does not
//
// It parses each body exactly as the route does - Parse, then NewDocument
// against the DEPLOYMENT catalog, which is the catalog the suite configures
// since #3895 - a fixture vocabulary can be published against and can never be
// ACTIVATED, and the suite activates -
// and requires both to succeed. It does NOT publish: publication needs a
// signing key and an edition, and the edition refusal is the thing the e2e leg
// is there to observe on a real deployment.
//
// The group-scoped document must VALIDATE too, and that is the load-bearing
// half of the second case: the e2e leg asserts it is refused with
// GROUP_SCOPE_NOT_IN_EDITION, and a document that failed save-time validation
// would be refused for a different reason entirely while the leg still went
// green on a substring search.
func TestTheRuntimeE2EBodiesParseAndValidate(t *testing.T) {
	root := filepath.Join("..", "..", "..", "runtime-e2e")
	// THE COMMUNITY MIRROR EXCLUDES runtime-e2e/ WHOLESALE, so on a mirror
	// checkout there is nothing here to pin and its absence is correct.
	//
	// The skip is deliberately keyed on the DIRECTORY, not on the file. A tree
	// that HAS runtime-e2e/ and not this suite is a suite that moved or was
	// deleted, and this test must say so rather than skip - which is the same
	// shape, and the same reasoning, as the census test's technical-docs skip.
	if _, err := os.Stat(root); err != nil {
		t.Skip("community mirror: runtime-e2e/ is excluded from the sync")
	}
	// runtime-e2e/3564_per_plane_enforcement's Phase E publishes and activates
	// E3564DOC on an Evaluation licence so the anchored engine has a document to
	// decide with; it is held to the same standard.
	// runtime-e2e/3593_tier_scale_limits' arm C publishes TS3593DOC on an
	// Evaluation licence to drive the organization-root ceiling across the agent
	// seam (#3973/#4009). The suite derives its N-rule bodies from this one with
	// jq, so this is the only hand-written document it has and the only one that
	// can drift from the wire format.
	suites := []struct {
		dir   string
		marks []string
	}{
		{dir: "1431_policy_path_alias", marks: []string{"TADOC", "TAGROUP"}},
		{dir: "3564_per_plane_enforcement", marks: []string{"E3564DOC"}},
		{dir: "3593_tier_scale_limits", marks: []string{"TS3593DOC"}},
	}
	sources := map[string]string{}
	bodies := map[string]string{}
	for _, s := range suites {
		path := filepath.Join(root, s.dir, "test.sh")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("this tree HAS runtime-e2e/ but not %s, so the fixtures this test pins have moved or been "+
				"deleted: %v", path, err)
		}
		sources[s.dir] = string(raw)
		for _, mark := range s.marks {
			bodies[mark] = heredoc(t, string(raw), mark)
		}
	}
	// THE DEPLOYMENT VOCABULARY, resolved for what each stack can wire. Neither
	// configures a SCIM directory, so no realm carries a group graph. 1431 is a
	// community stack and wires nothing else; 3564 boots in enterprise mode,
	// where a revocation source and a Shared Signals channel are declared only
	// when their collaborators were constructed. So every body is validated
	// against BOTH shapes, rather than asserting which one a booted stack gets.
	deployments := map[string]authoringvocabulary.CatalogDeployment{
		"nothing wired":          {},
		"revocation and signals": {HasRevocation: true, HasCAEP: true},
	}
	catalogs := map[string]*authoring.Catalog{}
	for shape, dep := range deployments {
		snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, dep)
		if err != nil || snap == nil {
			t.Fatalf("the deployment catalog must resolve with %s: %v", shape, err)
		}
		catalogs[shape] = snap.Catalog
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			var req struct {
				Document json.RawMessage     `json:"document"`
				Fixtures []authoring.Fixture `json:"fixtures"`
			}
			if err := json.Unmarshal([]byte(body), &req); err != nil {
				t.Fatalf("the %s body is not a valid publish request: %v", name, err)
			}
			if len(req.Fixtures) == 0 {
				t.Fatalf("%s declares no gauntlet fixtures; a publication with none is refused by name, so the "+
					"e2e leg would be asserting that refusal rather than the one it names", name)
			}
			d, err := authoring.Parse(req.Document)
			if err != nil {
				t.Fatalf("%s does not PARSE at the wire boundary: %v", name, err)
			}
			for shape, cat := range catalogs {
				if _, findings, err := authoring.NewDocument(authoring.Document{Metadata: d.Metadata, Policy: d.Policy}, cat); err != nil {
					t.Fatalf("%s does not VALIDATE against the deployment catalog with %s: %v\nfindings: %v", name, shape, err, findings)
				}
			}
		})
	}

	// ANTI-VACUITY: the two bodies must actually DIFFER in the construct the
	// second one exists to carry. Two copies of the same document would pass
	// every assertion above while leaving the edition-boundary leg asserting
	// nothing.
	if bodies["TADOC"] == bodies["TAGROUP"] {
		t.Fatal("the two e2e bodies are identical; the group-scope leg has no group scope to be refused for")
	}
	if !strings.Contains(bodies["TAGROUP"], `"groups"`) {
		t.Fatal("the TAGROUP body carries no group scope, so the leg that expects GROUP_SCOPE_NOT_IN_EDITION cannot provoke it")
	}
	if strings.Contains(bodies["TADOC"], `"groups"`) {
		t.Fatal("the TADOC body carries a group scope, so the community publication leg would be refused by the edition boundary")
	}

	// THE CONSTRAINT MUST NAME THE PRINCIPAL THE SEAM ADMITS. 3564's Phase E
	// expects an anchored explicit_constraint DENY for a token minted in the
	// portal's claim set, which the identity plane admits in the minted realm as
	// User::axonflow-minted:<sub>, and the suite mints it for ENF_BLOCKED_EMAIL.
	// A constraint naming anyone else validates, publishes and activates just the
	// same - and the DENY leg then reads the baseline pack's allow, which looks
	// like an engine defect rather than a fixture that drifted from its script.
	constrained := shellSingleQuotedAssignment(t, sources["3564_per_plane_enforcement"], "ENF_BLOCKED_EMAIL")
	principal := `{"kind":"principal","type":"User","qualifier":"axonflow-minted","local":"` + constrained + `"}`
	if !strings.Contains(bodies["E3564DOC"], principal) {
		t.Fatalf("E3564DOC scopes no policy to %s, the principal the suite's ENF_BLOCKED_EMAIL token is admitted as", principal)
	}
	if strings.Contains(bodies["E3564DOC"], `"groups"`) {
		t.Fatal("E3564DOC carries a group scope; the constraint must not depend on a directory the stack does not configure")
	}
}

// shellSingleQuotedAssignment returns the value of a top-level `NAME='value'`
// line in a shell script, failing when there is not exactly one.
func shellSingleQuotedAssignment(t *testing.T, src, name string) string {
	t.Helper()
	matches := regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(name)+`='([^']+)'$`).FindAllStringSubmatch(src, -1)
	if len(matches) != 1 {
		t.Fatalf("want exactly one %s='...' line in the suite, found %d; the fixture weld cannot tell which value the suite uses", name, len(matches))
	}
	return matches[0][1]
}

// heredoc extracts the body of `<<'MARK' ... MARK` from a shell script.
func heredoc(t *testing.T, src, mark string) string {
	t.Helper()
	open := "<<'" + mark + "'\n"
	i := strings.Index(src, open)
	if i < 0 {
		t.Fatalf("the suite no longer contains a %s heredoc; this test is pinning a fixture that has moved", mark)
	}
	start := i + len(open)
	end := strings.Index(src[start:], "\n"+mark+"\n")
	if end < 0 {
		t.Fatalf("the %s heredoc is not terminated", mark)
	}
	return src[start : start+end]
}
