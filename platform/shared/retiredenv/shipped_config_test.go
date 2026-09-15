// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package retiredenv

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil/gocensus"
	"axonflow/platform/testutil/manifests"
)

// retiredNames returns every variable Refuse refuses, across its families.
func retiredNames() []string {
	var out []string
	for _, f := range families {
		out = append(out, f.names...)
	}
	return out
}

// A retired variable must not come back through a file the platform ships. A
// compose file or a CloudFormation template that sets one boots a process
// Refuse stops - a pre-v11 compose default of "false" is exactly that - and one
// that passes it through empty keeps a switch on the page that does nothing.
// The names come from this package's lists, so a variable retired later is
// pinned the day it is listed.

// shippedKind names the kind of shipped configuration a manifest is, or "" for
// a YAML file that is neither: a compose file by its name, a CloudFormation
// template by the format version every template declares.
func shippedKind(path string, body []byte) string {
	base := filepath.Base(path)
	switch {
	case strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose."):
		return "compose file"
	case bytes.Contains(body, []byte("AWSTemplateFormatVersion")):
		return "CloudFormation template"
	}
	return ""
}

// retiredNamesIn reports every retired variable a shipped compose file or
// template under root names, and how many files of each kind it read.
func retiredNamesIn(t *testing.T, root string) ([]string, map[string]int) {
	t.Helper()
	retired := retiredNames()
	var findings []string
	read := map[string]int{}
	for _, path := range manifests.Files(t, root, ".yml", ".yaml") {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		kind := shippedKind(path, body)
		if kind == "" {
			continue
		}
		read[kind]++
		rel, _ := filepath.Rel(root, path)
		for _, name := range retired {
			if bytes.Contains(body, []byte(name)) {
				findings = append(findings, fmt.Sprintf("%s (%s) names %s", filepath.ToSlash(rel), kind, name))
			}
		}
	}
	return findings, read
}

func TestNoShippedComposeFileOrTemplateNamesARetiredVariable(t *testing.T) {
	findings, read := retiredNamesIn(t, gocensus.RepoRoot(t))
	for _, f := range findings {
		t.Errorf("%s: a retired variable refuses boot, so no file the platform ships may set or pass it through (%s)", f, PRD)
	}
	// Every checkout, the community mirror included, ships docker-compose.yml;
	// a walk that read no compose file checked nothing.
	if read["compose file"] == 0 {
		t.Fatal("no compose file was read, so the guard checked nothing")
	}
	t.Logf("read %d compose file(s) and %d CloudFormation template(s)", read["compose file"], read["CloudFormation template"])
}

// The guard can fail, and only on what it covers: a compose file and a template
// naming retired variables are each reported, and a workflow naming one is not
// shipped configuration.
func TestTheShippedConfigGuardReportsARetiredVariableAndNothingElse(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string]string{
		"docker-compose.yml":         "services:\n  agent:\n    environment:\n      MCP_DYNAMIC_POLICIES_ENABLED: ${MCP_DYNAMIC_POLICIES_ENABLED:-false}\n",
		"infra/stack.yaml":           "AWSTemplateFormatVersion: '2010-09-09'\n# - Name: AXONFLOW_DECISION_SHADOW_MODE\n",
		".github/workflows/e2e.yml":  "env:\n  MCP_DYNAMIC_POLICIES_GRACEFUL: 'true'\n",
		"infra/clean-template.yaml":  "AWSTemplateFormatVersion: '2010-09-09'\n",
		"runtime-e2e/compose.x.yml":  "services: {}\n",
		"runtime-e2e/unrelated.yaml": "MCP_DYNAMIC_POLICIES_TIMEOUT: 5s\n",
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	findings, read := retiredNamesIn(t, root)
	want := []string{
		"docker-compose.yml (compose file) names MCP_DYNAMIC_POLICIES_ENABLED",
		"infra/stack.yaml (CloudFormation template) names AXONFLOW_DECISION_SHADOW_MODE",
	}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("findings = %q, want %q", findings, want)
	}
	if read["compose file"] != 2 || read["CloudFormation template"] != 2 {
		t.Fatalf("read %v, want 2 compose files and 2 templates", read)
	}
}

// The upgrade preflight fails a deployment that still sets a variable Refuse
// stops. Operators run it without this tree, so it carries its own copy of the
// list, and the copy must name exactly the variables every family here refuses:
// a family added to Refuse that never reaches the preflight reds this test.
func TestThePreflightNamesExactlyTheRetiredVariables(t *testing.T) {
	path := filepath.Join(gocensus.RepoRoot(t), "scripts", "deployment", "v9_self_hosted_preflight.sh")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the preflight: %v", err)
	}
	const open = "C25_RETIRED_VARS=(\n"
	i := bytes.Index(body, []byte(open))
	if i < 0 {
		t.Fatalf("the preflight declares no C25_RETIRED_VARS array, so nothing fails a deployment that sets a retired variable")
	}
	j := bytes.Index(body[i:], []byte("\n)"))
	if j < 0 {
		t.Fatal("the preflight's C25_RETIRED_VARS array is never closed")
	}
	got := strings.Fields(string(body[i+len(open) : i+j]))
	want := retiredNames()
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the preflight fails on %v, but retiredenv refuses %v", got, want)
	}
}
