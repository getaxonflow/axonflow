// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package serviceauth

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestHeaderNamesAreTheOnesTheAgentSpecDeclares pins the two header constants
// to the wire: the names docs/api/agent-api.yaml gives the InternalServiceID
// and InternalServiceToken security schemes. Every Go reader and writer of the
// pair takes them from here, so this is the one place the spelling is checked
// against something other than itself.
func TestHeaderNamesAreTheOnesTheAgentSpecDeclares(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "api", "agent-api.yaml"))
	if err != nil {
		t.Fatalf("read the agent spec: %v", err)
	}
	var spec struct {
		Components struct {
			SecuritySchemes map[string]struct {
				In   string `yaml:"in"`
				Name string `yaml:"name"`
			} `yaml:"securitySchemes"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse the agent spec: %v", err)
	}
	for scheme, want := range map[string]string{
		"InternalServiceID":    ServiceIDHeader,
		"InternalServiceToken": ServiceTokenHeader,
	} {
		got, ok := spec.Components.SecuritySchemes[scheme]
		if !ok {
			t.Fatalf("the agent spec declares no %s security scheme; this test cannot vacuously pass", scheme)
		}
		if got.In != "header" || got.Name != want {
			t.Errorf("%s: the spec declares %s %q, the constant is %q", scheme, got.In, got.Name, want)
		}
	}
}
