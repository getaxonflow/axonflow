// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestAgentAPIObligationTypeEnumIsTheCanonicalVocabulary compares the
// obligation type enumeration the PUBLIC OpenAPI spec publishes with the Go
// declaration, in both directions (#3891). The AuthZEN schema drift suite
// binds the JSON schema; this binds the YAML a customer reads and an SDK is
// generated from, which is where a spelling can go stale without a Go test
// noticing.
//
// The enumeration is read with a deliberately narrow scanner rather than a
// YAML parser: the module carries no direct YAML dependency and the block's
// shape is a flow sequence under a named definition, so a shape change fails
// loudly here rather than silently matching nothing.
func TestAgentAPIObligationTypeEnumIsTheCanonicalVocabulary(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "api", "agent-api.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	spec := string(raw)
	start := strings.Index(spec, "\n    AuthZENObligation:\n")
	if start < 0 {
		t.Fatalf("%s declares no AuthZENObligation definition", path)
	}
	block := spec[start:]
	enumStart := strings.Index(block, "enum: [")
	if enumStart < 0 {
		t.Fatalf("AuthZENObligation.type declares no enumeration")
	}
	enumEnd := strings.Index(block[enumStart:], "]")
	if enumEnd < 0 {
		t.Fatalf("AuthZENObligation.type enumeration is not closed")
	}
	var published []string
	for _, v := range strings.Split(block[enumStart+len("enum: ["):enumStart+enumEnd], ",") {
		if v = strings.TrimSpace(v); v != "" {
			published = append(published, v)
		}
	}
	var declared []string
	for _, typ := range AllObligationTypes() {
		declared = append(declared, string(typ))
	}
	published = sortStrings(published)
	if !reflect.DeepEqual(published, declared) {
		t.Fatalf("docs/api/agent-api.yaml#AuthZENObligation.type enumerates\n  %v\nbut the canonical vocabulary declares\n  %v", published, declared)
	}
	// The losing spellings are absent from the spec: a customer cannot be
	// told to send a type the evaluator refuses.
	for _, losing := range []string{"field_redaction", "response_filtering", "schema_constrained_transform", "audit_notification"} {
		if strings.Contains(block[:enumStart+enumEnd], losing) {
			t.Errorf("the spec still publishes the losing spelling %q", losing)
		}
	}
}
