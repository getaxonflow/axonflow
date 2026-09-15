// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"encoding/json"
	"strings"
	"testing"
)

// shippedWith returns the embedded artifact with its scope_bindings section
// replaced, or removed when bindings is nil, so the loader can be driven with
// an artifact that is not the shipped one.
func shippedWith(t *testing.T, bindings map[string][]string) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(SystemCorpusSource, &top); err != nil {
		t.Fatal(err)
	}
	if bindings == nil {
		delete(top, "scope_bindings")
	} else {
		raw, err := json.Marshal(bindings)
		if err != nil {
			t.Fatal(err)
		}
		top["scope_bindings"] = raw
	}
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTheShippedCorpusScopeBindingsLoadAsACopy holds the accessor to its
// contract on the embedded artifact: it loads, every key is a control the
// system document ships, and the map a caller receives is its own.
func TestTheShippedCorpusScopeBindingsLoadAsACopy(t *testing.T) {
	sys, err := SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	template, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	// The system document's per-scope splits (#4046) and the template's
	// redactions bound by discharge (#4131).
	shipped := map[string]bool{}
	for _, doc := range []*Document{sys, template} {
		for _, p := range doc.Policies {
			shipped[p.ID] = true
		}
	}
	first, err := SystemCorpusScopeBindings()
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("the accessor returned nil; the section is required and an empty one is a map")
	}
	for id := range first {
		if !shipped[id] {
			t.Errorf("the shipped bindings name %q, which neither the system document nor the organization template ships", id)
		}
	}
	first["corpus:static_policies:planted"] = []string{"decide"}
	for id, scopes := range first {
		if len(scopes) > 0 {
			scopes[0] = "planted"
		}
		_ = id
	}
	second, err := SystemCorpusScopeBindings()
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := second["corpus:static_policies:planted"]; leaked {
		t.Fatal("a key added to one caller's bindings was visible to the next caller")
	}
	for id, scopes := range second {
		for _, s := range scopes {
			if s == "planted" {
				t.Fatalf("a scope written through one caller's copy of %q was visible to the next caller", id)
			}
		}
	}
}

// TestAScopeBindingThatCouldLeaveAControlOutSilentlyIsRefused drives every
// shape validateScopeBindings refuses through the real loader, and asserts each
// refusal by its REASON: a test that accepted any error would pass against a
// loader refusing for an unrelated cause, while the shape it names went through.
func TestAScopeBindingThatCouldLeaveAControlOutSilentlyIsRefused(t *testing.T) {
	sys, err := SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	real := sys.Policies[0].ID

	// CONTROL: a well-formed binding for a shipped control loads, and comes
	// back as written.
	_, _, got, _, err := parseShippedCorpus(shippedWith(t, map[string][]string{real: {"decide", "mcp:response"}}))
	if err != nil {
		t.Fatalf("CONTROL: a well-formed binding was refused: %v", err)
	}
	if len(got) != 1 || strings.Join(got[real], ",") != "decide,mcp:response" {
		t.Fatalf("CONTROL: the binding came back as %v", got)
	}

	for _, c := range []struct {
		name     string
		bindings map[string][]string
		reason   string
	}{
		{"the section is absent", nil, "carries no scope_bindings section"},
		{"a binding names a control the platform does not ship", map[string][]string{"corpus:static_policies:not_shipped": {"decide"}}, "not a policy of the system document"},
		{"a control is bound to no scope", map[string][]string{real: {}}, "bound to no scope"},
		{"a scope is blank", map[string][]string{real: {""}}, "blank or padded scope"},
		{"a scope is padded", map[string][]string{real: {" decide"}}, "blank or padded scope"},
		{"a scope appears twice", map[string][]string{real: {"decide", "decide"}}, "not strictly sorted"},
		{"the scopes are out of order", map[string][]string{real: {"mcp:response", "decide"}}, "not strictly sorted"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, _, err := parseShippedCorpus(shippedWith(t, c.bindings))
			if err == nil {
				t.Fatal("the loader accepted it")
			}
			if !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("refused for a different reason: %v; want one naming %q", err, c.reason)
			}
		})
	}
}
