// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
	"strings"
)

// PEPCapabilities is what one enforcement plane advertises it can discharge.
//
// ADR-065: "every enforcement plane publishes the exact obligation types and
// versions it supports". This type is the publication, and Supports is the
// negotiation. There is no wildcard, no "and later versions", and no implicit
// support: a plane that does not list a capability does not have it, and a
// mandatory obligation it does not list denies.
type PEPCapabilities struct {
	// PEPID identifies the plane (`wcp`, `map`, `mcp`, `openai_gateway`,
	// `envoy_ext_authz`). Bound into the decision proof.
	PEPID string
	// ProfileVersion is the AxonFlow context-profile version the PEP
	// negotiated. A PEP that did not negotiate a profile sees only the
	// AuthZEN boolean, so a missing profile is not an error here - but it is
	// carried into the proof so a verifier can tell the two apart.
	ProfileVersion string
	// Supported is the exact set. Order is irrelevant; Supports uses a set
	// built once by Normalize.
	Supported []Capability

	index map[Capability]struct{}
}

// Normalize builds the lookup index and returns a copy with a sorted,
// deduplicated capability list. Callers must use the returned value; Supports
// on an un-normalized value still works (it falls back to a linear scan) but
// is O(n) per call.
func (c PEPCapabilities) Normalize() PEPCapabilities {
	idx := make(map[Capability]struct{}, len(c.Supported))
	for _, cap := range c.Supported {
		idx[cap] = struct{}{}
	}
	out := make([]Capability, 0, len(idx))
	for cap := range idx {
		out = append(out, cap)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Version < out[j].Version
	})
	c.Supported = out
	c.index = idx
	return c
}

// Supports reports whether the PEP advertises this EXACT type and version.
func (c PEPCapabilities) Supports(cap Capability) bool {
	if c.index != nil {
		_, ok := c.index[cap]
		return ok
	}
	for _, s := range c.Supported {
		if s == cap {
			return true
		}
	}
	return false
}

// SupportedVersionsOf lists the versions of one type this PEP advertises.
// Used only to build a helpful refusal ("you support v1, the plan needs v2"),
// never to relax the exact-version rule.
func (c PEPCapabilities) SupportedVersionsOf(t Type) []int {
	var vs []int
	for _, s := range c.Supported {
		if s.Type == t {
			vs = append(vs, s.Version)
		}
	}
	sort.Ints(vs)
	return vs
}

// Digest renders the capability set for binding into a decision proof. Sorted
// and deduplicated, so two PEPs advertising the same set produce the same
// digest whatever order they listed it in.
func (c PEPCapabilities) Digest() string {
	n := c.Normalize()
	parts := make([]string, 0, len(n.Supported))
	for _, s := range n.Supported {
		parts = append(parts, s.String())
	}
	return fmt.Sprintf("pep=%s|profile=%s|caps=[%s]", c.PEPID, c.ProfileVersion, strings.Join(parts, ","))
}

// Validate checks a capability advertisement.
func (c PEPCapabilities) Validate() error {
	if c.PEPID == "" {
		return fmt.Errorf("pep capabilities: pep_id is required")
	}
	for _, s := range c.Supported {
		if s.Type == "" {
			return fmt.Errorf("pep capabilities: capability with empty type")
		}
		if s.Version <= 0 {
			return fmt.Errorf("pep capabilities: %s advertises version %d; 0 does not mean 'any'", s.Type, s.Version)
		}
	}
	return nil
}

// CheckAgainstRegistry reports capabilities the PEP advertises that the
// registry does not define.
//
// This is not a decision gate - a PEP advertising a capability nobody asks for
// is harmless - but it is the tell for a version-skewed deployment, and an
// operator wants it in a startup log rather than discovering it when a
// mandatory obligation denies in production.
func (c PEPCapabilities) CheckAgainstRegistry(r *Registry) []Capability {
	var unknown []Capability
	for _, s := range c.Normalize().Supported {
		if _, ok := r.Lookup(s.Type, s.Version); !ok {
			unknown = append(unknown, s)
		}
	}
	return unknown
}
