// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3456 — the segment-refusal literal's spelling is ENFORCED, not a
// convention.
//
// The operator-facing refusal text for a fail-closed segment-resolution deny
//
//	segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)
//
// is spelled out at NO production site in this package since #4253. Every
// plane that carried it (the gateway pre-check, the MCP-server tools, the four
// MCP REST routes, /decide, and last /api/request with its policy-test preview)
// is decided by the anchored engine, which reads no segments, so each copy went
// with its gate. Outside this package, orchestrator/wcp_policy_adapter.go
// carries its own spelling, which this test does not read.
//
// Two rules hold for the agent package:
//
//  1. EXACT-MATCH. Every Go STRING LITERAL in this package (production and
//     test sources alike) that mentions "segment resolution unavailable" must
//     be byte-identical to one of the two pinned variants below. A drifted
//     dash (normalising the em dash to a hyphen is the obvious accident, since
//     the repo's own dash convention pushes that way), a reworded clause, a
//     stray trailing space: each fails, naming the file, line and diff.
//  2. CENSUS. Neither variant has a PRODUCTION site, so a plane that re-grows
//     a segment refusal fails: that is a segment gate coming back.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// segRefusalNeedle is the substring that identifies a literal as one of the
// segment-refusal family. Deliberately short and dash-free so a DRIFTED
// literal is still FOUND (and then fails the exact-match rule) rather than
// silently escaping the scan.
const segRefusalNeedle = "segment resolution unavailable"

// The two pinned variants. Any other spelling is drift.
//
// They are written out here as literals on purpose: this test is the
// independent copy the sites are compared against.
const (
	// segRefusalPinnedRequestDeny is the enforcement deny. Em dash, and it
	// stays an em dash.
	segRefusalPinnedRequestDeny = "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"

	// segRefusalPinnedDryRunPreview was the policy-test / preview wording
	// (run.go's policyTestHandler before #4253): nothing was denied, so it said
	// what WOULD happen.
	segRefusalPinnedDryRunPreview = "segment resolution unavailable — a real request would be denied (fail-closed, ADR-060 #2989)"
)

// segRefusalLiteral is one occurrence found by the scanner.
type segRefusalLiteral struct {
	file  string // base name
	line  int
	value string // the UNQUOTED literal
	test  bool   // from a _test.go file
}

// scanSegRefusalLiterals parses every .go file in the package directory and
// returns each string literal containing segRefusalNeedle.
//
// Parsing rather than grepping is deliberate: it sees exactly what the
// COMPILER sees, so a mention inside a doc comment (this file is full of them)
// is not mistaken for a shipped message, and a literal split across lines by
// gofmt is still read as its full value.
func scanSegRefusalLiterals(t *testing.T) []segRefusalLiteral {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	var found []segRefusalLiteral
	scanned := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// This file's own pinned constants are the yardstick, not sites to
		// police.
		if name == "segment_refusal_literal_parity_test.go" {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		isTest := strings.HasSuffix(name, "_test.go")
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if !strings.Contains(val, segRefusalNeedle) {
				return true
			}
			found = append(found, segRefusalLiteral{
				file:  filepath.Base(name),
				line:  fset.Position(lit.Pos()).Line,
				value: val,
				test:  isTest,
			})
			return true
		})
	}

	if scanned == 0 {
		t.Fatal("scanned no .go files — the parity check would pass vacuously")
	}
	return found
}

// TestSegmentRefusalLiteral_ByteParityAcrossAgentPlanes is rule 1: every
// occurrence, production or test, is byte-identical to a pinned variant.
//
// What it catches: normalising the em dash to a hyphen on ANY single plane
// (the accident the repo's own dash convention invites); rewording one plane's
// clause; adding or losing whitespace; "fail closed" for "fail-closed"; a new
// plane inventing a fourth spelling. Before this test, each of those left every
// other plane's suite green and shipped two different messages for one
// contract.
func TestSegmentRefusalLiteral_ByteParityAcrossAgentPlanes(t *testing.T) {
	pinned := map[string]string{
		segRefusalPinnedRequestDeny:   "request-deny",
		segRefusalPinnedDryRunPreview: "policy-test / preview",
	}

	for _, lit := range scanSegRefusalLiterals(t) {
		if _, ok := pinned[lit.value]; ok {
			continue
		}
		t.Errorf("%s:%d: segment-refusal literal is not byte-identical to any pinned variant:\n"+
			"  got:    %q\n"+
			"  deny:   %q\n"+
			"  dryrun: %q\n"+
			"Do not 'normalise' the dash. If the wording genuinely must change, change every "+
			"site and the pinned constants here in one commit.",
			lit.file, lit.line, lit.value,
			segRefusalPinnedRequestDeny, segRefusalPinnedDryRunPreview)
	}
}

// TestSegmentRefusalLiteral_ProductionCensus is rule 2: neither variant is
// spelled out in production sources.
//
// What it catches: a plane re-growing a segment refusal of its own - rule 1
// alone cannot see that, since a correct copy is still a copy - including
// /api/request's gate or its preview's simulation, both retired by #4253.
//
// A scan that found nothing proves nothing on its own, so it shares
// scanSegRefusalLiterals with rule 1, which refuses a scan that parsed no file
// at all; rule 1's own subjects are the test sources, and this rule's are the
// production ones.
func TestSegmentRefusalLiteral_ProductionCensus(t *testing.T) {
	for _, lit := range scanSegRefusalLiterals(t) {
		if lit.test {
			continue
		}
		t.Errorf("%s:%d spells a segment refusal (%q). Nothing on the agent decides on a governance segment "+
			"since #4253 (PRD v11 §1 item 1); a refusal here is a segment gate coming back.", lit.file, lit.line, lit.value)
	}
}
