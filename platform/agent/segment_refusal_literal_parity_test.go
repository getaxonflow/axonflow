// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3456 — make the cross-plane segment-refusal literal's parity ENFORCED.
//
// The operator-facing refusal text for a fail-closed segment-resolution deny
//
//	segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)
//
// is the ONE message an operator (and any tooling keyed on it) sees for the
// same contract on every plane: clientRequestHandler (run.go), the gateway
// pre-check (gateway_handlers.go, #3312), the MCP-server JSON-RPC plane
// (mcp_identity.go, #3430), the four MCP REST routes + /decide (the shared
// constant in human_actor_segment_gate.go, #3447/#3456), and — outside this
// package — orchestrator/wcp_policy_adapter.go.
//
// Until now each plane pinned its OWN copy against a local constant or a local
// test literal, and NOTHING compared the sites. Drifting one — normalising the
// em dash to a hyphen is the obvious accident, since the repo's own dash
// convention pushes that way — left every other plane's test green, so the
// "byte-identical across planes" claim in five different doc comments was a
// convention, not a checked fact.
//
// This test turns it into a checked fact for the agent package, in two ways:
//
//  1. EXACT-MATCH. Every Go STRING LITERAL in this package (production and
//     test sources alike) that mentions "segment resolution unavailable" must
//     be byte-identical to one of the three pinned variants below. A drifted
//     dash, a reworded clause, a stray trailing space — each fails, naming the
//     file, line and diff.
//  2. CENSUS. The request-deny variant's PRODUCTION sites are pinned by file
//     and count, so a sixth hand-written copy fails too: a new caller must
//     reuse segmentResolutionFailedReason, not re-spell it.
//
// Scope, stated rather than implied: this test reads the agent package's own
// sources. orchestrator/wcp_policy_adapter.go carries a fourth spelling (P3b,
// plain hyphen) that is deliberately NOT unified here — cross-package
// enforcement is another issue's surface (#3456 explicitly does not rewrite
// other planes). What this test guarantees is that no AGENT-side site can
// drift without a red build.

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

// The three pinned variants. Any other spelling is drift.
//
// They are written out here as literals rather than referenced through the
// package constants on purpose: this test is the independent copy the others
// are compared against, so pointing it at the same constant it is meant to
// police would make it self-satisfying.
const (
	// segRefusalPinnedRequestDeny is the cross-plane one. Em dash, and it
	// stays an em dash: run.go, gateway_handlers.go, mcp_identity.go and
	// human_actor_segment_gate.go all carry exactly these bytes.
	segRefusalPinnedRequestDeny = "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"

	// segRefusalPinnedResponseWithheld is the MCP-server RESPONSE-phase
	// sibling (#3430, mcp_identity.go). It diverges on purpose — check_output
	// governs content already produced, so "request denied" would misdescribe
	// what happened — and has no cross-plane twin to match, hence the plain
	// hyphen.
	segRefusalPinnedResponseWithheld = "segment resolution unavailable - response withheld (fail-closed, ADR-060 #2989)"

	// segRefusalPinnedDryRunPreview is the policy-test / preview wording
	// (run.go's policyTestHandler): nothing was denied, so it says what WOULD
	// happen.
	segRefusalPinnedDryRunPreview = "segment resolution unavailable — a real request would be denied (fail-closed, ADR-060 #2989)"
)

// segRefusalProductionCensus pins WHERE the request-deny variant is spelled
// out in this package's PRODUCTION sources, and how many times.
//
// Every entry is a plane that predates the shared constant. New callers do NOT
// belong here: they must use segmentResolutionFailedReason
// (human_actor_segment_gate.go), which is why that file's count is 1 — the
// constant's own declaration — and why /decide and the four MCP REST routes
// contribute nothing.
var segRefusalProductionCensus = map[string]int{
	"run.go":                      1, // clientRequestHandler enforcement deny
	"gateway_handlers.go":         1, // #3312 pre-check deny
	"mcp_identity.go":             1, // #3430 MCP-server request phase
	"human_actor_segment_gate.go": 1, // the shared constant itself (#3447/#3456)
}

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
	// Guard against a future refactor that moves every literal behind helpers
	// and leaves this test asserting nothing.
	if len(found) < len(segRefusalProductionCensus) {
		t.Fatalf("found only %d segment-refusal literal(s) across %d files; the census alone expects at least %d — "+
			"if the sites genuinely moved, update segRefusalProductionCensus rather than leaving this test vacuous",
			len(found), scanned, len(segRefusalProductionCensus))
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
		segRefusalPinnedRequestDeny:      "cross-plane request-deny",
		segRefusalPinnedResponseWithheld: "MCP-server response-withheld (#3430)",
		segRefusalPinnedDryRunPreview:    "policy-test / preview",
	}

	// The shared constant must itself be the pinned request-deny text — the
	// hinge the other sites are compared against.
	if segmentResolutionFailedReason != segRefusalPinnedRequestDeny {
		t.Fatalf("segmentResolutionFailedReason has drifted from the cross-plane refusal text:\n  const: %q\n  pinned: %q",
			segmentResolutionFailedReason, segRefusalPinnedRequestDeny)
	}

	for _, lit := range scanSegRefusalLiterals(t) {
		if _, ok := pinned[lit.value]; ok {
			continue
		}
		t.Errorf("%s:%d: segment-refusal literal is not byte-identical to any pinned variant:\n"+
			"  got:    %q\n"+
			"  deny:   %q\n"+
			"  resp:   %q\n"+
			"  dryrun: %q\n"+
			"This message is cross-plane by contract (ADR-060 #2989): run.go, gateway_handlers.go, "+
			"mcp_identity.go, the MCP REST routes and /decide must all emit the SAME bytes, em dash "+
			"included. Do not 'normalise' the dash. If the wording genuinely must change, change every "+
			"site and the pinned constants here in one commit.",
			lit.file, lit.line, lit.value,
			segRefusalPinnedRequestDeny, segRefusalPinnedResponseWithheld, segRefusalPinnedDryRunPreview)
	}
}

// TestSegmentRefusalLiteral_ProductionCensus is rule 2: the request-deny text
// is spelled out in production sources ONLY at the pinned sites.
//
// What it catches: a sixth plane hand-copying the string instead of reusing
// segmentResolutionFailedReason — the exact thing #3456 was asked to prevent,
// and the thing rule 1 alone cannot see (a correct copy is still a copy). It
// also catches a site quietly LOSING its refusal (count drops), which would
// mean a plane stopped emitting the cross-plane message.
func TestSegmentRefusalLiteral_ProductionCensus(t *testing.T) {
	got := map[string]int{}
	for _, lit := range scanSegRefusalLiterals(t) {
		if lit.test || lit.value != segRefusalPinnedRequestDeny {
			continue
		}
		got[lit.file]++
	}

	for file, want := range segRefusalProductionCensus {
		if got[file] != want {
			t.Errorf("%s spells the request-deny refusal %d time(s), want %d", file, got[file], want)
		}
	}
	for file, n := range got {
		if _, expected := segRefusalProductionCensus[file]; !expected {
			t.Errorf("%s carries %d hand-written copy(ies) of the cross-plane refusal text. "+
				"A new caller must use the shared constant segmentResolutionFailedReason "+
				"(human_actor_segment_gate.go) — that is what makes the parity enforceable at all. "+
				"If this file legitimately predates the constant, add it to segRefusalProductionCensus "+
				"with a one-line reason.", file, n)
		}
	}
}
