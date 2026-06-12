// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestEveryPolicyEnforcementPointAudits is the structural regression guard
// for the audit-coverage close-out epic (#2625 / #2675 / #2687). It is the
// permanent successor to the four hand-run audit sweeps (#2626, #2641, #2643,
// #2683 …) that each flushed out a fresh batch of "evaluates policy but the
// deny path writes no canonical audit_logs row" holes only AFTER they had
// shipped. Those sweeps were exhaustive-by-eyeball and so kept missing a
// different subset each time; this test makes the invariant machine-checked
// and deterministic, so the no-audit-at-all class can no longer reach release
// undetected. It is NOT a total proof of audit coverage — its precise scope and
// the two documented limitations (one-hop indirection, single-deny Tier 2) are
// spelled out below; do not advertise it beyond that.
//
// # The invariant
//
//	Every Policy Enforcement Point (PEP) — every function that invokes the
//	policy / decision engine — MUST, on its deny / block / redact path,
//	write a canonical audit row through one of the blessed audit writers.
//	"Canonical" means the row lands in audit_logs (the portal /decisions
//	feed, /explain, the audit summary, and the SEBI / EU-AI-Act / OJK / RBI
//	exporters all read audit_logs) or, for control-plane mutations, in the
//	first-class control-plane log (config_audit_log / admin_audit_log /
//	scim_audit_log). A satellite-only write (llm_call_audits, mcp_query_audits)
//	or an OTel-span-only emit does NOT count — those were exactly the holes
//	#2679 / #2686 closed.
//
// # How a PEP is identified (AST + one call hop, not a name grep)
//
//	A function is a PEP iff its body contains a *call expression* whose
//	resolved callee name is in pepMarkers() — i.e. either:
//	  - a policyEvalSinks() entrypoint (EvaluateRequest / EvaluateResponse /
//	    EvaluateDynamicPolicies / EvaluatePolicy / EvaluateStepGate /
//	    EvaluateMCPPermission / …), the leaf of the policy call graph; OR
//	  - a policyDelegatingHelpers() helper — a known in-tree function that
//	    evaluates policy and DELEGATES the audit to its caller (e.g.
//	    evaluateInputPolicies). Following this one hop is what catches handlers
//	    that enforce purely through such a helper (mcp_server_handler.go's
//	    mcpToolCheckPolicy / mcpToolCheckOutput) — the wrapper-hop blind spot.
//	Resolution is by walking the parsed AST and matching the CallExpr's
//	selector/ident, NOT by regex-matching the word "policy" in source text.
//	Enumerating from engine call sites + one delegating hop also catches
//	enforcement inside helpers below an HTTP handler, and avoids fragile
//	cross-module / interface-method type resolution (this tree spans three Go
//	modules — platform/, ee/, and the nested customer-portal module — with
//	`//go:build enterprise` variants, which a single go/packages load cannot
//	type-check cleanly). For traceability the report cross-references each PEP
//	against the router-registered handler set (routerRegisteredHandlerNames).
//
//	Limitation (documented, not a bug): indirection is followed exactly ONE
//	hop. A handler that enforces through a helper NOT in policyDelegatingHelpers,
//	or two hops down, is not auto-enrolled. The delegating-helper set is curated
//	from the known caller-audits helpers (and TestAuditCoverageHelpers asserts it
//	stays in sync with the allowlist); extend both together when a new such
//	helper appears. Deeper SSA-based reachability is tracked in #2697.
//
//	Symmetric one hop on the WRITE side: a PEP that records its verdict by
//	calling a thin in-tree wrapper which itself calls a canonical writer (e.g.
//	ExecuteWithHITL → auditStepGate → LogWorkflowOperation, #2693; Service.StepGate
//	→ s.logAudit → LogWorkflowOperation) counts as auditing. These wrappers are
//	curated in auditDelegatingWrappers() and resolved PER PACKAGE DIRECTORY so a
//	deliberately-generic method name (logAudit has a canonical forwarder in
//	workflow_control but a NON-canonical one in planning) cannot cross-credit the
//	wrong package. See auditResolver / buildAuditResolver. This is the writer-side
//	mirror of policyDelegatingHelpers and removes the prior Service.StepGate
//	"wrapper not in writer set" allowlist concession.
//
// # The two findings the walk emits
//
//	Tier 1 (no-audit-at-all): a PEP whose body contains ZERO canonical audit
//	  writer calls. This is the gross hole class — #2643 (decode/stage early
//	  denies wrote nothing), #2679 (satellite mcp_query_audits only), #2686
//	  (OTel span only). High confidence, zero heuristics.
//
//	Tier 2 (deny-before-audit): a PEP that DOES audit somewhere, but has a
//	  deny-shaped early return (`if x.Blocked { … return }`, `if !x.Allowed
//	  { … return }`, `if verdict == VerdictDeny { … return }`) that is NOT
//	  preceded — lexically, within the same FuncDecl — by any canonical audit
//	  writer call. This is the subtle class: the main path audits but an early
//	  refusal slips out un-recorded (the shape #2643 fixed on /decide).
//
//	  Known limitation (documented, not a bug): Tier 2 is a lexical-precedence
//	  heuristic, not dataflow dominance. If a function has MULTIPLE deny
//	  branches and an EARLIER one audits, a LATER un-audited deny return is not
//	  flagged (some audit lexically precedes it). True per-branch coverage of
//	  that shape needs SSA dominance; it is out of scope for this go/parser walk
//	  and is tracked as a follow-up in #2697. Tier 1 still guarantees every PEP
//	  audits at least one terminal verdict, and the synthetic regression tests
//	  pin the single-deny shape that every historical fix took. This gate does
//	  NOT claim full per-branch deny-path coverage.
//
// # Allowlist (honest, ticketed)
//
//	A PEP that legitimately does not audit in its own body — a pure engine
//	internal whose caller audits, a dry-run policy simulation, an adapter that
//	returns its verdict up to a gate that records it, or a consciously
//	deferred LOW-severity endpoint — is registered in auditCoverageAllowlist()
//	with a one-line reason and, where the work is deferred rather than
//	by-design, a tracking issue ref (#2684 / 9.1.0). The test passes only when
//	every PEP is either covered or allowlisted-with-reason. No silent gaps:
//	the allowlist is the checked-in, reviewable record of every conscious
//	exception, and each entry's reason is printed in the test log.
//
// # Scope
//
//	platform/**/*.go + ee/platform/**/*.go, excluding *_test.go. On a
//	community-mirror checkout ee/platform/ is absent (sync-filtered) and is
//	dropped from the scan cleanly.
//
// # Mutation discipline
//
//	Adding a new route that evaluates policy without auditing its deny path
//	MUST fire this test (synthetic coverage in TestAuditCoverageHelpers).
//	Reverting any of the #2626/#2641/#2643/#2679/#2680/#2686/#2683 audit
//	fixes MUST fire it. Demoting a canonical writer to a satellite-only write
//	MUST fire it.
func TestEveryPolicyEnforcementPointAudits(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	scanDirs := []string{
		filepath.Join(repoRoot, "platform"),
		filepath.Join(repoRoot, "ee", "platform"),
	}
	presentDirs := scanDirs[:0]
	for _, d := range scanDirs {
		if _, err := os.Stat(d); err == nil {
			presentDirs = append(presentDirs, d)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", d, err)
		} else {
			t.Logf("scan dir %s not present (likely community-mirror checkout); skipping", d)
		}
	}
	scanDirs = presentDirs

	markers := pepMarkers()
	audit := buildAuditResolver(scanDirs, repoRoot)
	allowFuncs := auditCoverageAllowlist()
	routerHandlers := routerRegisteredHandlerNames(scanDirs)

	var findings []string
	var peps []pepReport
	for _, root := range scanDirs {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", ".claude":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)

			src, err := os.ReadFile(path)
			if err != nil {
				findings = append(findings, rel+": read: "+err.Error())
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, src, 0)
			if perr != nil {
				findings = append(findings, rel+": parse: "+perr.Error())
				return nil
			}

			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				rep, isPEP, fnd := analyzePEP(rel, fn, fset, markers, audit)
				if !isPEP {
					continue
				}
				rep.isRoute = routerHandlers[fn.Name.Name]

				// Every PEP is recorded in the enumeration exactly once,
				// regardless of outcome — the map IS the #2687 work-list.
				if reason, ok := allowFuncs[rep.qualified]; ok {
					rep.allowlisted = reason
					peps = append(peps, rep)
					continue
				}
				peps = append(peps, rep)
				findings = append(findings, fnd...)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// Always print the full enumeration — this IS the #2687 work-list.
	logPEPReport(t, peps)

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("audit-coverage gate failed (#2687): %d policy enforcement point(s) do not "+
			"write a canonical audit row on their deny path. Every PEP must record its "+
			"terminal verdict in audit_logs (or config_audit_log/admin_audit_log/"+
			"scim_audit_log for control-plane mutations) — the portal /decisions feed, "+
			"/explain, and every compliance exporter read those tables. Fix the deny path "+
			"or add the site to auditCoverageAllowlist() with a reason + ticket.\n\nFindings:\n  - %s",
			len(findings), strings.Join(findings, "\n  - "))
	}
}

// analyzePEP inspects one FuncDecl and, if it is a Policy Enforcement Point
// (its body calls a policyEvalSinks entrypoint), returns a populated pepReport,
// isPEP=true, and the Tier-1 / Tier-2 findings the function triggers (empty when
// it audits correctly). The allowlist and router annotation are applied by the
// caller — analyzePEP reports the raw structural facts only, so it is unit-
// testable against synthetic sources (TestAuditCoverageHelpers). markers is the
// PEP-marker set (policy engine sinks ∪ one-hop delegating helpers); audit is
// the writer resolver (canonical writers ∪ one-hop forwarding wrappers, the
// latter scoped to the caller's package directory — see auditResolver).
func analyzePEP(rel string, fn *ast.FuncDecl, fset *token.FileSet, markers map[string]bool, audit auditResolver) (rep pepReport, isPEP bool, findings []string) {
	if fn.Body == nil {
		return pepReport{}, false, nil
	}
	evalNames, evalPos := callsInto(fn.Body, markers)
	if len(evalNames) == 0 {
		return pepReport{}, false, nil
	}
	dir := pathpkg.Dir(rel)
	qualified := rel + "::" + funcKey(fn)
	auditNames, auditPos := auditCallsInto(fn.Body, audit, dir)
	rep = pepReport{
		qualified:    qualified,
		line:         fset.Position(evalPos[0]).Line,
		evalSinks:    dedup(evalNames),
		auditWriters: dedup(auditNames),
	}

	// Tier 1: a PEP must write at least one canonical audit row.
	if len(auditPos) == 0 {
		findings = append(findings, rel+":"+strconv.Itoa(rep.line)+":"+funcKey(fn)+
			" evaluates policy (calls "+strings.Join(rep.evalSinks, ", ")+
			") but its body writes NO canonical audit row. Add a canonical writer "+
			"("+strings.Join(canonicalWriterHints(), " / ")+") on every terminal "+
			"verdict, or add "+qualified+" to auditCoverageAllowlist() with a reason.")
		return rep, true, findings
	}

	// Tier 2: every deny-shaped early return must be preceded by an audit
	// write (lexically, within this FuncDecl).
	firstAudit := minPos(auditPos)
	for _, ret := range denyReturnPositions(fn.Body) {
		if ret < firstAudit {
			findings = append(findings, rel+":"+strconv.Itoa(fset.Position(ret).Line)+":"+funcKey(fn)+
				" has a deny-shaped early return that precedes the first canonical "+
				"audit write (the deny path is recorded only as an error/allow or not "+
				"at all). Audit BEFORE this return, or allowlist "+qualified+".")
			break // one finding per func is enough to drive the fix
		}
	}
	return rep, true, findings
}

// pepReport captures one PEP function for the enumeration log.
type pepReport struct {
	qualified    string
	line         int
	evalSinks    []string
	auditWriters []string
	isRoute      bool
	allowlisted  string
}

func logPEPReport(t *testing.T, peps []pepReport) {
	t.Helper()
	sort.Slice(peps, func(i, j int) bool { return peps[i].qualified < peps[j].qualified })
	var b strings.Builder
	b.WriteString("\n=== Policy Enforcement Point audit-coverage map (#2687) ===\n")
	for _, p := range peps {
		status := "AUDITS"
		if p.allowlisted != "" {
			status = "ALLOWLISTED"
		} else if len(p.auditWriters) == 0 {
			status = "NO-AUDIT"
		}
		route := ""
		if p.isRoute {
			route = " [route]"
		}
		b.WriteString("  " + status + route + "  " + p.qualified +
			"  eval={" + strings.Join(p.evalSinks, ",") + "}" +
			"  audit={" + strings.Join(p.auditWriters, ",") + "}")
		if p.allowlisted != "" {
			b.WriteString("  — " + p.allowlisted)
		}
		b.WriteString("\n")
	}
	t.Log(b.String())
}

// funcKey returns "Recv.Name" for methods and "Name" for free functions, so
// allowlist entries can disambiguate same-named methods on different types.
func funcKey(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		if recv := recvTypeName(fn.Recv.List[0].Type); recv != "" {
			return recv + "." + fn.Name.Name
		}
	}
	return fn.Name.Name
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver
		return recvTypeName(t.X)
	}
	return ""
}

// callsInto walks block and returns (callee names, positions) for every
// CallExpr whose resolved callee name is in want. Resolution is via the
// existing callName helper (Sel.Name for selectors, ident name for bare
// calls) — the same AST resolution the RLS walker uses.
func callsInto(block *ast.BlockStmt, want map[string]bool) ([]string, []token.Pos) {
	var names []string
	var pos []token.Pos
	ast.Inspect(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call.Fun)
		if name != "" && want[name] {
			names = append(names, name)
			pos = append(pos, call.Lparen)
		}
		return true
	})
	return names, pos
}

// denyReturnPositions returns the position of the return statement inside
// every deny-shaped IfStmt in block. A deny-shaped IfStmt is one whose
// condition, when true, means "this request was refused" — see isDenyCond.
// Only returns that sit directly in the if-block body are considered (the
// early-exit refusal shape); nested returns under further conditionals are
// left to the per-function audit-presence requirement.
func denyReturnPositions(block *ast.BlockStmt) []token.Pos {
	var out []token.Pos
	ast.Inspect(block, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Body == nil {
			return true
		}
		if !isDenyCond(ifs.Cond) {
			return true
		}
		for _, stmt := range ifs.Body.List {
			if ret, ok := stmt.(*ast.ReturnStmt); ok {
				out = append(out, ret.Pos())
			}
		}
		return true
	})
	return out
}

// isDenyCond reports whether an if-condition, when satisfied, denotes a
// policy refusal (block / deny / not-allowed). Recognized shapes, calibrated
// against the real deny branches in the tree:
//
//	x.Blocked                      // openai_compat, mcp, gateway
//	!x.Allowed                     // orchestrator run.go
//	x.Denied
//	x.Verdict == VerdictDeny       // == "deny"/"block"/"blocked"
//	x.Decision == "..."(deny)
//	x.Action == ActionBlock
//
// && / || compositions are recursed so `requestResult != nil &&
// requestResult.Blocked` is recognized. Allow-shaped (`if x.Allowed { … }`)
// and bare error guards (`if err != nil`) are intentionally NOT deny-shaped.
func isDenyCond(cond ast.Expr) bool {
	switch c := cond.(type) {
	case *ast.UnaryExpr:
		if c.Op.String() == "!" {
			// !x.Allowed / !x.Allow → deny.
			if sel, ok := c.X.(*ast.SelectorExpr); ok {
				return isAllowField(sel.Sel.Name)
			}
		}
		return false
	case *ast.BinaryExpr:
		switch c.Op.String() {
		case "&&", "||":
			return isDenyCond(c.X) || isDenyCond(c.Y)
		case "==":
			return isDenyComparison(c.X, c.Y) || isDenyComparison(c.Y, c.X)
		}
		return false
	case *ast.SelectorExpr:
		return isBlockedField(c.Sel.Name)
	case *ast.ParenExpr:
		return isDenyCond(c.X)
	}
	return false
}

// isDenyComparison reports whether `field == val` denotes a deny, where field
// is a verdict/decision/action selector and val is a deny constant/literal.
func isDenyComparison(field, val ast.Expr) bool {
	sel, ok := field.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Verdict", "Decision", "Action", "Status", "Outcome":
	default:
		return false
	}
	return isDenyConst(val)
}

func isDenyConst(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return strings.Contains(v.Name, "Deny") || strings.Contains(v.Name, "Block")
	case *ast.SelectorExpr:
		return strings.Contains(v.Sel.Name, "Deny") || strings.Contains(v.Sel.Name, "Block")
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return false
		}
		switch s {
		case "deny", "block", "blocked", "denied":
			return true
		}
	}
	return false
}

func isBlockedField(name string) bool {
	switch name {
	case "Blocked", "Denied", "IsBlocked", "IsDenied", "ShouldBlock":
		return true
	}
	return false
}

func isAllowField(name string) bool {
	switch name {
	case "Allowed", "Allow", "IsAllowed":
		return true
	}
	return false
}

func minPos(p []token.Pos) token.Pos {
	m := p[0]
	for _, x := range p[1:] {
		if x < m {
			m = x
		}
	}
	return m
}

func dedup(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// policyEvalSinks is the set of decision-engine entrypoints whose invocation
// makes the enclosing function a Policy Enforcement Point. These are the
// request/response ENFORCEMENT decisions — not the internal pattern-matching
// primitives (EvaluateMultiple / EvaluateAll on PatternEvaluator) which carry
// no audit obligation of their own. Sourced from the engine definitions:
//
//	platform/shared/policy/engine.go      EvaluateRequest / EvaluateResponse
//	platform/agent/tier_aware_policy_engine.go   EvaluatePolicy / EvaluateAllPolicies
//	platform/agent/policy/permissions.go         EvaluateMCPPermission
//	platform/shared/policy/dynamic_evaluator.go  EvaluateWithGracefulDegradation
//	platform/orchestrator/dynamic_policy_engine.go + db_dynamic_policies.go  EvaluateDynamicPolicies
//	platform/orchestrator/workflow_control/service.go  EvaluateStepGate
func policyEvalSinks() map[string]bool {
	return map[string]bool{
		"EvaluateRequest":                 true,
		"EvaluateResponse":                true,
		"EvaluateDynamicPolicies":         true,
		"EvaluatePolicy":                  true,
		"EvaluateAllPolicies":             true,
		"EvaluateMCPPermission":           true,
		"EvaluateWithGracefulDegradation": true,
		"EvaluateStepGate":                true,
	}
}

// policyDelegatingHelpers closes the wrapper-hop blind spot. These are in-tree
// helpers that evaluate policy and DELEGATE the audit obligation to their
// caller — they return the verdict up rather than recording it. A function that
// calls one of them is therefore one hop above the engine and is itself a PEP
// that must record (or be allowlisted). Without this, a handler that enforces
// purely through such a helper (e.g. mcp_server_handler.go's mcpToolCheckPolicy
// / mcpToolCheckOutput, which gate via evaluateInput/OutputPolicies) is
// invisible to the gate — the exact false-confidence trap this gate exists to
// kill. A new wrapper-hop handler with a silent deny now turns the gate RED
// (proven by the synthetic wrapper-hop regression in TestAuditCoverageHelpers).
//
// Detection is ONE hop only — deeper indirection is a documented limitation.
// Every name here is a helper that is itself an allowlisted "caller audits"
// PEP; TestAuditCoverageHelpers asserts each appears in auditCoverageAllowlist()
// so the two cannot drift. All six have a unique definition in the tree, so
// matching by call name is unambiguous.
func policyDelegatingHelpers() map[string]bool {
	return map[string]bool{
		"evaluateInputPolicies":   true, // mcp_handler.go — MCP input plane
		"evaluateOutputPolicies":  true, // mcp_handler.go — MCP output plane
		"redactInputStatement":    true, // mcp_handler.go — MCP redaction
		"DetectWithSharedEngine":  true, // pii_detector.go — response detector
		"processWithSharedEngine": true, // response_processor.go — response plane
		"CheckPolicy":             true, // map_hitl_adapter.go — MAP/HITL step gate
	}
}

// pepMarkers is the union of the engine sinks and the one-hop delegating
// helpers — the full set whose invocation makes the enclosing function a PEP.
func pepMarkers() map[string]bool {
	out := map[string]bool{}
	for k := range policyEvalSinks() {
		out[k] = true
	}
	for k := range policyDelegatingHelpers() {
		out[k] = true
	}
	return out
}

// auditDelegatingWrappers closes the WRITER-side wrapper-hop blind spot — the
// symmetric mirror of policyDelegatingHelpers. These are thin in-tree wrappers
// whose only job is to forward to a canonical audit writer (an optional
// nil-guard plus a single LogWorkflowOperation call). A PEP that records its
// terminal verdict by calling one of these discharges its audit obligation
// exactly as if it had called the canonical writer directly — the row still
// lands in audit_logs. Following this one hop on the WRITE side is what lets the
// gate SEE the audit that:
//
//   - HITLWorkflowEngine.ExecuteWithHITL performs via auditStepGate →
//     LogWorkflowOperation (#2693, merged), and
//   - workflow_control Service.StepGate performs via s.logAudit →
//     LogWorkflowOperation,
//
// without polluting canonicalAuditWriters() with these deliberately-generic
// method names. That generic-name hazard is real and is exactly why bare-leaf
// matching is unsafe here: `logAudit` has THREE definitions in the tree —
// workflow_control/service.go (→ LogWorkflowOperation, canonical), planning/
// service.go (→ LogPlanOperation, NOT canonical), and a dynamic_policy_engine
// logAuditEvent (different name). A bare-name match would wrongly credit a
// planning PEP that calls its own non-canonical logAudit.
//
// To stay collision-safe, the wrapper hop is resolved PER PACKAGE DIRECTORY: a
// call to wrapper W in directory D counts as an audit only when a same-named
// FuncDecl IN D actually forwards to a canonical writer (see buildAuditResolver
// / indexForwardingWrappers). So workflow_control's logAudit credits
// Service.StepGate, while planning's logAudit (which forwards to the
// non-canonical LogPlanOperation) credits nothing. The
// "writer-side hop is package-scoped (generic-name collision guard)" subtest
// pins this exactly.
//
// Detection is ONE hop only (documented limitation, #2697): a PEP that audits
// two wrapper-hops deep is not auto-covered. Each name here is asserted to
// resolve to at least one real canonical-forwarding definition by
// TestAuditCoverageHelpers, so the curated set cannot silently drift from the
// tree (e.g. reverting auditStepGate's LogWorkflowOperation call fails the gate).
func auditDelegatingWrappers() map[string]bool {
	return map[string]bool{
		"auditStepGate": true, // hitl_execution.go (HITLWorkflowEngine) → LogWorkflowOperation (#2693)
		"logAudit":      true, // workflow_control/service.go (Service) → LogWorkflowOperation
	}
}

// auditResolver answers "does calling NAME from package directory DIR discharge
// the audit obligation?". A direct call to a canonical writer always counts. A
// call to a one-hop forwarding wrapper counts only when a same-named definition
// in the SAME directory forwards to a canonical writer — the package-scoping
// that makes the generic `logAudit` name safe (see auditDelegatingWrappers).
type auditResolver struct {
	canonical   map[string]bool            // direct canonical writers (canonicalAuditWriters)
	wrapperDirs map[string]map[string]bool // wrapper name -> set of dirs whose same-named def forwards to a canonical writer
}

func (r auditResolver) isAudit(name, dir string) bool {
	if r.canonical[name] {
		return true
	}
	if dirs, ok := r.wrapperDirs[name]; ok && dirs[dir] {
		return true
	}
	return false
}

// buildAuditResolver pre-scans the tree once to index which audit-delegating
// wrappers actually forward to a canonical writer, keyed by the package
// directory of their definition. The result drives auditCallsInto. Parsing here
// is structural (go/parser, no type-check), matching the rest of this gate.
func buildAuditResolver(scanDirs []string, repoRoot string) auditResolver {
	canonical := canonicalAuditWriters()
	wrappers := auditDelegatingWrappers()
	wrapperDirs := map[string]map[string]bool{}
	for _, root := range scanDirs {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", ".claude":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, src, 0)
			if perr != nil {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				rel = path
			}
			indexForwardingWrappers(filepath.ToSlash(rel), f, wrappers, canonical, wrapperDirs)
			return nil
		})
	}
	return auditResolver{canonical: canonical, wrapperDirs: wrapperDirs}
}

// indexForwardingWrappers records, for every FuncDecl in f whose name is a
// curated audit-delegating wrapper AND whose body calls a canonical writer, the
// package directory of rel into out[name]. Scoped per directory so a generic
// wrapper name (logAudit) that forwards to a canonical writer in one package
// does NOT credit a same-named, non-canonical-forwarding definition in another.
func indexForwardingWrappers(rel string, f *ast.File, wrappers, canonical map[string]bool, out map[string]map[string]bool) {
	dir := pathpkg.Dir(rel)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if !wrappers[fn.Name.Name] {
			continue
		}
		if names, _ := callsInto(fn.Body, canonical); len(names) > 0 {
			if out[fn.Name.Name] == nil {
				out[fn.Name.Name] = map[string]bool{}
			}
			out[fn.Name.Name][dir] = true
		}
	}
}

// auditCallsInto is the writer-side analogue of callsInto: it returns the
// (names, positions) of every CallExpr in block that discharges the audit
// obligation when invoked from package directory dir (a direct canonical writer,
// or a same-directory forwarding wrapper).
func auditCallsInto(block *ast.BlockStmt, r auditResolver, dir string) ([]string, []token.Pos) {
	var names []string
	var pos []token.Pos
	ast.Inspect(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call.Fun)
		if name != "" && r.isAudit(name, dir) {
			names = append(names, name)
			pos = append(pos, call.Lparen)
		}
		return true
	})
	return names, pos
}

// presentScanDirs returns the audit-coverage scan roots (platform/ +
// ee/platform/) that actually exist in this checkout. ee/platform/ is absent on
// the community mirror and is dropped cleanly.
func presentScanDirs(repoRoot string) []string {
	var out []string
	for _, d := range []string{
		filepath.Join(repoRoot, "platform"),
		filepath.Join(repoRoot, "ee", "platform"),
	} {
		if _, err := os.Stat(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// funcDefsByLeaf maps a function's leaf name to the set of "<rel-path>::<funcKey>"
// qualified keys where a NON-test FuncDecl of that name is defined. Used by the
// allowlist-sync test to match a delegating helper against its REAL definition's
// qualified key rather than a bare leaf name (so a same-named method elsewhere
// cannot spuriously satisfy the invariant).
func funcDefsByLeaf(scanDirs []string, repoRoot string) map[string][]string {
	out := map[string][]string{}
	for _, root := range scanDirs {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", ".claude":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, src, 0)
			if perr != nil {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				out[fn.Name.Name] = append(out[fn.Name.Name], rel+"::"+funcKey(fn))
			}
			return nil
		})
	}
	return out
}

// canonicalAuditWriters is the set of blessed writers that land a row in
// audit_logs (or a first-class control-plane log). A call to any of these
// discharges the audit obligation. Sourced from:
//
//	platform/agent/decision_handler.go     recordDecideDecision / writeDecisionAuditLog
//	platform/agent/gateway_handlers.go     recordGatewayPreCheckAudit
//	platform/agent/mcp_richer_context.go   writeMCPDecisionAudit / writeExplainableAuditLog
//	platform/orchestrator/audit_logger.go  LogBlockedRequest / LogBlockedResponse / LogBlockedMedia / LogWorkflowOperation
//	ee/.../api/admin_audit.go              writeAdminAuditLog / WriteDetectionPostureAudit
//	ee/.../api/config_change_audit.go      writeConfigAuditLog
//	ee/.../scim/audit.go                   auditInvalidJSON / auditMissingTenant
//
// recordOpenAICompatAudit / recordMCPQueryAudit are EXCLUDED on purpose: they
// write satellite tables (llm_call_audits / mcp_query_audits), not audit_logs.
// A PEP that records ONLY into a satellite is the #2679/#2686 hole class and
// MUST still call a canonical writer.
func canonicalAuditWriters() map[string]bool {
	return map[string]bool{
		"recordDecideDecision":       true,
		"writeDecisionAuditLog":      true,
		"recordGatewayPreCheckAudit": true,
		"writeMCPDecisionAudit":      true,
		"writeExplainableAuditLog":   true,
		"LogBlockedRequest":          true,
		"LogBlockedResponse":         true,
		"LogBlockedMedia":            true,
		"LogWorkflowOperation":       true,
		"writeAdminAuditLog":         true,
		"WriteDetectionPostureAudit": true,
		"writeConfigAuditLog":        true,
		"auditInvalidJSON":           true,
		"auditMissingTenant":         true,
	}
}

func canonicalWriterHints() []string {
	return []string{
		"recordDecideDecision", "writeMCPDecisionAudit", "LogBlockedRequest", "writeConfigAuditLog",
	}
}

// routerRegisteredHandlerNames scans every X.HandleFunc(pattern, handler) and
// X.Handle(pattern, handler) registration and returns the set of handler
// function NAMES referenced as the handler argument (bare ident, selector, or
// method value). Used only to annotate the report — the coverage assertion is
// driven by the engine call sites, which are a superset of router-reachable
// enforcement.
func routerRegisteredHandlerNames(scanDirs []string) map[string]bool {
	out := map[string]bool{}
	for _, root := range scanDirs {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", ".claude":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, src, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
					return true
				}
				if len(call.Args) < 2 {
					return true
				}
				if name := callName(call.Args[1]); name != "" {
					out[name] = true
				}
				return true
			})
			return nil
		})
	}
	return out
}

// auditCoverageSyntheticFindings parses an in-memory Go source string and
// returns the Tier-1/Tier-2 findings analyzePEP raises for every FuncDecl in
// it. Used by TestAuditCoverageHelpers to assert that specific shapes fire (or
// do not) without depending on the live tree.
func auditCoverageSyntheticFindings(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synth.go", src, 0)
	if err != nil {
		t.Fatalf("parse synth: %v", err)
	}
	markers := pepMarkers()
	// Build the writer resolver from the synth source itself, so a thin
	// forwarding wrapper defined in the same synthetic file (package dir ".")
	// is recognized one hop up — the writer-side analogue of the eval hop.
	wrapperDirs := map[string]map[string]bool{}
	indexForwardingWrappers("synth.go", f, auditDelegatingWrappers(), canonicalAuditWriters(), wrapperDirs)
	audit := auditResolver{canonical: canonicalAuditWriters(), wrapperDirs: wrapperDirs}
	var findings []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, isPEP, fnd := analyzePEP("synth.go", fn, fset, markers, audit); isPEP {
			findings = append(findings, fnd...)
		}
	}
	return findings
}

// parseSingleCond parses `if <expr> {}` and returns the condition expr, for
// unit-testing isDenyCond in isolation.
func parseSingleCond(t *testing.T, cond string) ast.Expr {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "c.go",
		"package x\nfunc f(){ if "+cond+" { _ = 0 } }", 0)
	if err != nil {
		t.Fatalf("parse cond %q: %v", cond, err)
	}
	fn := f.Decls[0].(*ast.FuncDecl)
	return fn.Body.List[0].(*ast.IfStmt).Cond
}

// TestAuditCoverageHelpers exercises the machinery in isolation so a refactor
// of the sink/writer resolution, the deny-shape classifier, or the lexical
// before/after audit check surfaces here BEFORE the full-tree walk passes or
// fails for unrelated reasons. Each subtest pins one regression.
func TestAuditCoverageHelpers(t *testing.T) {
	t.Run("tier1 fires: evaluates but never audits", func(t *testing.T) {
		src := `package x
import "context"
func h(ctx context.Context) {
	res := engine.EvaluateRequest(ctx, "q", nil)
	if res.Blocked { sendError(); return }
}`
		findings := auditCoverageSyntheticFindings(t, src)
		if !containsAll(findings, "synth.go", "::h", "writes NO canonical audit row") {
			t.Fatalf("tier1 not raised for un-audited PEP: %v", findings)
		}
	})

	t.Run("tier1 clean: evaluates and audits", func(t *testing.T) {
		src := `package x
import "context"
func h(ctx context.Context) {
	res := engine.EvaluateRequest(ctx, "q", nil)
	if res.Blocked {
		recordDecideDecision(ctx, "id", "o", "t", "llm", "deny", nil, 0, nil, "", nil, false, nil)
		return
	}
}`
		if findings := auditCoverageSyntheticFindings(t, src); len(findings) != 0 {
			t.Fatalf("clean PEP wrongly flagged: %v", findings)
		}
	})

	t.Run("satellite-only write is NOT canonical (tier1 fires)", func(t *testing.T) {
		// recordOpenAICompatAudit writes llm_call_audits, not audit_logs — it is
		// deliberately absent from canonicalAuditWriters(). A PEP that records
		// ONLY into a satellite must still be flagged (#2679/#2686 class).
		src := `package x
import "context"
func h(ctx context.Context) {
	res := engine.EvaluateRequest(ctx, "q", nil)
	if res.Blocked {
		recordOpenAICompatAudit("id", "c", "o", "t", "openai", "m", 0, 0, 0, 0, 0, "deny", "")
		return
	}
}`
		findings := auditCoverageSyntheticFindings(t, src)
		if !containsAll(findings, "::h", "writes NO canonical audit row") {
			t.Fatalf("satellite-only write should fire tier1: %v", findings)
		}
	})

	t.Run("tier2 fires: deny early-return precedes the audit", func(t *testing.T) {
		// The main path audits, but a blocked early-return slips out un-recorded
		// (the #2643 shape: early deny before the canonical write).
		src := `package x
import "context"
func h(ctx context.Context) {
	res := engine.EvaluateRequest(ctx, "q", nil)
	if res.Blocked { sendError(); return }
	recordDecideDecision(ctx, "id", "o", "t", "llm", "allow", nil, 0, nil, "", nil, false, nil)
}`
		findings := auditCoverageSyntheticFindings(t, src)
		if !containsAll(findings, "::h", "deny-shaped early return") {
			t.Fatalf("tier2 not raised for deny-before-audit: %v", findings)
		}
	})

	t.Run("tier2 clean: audit precedes the deny return", func(t *testing.T) {
		src := `package x
import "context"
func h(ctx context.Context) {
	res := engine.EvaluateRequest(ctx, "q", nil)
	recordDecideDecision(ctx, "id", "o", "t", "llm", verdict, nil, 0, nil, "", nil, false, nil)
	if res.Blocked { sendError(); return }
}`
		if findings := auditCoverageSyntheticFindings(t, src); len(findings) != 0 {
			t.Fatalf("audit-then-deny wrongly flagged: %v", findings)
		}
	})

	t.Run("not a PEP: no eval sink, no findings", func(t *testing.T) {
		src := `package x
func h() { doSomething(); return }`
		if findings := auditCoverageSyntheticFindings(t, src); len(findings) != 0 {
			t.Fatalf("non-PEP function flagged: %v", findings)
		}
	})

	t.Run("wrapper-hop fires: enforces via a delegating helper, no audit", func(t *testing.T) {
		// The exact blind spot R3 caught: a handler that enforces ONLY through a
		// delegating helper (evaluateInputPolicies) and silently denies. It must
		// be RED — proving a NEW wrapper-hop handler can't slip past green.
		src := `package x
import "context"
func mcpToolLike(ctx context.Context) {
	outcome := evaluateInputPolicies(ctx, "stmt")
	if outcome.Blocked { sendError(); return }
}`
		findings := auditCoverageSyntheticFindings(t, src)
		if !containsAll(findings, "::mcpToolLike", "writes NO canonical audit row") {
			t.Fatalf("wrapper-hop handler not flagged — the blind spot is open: %v", findings)
		}
	})

	t.Run("wrapper-hop clean: delegating helper + caller audits", func(t *testing.T) {
		src := `package x
import "context"
func mcpToolLike(ctx context.Context) {
	outcome := evaluateInputPolicies(ctx, "stmt")
	if outcome.Blocked {
		writeMCPDecisionAudit(ctx, "deny")
		return
	}
}`
		if findings := auditCoverageSyntheticFindings(t, src); len(findings) != 0 {
			t.Fatalf("audited wrapper-hop handler wrongly flagged: %v", findings)
		}
	})

	t.Run("writer-side wrapper-hop clean: PEP audits via a thin forwarding wrapper", func(t *testing.T) {
		// The symmetric write-side hop: a PEP records its verdict by calling a
		// thin wrapper (auditStepGate) defined in the SAME package that forwards
		// to a canonical writer (LogWorkflowOperation). This is the shape
		// ExecuteWithHITL takes after #2693, and it must NOT be flagged.
		src := `package x
import "context"
func auditStepGate(ctx context.Context) { LogWorkflowOperation(ctx, nil) }
func enforce(ctx context.Context) {
	res := engine.EvaluateRequest(ctx, "q", nil)
	if res.Blocked { auditStepGate(ctx); return }
}`
		if findings := auditCoverageSyntheticFindings(t, src); len(findings) != 0 {
			t.Fatalf("PEP auditing via a thin forwarding wrapper wrongly flagged: %v", findings)
		}
	})

	t.Run("writer-side wrapper-hop red-on-revert: wrapper no longer forwards", func(t *testing.T) {
		// Revert #2693: empty out auditStepGate's canonical write. The wrapper no
		// longer forwards, so the PEP is back to NO-AUDIT and the gate must fire.
		// This is the regression guard that keeps the #2693 HITL fix in place.
		src := `package x
import "context"
func auditStepGate(ctx context.Context) { /* reverted: no canonical write */ }
func enforce(ctx context.Context) {
	res := engine.EvaluateRequest(ctx, "q", nil)
	if res.Blocked { auditStepGate(ctx); return }
}`
		findings := auditCoverageSyntheticFindings(t, src)
		if !containsAll(findings, "::enforce", "writes NO canonical audit row") {
			t.Fatalf("a non-forwarding wrapper must leave the PEP un-audited: %v", findings)
		}
	})

	t.Run("writer-side hop is package-scoped (generic-name collision guard)", func(t *testing.T) {
		// The exact logAudit hazard: two packages both define a wrapper named
		// `logAudit`. In pkgA it forwards to a CANONICAL writer; in pkgB it
		// forwards to a NON-canonical one (the real workflow_control vs planning
		// split). A PEP in pkgB that calls logAudit must NOT be credited — only
		// the same-directory canonical forwarder counts.
		canonical := canonicalAuditWriters()
		wrappers := auditDelegatingWrappers()
		wrapperDirs := map[string]map[string]bool{}
		parseInto := func(rel, src string) {
			f, err := parser.ParseFile(token.NewFileSet(), rel, src, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			indexForwardingWrappers(rel, f, wrappers, canonical, wrapperDirs)
		}
		parseInto("pkgA/x.go", "package a\nfunc logAudit() { LogWorkflowOperation() }")
		parseInto("pkgB/y.go", "package b\nfunc logAudit() { LogPlanOperation() }")
		r := auditResolver{canonical: canonical, wrapperDirs: wrapperDirs}
		if !r.isAudit("logAudit", "pkgA") {
			t.Error("pkgA logAudit forwards to a canonical writer → must credit its package")
		}
		if r.isAudit("logAudit", "pkgB") {
			t.Error("pkgB logAudit forwards to a NON-canonical writer → must NOT credit (collision guard breached)")
		}
		if r.isAudit("logAudit", "pkgC") {
			t.Error("a package with no logAudit definition must not be credited")
		}
	})

	t.Run("audit wrappers resolve to a real canonical-forwarding definition", func(t *testing.T) {
		// Drift guard: every curated wrapper must resolve to at least one real
		// in-tree definition that forwards to a canonical writer. If a wrapper is
		// renamed or its canonical call is removed, this fails — the curated set
		// can never silently credit nothing.
		repoRoot, err := findRepoRoot()
		if err != nil {
			t.Fatalf("locate repo root: %v", err)
		}
		resolver := buildAuditResolver(presentScanDirs(repoRoot), repoRoot)
		for w := range auditDelegatingWrappers() {
			if len(resolver.wrapperDirs[w]) == 0 {
				t.Errorf("audit wrapper %q resolves to NO canonical-forwarding definition in the tree — fix the wrapper or remove it from auditDelegatingWrappers()", w)
			}
		}
	})

	t.Run("isDenyCond classifier", func(t *testing.T) {
		deny := []string{
			"res.Blocked",
			"!res.Allowed",
			"result != nil && result.Blocked",
			"d.Verdict == VerdictDeny",
			"d.Action == ActionBlock",
			`d.Decision == "block"`,
			"res.Denied",
			"(res.Blocked)",
		}
		notDeny := []string{
			"err != nil",
			"res.Allowed",
			"d.Verdict == VerdictAllow",
			"len(x) == 0",
			"res.Count > 0",
		}
		for _, c := range deny {
			if !isDenyCond(parseSingleCond(t, c)) {
				t.Errorf("isDenyCond(%q) = false, want true", c)
			}
		}
		for _, c := range notDeny {
			if isDenyCond(parseSingleCond(t, c)) {
				t.Errorf("isDenyCond(%q) = true, want false", c)
			}
		}
	})

	t.Run("sink and writer sets are non-empty and disjoint", func(t *testing.T) {
		sinks, writers, wrappers := policyEvalSinks(), canonicalAuditWriters(), auditDelegatingWrappers()
		if len(sinks) == 0 || len(writers) == 0 || len(wrappers) == 0 {
			t.Fatal("sink/writer/wrapper set unexpectedly empty")
		}
		for s := range sinks {
			if writers[s] {
				t.Errorf("%q is both an eval sink and an audit writer", s)
			}
		}
		// A forwarding wrapper is NOT itself a direct canonical writer (it is the
		// one-hop indirection), nor an eval sink.
		for w := range wrappers {
			if writers[w] {
				t.Errorf("%q is in both the wrapper set and the direct canonical-writer set", w)
			}
			if sinks[w] {
				t.Errorf("%q is both an eval sink and an audit wrapper", w)
			}
		}
		// recordOpenAICompatAudit must never be treated as canonical.
		if writers["recordOpenAICompatAudit"] {
			t.Error("recordOpenAICompatAudit (satellite) must not be a canonical writer")
		}
	})

	t.Run("delegating helpers are allowlisted by QUALIFIED key", func(t *testing.T) {
		// Every one-hop EVAL delegating helper must itself be an allowlisted PEP
		// (it evaluates policy and delegates auditing), so the two sets cannot
		// drift. Match each helper against the QUALIFIED key of its REAL in-tree
		// definition (<path>::<funcKey>), not a bare leaf name — a same-named
		// method elsewhere could otherwise spuriously satisfy the invariant.
		repoRoot, err := findRepoRoot()
		if err != nil {
			t.Fatalf("locate repo root: %v", err)
		}
		defsByLeaf := funcDefsByLeaf(presentScanDirs(repoRoot), repoRoot)
		allow := auditCoverageAllowlist()
		for h := range policyDelegatingHelpers() {
			defs := defsByLeaf[h]
			if len(defs) == 0 {
				t.Errorf("delegating helper %q has no non-test definition in the scanned tree", h)
				continue
			}
			for _, qk := range defs {
				if _, ok := allow[qk]; !ok {
					t.Errorf("delegating helper definition %q is not allowlisted by qualified key — add it to auditCoverageAllowlist() (it evaluates policy and delegates auditing)", qk)
				}
			}
		}
	})

	t.Run("allowlist keys are well-formed and reasoned", func(t *testing.T) {
		for key, reason := range auditCoverageAllowlist() {
			if !strings.Contains(key, "::") {
				t.Errorf("allowlist key %q is not <path>::<func>", key)
			}
			if len(strings.TrimSpace(reason)) < 20 {
				t.Errorf("allowlist key %q has too-thin a reason: %q", key, reason)
			}
			// Deferred entries must cite a tracking issue.
			if strings.HasPrefix(reason, "DEFERRED") && !strings.Contains(reason, "#") {
				t.Errorf("DEFERRED allowlist key %q must cite an issue: %q", key, reason)
			}
		}
	})
}

func containsAll(findings []string, subs ...string) bool {
	for _, f := range findings {
		ok := true
		for _, s := range subs {
			if !strings.Contains(f, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
