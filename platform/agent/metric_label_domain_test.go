// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/decision/contract"

	"axonflow/platform/agent/license"
	"axonflow/platform/shared/metricdomain"
)

// ---------------------------------------------------------------------------
// #3720: A LIST-VS-LIST LABEL TEST IS BLIND TO CARDINALITY BY CONSTRUCTION.
//
// The one test in the tree that looked like it guarded this -
// platform/gateway-adapters/telemetry_test.go's TestNoLabelCarriesRequestContent
// - compares a sorted list of expected label NAMES against the actual ones. It
// reads l.GetName() and never l.GetValue(), so replacing a constant argument
// with r.Header.Get("X-Whatever") leaves the names identical, the assertion
// green, and the metric minting one time series per header value.
//
// Its own doc states the premise it cannot check: "both label values come from
// the constants above and there is no path by which a request can introduce a
// tenth". Every metric declaration in this file's guarded set makes a claim of
// the same shape, in prose, and nothing checked any of them either.
//
// This file makes those claims machine-checkable, in two halves that fail for
// different reasons:
//
//	CENSUS       every label of every metric declared in the guarded files has
//	             a declared domain, and every declared domain names a live
//	             label. Derived from the SOURCE, so a new metric or a new label
//	             position fails here until somebody decides what bounds it.
//	BEHAVIOURAL  the real write sites are driven with out-of-domain input and
//	             every emitted value must land inside its declared domain.
//
// Neither is sufficient alone. The census cannot see a value; the behavioural
// half cannot see a metric nobody drove.
// ---------------------------------------------------------------------------

// guardedMetricFiles are the metric declarations whose labels are most exposed
// to caller input - the decision, handshake and client-version families named
// in #3720's disposition.
//
// It is a FILE list rather than a metric list on purpose: the metrics inside
// are derived, so adding one to a guarded file is caught, which is the case a
// metric list would miss.
//
// WHAT IS EXCLUDED is every other metric-declaring file in this tree, and
// saying it that way round is the honest statement: this guards 4 files of the
// 44 that call WithLabelValues, out of 491 non-test call sites across several
// vocabularies. That wider sweep is the lane #3720 scopes separately, and the
// shape here is what generalises to it - the point of starting with the
// caller-exposed families is that they are where the class bites first, not
// that the others are clean.
var guardedMetricFiles = []string{
	"decision_handler.go",
	"authzen_handler.go",
	"pep_handshake.go",
	"client_version_telemetry.go",
	// A sub-package, parsed the same way: the verified licence read's
	// refusal counter (#3709 row 1). Its label comes from a validator MESSAGE
	// folded onto five constants, which is exactly the shape this census is
	// for.
	"license/tier_read.go",
}

// declaredMetric is one metric vec found in a guarded file.
type declaredMetric struct {
	Name   string
	Labels []string
	File   string
	Line   int
}

// deriveGuardedMetrics parses the guarded files and returns every
// prometheus/promauto *Vec they declare, with its label names.
//
// Build tags are irrelevant here because go/parser does not evaluate them, so
// client_version_telemetry.go's enterprise-tagged declarations are derived in
// BOTH builds. That is deliberate: a metric only visible under one tag is
// exactly the one a census run under the other tag would silently omit.
func deriveGuardedMetrics(t *testing.T) []declaredMetric {
	t.Helper()
	var out []declaredMetric
	for _, file := range guardedMetricFiles {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("guarded metric file %s is missing: %v. Either it was renamed - in which case "+
				"this list is stale and the metrics in it are unguarded - or the test is running "+
				"from the wrong directory.", file, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		consts := stringConstsOf(f)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// THE SELECTOR IS MATCHED ON THE METHOD NAME FIRST, and the
			// receiver is checked second, because the receiver is the part a
			// future author varies. An earlier version required
			// `sel.X` to be the identifier `prometheus` or `promauto`, so
			//
			//	promauto.With(prometheus.DefaultRegisterer).NewCounterVec(opts, labels)
			//
			// - whose receiver is a CallExpr - matched nothing and was skipped
			// SILENTLY. R3 added exactly that, with an unbounded `raw_pep_id`
			// label, and every lane stayed green. An aliased import
			// (`prom "…/prometheus"`) is the same hole.
			if !strings.HasPrefix(sel.Sel.Name, "New") || !strings.HasSuffix(sel.Sel.Name, "Vec") {
				return true
			}
			if len(call.Args) != 2 {
				t.Errorf("%s:%d declares %s with %d arguments; this census reads (opts, labels) and "+
					"cannot read this form. A declaration it cannot read is a metric with no declared "+
					"domain and no sign of it.", file, fset.Position(call.Pos()).Line, sel.Sel.Name, len(call.Args))
				return true
			}
			name, ok := metricNameOf(call.Args[0], consts)
			if !ok {
				// REPORTED, NEVER SKIPPED. A declaration this extraction cannot
				// read is a metric with no declared domain and no sign of it -
				// the silent omission the whole census exists to prevent.
				t.Errorf("%s:%d declares a metric vec whose Name this census cannot resolve to a "+
					"string. Every guarded metric must be derivable, or it is unguarded while "+
					"looking guarded.", file, fset.Position(call.Pos()).Line)
				return true
			}
			labels, ok := stringSliceOf(call.Args[1], consts)
			if !ok {
				t.Errorf("%s:%d declares metric %q with a label list this census cannot read",
					file, fset.Position(call.Pos()).Line, name)
				return true
			}
			// ConstLabels are label positions the second argument cannot show.
			// They appear on every series of the metric, so a per-subject id
			// smuggled in there is exactly as unbounded as one in the label
			// list - and invisible to a census that reads only call.Args[1].
			constNames, unreadable := constLabelNamesOf(call.Args[0], consts)
			if unreadable {
				t.Errorf("%s:%d metric %q declares ConstLabels this census cannot read. A ConstLabel "+
					"is a label position on EVERY series, so one it cannot see is a cardinality "+
					"decision nobody declared - spell them as literal keys in a literal "+
					"prometheus.Labels{}.", file, fset.Position(call.Pos()).Line, name)
			}
			labels = append(labels, constNames...)
			out = append(out, declaredMetric{
				Name: name, Labels: labels, File: file, Line: fset.Position(call.Pos()).Line,
			})
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// vecsWrittenIn returns the identifier of every vec a guarded file calls
// WithLabelValues on, with the line of the call.
//
// # WHY THE WRITE SITES AND NOT ONLY THE DECLARATIONS
//
// deriveGuardedMetrics reads DECLARATIONS, and a declaration it cannot parse is
// one it does not report. R3 found the residue: a vec built by a helper living
// in an UNGUARDED file and merely assigned in a guarded one
// (`var m = newMutantVec()`) matched no constructor shape, was skipped
// silently, and carried an unbounded label past every lane.
//
// Deriving the write sites instead is the inversion. A metric is only useful if
// something WRITES to it, so requiring every written vec to be one the census
// derived closes the shape without needing to enumerate the ways a vec can be
// constructed - which is the enumeration that cannot terminate.
func vecsWrittenIn(t *testing.T, file string) map[string]int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithLabelValues" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if _, seen := out[id.Name]; !seen {
				out[id.Name] = fset.Position(call.Pos()).Line
			}
		}
		return true
	})
	return out
}

// vecNamesDeclaredIn maps the VARIABLE each guarded file binds a derived metric
// to, so a write site can be matched against a declaration.
func vecNamesDeclaredIn(t *testing.T, file string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, id := range vs.Names {
			if i >= len(vs.Values) {
				continue
			}
			call, ok := vs.Values[i].(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
				strings.HasPrefix(sel.Sel.Name, "New") && strings.HasSuffix(sel.Sel.Name, "Vec") {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

// constLabelNamesOf pulls the ConstLabels keys out of a prometheus.XxxOpts
// composite literal.
func constLabelNamesOf(e ast.Expr, consts map[string]string) (names []string, unreadable bool) {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		// Opts supplied by something other than a literal - the whole label set
		// is then unreadable, so REPORT rather than return an empty list. Its
		// siblings metricNameOf/stringSliceOf already fail closed here; only
		// this helper failed open, and for a census-only metric nothing else
		// could see it.
		return nil, true
	}
	var out []string
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "ConstLabels" {
			continue
		}
		inner, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			// ConstLabels built by a call or a variable: every key it carries is
			// a label position this census cannot see.
			return out, true
		}
		for _, e2 := range inner.Elts {
			kv2, ok := e2.(*ast.KeyValueExpr)
			if !ok {
				return out, true
			}
			if lit, ok := unquote(kv2.Key); ok {
				out = append(out, lit)
				continue
			}
			if id, ok := kv2.Key.(*ast.Ident); ok {
				if v, found := consts[id.Name]; found {
					out = append(out, v)
					continue
				}
			}
			// A key this FILE's constants cannot resolve - it may be declared in
			// another file of the same package. Unreadable, not absent.
			return out, true
		}
	}
	return out, false
}

func stringConstsOf(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, id := range vs.Names {
				if i < len(vs.Values) {
					if s, ok := unquote(vs.Values[i]); ok {
						out[id.Name] = s
					}
				}
			}
		}
	}
	return out
}

// metricNameOf pulls the Name field out of a prometheus.XxxOpts composite.
func metricNameOf(e ast.Expr, consts map[string]string) (string, bool) {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Name" {
			continue
		}
		if s, ok := unquote(kv.Value); ok {
			return s, true
		}
		if id, ok := kv.Value.(*ast.Ident); ok {
			if v, found := consts[id.Name]; found {
				return v, true
			}
		}
	}
	return "", false
}

func stringSliceOf(e ast.Expr, consts map[string]string) ([]string, bool) {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		if s, ok := unquote(elt); ok {
			out = append(out, s)
			continue
		}
		if id, ok := elt.(*ast.Ident); ok {
			if v, found := consts[id.Name]; found {
				out = append(out, v)
				continue
			}
		}
		return nil, false
	}
	return out, true
}

func unquote(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// guardedMetricDomains declares, per metric and per label, what bounds the
// value.
//
// Each Why says WHERE THE VALUE COMES FROM and WHAT COLLAPSES IT, because that
// is the claim; the value list alone is a set of strings the next reader has to
// re-derive from the call sites.
func guardedMetricDomains() map[string]map[string]metricdomain.Domain {
	// The six origin buckets. classifyDecisionOrigin returns one of these and
	// nothing else: every arm returns a constant and the fall-through is
	// OriginUnknown, so the X-Axonflow-Client header cannot reach the label.
	origin := metricdomain.Closed(
		"classifyDecisionOrigin buckets the X-Axonflow-Client header and caller_identity.gateway_id; "+
			"every arm returns an OriginXxx constant and the fall-through is OriginUnknown, so no "+
			"caller string reaches the label",
		OriginClaudeCode, OriginClaudeDesktop, OriginSDK, OriginPlugin, OriginGateway, OriginUnknown)

	// llm|tool|agent, plus the literal "unknown" the early-deny path passes.
	// isValidStage rejects everything else at the API boundary with a return,
	// so an out-of-domain stage never reaches a label at all.
	stage := metricdomain.Closed(
		"req.Stage, lower-cased and trimmed, then gated by isValidStage which RETURNS 400 on anything "+
			"else; the early-deny path passes the literal \"unknown\"",
		DecisionStageLLM, DecisionStageTool, DecisionStageAgent, "unknown")

	return map[string]map[string]metricdomain.Domain{
		"axonflow_license_tier_read_rejected_total": {
			"reason": metricdomain.Closed(
				"classifyTierRejection folds the validator's refusal message onto five constants by "+
					"substring, with TierReadRejectedInvalid as the fall-through; the message itself never "+
					"reaches the label. Checked live in license/tier_read_domain_test.go.",
				license.TierReadRejectedSignature, license.TierReadRejectedExpired, license.TierReadRejectedTier,
				license.TierReadRejectedMalformed, license.TierReadRejectedInvalid),
		},
		"axonflow_decision_requests_total": {
			"verdict": metricdomain.Closed(
				"the handler's own verdict constants, plus two literals: \"circuit_breaker\", which "+
					"recordDecideMetrics is called with when the breaker is open, and \"error\", "+
					"which the early-deny closure writes to the counter DIRECTLY rather than through "+
					"recordDecideMetrics. Never a value from the request.",
				VerdictAllow, VerdictDeny, VerdictNeedsApproval, "error", "circuit_breaker"),
			"stage":  stage,
			"origin": origin,
		},
		"axonflow_decision_duration_milliseconds": {
			"origin": origin,
		},
		"axonflow_decision_obligations_total": {
			"obligation": metricdomain.Closed(
				"DecisionObligation.Type, whose only non-test constructor sets ObligationRedactPII; "+
					"the write site also skips an empty Type",
				ObligationRedactPII),
			"stage":  stage,
			"origin": origin,
		},
		"axonflow_decision_obligation_fallbacks_total": {
			"obligation": metricdomain.Closed(
				"DecisionObligation.Type, as above", ObligationRedactPII),
			"action": metricdomain.Closed(
				"obligationFallback.action, typed DetectionAction, assigned once from "+
					"ResolveObligationFallbackAction",
				"log", "block"),
			"stage":  stage,
			"origin": origin,
		},
		"axonflow_decision_blocks_total": {
			// THE ONE POSITION WHOSE BOUND IS NOT ON THE VALUE. See
			// TestBoundedBlockPolicyCollapsesPerTenantIds for the measurement,
			// and the #3709 row for the residual.
			"policy": metricdomain.Shaped(
				"boundedBlockPolicy collapses a per-tenant policy id to \"tenant_custom\" - but it "+
					"keys that on the sibling TIER column, not on the value, so a policy row whose "+
					"tier is system/enterprise/\"\" has its id surfaced verbatim. Seeded system ids "+
					"are a fixed set; the residual is a non-seeded row carrying one of those tiers. "+
					"Reported on #3709, deliberately not changed by a test-shape PR.",
				// Cap 0, NOT a number: boundedBlockPolicy is a four-arm switch with
				// no cap anywhere, and nothing on decideBlocks's write path counts
				// distinct values. An earlier draft declared 64, which described
				// no code - a bound invented by the declaration is exactly the
				// unsourced prose this package exists to replace.
				policyIDShape, 0, "unknown", "tenant_custom"),
			"origin": origin,
		},
		"axonflow_decision_audit_write_failures_total": {
			"reason": metricdomain.Closed(
				"a literal at each of the six call sites; two of them package constants on the "+
					"AuthZEN amendment path",
				"nodb", "empty_decision_id", "marshal", "insert",
				authzenAuditAmendFailed, authzenAuditAmendNoRow),
		},
		"axonflow_authzen_requests_total": {
			"outcome": metricdomain.Closed(
				"string(state) from contract.OperationalState - domain declared by "+
					"contract.AllOperationalStates() - plus the withheld-obligation outcome and the "+
					"literal \"refused\". The AuthZEN envelope is caller-supplied; the renderer's "+
					"verdict is not.",
				append(operationalStateNames(), authzenOutcomeObligationWithheld, "refused")...),
			"shape": metricdomain.Closed(
				"the envelope shape the decoder resolved (one subject vs many), plus the literal "+
					"\"unknown\" on the refusal path",
				"singular", "plural", "unknown"),
			"origin": origin,
		},
		"axonflow_authzen_refusals_total": {
			"code": metricdomain.Closed(
				"string(e.Code), a contract.AuthZENErrorCode - domain declared by "+
					"contract.AllAuthZENErrorCodes(), not copied here",
				authzenErrorCodeNames()...),
		},
		"axonflow_pep_handshake_total": {
			"outcome": metricdomain.Closed(
				"resolvePEPHandshake's verdict; the X-Axonflow-PEP-Handshake header is the INPUT and "+
					"never the label. Domain declared by allPEPHandshakeOutcomes().",
				allPEPHandshakeOutcomes()...),
			"plane": metricdomain.Closed(
				"decisionPlaneFromContext, which defaults to PlaneDecision and is overridden only by "+
					"withDecisionPlane(PlaneAccessEvaluation); plus PlaneMCP, passed as a compile-time "+
					"constant by resolveMCPPEPHandshake (#3766) at the three MCP call sites, and "+
					"PlaneGateway, passed the same way by resolvePreCheckPEPHandshake (#3778) - four "+
					"compile-time values, none of them caller data",
				PlaneDecision, PlaneAccessEvaluation, PlaneMCP, PlaneGateway),
		},
		"axonflow_pep_capability_refusals_total": {
			"status": metricdomain.Closed(
				"capabilityRefusalStatusLabel, whose !IsValid() arm collapses to \"undeclared\" - the "+
					"#3708 bounding step. Without it CapabilityStatus.String() renders "+
					"\"CapabilityStatus(9999)\", one distinct string per value.",
				allCapabilityRefusalStatuses()...),
			"obligation": metricdomain.Closed(
				"gap.Type from projectDecisionObligations, a CLOSED table whose absent key is an "+
					"error rather than a default, plus the sibling literal written when the refusal "+
					"is raised before any obligation is known. That literal lives in an "+
					"an enterprise-tagged file this untagged declaration cannot name, so it is "+
					"mirrored and pinned by TestEnterpriseOnlyLabelConstantsMatchTheirMirrors.",
				append(obligationTypeNames(), unknownObligationLabelDeclared)...),
			"plane": metricdomain.Closed(
				"as axonflow_pep_handshake_total", PlaneDecision, PlaneAccessEvaluation, PlaneMCP, PlaneGateway),
		},
		// THE CLIENT-VERSION FAMILY IS DECLARED HERE WITH LITERALS, NOT WITH ITS
		// OWN CONSTANTS, and that is forced rather than lazy: the METRICS AND
		// their constants both live in an //go:build enterprise file, so this
		// untagged file cannot name either - while go/parser ignores build
		// constraints, so the census derives the metrics in BOTH builds and
		// leaving them undeclared would fail the community build.
		//
		// A literal copy is a second list, which is the defect this file is
		// about. So it is PINNED: TestEnterpriseOnlyLabelConstantsMatchTheirMirrors
		// in the enterprise-tagged sibling asserts each literal below against
		// the constant it mirrors, and fails if either moves.
		"axonflow_client_version_requests_total": {
			"plane": metricdomain.Closed(
				"the two call sites pass a Plane constant: decision_handler.go passes the resolved "+
					"decision plane, mcp_handler.go passes PlaneMCP",
				PlaneDecision, PlaneAccessEvaluation, PlaneMCP),
			"client": metricdomain.Shaped(
				"the X-Axonflow-Client header, split at the last '/' and lower-cased. THIS IS THE "+
					"ONLY LABEL IN THE GUARDED SET FED BY CALLER DATA THAT IS NOT MAPPED ONTO A "+
					"CLOSED SET: the file's own contract is a shape allowlist, so a well-formed "+
					"slug nobody enumerated is admitted on purpose (forward-compat for a new "+
					"client), and the bound is the per-process series cap plus the regexp.",
				clientSlugShape, clientVersionMaxSeriesDeclared),
			"client_version": metricdomain.Shaped(
				"the segment after the last '/' of the same header, or the literal \"unversioned\"; "+
					"same shape-plus-cap bound",
				clientVersionShape, clientVersionMaxSeriesDeclared, "unversioned"),
			"deployment_mode": metricdomain.Closed(
				"clientVersionDeploymentModeFor(deploymode.Current()) - a PROCESS property, never a "+
					"header; \"\" becomes \"unset\" and an unrecognised value becomes \"unknown\". "+
					"Derived from deploymode.CanonicalModes(), NOT RecognisedModes(): the recorder "+
					"returns deploymode.Resolve's canonical answer, which folds an alias onto its "+
					"canonical name, so `invpc` and `enterprise` can never be emitted. A domain "+
					"admitting them would pass a regression that surfaced the raw alias.",
				append(canonicalModeNames(), "unset", "unknown")...),
			"licensed": metricdomain.Closed(
				"clientVersionLicensed(), a process property with two values", "true", "false"),
		},
		"axonflow_client_version_dropped_total": {
			"reason": metricdomain.Closed(
				"a literal at each of the three call sites", "absent", "invalid", "overflow"),
		},
		"axonflow_pep_capability_over_advertised_total": {
			"family": metricdomain.Closed(
				"contract.FamilyOf(c.Type) - a closed map lookup whose error arm collapses to "+
					"overAdvertisedFamilyUnresolved. c.Type comes from the DECODED CALLER HEADER, so "+
					"this bounding step is the one standing between a header and a series.",
				allOverAdvertisedFamilies()...),
			"plane": metricdomain.Closed(
				"as axonflow_pep_handshake_total", PlaneDecision, PlaneAccessEvaluation, PlaneMCP, PlaneGateway),
		},
	}
}

// decideProbe is one hostile input for the decision plane.
type decideProbe struct{ name, clientHeader, gatewayID, stage string }

// hostileDecideInputs is the caller-controlled surface of POST /api/v1/decide:
// the X-Axonflow-Client header, caller_identity.gateway_id, and the body's
// stage. ONE copy, because both the behavioural test and the membership
// measurement in TestTheDrivenSetIsWhatItClaims drive it - two copies would be
// two things to keep in step, which is the defect this whole change is about.
func hostileDecideInputs() []decideProbe {
	return []decideProbe{
		{"label-injection in the client header",
			`mcp-proxy/0.3.0",origin="claude-code`, "", DecisionStageLLM},
		{"an unenumerated client slug", "some-brand-new-agent/9.9.9", "", DecisionStageTool},
		{"a newline in the client header", "sdk-go/1.0\nX-Injected: 1", "", DecisionStageAgent},
		{"an unenumerated gateway id", "", "acme-mesh.pod-7f3a9b", DecisionStageLLM},
		{"an out-of-domain stage", "claude-code", "", "../../etc/passwd"},
		{"an empty stage", "", "", ""},
		{"a very long client header", strings.Repeat("a", 4096), "", DecisionStageLLM},
	}
}

// TestEveryCallerExposedMetricLabelHasADeclaredDomain is the CENSUS half, and
// it is derived from the source rather than from a list of metrics.
//
// A new metric in a guarded file, or a new label on an existing one, fails here
// until somebody states what bounds it. That is the forcing function a
// list-vs-list test cannot provide: adding a label to both hand-written lists
// keeps such a test green, and it is the adding that needed a decision.
func TestEveryCallerExposedMetricLabelHasADeclaredDomain(t *testing.T) {
	derived := deriveGuardedMetrics(t)
	domains := guardedMetricDomains()

	// ANTI-VACUITY. A parse that found nothing satisfies every loop below.
	if len(derived) == 0 {
		t.Fatal("the census derived zero metrics from the guarded files; the extraction, not the " +
			"code, is broken - and a broken extraction reports a fully declared tree")
	}

	declaredNames := map[string]bool{}
	for _, m := range derived {
		declaredNames[m.Name] = true
		byLabel, ok := domains[m.Name]
		if !ok {
			t.Errorf("%s:%d declares metric %q with labels %v and no domain declaration.\n\n"+
				"Every label is a cardinality decision. State where each value comes from and what "+
				"collapses an out-of-domain one, in guardedMetricDomains(). A label fed by "+
				"caller-supplied data with no bounding step is one time series per distinct value.",
				m.File, m.Line, m.Name, m.Labels)
			continue
		}
		for _, label := range m.Labels {
			if _, ok := byLabel[label]; !ok {
				t.Errorf("%s:%d metric %q declares label %q with no domain.\n\n"+
					"A label position added to an existing metric is a new cardinality decision, and "+
					"it is the one a test that compares two hand-written NAME lists stays green for.",
					m.File, m.Line, m.Name, label)
			}
		}
		for label := range byLabel {
			found := false
			for _, l := range m.Labels {
				if l == label {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("metric %q has a declared domain for label %q, which it does not declare "+
					"(it declares %v). A domain for a label that is gone covers nothing while reading "+
					"as a decision somebody made.", m.Name, label, m.Labels)
			}
		}
	}

	// EVERY VEC WRITTEN IN A GUARDED FILE MUST BE ONE THIS CENSUS DERIVED.
	// See vecsWrittenIn: a vec built by a helper in an unguarded file and merely
	// assigned here matched no constructor shape and was skipped silently.
	// The union across ALL guarded files, not per file: authzen_handler.go
	// legitimately writes decideAuditWriteFailures, which decision_handler.go
	// declares. A per-file check would report that correct cross-file write.
	declaredVars := map[string]bool{}
	for _, file := range guardedMetricFiles {
		for v := range vecNamesDeclaredIn(t, file) {
			declaredVars[v] = true
		}
	}
	for _, file := range guardedMetricFiles {
		for v, line := range vecsWrittenIn(t, file) {
			if !declaredVars[v] {
				t.Errorf("%s:%d writes to vec %q, which this census did not derive a metric "+
					"declaration for.\n\n"+
					"A vec constructed anywhere this census cannot read - by a helper, in another "+
					"file, behind an alias - carries labels nobody declared, and the declaration "+
					"half of this test cannot see it. Declare the metric in a guarded file with a "+
					"literal prometheus/promauto constructor.", file, line, v)
			}
		}
	}

	for name := range domains {
		if !declaredNames[name] {
			t.Errorf("a domain is declared for metric %q, which no guarded file declares. Either the "+
				"metric moved out of the guarded set - in which case its labels are now unguarded - "+
				"or the entry is dead.", name)
		}
	}
}

// TestDecisionMetricLabelsSurviveHostileInput is the BEHAVIOURAL half for the
// decision family, and it drives the REAL handler.
//
// This is the shape #3720 asks for and the shape that found the instance behind
// it: put an out-of-domain input through the real write path and require the
// emitted label to land in a declared set. The inputs below are the ones a
// caller actually controls - the X-Axonflow-Client header, the gateway_id, and
// the request body's stage - including values chosen to break out of a label if
// they reached one unescaped.
func TestDecisionMetricLabelsSurviveHostileInput(t *testing.T) {
	// handleDecide also writes decideAuditWriteFailures (reason="nodb", since no
	// usage DB is wired here) and, through the unconditional handshake resolve,
	// pepHandshakeOutcomes and the client-version pair. RESET AND CHECK the ones
	// this test can judge, and reset the rest rather than leaving them on the
	// default registry for the remainder of the binary.
	vecs := map[string]prometheus.Collector{
		"axonflow_decision_requests_total":             decideRequests,
		"axonflow_decision_duration_milliseconds":      decideDuration,
		"axonflow_decision_audit_write_failures_total": decideAuditWriteFailures,
	}
	reset := func() {
		decideRequests.Reset()
		decideDuration.Reset()
		decideAuditWriteFailures.Reset()
		pepHandshakeOutcomes.Reset()
	}
	reset()
	t.Cleanup(reset)

	hostile := hostileDecideInputs()

	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			driveDecideForLabels(t, h.clientHeader, h.gatewayID, h.stage)
		})
	}

	// THE PRE-DECODE ARMS, which carry the origin computed at the FIRST
	// classifyDecisionOrigin call site. Every case above is a well-formed body
	// that reaches the second one, so without these two the up-front call could
	// be replaced by the raw header and nothing in platform/agent would notice
	// - R3 measured exactly that.
	t.Run("a body that does not decode, with a hostile client header", func(t *testing.T) {
		driveDecideRaw(t, `acme-tool/1.2.3",origin="claude-code`, []byte("{not json"), nil)
	})
	t.Run("a refused PEP handshake, with a hostile client header", func(t *testing.T) {
		driveDecideRaw(t, "another-unenumerated-tool/9.9", []byte(`{"stage":"llm"}`),
			map[string]string{contract.PEPHandshakeHeader: "!!! not base64 !!!"})
	})

	domains := guardedMetricDomains()
	for name, vec := range vecs {
		for _, p := range metricdomain.Check(name, vec, domains[name]) {
			t.Errorf("%s\n\nA caller-supplied value reached a Prometheus label. One such value is one "+
				"new time series per distinct value, which eventually takes down the scrape - and it "+
				"arrives from whoever is calling, so it is not bounded by anything the operator "+
				"controls.", p)
		}
	}
}

// TestBoundedBlockPolicyCollapsesPerTenantIds drives the one bounding step in
// the decision family whose input is a DATABASE ROW rather than a request, so
// no HTTP driver can reach it.
//
// It is here rather than left to the census because the census cannot see a
// value, and because this bound is the weakest one in the family: it keys on
// the sibling `tier` column instead of on the value being labelled. The
// measurement below is what makes that statement checkable rather than a
// reading of the code.
func TestBoundedBlockPolicyCollapsesPerTenantIds(t *testing.T) {
	perTenant := []string{"custom_9f2c1ab4", "custom_00000001", "custom_deadbeef"}
	for _, id := range perTenant {
		for _, tier := range []string{"organization", "tenant", "something-new"} {
			if got := boundedBlockPolicy(id, tier); got != "tenant_custom" {
				t.Errorf("boundedBlockPolicy(%q, %q) = %q, want tenant_custom: a per-tenant policy id "+
					"is unbounded across tenants and there is no tenant label to scope it", id, tier, got)
			}
		}
	}
	if got := boundedBlockPolicy("", "system"); got != "unknown" {
		t.Errorf(`boundedBlockPolicy("", "system") = %q, want "unknown"`, got)
	}

	// THE RESIDUAL, ASSERTED AS IT ACTUALLY IS rather than as the prose says.
	// A row carrying one of these three tiers keeps its id verbatim, whatever
	// the id is. That is the finding on #3709; pinning it here means a future
	// change to boundedBlockPolicy has to come past this test, and means the
	// declared domain above is not a guess.
	for _, tier := range []string{"system", "enterprise", ""} {
		if got := boundedBlockPolicy("an_id_nobody_seeded", tier); got != "an_id_nobody_seeded" {
			t.Errorf("boundedBlockPolicy with tier %q now collapses the id to %q. If that is the "+
				"intended fix for the #3709 residual, narrow the declared domain for the `policy` "+
				"label to match - it currently admits a shaped id precisely because this does not "+
				"collapse.", tier, got)
		}
	}
}

// TestHandshakeMetricLabelsSurviveHostileInput drives the PEP handshake
// resolver with caller-supplied headers.
//
// The `family` label is the one that matters here: its value derives from a
// capability TYPE in the decoded caller header, and contract.FamilyOf is the
// only thing between that header and a new time series.
func TestHandshakeMetricLabelsSurviveHostileInput(t *testing.T) {
	// EditionCommunity, because SplitOverAdvertised is the only producer of the
	// over-advertised counter and it drops nothing under Enterprise. Without
	// this the family label is never written and every claim about it is
	// vacuous - which is what metricdomain.Check's zero-series floor reported
	// the first time this ran.
	t.Setenv("DEPLOYMENT_MODE", "community")

	pepHandshakeOutcomes.Reset()
	pepCapabilityOverAdvertised.Reset()
	t.Cleanup(func() { pepHandshakeOutcomes.Reset(); pepCapabilityOverAdvertised.Reset() })

	for _, header := range hostilePEPHandshakeHeaders(t) {
		drivePEPHandshakeForLabels(t, header)
	}

	// AN ARM FLOOR, NOT JUST A SERIES FLOOR. metricdomain.Check refuses zero
	// series, but ONE series satisfies that - and the arms this test exists for
	// are the over-advertised drop and the malformed refusal, either of which
	// can stop being reached by a change to the resolver rather than to the
	// metric. Naming them here means the driver going stale fails loudly
	// instead of quietly narrowing what is checked.
	requireLabelValueSeen(t, "axonflow_pep_capability_over_advertised_total",
		pepCapabilityOverAdvertised, "family", string(contract.FamilyApproval))
	requireLabelValueSeen(t, "axonflow_pep_handshake_total",
		pepHandshakeOutcomes, "outcome", pepHandshakeOverAdvertised)
	requireLabelValueSeen(t, "axonflow_pep_handshake_total",
		pepHandshakeOutcomes, "outcome", pepHandshakeMalformed)
	requireLabelValueSeen(t, "axonflow_pep_handshake_total",
		pepHandshakeOutcomes, "outcome", pepHandshakeAccepted)

	domains := guardedMetricDomains()
	for name, vec := range map[string]prometheus.Collector{
		"axonflow_pep_handshake_total":                  pepHandshakeOutcomes,
		"axonflow_pep_capability_over_advertised_total": pepCapabilityOverAdvertised,
	} {
		for _, p := range metricdomain.Check(name, vec, domains[name]) {
			t.Errorf("%s\n\nThe handshake header is caller-supplied, so a capability type that "+
				"escapes contract.FamilyOf's closed lookup is one series per distinct type an "+
				"attacker chooses to send.", p)
		}
	}
}

// requireLabelValueSeen fails unless c emitted at least one series carrying
// label=value.
//
// It exists because "at least one series" is a weak floor: a driver that
// stopped reaching an arm still produces series from the arms it does reach,
// and the domains would then be checked only against the easy ones.
func requireLabelValueSeen(t *testing.T, metric string, c prometheus.Collector, label, value string) {
	t.Helper()
	ch := make(chan prometheus.Metric, 1024)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			continue
		}
		for _, lp := range d.GetLabel() {
			if lp.GetName() == label && lp.GetValue() == value {
				return
			}
		}
	}
	t.Errorf("%s emitted no series with %s=%q. The driver no longer reaches that arm, so every "+
		"domain assertion about it passed against inputs that never arrived.", metric, label, value)
}

// TestTheCheckerCatchesAnUnboundedLabelOnTheRealMetric is the plant, performed
// on the REAL decideRequests vec rather than a lookalike.
//
// #3720's whole argument is that the existing shape cannot see this class, so a
// demonstration that the new shape can is the load-bearing evidence. Writing
// into a freshly-built CounterVec would prove it about a lookalike; this uses
// the metric object the handler itself writes to, with the label names the
// handler itself declared, so the only thing changed is the VALUE - which is
// exactly the change a real regression makes.
func TestTheCheckerCatchesAnUnboundedLabelOnTheRealMetric(t *testing.T) {
	decideRequests.Reset()
	t.Cleanup(decideRequests.Reset)

	// THE CONTROL FIRST. A bounded write must pass, or the failure below is
	// evidence about a checker that always complains.
	decideRequests.WithLabelValues(VerdictAllow, DecisionStageLLM, OriginSDK).Inc()
	domains := guardedMetricDomains()["axonflow_decision_requests_total"]
	if p := metricdomain.Check("axonflow_decision_requests_total", decideRequests, domains); len(p) != 0 {
		t.Fatalf("a correctly bounded write was reported as defective: %v", p)
	}

	before := collectedLabelNames(t, decideRequests)

	// THE PLANT: the raw X-Axonflow-Client header in the origin position,
	// which is what removing classifyDecisionOrigin from the call site would
	// do. Four callers, four new time series.
	for _, raw := range []string{
		"claude-code/1.6.0", "claude-code/1.6.1", "sdk-go/2.0.0", "acme-internal-tool/0.1",
	} {
		decideRequests.WithLabelValues(VerdictAllow, DecisionStageLLM, raw).Inc()
	}
	after := collectedLabelNames(t, decideRequests)
	problems := metricdomain.Check("axonflow_decision_requests_total", decideRequests, domains)
	if len(problems) == 0 {
		t.Fatal("the raw client header reached the `origin` label of the real metric and the check " +
			"reported nothing. This is the defect class #3720 was filed for, and a check blind to it " +
			"is the list-vs-list test with extra steps")
	}
	joined := strings.Join(problems, "\n")
	for _, raw := range []string{"claude-code/1.6.0", "sdk-go/2.0.0", "acme-internal-tool/0.1"} {
		if !strings.Contains(joined, raw) {
			t.Errorf("the report did not name the escaping value %q:\n%s", raw, joined)
		}
	}

	// AND THE LIST-VS-LIST SHAPE IS SHOWN TO MISS IT, on the same series.
	//
	// Compared BEFORE against AFTER rather than against a hardcoded
	// "origin,stage,verdict": the claim is that the plant does not move the
	// names, and a literal would additionally pin the names themselves - hard-
	// failing on a legitimate rename that the census already reports with a far
	// better message, and quietly becoming the joined-string assertion this
	// package's own doc argues against.
	if before != after {
		t.Fatalf("the label NAMES changed across the plant (%q -> %q); the whole point is that they "+
			"do NOT, which is why a test comparing them stays green while the metric mints one "+
			"series per caller", before, after)
	}
}

// collectedLabelNames renders the sorted label names of the first collected
// series - the value the list-vs-list shape compares.
func collectedLabelNames(t *testing.T, c prometheus.Collector) string {
	t.Helper()
	ch := make(chan prometheus.Metric, 1024)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			continue
		}
		var names []string
		for _, lp := range d.GetLabel() {
			names = append(names, lp.GetName())
		}
		sort.Strings(names)
		//nolint:revive // draining the channel is required; the goroutine blocks otherwise
		for range ch {
		}
		return strings.Join(names, ",")
	}
	t.Fatal("no series collected")
	return ""
}

// behaviourallyDrivenMetrics names the guarded metrics whose labels this file
// checks by DRIVING a real write site, and censusOnlyMetrics names the rest,
// each with the reason no driver reaches it.
//
// # WHY THE SPLIT IS DECLARED RATHER THAN LEFT IMPLICIT
//
// For a metric nobody drives, this file is a NAME census - which is the shape
// #3720 argues against. R3 measured the consequence: adding
// `ConstLabels{"subject_id": …}` to the UNDRIVEN axonflow_authzen_requests_total
// was green, while the identical mutant on the DRIVEN pepHandshakeOutcomes was
// caught. (The ConstLabels hole itself is now closed in the census, but the
// general point stands: a domain checked against no value is a claim nobody
// tested.)
//
// So the split is stated, and TestTheDrivenSetIsWhatItClaims holds it: a metric
// that silently stops being driven moves between these sets and fails, instead
// of quietly degrading to a name check.
func behaviourallyDrivenMetrics() []string {
	return []string{
		"axonflow_decision_requests_total",
		"axonflow_decision_duration_milliseconds",
		"axonflow_decision_audit_write_failures_total",
		"axonflow_authzen_requests_total",
		"axonflow_authzen_refusals_total",
		"axonflow_pep_handshake_total",
		"axonflow_pep_capability_over_advertised_total",
		// Enterprise-tagged; driven by the sibling file under that tag. Listed
		// here because the census derives the metric in BOTH builds.
		"axonflow_client_version_requests_total",
		"axonflow_client_version_dropped_total",
		// Declared in license/tier_read.go (no build tag). Driven by
		// driveLicenceTierRefusals in license_tier_source_test.go, which puts a
		// forged, an expired and a malformed key through the REAL validator via
		// the agent's registered source (#3709 row 1).
		"axonflow_license_tier_read_rejected_total",
	}
}

func censusOnlyMetrics() map[string]string {
	return map[string]string{
		"axonflow_decision_obligations_total": "written only when the policy engine attaches an " +
			"obligation to an allow verdict, which needs a wired engine and a PII-bearing query. " +
			"Its three labels are the obligation type (a single constant today), plus stage and " +
			"origin, both of which ARE driven on axonflow_decision_requests_total.",
		"axonflow_decision_obligation_fallbacks_total": "written only when a caller advertises a seam " +
			"that cannot fulfil an obligation the engine attached - a wired engine plus a handshake. " +
			"Its `action` label is the only position not driven elsewhere.",
		"axonflow_decision_blocks_total": "written only on a DENY from a loaded policy row, so the " +
			"`policy` label needs a database. Its bounding step is driven directly instead by " +
			"TestBoundedBlockPolicyCollapsesPerTenantIds, which is the honest substitute: it tests " +
			"the function, not the call site, and says so.",
		"axonflow_pep_capability_refusals_total": "written only from the enterprise-tagged " +
			"enforcement arm, and only when a mandatory obligation meets a PEP that declared it " +
			"unsupported. Both its non-plane labels are already pinned by the pre-existing " +
			"TestTheCapabilityRefusalStatusLabelIsBounded, which drives the real refusal path.",
	}
}

// guardedCollectors maps each guarded metric to its vec, for the membership
// MEASUREMENT below. A metric with no entry cannot be measured and is reported.
func guardedCollectors() map[string]prometheus.Collector {
	out := map[string]prometheus.Collector{
		"axonflow_decision_requests_total":              decideRequests,
		"axonflow_decision_duration_milliseconds":       decideDuration,
		"axonflow_decision_audit_write_failures_total":  decideAuditWriteFailures,
		"axonflow_decision_obligations_total":           decideObligations,
		"axonflow_decision_obligation_fallbacks_total":  decideObligationFallbacks,
		"axonflow_decision_blocks_total":                decideBlocks,
		"axonflow_authzen_requests_total":               authzenRequests,
		"axonflow_authzen_refusals_total":               authzenRefusals,
		"axonflow_pep_handshake_total":                  pepHandshakeOutcomes,
		"axonflow_pep_capability_over_advertised_total": pepCapabilityOverAdvertised,
		"axonflow_pep_capability_refusals_total":        pepCapabilityRefusals,
		"axonflow_license_tier_read_rejected_total":     license.TierReadRejectedCollectorForTest(),
	}
	// The client-version pair is declared in an //go:build enterprise file, so
	// its vecs do not EXIST in a community build. go/parser derives the metrics
	// in both builds (which is why they have domains here), but only one build
	// can measure them.
	for name, c := range enterpriseOnlyCollectors() {
		out[name] = c
	}
	return out
}

// seriesCount reports how many children c currently holds.
func seriesCount(c prometheus.Collector) int {
	ch := make(chan prometheus.Metric, 4096)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	n := 0
	for range ch {
		n++
	}
	return n
}

// TestTheDrivenSetIsWhatItClaims holds the split above against the census AND
// against what the drivers actually reach.
//
// # THE PARTITION CHECK ALONE WAS THE LIST-VS-LIST SHAPE AGAIN
//
// The first version only errored when a metric was in BOTH sets or NEITHER.
// Moving axonflow_decision_blocks_total from census-only to driven passed; so
// did adding t.Skip to the sole driver of the two AuthZEN metrics. That is a
// partition check over two hand-written lists - exactly what this file argues
// against - and its doc claimed the opposite ("a metric that silently stops
// being driven moves between these sets and fails").
//
// So the drivers are RUN here and membership is MEASURED: a metric called
// driven must end with at least one series, and a metric called census-only
// must end with none. Both mutants above now fail.
func TestTheDrivenSetIsWhatItClaims(t *testing.T) {
	derived := deriveGuardedMetrics(t)
	if len(derived) == 0 {
		t.Fatal("no metrics derived; the extraction is broken")
	}
	driven := map[string]bool{}
	for _, m := range behaviourallyDrivenMetrics() {
		driven[m] = true
	}
	censusOnly := censusOnlyMetrics()

	declared := map[string]bool{}
	for _, m := range derived {
		declared[m.Name] = true
		inDriven, inCensus := driven[m.Name], censusOnly[m.Name] != ""
		switch {
		case inDriven && inCensus:
			t.Errorf("%s is in BOTH the driven and census-only sets", m.Name)
		case !inDriven && !inCensus:
			t.Errorf("%s (%s:%d) is in neither set.\n\n"+
				"Either drive a real write site for it and add it to behaviourallyDrivenMetrics, or "+
				"add it to censusOnlyMetrics with the reason no driver reaches it. A metric in "+
				"neither is one whose declared domain is checked against no value at all - which is "+
				"the name-census shape #3720 was filed about.", m.Name, m.File, m.Line)
		}
	}
	for _, name := range behaviourallyDrivenMetrics() {
		if !declared[name] {
			t.Errorf("behaviourallyDrivenMetrics names %q, which no guarded file declares", name)
		}
	}
	for name := range censusOnly {
		if !declared[name] {
			t.Errorf("censusOnlyMetrics names %q, which no guarded file declares", name)
		}
	}

	// EVERY DOMAIN CARRIES A REASON, including the census-only metrics.
	//
	// metricdomain.Check enforces this, but Check runs only for driven
	// metrics - so blanking the Why on a census-only domain survived every
	// lane. The census is the only place that sees all thirteen.
	for metric, byLabel := range guardedMetricDomains() {
		for label, dom := range byLabel {
			if strings.TrimSpace(dom.Why) == "" {
				t.Errorf("%s: the domain for label %q carries no Why. A domain is a claim about "+
					"where the value comes from; without it the permitted list is something the next "+
					"reader has to re-derive from the call sites.", metric, label)
			}
		}
	}

	// MEMBERSHIP IS MEASURED, NOT DECLARED. Run every driver, then require a
	// "driven" metric to hold series and a "census-only" metric to hold none.
	collectors := guardedCollectors()
	for _, m := range derived {
		if _, ok := collectors[m.Name]; ok || !driven[m.Name] {
			continue
		}
		if why := unmeasurableInThisBuild()[m.Name]; why != "" {
			t.Logf("%s: membership not measured in this build (%s)", m.Name, why)
			continue
		}
		t.Errorf("%s is called driven but has no entry in guardedCollectors, so its membership "+
			"cannot be measured", m.Name)
	}
	for _, c := range collectors {
		if v, ok := c.(interface{ Reset() }); ok {
			v.Reset()
		}
	}
	t.Cleanup(func() {
		for _, c := range collectors {
			if v, ok := c.(interface{ Reset() }); ok {
				v.Reset()
			}
		}
	})
	runEveryDriver(t)

	for name, c := range collectors {
		n := seriesCount(c)
		switch {
		case driven[name] && n == 0:
			t.Errorf("%s is listed as behaviourally driven and ended with ZERO series. Its declared "+
				"domain is therefore checked against no value at all, which is the name-census shape "+
				"#3720 was filed about - either restore the driver or move it to censusOnlyMetrics "+
				"with the reason.", name)
		case censusOnly[name] != "" && n > 0:
			t.Errorf("%s is listed as census-only but a driver DID reach it (%d series). Move it to "+
				"behaviourallyDrivenMetrics and pass it to metricdomain.Check - an admission that "+
				"nothing drives it is worse than useless once something does.", name, n)
		}
	}
}

// runEveryDriver invokes every write-site driver this file owns. It is the
// measurement input for TestTheDrivenSetIsWhatItClaims.
func runEveryDriver(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "community")
	driveLicenceTierRefusals(t)
	for _, h := range hostileDecideInputs() {
		driveDecideForLabels(t, h.clientHeader, h.gatewayID, h.stage)
	}
	driveDecideRaw(t, `probe/1.0",origin="claude-code`, []byte("{not json"), nil)
	driveDecideRaw(t, "probe-two/9.9", []byte(`{"stage":"llm"}`),
		map[string]string{contract.PEPHandshakeHeader: "!!! not base64 !!!"})
	for _, body := range hostileAuthZENEnvelopes() {
		driveAuthZENForLabels(t, `evil-tool/1.0",origin="claude-code`, body)
	}
	for _, header := range hostilePEPHandshakeHeaders(t) {
		drivePEPHandshakeForLabels(t, header)
	}
	runEnterpriseOnlyDrivers(t)
}

// TestAuthZENMetricLabelsSurviveHostileInput drives the AuthZEN evaluation
// route, whose `origin` comes from the same classifyDecisionOrigin shape that
// survived a mutant on the decide plane until this round.
//
// # WHICH ARMS THIS ACTUALLY REACHES, MEASURED
//
// All six envelopes refuse with code=malformed_envelope, so exactly two series
// exist afterwards: outcome=refused/shape=unknown and code=malformed_envelope.
// The SUCCESS write needs a wired policy engine and an authenticated caller,
// which this driver does not build - so `outcome` and `shape` are exercised
// only against the two literals the refusal path passes, and a mutant that
// replaced `shape` at the SUCCESS write site survives this test (three
// pre-existing tests catch that one).
//
// Stated rather than implied, because the arm floor below would otherwise read
// as coverage of the whole family. The `origin` label - the one this test is
// really for - IS driven through the real classifier on the refusal path.
func TestAuthZENMetricLabelsSurviveHostileInput(t *testing.T) {
	authzenRequests.Reset()
	authzenRefusals.Reset()
	t.Cleanup(func() { authzenRequests.Reset(); authzenRefusals.Reset() })

	for _, body := range hostileAuthZENEnvelopes() {
		driveAuthZENForLabels(t, `evil-tool/1.0",origin="claude-code`, body)
	}

	// ARM FLOOR. One series satisfies a series floor while the arm the test
	// exists for goes unreached - this file argues that ten lines above the
	// handshake driver, and the AuthZEN driver shipped without one.
	requireLabelValueSeen(t, "axonflow_authzen_requests_total", authzenRequests, "outcome", "refused")
	requireLabelValueSeen(t, "axonflow_authzen_requests_total", authzenRequests, "origin", OriginUnknown)
	requireLabelValueSeen(t, "axonflow_authzen_refusals_total", authzenRefusals,
		"code", string(contract.ErrMalformedEnvelope))

	domains := guardedMetricDomains()
	for name, vec := range map[string]prometheus.Collector{
		"axonflow_authzen_requests_total": authzenRequests,
		"axonflow_authzen_refusals_total": authzenRefusals,
	} {
		for _, p := range metricdomain.Check(name, vec, domains[name]) {
			t.Errorf("%s\n\nThe AuthZEN envelope and the X-Axonflow-Client header are both "+
				"caller-supplied.", p)
		}
	}
}
