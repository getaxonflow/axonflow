// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package path_template normalizes raw HTTP request paths to their
// OpenAPI template form for cross-surface analytics (epic #2047 Q-C).
//
// The agent middleware (System A entry point at platform/agent/) calls
// Normalize at write time so the persisted endpoint column has a
// closed-cardinality vocabulary instead of one-row-per-tenant-id
// explosions ("/api/v1/users/cs_abc1234" rolled up to "/api/v1/users").
//
// Algorithm:
//
//  1. Match the raw path against the registered template list.
//     Specificity ranks: literal segments > parameter segments. So an
//     incoming "/api/v1/users/me" prefers "/api/v1/users/me" over
//     "/api/v1/users/{id}" when both are registered.
//  2. Drop ONE trailing /{param} segment from the matched template.
//     That collapses "/api/v1/users/{id}" → "/api/v1/users" per the
//     epic decision. Templates that end on a literal (e.g.
//     "/api/v1/conformity/assessments/{id}/start") keep all params.
//  3. Unmatched paths return as-is (fail-closed). No synthetic
//     templates, no silent rejection — analytics gets the raw path
//     and a downstream alarm can detect their growth.
//
// Templates is the closed list maintained in lockstep with
// docs/api/agent-api.yaml; CI test TestTemplatesMatchAgentAPISpec diffs
// the two and fails CI on drift.
package path_template

import (
	"regexp"
	"strings"
	"sync"
)

// Templates is the registered OpenAPI path-template list. Sorted
// alphabetically for determinism + diff stability with agent-api.yaml.
//
// LOCKSTEP CONTRACT: this list MUST stay in sync with the paths defined
// in docs/api/agent-api.yaml. The CI test TestTemplatesMatchAgentAPISpec
// parses the YAML and asserts byte-identical equality with this slice.
// Adding a new endpoint to the OpenAPI spec without adding it here is
// a fail-closed degradation — Normalize returns the raw path for the
// new endpoint until someone updates this list — but never an outright
// outage.
var Templates = []string{
	"/api/audit/llm-call",
	"/api/clients",
	"/api/policies/test",
	"/api/policy/pre-check",
	"/api/request",
	"/api/v1/accuracy/alerts",
	"/api/v1/accuracy/alerts/{id}/acknowledge",
	"/api/v1/accuracy/alerts/{id}/resolve",
	"/api/v1/accuracy/bias",
	"/api/v1/accuracy/metrics",
	"/api/v1/accuracy/thresholds",
	"/api/v1/circuit-breaker/activate",
	"/api/v1/circuit-breaker/config",
	"/api/v1/circuit-breaker/deactivate",
	"/api/v1/circuit-breaker/history",
	"/api/v1/circuit-breaker/notifications",
	"/api/v1/circuit-breaker/notifications/{id}",
	"/api/v1/circuit-breaker/status",
	"/api/v1/conformity/assessments",
	"/api/v1/conformity/assessments/{id}",
	"/api/v1/conformity/assessments/{id}/approve",
	"/api/v1/conformity/assessments/{id}/checks/{checkId}",
	"/api/v1/conformity/assessments/{id}/findings",
	"/api/v1/conformity/assessments/{id}/reject",
	"/api/v1/conformity/assessments/{id}/start",
	"/api/v1/conformity/assessments/{id}/submit",
	"/api/v1/conformity/summary",
	"/api/v1/connectors/cache/stats",
	"/api/v1/connectors/refresh",
	"/api/v1/connectors/refresh/{tenant_id}",
	"/api/v1/connectors/refresh/{tenant_id}/{connector_name}",
	"/api/v1/euaiact/export",
	"/api/v1/euaiact/summary",
	"/api/v1/hitl/queue",
	"/api/v1/hitl/queue/{id}",
	"/api/v1/hitl/queue/{id}/approve",
	"/api/v1/hitl/queue/{id}/reject",
	"/api/v1/static-policies",
	"/api/v1/static-policies/effective",
	"/api/v1/static-policies/overrides",
	"/api/v1/static-policies/test",
	"/api/v1/static-policies/{id}",
	"/api/v1/static-policies/{id}/override",
	"/api/v1/static-policies/{id}/versions",
	"/health",
	"/mcp/check-input",
	"/mcp/check-output",
	"/mcp/connectors",
	"/mcp/connectors/{name}/health",
	"/mcp/health",
	"/mcp/resources/query",
	"/mcp/tools/execute",
	"/metrics",
	"/prometheus",
}

// paramSegmentRE matches a single OpenAPI path parameter (e.g.
// "{tenant_id}", "{checkId}"). Used both to construct the matcher
// regex and to detect trailing-param segments for stripping.
var paramSegmentRE = regexp.MustCompile(`^\{[^/]+\}$`)

type templateEntry struct {
	template    string
	re          *regexp.Regexp
	specificity int // count of literal (non-param) segments
}

var (
	defaultMatcher *Matcher
	defaultOnce    sync.Once
)

// Matcher is the compiled, ready-to-Normalize form of a template list.
// Reusing a single Matcher across many requests is the intended pattern;
// the regex compile cost is paid once at construction.
type Matcher struct {
	entries []*templateEntry
}

// NewMatcher compiles the supplied template list into a Matcher.
// Templates that fail to compile are dropped (logged at runtime would
// be ideal but the package is import-cycle-sensitive so we silently
// skip; the in-package test asserts every Templates entry compiles).
func NewMatcher(templates []string) *Matcher {
	m := &Matcher{entries: make([]*templateEntry, 0, len(templates))}
	for _, t := range templates {
		entry, err := compileTemplate(t)
		if err != nil {
			continue
		}
		m.entries = append(m.entries, entry)
	}
	return m
}

// Default returns the package-level Matcher built from Templates. Use
// this from production code paths (agent middleware); tests construct
// their own via NewMatcher.
func Default() *Matcher {
	defaultOnce.Do(func() {
		defaultMatcher = NewMatcher(Templates)
	})
	return defaultMatcher
}

// Normalize is the package-level convenience that delegates to the
// Default matcher. See Matcher.Normalize for the algorithm.
func Normalize(rawPath string) string {
	return Default().Normalize(rawPath)
}

// Normalize maps a raw request path to its OpenAPI-template form,
// stripping one trailing /{param} segment per the epic decision. Falls
// back to returning the raw path for templates not in the registered
// list (fail-closed).
func (m *Matcher) Normalize(rawPath string) string {
	// Strip query string defensively. The agent middleware already does
	// this (it persists r.URL.Path, not r.URL.RequestURI), but the
	// mirror Lambda receives endpoint values that may carry trailing
	// "?foo=bar" if a future writer regresses the rule. Belt + braces.
	if i := strings.IndexByte(rawPath, '?'); i >= 0 {
		rawPath = rawPath[:i]
	}

	var best *templateEntry
	for _, entry := range m.entries {
		if !entry.re.MatchString(rawPath) {
			continue
		}
		// Higher specificity wins: a literal-segment template beats a
		// param template when both match the same path. Equal-specificity
		// ties are resolved by preferring the entry registered first
		// (alphabetical order, which is also how the YAML list is
		// emitted).
		if best == nil || entry.specificity > best.specificity {
			best = entry
		}
	}
	if best == nil {
		return rawPath
	}
	return stripTrailingParam(best.template)
}

// compileTemplate converts an OpenAPI path template (e.g.
// "/api/v1/users/{id}") into a regex that matches concrete request
// paths AND records its specificity for tie-breaking.
//
// Each {param} segment becomes [^/]+ (a non-empty path segment). Literal
// segments are regex-quoted so they match exactly. The pattern is
// anchored on both ends so partial matches don't sneak through.
func compileTemplate(template string) (*templateEntry, error) {
	if template == "" {
		return nil, errEmptyTemplate
	}
	segments := strings.Split(template, "/")
	specificity := 0
	parts := make([]string, 0, len(segments))
	for _, seg := range segments {
		if paramSegmentRE.MatchString(seg) {
			parts = append(parts, `[^/]+`)
			continue
		}
		// Literal — quote it for regex use. Literal counts toward specificity
		// only when it carries content (the leading "" from a leading slash
		// isn't a real segment).
		if seg != "" {
			specificity++
		}
		parts = append(parts, regexp.QuoteMeta(seg))
	}
	pattern := "^" + strings.Join(parts, "/") + "$"
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &templateEntry{
		template:    template,
		re:          re,
		specificity: specificity,
	}, nil
}

// stripTrailingParam removes ONE trailing /{param} segment from a
// template if present. "/api/v1/users/{id}" → "/api/v1/users". Templates
// that end on a literal segment (e.g. ".../approve") are returned
// unchanged.
//
// Singular-strip per the epic decision: only the FINAL /{param} is
// dropped. Templates with mid-path params keep them. So
// "/api/v1/conformity/assessments/{id}/checks/{checkId}" becomes
// "/api/v1/conformity/assessments/{id}/checks", not the more aggressive
// "/api/v1/conformity/assessments". That preserves the analyst's
// ability to roll up by check-class without losing the assessment
// dimension entirely.
func stripTrailingParam(template string) string {
	idx := strings.LastIndexByte(template, '/')
	if idx < 0 {
		return template
	}
	last := template[idx+1:]
	if !paramSegmentRE.MatchString(last) {
		return template
	}
	stripped := template[:idx]
	if stripped == "" {
		// Edge case: a template like "/{id}" would strip to "" — return
		// the original since the empty path conveys no analytics value
		// and would collide with the empty-fallback path elsewhere.
		return template
	}
	return stripped
}

var errEmptyTemplate = templateError("empty template")

type templateError string

func (e templateError) Error() string { return string(e) }
