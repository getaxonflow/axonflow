// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
)

// TestEverySeamPresentsWhatScopeActionsStates holds legacycompile's statement
// of which actions each scope presents (#4371) to this binary's seams, by
// value. The publish validator refuses a `binds_on` scope that presents none of
// a control's actions from that statement, so a seam that presents an action
// the statement omits would refuse an author a scope the control really binds
// on, and one the statement lists and no seam presents would admit a scope the
// control can never reach.
//
// What each request-pass scope presents is READ from its call sites: the
// `stage:` each enforceRequestPass call passes, resolved through
// authzenActionStage, the one table that maps a stage to an action. A new call
// site on a scope, or a changed stage, moves the observed set.
func TestEverySeamPresentsWhatScopeActionsStates(t *testing.T) {
	seamVars := map[string]legacycompile.EnforcementScope{
		"decideSeamScope":           decideSeamScope,
		"gatewayRequestSeamScope":   gatewayRequestSeamScope,
		"mcpRequestSeamScope":       mcpRequestSeamScope,
		"proxyRequestSeamScope":     proxyRequestSeamScope,
		"openaiCompatibleSeamScope": openaiCompatibleSeamScope,
	}
	stageToAction := map[string]string{}
	for action, stage := range authzenActionStage {
		stageToAction[stage] = action
	}
	everyStage := func() []string {
		var out []string
		for _, s := range authzenActionStage {
			out = append(out, s)
		}
		return out
	}
	// The stage expressions a call site may pass, and the stages each can be.
	stagesOf := map[string][]string{
		"DecisionStageLLM":   {DecisionStageLLM},
		"DecisionStageTool":  {DecisionStageTool},
		"DecisionStageAgent": {DecisionStageAgent},
		// The Decision API: the caller's stage, which the handler admits only
		// when authzenActionStage maps it.
		"stage": everyStage(),
		// The gateway pre-check: decisionStageForPreCheck's two answers.
		"precheckStage": {
			decisionStageForPreCheck(PreCheckRequest{}),
			decisionStageForPreCheck(PreCheckRequest{DataSources: []string{"db"}}),
		},
	}

	call := regexp.MustCompile(`enforceRequestPass\([^,]+, (\w+), `)
	// A call split after its opening parenthesis would not match call; this
	// catches it so the census cannot skip a site silently.
	anyCall := regexp.MustCompile(`enforceRequestPass\(`)
	stageField := regexp.MustCompile(`^\s*stage:\s+(\w+),`)
	inStage := regexp.MustCompile(`in\.stage = (\w+)`)
	observed := map[string]map[string]bool{}
	sites := 0
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		name := f.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if strings.Contains(line, "func enforceRequestPass") {
				continue
			}
			m := call.FindStringSubmatch(line)
			if m == nil {
				if anyCall.MatchString(line) {
					t.Errorf("%s:%d: an enforceRequestPass call this census cannot read (its scope is not on the call line)", name, i+1)
				}
				continue
			}
			scope, ok := seamVars[m[1]]
			if !ok {
				t.Errorf("%s:%d: enforceRequestPass on %q, which this census does not know; add it to seamVars", name, i+1, m[1])
				continue
			}
			var expr string
			for j := i; j < len(lines) && j < i+8 && expr == ""; j++ {
				if s := stageField.FindStringSubmatch(lines[j]); s != nil {
					expr = s[1]
				}
			}
			if expr == "" && strings.Contains(line, ", in)") {
				// The MCP request pass fills its input just before the call:
				// the nearest in.stage assignment above it.
				for j := i - 1; j >= 0 && j >= i-15 && expr == ""; j-- {
					if s := inStage.FindStringSubmatch(lines[j]); s != nil {
						expr = s[1]
					}
				}
			}
			stages, known := stagesOf[expr]
			if !known {
				t.Errorf("%s:%d: the stage passed on %s is %q, which this census cannot resolve", name, i+1, scope, expr)
				continue
			}
			sites++
			for _, s := range stages {
				action, ok := stageToAction[s]
				if !ok {
					t.Errorf("%s:%d: stage %q maps to no action", name, i+1, s)
					continue
				}
				if observed[scope.String()] == nil {
					observed[scope.String()] = map[string]bool{}
				}
				observed[scope.String()][action] = true
			}
		}
	}
	// The MCP response pass decides the tool's response with no request-pass
	// input: its action is the one mcp_response_enforcing_seam.go names on its
	// call, read from that file.
	respSrc, err := os.ReadFile("mcp_response_enforcing_seam.go")
	if err != nil {
		t.Fatal(err)
	}
	respActions := map[string]bool{}
	actionLocal := map[string]string{
		"ActionToolCall": authoringcatalog.ActionToolCall, "ActionLLMCompletion": authoringcatalog.ActionLLMCompletion,
		"ActionAgentInvoke": authoringcatalog.ActionAgentInvoke,
	}
	for _, m := range regexp.MustCompile(`action:\s+authoringcatalog\.(Action\w+)`).FindAllStringSubmatch(string(respSrc), -1) {
		respActions[actionLocal[m[1]]] = true
	}
	if len(respActions) == 0 {
		t.Fatal("mcp_response_enforcing_seam.go names no action on its call; the census read nothing")
	}
	observed[mcpResponseSeamScope.String()] = respActions

	// The cowork ingest storage pass (the Enterprise build's, #4259) decides
	// each content event as the action coworkActionFor returns, read from that
	// function's return statements. The file is read whatever this binary's
	// build, because it is the one statement of what the pass presents.
	coworkSrc, err := os.ReadFile("cowork_ingest_enforcing_seam.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?s)func coworkActionFor\(event string\) string \{(.*?)\n\}`).FindSubmatch(coworkSrc)
	if fn == nil {
		t.Fatal("cowork_ingest_enforcing_seam.go has no coworkActionFor; the census read nothing")
	}
	coworkActions := map[string]bool{}
	for _, m := range regexp.MustCompile(`return authoringcatalog\.(Action\w+)`).FindAllStringSubmatch(string(fn[1]), -1) {
		coworkActions[actionLocal[m[1]]] = true
	}
	if len(coworkActions) == 0 {
		t.Fatal("coworkActionFor returns no action the census can read")
	}
	observed[legacycompile.MustScopeFor(legacycompile.PlaneCoworkIngest, "").String()] = coworkActions

	if sites < 6 {
		t.Fatalf("read %d enforceRequestPass call sites; the census read nothing it can trust", sites)
	}
	for _, seam := range enforcingSeams {
		name := seam.scope.String()
		got := sortedSet(observed[name])
		if len(got) == 0 {
			t.Errorf("%s is registered and this census observed no call site presenting anything on it; it cannot compare nothing", name)
			continue
		}
		want := legacycompile.ScopeActions(seam.scope)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s presents %v and legacycompile's scopeActions states %v", name, got, want)
		}
	}
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
