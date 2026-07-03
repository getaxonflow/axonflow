// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import "strings"

// Capability-scoped policy evaluation (#2801, epic #2800).
//
// Execution-class detector families (SQL injection, dangerous shell commands,
// dynamic code execution, config-file writes, SSRF endpoints) model the threat
// "this input is about to be EXECUTED by the governed tool". Applied to a tool
// that can only write prose into a SaaS document (a Jira issue, a Confluence
// page), they evaluate documentation text as though it were executable input
// and hard-block legitimate content: a design partner hit 5 false-positive
// blocks on text-only Jira edits — a markdown table divider plus the phrase
// "admin console" (sys_sqli_admin_bypass, critical, non-overridable by design
// per migration core/076 / ADR-044), plain-English "revoke" (sys_sqli_revoke),
// "eval (" inside an org id ending in "-eval (staging)"
// (sys_dangerous_eval_exec), and prose mentioning ".env" / "credentials.json"
// filenames (sys_dangerous_agent_config).
//
// The fix is SCOPING, not detector loosening: when — and only when — the
// governed tool is POSITIVELY classified as a text-document tool, the
// execution-class detector families are skipped. Everything content-borne
// keeps evaluating everywhere:
//
//   - PII (all pii-* categories, media-pii, legacy pii_detection): a NIK in a
//     Jira ticket is still a leak.
//   - Prompt injection (sys_dangerous_injection_*): an injection string
//     WRITTEN into a document is stored/indirect prompt injection — it will
//     re-enter a model's context when the document is read back.
//   - sensitive-data (secrets), compliance-*, admin-access, and every other
//     category.
//
// FAIL-CLOSED CONTRACT (the security-critical edge):
//  1. A tool identity that is empty, unknown, or not positively classified
//     gets FULL evaluation. Classification can only RELAX, never widen.
//  2. A policy is skipped only when it is POSITIVELY classified as
//     execution-class — via a category whose every seeded policy models
//     executable input (executionScopedCategories) or via an explicitly
//     enumerated policy id (executionScopedPolicyIDs). New/unknown policies —
//     including tenant-authored custom policies in the mixed
//     security-dangerous category — keep evaluating for text-document tools
//     until someone explicitly classifies them.
//  3. Classification is NEVER caller-asserted: callers pass the raw tool
//     identity string (EvalOptions.ToolIdentity) and the classification
//     happens here against a server-side registry. There is no request field
//     through which a caller can claim "I am text-only".
//
// Threat-model note on caller-controlled tool NAMES: capability scoping
// applies ONLY on the ADVISORY planes (check-input / check-output /
// mcp-server check_policy + check_output / /decide target.tool), where the
// enforcing client itself executes the tool and reports its name (e.g. the
// Claude Code plugin hook). A client that lies about the tool name could
// equally not call the PEP at all — the name is already the trust anchor for
// that plane (the same trust the existing read-only posture classifier,
// mcp_readonly_posture.go, places in it). A backend MCP server that names a
// shell-executing tool "editJiraIssue" is a trojan connector: it controls
// execution regardless of what this evaluation decides, and is governed by
// connector registration/allowlisting, not by request-content scanning.
//
// The managed-connector planes (resources/query, tools/execute) — where the
// AGENT executes the statement against a real connector — NEVER apply
// capability scoping: their callers pass an empty ToolIdentity (R3 round-1
// finding). The registered connector NAME is tenant-chosen free-form text,
// not a capability statement; a postgres connector registered as
// "jira_get_issue" must not lose SQLi enforcement.

// executionScopedCategories are the policy categories whose EVERY seeded
// policy models executable input, so the whole category is skipped for
// text-document tools. Verified against the seed migrations before inclusion:
//
//   - security-sqli (core/031): SQL-injection and dangerous-SQL statement
//     detectors (UNION/stacked/blind, DROP/GRANT/REVOKE/TRUNCATE, ...).
//   - sql_injection, dangerous_queries (core/010 legacy tenant starter
//     policies): UNION/boolean injection + DROP/TRUNCATE TABLE — all SQL
//     execution semantics.
//
// Deliberately NOT here: security-dangerous (mixes executable command
// patterns with content-borne prompt-injection guards — split per policy id
// below), security-admin / admin_access (access semantics, low FP risk, keep
// conservative), and every PII / sensitive-data / compliance category.
var executionScopedCategories = map[PolicyCategory]bool{
	CategorySecuritySQLi:                true,
	PolicyCategory("sql_injection"):     true,
	PolicyCategory("dangerous_queries"): true,
}

// executionScopedPolicyIDs individually classifies the execution-class
// policies inside the MIXED security-dangerous category (and the integration
// config-file packs). The category also carries the content-borne
// sys_dangerous_injection_* prompt-injection guards (core/116), which MUST
// keep evaluating for text-document tools — so the category cannot be scoped
// wholesale and each execution-class policy is enumerated explicitly.
//
// Fail-closed by construction: a NEW security-dangerous policy (seeded or
// tenant-authored) is NOT in this set and therefore keeps evaluating for
// text-document tools until explicitly classified here. The realpg
// classification-completeness test (capability_scope_realpg_test.go) fails
// when a migration seeds a security-dangerous policy that is in neither this
// set nor contentBorneSecurityDangerousPolicyIDs, forcing that decision.
var executionScopedPolicyIDs = map[string]bool{
	// migrations/core/059 — dangerous command execution / SSRF / config files
	"sys_dangerous_reverse_shell":     true, // shell execution
	"sys_dangerous_destructive_fs":    true, // shell / filesystem
	"sys_dangerous_credential_access": true, // shell / file read
	"sys_dangerous_shell_download":    true, // shell execution
	"sys_dangerous_cloud_metadata":    true, // network fetch (SSRF)
	"sys_dangerous_internal_network":  true, // network fetch (SSRF)
	"sys_dangerous_agent_config":      true, // file write
	"sys_dangerous_path_traversal":    true, // file read/write
	"sys_dangerous_eval_exec":         true, // dynamic code execution
	"sys_dangerous_package_install":   true, // shell execution

	// migrations/core/060+064 — IDE/agent-integration config-file protection
	// (fire on file WRITE paths; a document merely mentioning
	// ".claude/settings.json" is not a file write)
	"int_claude_settings":         true,
	"int_claude_hooks":            true,
	"int_cursor_settings":         true,
	"int_cursor_hooks":            true,
	"int_cursor_rules":            true,
	"int_codex_settings":          true,
	"int_openclaw_agent_identity": true,
	"int_openclaw_agent_memory":   true,
	"int_openclaw_config":         true,
}

// contentBorneSecurityDangerousPolicyIDs are the security-dangerous policies
// that are explicitly classified CONTENT-BORNE: they always evaluate,
// including for text-document tools. Kept as an explicit set (not "everything
// not execution-scoped") so the realpg completeness test can prove every
// seeded security-dangerous policy carries a DELIBERATE classification.
var contentBorneSecurityDangerousPolicyIDs = map[string]bool{
	// migrations/core/116 — indirect prompt-injection guards. Writing an
	// injection string into a document plants stored prompt injection.
	"sys_dangerous_injection_override":       true,
	"sys_dangerous_injection_role_override":  true,
	"sys_dangerous_injection_system_exfil":   true,
	"sys_dangerous_injection_bracket_marker": true,
}

// HasExplicitSecurityDangerousClassification reports whether a
// security-dangerous policy id carries a DELIBERATE capability
// classification (execution-class or content-borne). Consumed by the realpg
// classification-completeness test: a migration that seeds a NEW
// security-dangerous policy without classifying it here fails that test,
// forcing the seeding author to decide. (Unclassified policies are still
// fail-closed at runtime — they evaluate everywhere — the test exists so the
// decision is explicit, not accidental.)
func HasExplicitSecurityDangerousClassification(policyID string) bool {
	return executionScopedPolicyIDs[policyID] || contentBorneSecurityDangerousPolicyIDs[policyID]
}

// IsExecutionScopedPolicy reports whether a policy is positively classified
// as an execution-class detector — i.e. it may be skipped when the governed
// tool is positively classified as a text-document tool. Anything not
// positively classified keeps evaluating (fail-closed rule 2 above).
func IsExecutionScopedPolicy(p *CompiledPolicy) bool {
	if executionScopedCategories[p.Category] {
		return true
	}
	return executionScopedPolicyIDs[p.PolicyID]
}

// builtinTextDocumentTools is the conservative built-in registry of tool
// names positively classified as text-document tools: their backend is a SaaS
// document API and their input is prose/identifiers — no shell, no SQL/DSL
// execution, no local file access, no arbitrary network fetch. Matching is
// case-insensitive on the FULL identity and on its terminal segment (see
// normalizeToolIdentity), so both `editJiraIssue` and
// `claude_code.mcp__atlassian__editJiraIssue` classify.
//
// Two naming families are listed: the official Atlassian remote MCP server
// (camelCase) and the widely-deployed mcp-atlassian server (snake_case).
//
// Deliberately EXCLUDED (input is a query language, not prose — JQL/CQL get
// full evaluation): searchJiraIssuesUsingJql, searchConfluenceUsingCql,
// jira_search, confluence_search. Also excluded: every Claude Code builtin
// (Bash/Write/Edit/Read run shell or touch local files) and any
// attachment/download tool.
//
// Enterprise deployments can extend this registry via
// AXONFLOW_TEXT_DOCUMENT_TOOLS (EngineConfig.ExtraTextDocumentTools); the
// community edition ships the built-in registry only.
var builtinTextDocumentTools = map[string]bool{
	// Official Atlassian remote MCP server — Jira
	"createjiraissue":                  true,
	"editjiraissue":                    true,
	"addcommenttojiraissue":            true,
	"transitionjiraissue":              true,
	"getjiraissue":                     true,
	"gettransitionsforjiraissue":       true,
	"getjiraissueremoteissuelinks":     true,
	"getvisiblejiraprojects":           true,
	"getjiraprojectissuetypesmetadata": true,
	"lookupjiraaccountid":              true,
	// Official Atlassian remote MCP server — Confluence
	"createconfluencepage":            true,
	"updateconfluencepage":            true,
	"createconfluencefootercomment":   true,
	"createconfluenceinlinecomment":   true,
	"getconfluencepage":               true,
	"getconfluencespaces":             true,
	"getpagesinconfluencespace":       true,
	"getconfluencepageancestors":      true,
	"getconfluencepagefootercomments": true,
	"getconfluencepageinlinecomments": true,
	"getconfluencepagedescendants":    true,
	// mcp-atlassian (snake_case) — Jira
	"jira_get_issue":        true,
	"jira_create_issue":     true,
	"jira_update_issue":     true,
	"jira_add_comment":      true,
	"jira_transition_issue": true,
	// mcp-atlassian (snake_case) — Confluence
	"confluence_create_page":  true,
	"confluence_update_page":  true,
	"confluence_add_comment":  true,
	"confluence_get_page":     true,
	"confluence_get_comments": true,
}

// normalizeToolIdentity lowercases the identity and extracts its terminal
// tool segment. Identities arrive in several shapes:
//
//   - `claude_code.mcp__atlassian__editJiraIssue` (Claude Code plugin:
//     connector_type = claude_code.<ToolName>, where Claude Code names MCP
//     tools mcp__<server>__<tool>) → editjiraissue
//   - `editJiraIssue` (a PEP passing the bare tool name, e.g. /decide
//     target.tool) → editjiraissue
//   - `jira_update_issue` (snake_case tool name; the trailing `__`-split
//     only applies to DOUBLE underscores, so single-underscore names
//     survive intact) → jira_update_issue
func normalizeToolIdentity(identity string) (full, terminal string) {
	full = strings.ToLower(strings.TrimSpace(identity))
	terminal = full
	if i := strings.LastIndexAny(terminal, "./:"); i >= 0 {
		terminal = terminal[i+1:]
	}
	if i := strings.LastIndex(terminal, "__"); i >= 0 {
		terminal = terminal[i+2:]
	}
	return full, terminal
}

// isTextDocumentTool reports whether the tool identity is POSITIVELY
// classified as a text-document tool by the built-in registry or the
// operator-extended set. Empty/unknown identities return false (fail-closed
// rule 1: unknown tool = full evaluation).
func isTextDocumentTool(identity string, extra map[string]bool) bool {
	full, terminal := normalizeToolIdentity(identity)
	if full == "" {
		return false
	}
	if builtinTextDocumentTools[full] || builtinTextDocumentTools[terminal] {
		return true
	}
	if len(extra) > 0 && (extra[full] || extra[terminal]) {
		return true
	}
	return false
}

// buildToolNameSet lowercases and de-blanks a configured tool-name list into
// the lookup set used by isTextDocumentTool.
func buildToolNameSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			set[n] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}
