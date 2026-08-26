// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #2941 census-as-test: the per-user token (#2924/#2930) rides exactly TWO
// ingest envelopes by design — the /api/v1/decide request-body user_token and
// the X-User-Token header (MCP-server + agent-proxied REST). Every allowed
// ingest point is pinned below; a NEW header-read site or a NEW
// json:"user_token" schema field fails this test, forcing conscious review
// instead of a silent second identity channel (the #2896 lesson: a census
// must live in CI, not tribal knowledge). The collision rule — an endpoint
// that ever accepts BOTH envelopes must REJECT both-present-and-different,
// never apply silent precedence — is documented on the
// platform/shared/identity package doc.
//
// The legacy MCP-connector auth fields and the legacy examples tenant JWT
// (see #2937) also spell their field json:"user_token", but they are a
// DIFFERENT credential class (connector/tenant auth, not the #2924 per-user
// token). The census annotates them so they are distinguished, not conflated;
// they converge at the next major (#2941 convergence path).

// xUserTokenReadAllowlist is the exact set of production files that may READ
// the X-User-Token header. All header ingest stays behind these two seams
// (extractPerUserToken on the MCP-server plane; the proxied-REST read in
// proxy.go) so downstream behavior — ResolveToken validation, fail-closed
// posture, attribution — can never fork per read site.
var xUserTokenReadAllowlist = map[string]string{
	"platform/agent/mcp_identity.go": "extractPerUserToken — the MCP-server plane seam (X-User-Token / Bearer)",
	"platform/agent/proxy.go":        "agent-proxied REST plane — reads X-User-Token ONLY (Authorization carries the tenant credential)",
}

// xUserTokenMentionOnlyAllowlist are production files that may reference the
// header NAME (docs/comments) but must NOT read it — the census additionally
// asserts no read marker appears in them.
var xUserTokenMentionOnlyAllowlist = map[string]string{
	"platform/agent/mcp_server_handler.go": "doc comments describing the per-user identity model; reads go through extractPerUserToken",
	"platform/shared/identity/trust.go":    "package doc — the #2941 dual-envelope census + collision rule",
	// #3062: names the header in a 401 error STRING as the alternative remedy
	// when the identity trust gate dropped the caller's X-User-Email. Prose
	// only — it never reads the header, and the orchestrator has no per-user
	// token ingest at all (validators are enterprise/agent-side). Reviewed and
	// admitted deliberately: telling a blocked user which credential to
	// present is the entire point of the message, and a vaguer wording would
	// re-create the unactionable error this fixes.
	//
	// #3077 moved those message BODIES out of
	// platform/orchestrator/identity_required_error.go and into the shared
	// package, so the MCP-server plane (platform/agent, which cannot import
	// platform/orchestrator without a cycle) refuses through the same choke
	// point. The prose-only admission moves with them, unchanged in kind:
	//
	//   - identity_required.go holds all three refusal bodies. Still prose
	//     only; the shared package has no request-reading code at all.
	//   - identity_trust.go names the header in the doc comment explaining WHY
	//     the MCP refusal offers a token only to enterprise sessions. That
	//     conditional is the point: the census's own fail-closed posture is
	//     what makes "not resolvable here" a true statement, so the comment
	//     citing it is load-bearing documentation, not a second channel.
	//
	// The orchestrator file keeps only the marker-trust helper and no longer
	// spells the header, so its entry is retired rather than kept as a
	// no-longer-true allowance.
	"platform/shared/identity/identity_required.go": "#3062/#3077 actionable refusal bodies — names the header as a remedy; no read, no ingest",
	"platform/agent/identity_trust.go":              "#3077 doc comment on why the MCP refusal offers a token only for enterprise sessions; no read, no ingest",
	// #3456: the shared human-actor segment gate's header documents, for every
	// plane that calls it, WHICH envelope carries the per-user token on that
	// plane — MCP REST and /decide both read it from the JSON BODY, and
	// neither reads the header. Naming the header is the point of the note:
	// #2941's promotion trigger is "any single endpoint starts accepting both
	// spellings", so the reason a new caller must NOT reach for it belongs
	// next to the contract a new caller reads. Prose only — the census's
	// read-marker assertion below is what keeps that true.
	"platform/agent/human_actor_segment_gate.go": "#3456 gate doc — records that this plane's token rides the body envelope, never the header; no read, no ingest",
}

// userTokenBodyFieldAllowlist is the exact set of production files whose
// request/wire schemas may carry a json:"user_token" field, annotated by
// credential class.
var userTokenBodyFieldAllowlist = map[string]string{
	// THE per-user body envelope (#2924): the caller is a PEP deciding on
	// behalf of an end user; the token is an input to the decision.
	"platform/agent/decision_handler.go": "per-user token — DecideRequest, the /api/v1/decide body envelope",
	"platform/shared/pep/pep.go":         "per-user token — client-side mirror of the published PEP DecideRequest contract",

	// LEGACY, different credential class — connector/tenant auth, NOT the
	// #2924 per-user token. Do not conflate; converges at the next major.
	"platform/agent/mcp_handler.go":       "legacy connector auth — MCPQuery/MCPExecute/MCPCheckInput/MCPCheckOutput request schemas",
	"platform/shared/pep/check_output.go": "legacy connector auth — wire mirror of MCPCheckOutputRequest",
	"platform/agent/run.go":               "legacy examples tenant JWT — ClientRequest (#2937)",
	"platform/agent/gateway_handlers.go":  "legacy examples tenant JWT — PreCheckRequest (SDK gateway mode)",
}

// userTokenCensusScan walks the production Go source (platform/ + ee/, when
// present) and returns repo-root-relative paths of files matching match.
// _test.go files and examples/ trees (client-side code, not ingest points)
// are out of census scope.
func userTokenCensusScan(t *testing.T, match func(content string) bool) map[string]bool {
	t.Helper()
	const repoRoot = "../.." // this file lives at platform/agent/
	roots := []string{"platform", "ee"}
	found := map[string]bool{}
	for _, root := range roots {
		absRoot := filepath.Join(repoRoot, root)
		if _, err := os.Stat(absRoot); err != nil {
			// ee/ may be absent in a community build context; platform/ never is.
			if root == "platform" {
				t.Fatalf("census scan root missing: %v", err)
			}
			continue
		}
		err := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repoRoot, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				base := d.Name()
				if base == "examples" || base == "node_modules" || base == "vendor" || strings.HasPrefix(base, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if match(string(b)) {
				found[rel] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("census scan failed under %s: %v", root, err)
		}
	}
	return found
}

// assertCensusExact fails on any scanned file missing from the allowlists
// (a NEW ingest point — needs conscious review) AND on any allowlisted file
// no longer matching (a stale census entry — prune it so the census stays
// ground truth).
func assertCensusExact(t *testing.T, what string, found map[string]bool, allowlists ...map[string]string) {
	t.Helper()
	allowed := map[string]string{}
	for _, al := range allowlists {
		for f, why := range al {
			allowed[f] = why
		}
	}
	for f := range found {
		if _, ok := allowed[f]; !ok {
			t.Errorf("NEW %s site: %s — a second identity channel must be a conscious, reviewed act. If this ingest point is intentional, add it to the census allowlist with its credential class and confirm the shared-ResolveToken + fail-closed + collision-rule posture (#2941).", what, f)
		}
	}
	for f, why := range allowed {
		if strings.HasPrefix(f, "ee/") {
			if _, err := os.Stat(filepath.Join("../..", filepath.FromSlash(f))); err != nil {
				continue // ee tree absent in this build context
			}
		}
		if !found[f] {
			t.Errorf("stale census entry: %s (%s) no longer matches — update the allowlist so the census stays ground truth", f, why)
		}
	}
}

func TestUserTokenIngestCensus_XUserTokenHeader(t *testing.T) {
	// Bare, case-insensitive name match so comment mentions are censused too —
	// a mention is where the next read gets written.
	nameMentioned := func(c string) bool {
		return strings.Contains(strings.ToLower(c), "x-user-token")
	}
	found := userTokenCensusScan(t, nameMentioned)
	assertCensusExact(t, "X-User-Token header reference", found, xUserTokenReadAllowlist, xUserTokenMentionOnlyAllowlist)

	// Mention-only files must never gain an actual read: header ingest stays
	// behind the two allowlisted seams. Match case-INSENSITIVELY because
	// http.Header.Get canonicalizes its key — r.Header.Get("x-user-token")
	// reads the same header, so a lowercase literal must not slip past this
	// "must NOT read" check (#2938 R3 MED-2). Residual, accepted: a read via a
	// named string const (no literal in the reading file) escapes BOTH this and
	// the bare-name scan when the const lives in an already-allowlisted file —
	// keep the header name a literal at the two seams, not a shared const.
	readMarkers := []string{`.get("x-user-token")`, `.values("x-user-token")`, `header["x-user-token"]`}
	hasRead := func(c string) bool {
		lc := strings.ToLower(c)
		for _, m := range readMarkers {
			if strings.Contains(lc, m) {
				return true
			}
		}
		return false
	}
	reads := userTokenCensusScan(t, hasRead)
	for f := range reads {
		if _, ok := xUserTokenReadAllowlist[f]; !ok {
			t.Errorf("X-User-Token is READ outside the allowed seams: %s — route it through extractPerUserToken/the proxy seam or census it consciously (#2941)", f)
		}
	}
	// And the allowed seams do still read it (guards against the read moving
	// without the census following).
	for f := range xUserTokenReadAllowlist {
		if !reads[f] {
			t.Errorf("allowlisted read seam %s no longer reads X-User-Token — update the census", f)
		}
	}
}

func TestUserTokenIngestCensus_BodyField(t *testing.T) {
	// Backtick-prefixed so only real struct TAGS match — prose mentions of the
	// field name in doc comments are not schema fields.
	found := userTokenCensusScan(t, func(c string) bool {
		return strings.Contains(c, "`json:\"user_token")
	})
	assertCensusExact(t, `json:"user_token" schema field`, found, userTokenBodyFieldAllowlist)
}
