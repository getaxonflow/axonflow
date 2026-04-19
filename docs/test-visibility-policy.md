# Test Visibility Policy

**Status:** Active (2026-04-19)
**Scope:** `axonflow-enterprise` + community mirror `axonflow` + 4 plugin repos

## Principle

Public by default, with explicit private exceptions.

- Top-level `tests/` **syncs to the community mirror**.
- `ee/**/tests/` stays private (colocated with enterprise-only code).
- Unit tests live next to the code they cover (`*_test.go`, `*.test.ts`) and follow whatever directory's public/private status they're in.

No test may contain:
- Real credentials, API keys, license keys, OAuth tokens, or AWS account IDs.
- Internal hostnames (`.internal`, real RDS endpoints, staging subdomains, non-public load balancer DNS).
- References to private sibling repositories (`axonflow-business-docs`, `axonflow-operations`, etc.). Link to the relevant public CHANGELOG entry, public ADR, or inline a self-contained explanation instead.
- Customer names, customer-specific policy content, or demo-account details other than the documented public demo credentials (`demo-client:demo-secret`).

If a test genuinely needs any of the above, it belongs under `ee/**/tests/` or a private sibling repo — not in `tests/`.

## Where tests live

The `tests/e2e/plugin-batch-1/` pattern (full matrices here, smoke scenarios in each plugin repo) is the canonical shape for any install-and-use test batch.

### Plugin repo owns

- **Install works** — package fetches and resolves against the latest registry release.
- **Hook / script wiring works** — `pre-tool-check.sh`, `post-tool-audit.sh`, `hooks.json`, `plugin.json`, `mcp.json` registered correctly; entry-point scripts syntax-check and exec.
- **One local deny UX** — a single smoke scenario that exercises the plugin's own deny path end-to-end against a running stack (bash plugins: exit code + stderr; Claude Code: `permissionDecision: deny` JSON) and asserts the Plugin Batch 1 richer-context markers (`decision:`, `risk:`) reach the user.
- **Any host-surface-specific wiring** — Claude Code `hooks.json` v1, Cursor `hooks.json` v1, Codex TOML registration, OpenClaw plugin manifest.

**Implementation:** one script under `tests/e2e/` + a `workflow_dispatch` workflow. Runs against an operator-supplied reachable endpoint. Not wired to GitHub-hosted PR runs (no stack there).

### Enterprise repo owns

- **Explain endpoint** — `GET /api/v1/decisions/:id/explain` shape + access control, including MCP-path decisions.
- **Override lifecycle** — `POST /api/v1/overrides` → allow path → `DELETE` → deny returns, across both HTTP check-input and MCP `tools/call` surfaces.
- **Audit search filter parity** — `decision_id`, `policy_name`, `override_id` filters return matching rows.
- **Cache invalidation** — override create flushes the WCP step-gate deny cache so the next request re-evaluates.
- **Cross-plugin consistency** — all plugins surface the same richer-context markers; block-path shape is identical.
- **Anything that requires a licensed stack** — evaluation-tier override creation, enterprise-tier audit export, license-gated policy categories.

**Implementation:** multiple scenarios under `tests/e2e/<batch>/<plugin>-install/` + `run-scenarios.sh` runner + docker-compose stack via `./scripts/setup-e2e-testing.sh`.

### What does NOT belong in plugin repos

Anything that needs license gating, cross-plugin parity assertions, or shared MCP / audit / override semantics. These are platform contracts and must be exercised against a licensed stack in the enterprise full matrix so all plugins see consistent behavior.

### What does NOT belong in enterprise

Plugin-internal wiring (hook registration path, manifest correctness, bash script entry-point structure, telemetry ping fires once per install). These are plugin-specific and owned by each plugin's own test suite.

## Release-blocking gates

| Release | Blocked by | Not blocked by |
|---|---|---|
| **Platform tag** (`axonflow-enterprise` → `v7.x.y`) | `tests/e2e/<batch>/<plugin>-install/` full matrix for every batch (all plugins, all scenarios green against the tagged commit). Run via `run-scenarios.sh` against a stack built from the release candidate. | Plugin-repo smoke scenarios. Those verify plugin-internal wiring, which is plugin-tag-blocking, not platform-tag-blocking. |
| **Plugin tag** (`axonflow-{plugin}-plugin` → `vX.Y.Z`) | The plugin's own `tests/e2e/` smoke scenario plus its unit test suite. Run manually via `workflow_dispatch` against a reachable stack (typically the latest platform release) before tagging. | Enterprise full matrix. That's for the platform tag — plugins version independently. |

**Operational rule:** a platform release tag may land without every plugin passing against it (plugins can catch up), but a plugin release tag must pass its own smoke scenario against a specific platform version — and that version should be named in the plugin's CHANGELOG compatibility line.

**Why this split:** a platform regression that breaks multiple plugins is a platform problem — catching it in each plugin repo separately would fragment the signal and delay the fix. A plugin-internal wiring bug (wrong hook registration path, broken manifest) is invisible to the platform matrix because the platform never sees the plugin's internal structure. Splitting the gates by where the bug can originate keeps both signals clean.

## Writing new tests

- Drop new cross-cutting E2E under `tests/e2e/<batch>/` in this repo. They'll sync to the community mirror automatically.
- Drop new unit tests next to the code they cover.
- If you need a private-only test (e.g. it exercises customer-specific data or a private sibling repo's content), put it under `ee/**/tests/` and add a comment explaining why it can't be public.

## CI enforcement

`.github/workflows/tests-hygiene.yml` scans every PR that touches `tests/` for the forbidden patterns in the "No test may contain" list. Failures block merge. See that workflow for the exact regexes.

## History

- **2026-04-19**: Policy established. Previously `tests/` was blanket-excluded from community sync by a 2025-12-16 commit (`a91c09d2`) as one of ~18 preemptive exclusions during the OSS→community rename — before anything lived in `tests/`. Audit of the 15 files that eventually landed there showed no sensitive content; exclusion flipped and policy formalized.
- **2026-04-19** (later same day): Expanded "Hybrid split" section into explicit "Where tests live" and "Release-blocking gates" sections. The original table buried the owner-vs-release-blocker split in two row footers; contributors asked for a dedicated scannable section. No policy change — same rules, clearer phrasing.
