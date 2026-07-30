## Is this user-facing?

<!-- Required: choose one. See `runtime-e2e/README.md` for the convention. -->

- [ ] **Yes** — includes a runtime-path test that exercises this from the user's actual surface (OpenClaw tool / Claude skill / Cursor tool / Codex tool / portal page / SDK example invoked end-to-end through the live stack). Examples that import the SDK client class directly do NOT count.
- [ ] **No** — internal-only capability. Reason (must name a specific downstream consumer — a named test, a scheduled job, an internal CLI; "future PRs" or "wire later" is NOT acceptable): ___________

If user-facing, the wiring PR for every relevant runtime must land with this PR (or be linked and merged in the same release window). No "wire it later."

> **If a user cannot reach the feature from their runtime, we did not ship a feature, we shipped a library.**

See [`runtime-e2e/README.md`](../runtime-e2e/README.md) for the convention. The cross-plugin coverage matrix lives at `axonflow-internal-docs/engineering/FEATURE_RUNTIME_COVERAGE.md` (private; engineering team only).

The `Runtime E2E required for user-facing changes` gate is a **required** check.
A PR that touches `platform/`, `ee/platform/`, `migrations/` or `docs/api/`
without adding or updating a `runtime-e2e/` test fails it, unless the escape
hatch below is claimed — which takes **both** `[skip-runtime-e2e]` in the PR
title **and** the filled-in section below. Per CLAUDE.md HARD RULE #9 the
escape hatch also requires explicit operator approval; name it in the section.

## Skip-runtime-e2e justification

<!-- Not claiming the escape hatch? Leave this section as-is or delete it.

     Claiming it? REPLACE this comment with the reason, and name the operator
     who approved it. The gate reads this heading by name and requires real
     text under it — a heading followed only by this comment does not count,
     nor does an empty one, nor one followed only by a horizontal rule (#3144).

     e.g. "Build-only change to the Dockerfile base image; no shipped runtime
     surface. Exemption approved by <operator>."
     See CONTRIBUTING.md ("Runtime-E2E-per-user-facing-change"). -->

---

## Description

<!-- Provide a clear and concise description of the changes in this PR -->

## Type of Change

<!-- Mark all relevant options with an "x" -->

- [ ] feat: New feature (non-breaking change that adds functionality)
- [ ] fix: Bug fix (non-breaking change that fixes an issue)
- [ ] docs: Documentation update (README, guides, API docs)
- [ ] refactor: Code refactoring (no behavior change)
- [ ] test: Adding or updating tests
- [ ] chore: Build, CI/CD, or dependency updates
- [ ] perf: Performance improvement
- [ ] security: Security improvement or vulnerability fix
- [ ] breaking: Breaking change (fix or feature that causes existing functionality to change)

## What Changed

<!-- Detailed explanation of what changed and why -->

**Problem Solved:**
<!-- What problem does this PR address? Link to issue if applicable -->

**Solution Implemented:**
<!-- How does this PR solve the problem? -->

**Impact:**
<!-- What is the impact of this change on the system? -->

## How to Test

<!-- Provide clear steps to test the changes -->

1.
2.
3.

**Test Environment:**
<!-- Describe the environment where this was tested -->
- [ ] Local development
- [ ] Docker Compose
- [ ] ECS Fargate (staging)
- [ ] AWS Marketplace CloudFormation
- [ ] Other: <!-- specify -->

## Component(s) Affected

<!-- Mark all components affected by this PR -->

- [ ] Agent (service execution)
- [ ] Orchestrator (workflow coordination)
- [ ] MCP Integration (LLM context protocol)
- [ ] Multi-tenant System
- [ ] SDK (Golang / Python / Node.js)
- [ ] Database (migrations, schema changes)
- [ ] AWS Marketplace Integration
- [ ] License Management
- [ ] Service Identity System
- [ ] Deployment Scripts / Infrastructure
- [ ] CI/CD Pipelines
- [ ] Documentation
- [ ] Other: <!-- specify -->

## Performance Impact

<!-- Does this change affect performance? -->

- [ ] No performance impact
- [ ] Performance improvement (provide benchmarks below)
- [ ] Potential performance regression (explain below)
- [ ] Unknown (needs benchmark testing)

**Benchmark Results:**
<!-- If applicable, include benchmark results before/after -->
```
Paste benchmark results here
```

## Database Changes

<!-- Does this PR include database migrations or schema changes? -->

- [ ] No database changes
- [ ] New migration added (migration number: )
- [ ] Schema changes (describe below)

**Migration Details:**
<!-- If applicable, describe the migration -->

## Breaking Changes

<!-- Does this PR introduce any breaking changes? -->

- [ ] No breaking changes
- [ ] Breaking changes (describe below and update CHANGELOG.md)

**Breaking Change Details:**
<!-- Describe what breaks and how users should migrate -->

## Security Considerations

<!-- Does this PR have security implications? -->

- [ ] No security implications
- [ ] Security improvement (describe below)
- [ ] Potential security concern (needs review)

**Security Notes:**
<!-- Describe any security considerations -->

## Checklist

### Code Quality
- [ ] Code follows the project's style guidelines
- [ ] Self-review completed (checked for bugs, edge cases)
- [ ] Code is DRY (Don't Repeat Yourself)
- [ ] No commented-out code or debug statements
- [ ] No hardcoded values (use constants or config)

### Testing
- [ ] Unit tests added/updated for new functionality
- [ ] Integration tests added/updated (if applicable)
- [ ] Benchmark tests added/updated (if performance-critical)
- [ ] All tests pass locally (`go test ./...`)
- [ ] Manual testing completed

### Regression test (bug-fix PRs)

For PRs whose title starts with `fix(` or that carry the `bug` label, the
`regression-test-required` CI gate (QF-19) will fail unless the diff adds at
least one test file at the layer that failed.

- [ ] Bug-fix PR includes a regression test that would have caught the bug
- [ ] OR the `regression-test-exempt` label is applied **and** the section
      below is filled in. The label on its own is not an exemption and will
      fail the gate (#3120).

### Regression-test-exempt justification

<!-- Not claiming the exemption? Leave this section as-is or delete it.

     Claiming it? REPLACE this comment with the reason. The gate reads this
     heading by name and requires real text under it — a heading followed only
     by this comment does not count, and neither does an empty one.

     e.g. "infra-only change to CFN template", "generated artifact regen",
     "test harness wiring with no executable behaviour change".
     See CONTRIBUTING.md ("Regression-test-per-bug") for accepted patterns. -->

### Cross-plane parity (ADR-046)
- [ ] If this PR extends `StepGateResponse`, `StepGateHTTPResponse`, or any
      `workflow_steps` / `hitl_approval_queue` field: the projection through
      `workflow_control.ProjectStepGateToHTTP` fires on both the WCP plane
      (`/api/v1/workflows/{id}/steps/{step_id}/<verb>`) and the MAP plane
      (`/api/v1/plans/{id}/steps/{step_id}/<verb>`).
- [ ] If a field is intentionally WCP-only or MAP-only, it is annotated with
      a `// WCP-only:` or `// MAP-only:` doc comment and noted in
      `HITLResponseFieldSet` accordingly. `TestHITLResponseParity` must still
      pass.

### Documentation
- [ ] Code is self-documenting with clear function/variable names
- [ ] Comments added for complex logic
- [ ] API documentation updated (if applicable)
- [ ] README updated (if applicable)
- [ ] CHANGELOG.md updated (for user-facing changes)
- [ ] Migration guide provided (if breaking change)

### Git Hygiene
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) format
- [ ] Commit subjects are ≤72 characters
- [ ] Commits are atomic (each commit represents one logical change)
- [ ] No merge commits (use rebase workflow)
- [ ] Branch is up to date with main/master

### Security
- [ ] No sensitive data (secrets, API keys, passwords) in code
- [ ] No sensitive data in commit history
- [ ] No new security vulnerabilities introduced
- [ ] Dependencies are up to date (if applicable)
- [ ] Input validation added for user-facing changes

### Deployment
- [ ] Deployment instructions provided (if needed)
- [ ] CloudFormation template updated (if infrastructure changes)
- [ ] Environment variables documented (if new config added)
- [ ] Backward compatible (or migration plan provided)

## Related Issues

<!-- Link to related issues using GitHub keywords -->

Closes #
Fixes #
Relates to #

## Additional Context

<!-- Add any other context, screenshots, diagrams, or references -->

## Reviewers Needed

<!-- Tag specific reviewers if domain expertise is required -->

- [ ] Backend reviewer (Go expertise)
- [ ] Infrastructure reviewer (AWS/ECS expertise)
- [ ] Security reviewer (for security-sensitive changes)
- [ ] Database reviewer (for migration changes)
- [ ] Documentation reviewer

## Post-Merge Actions

<!-- Any actions needed after merging? -->

- [ ] Deploy to staging
- [ ] Run database migrations
- [ ] Update documentation site
- [ ] Announce in community channels
- [ ] Other: <!-- specify -->

---

**Note to Reviewers:** Please pay special attention to <!-- highlight specific areas for review -->
