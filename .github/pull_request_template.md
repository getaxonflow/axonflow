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
