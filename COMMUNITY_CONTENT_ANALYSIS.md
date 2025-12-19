# Community Content Analysis - What Should Be Public vs Private

## Executive Summary

The current sync workflow only excludes `ee/` directory, but many other directories contain sensitive business information that should NOT be public.

---

## Classification Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | **INCLUDE in Community** - Public, open source |
| ❌ | **EXCLUDE from Community** - Private, enterprise-only |
| ⚠️ | **PARTIAL** - Some content OK, some should be excluded |

---

## Top-Level Directories

| Directory | Decision | Reason |
|-----------|----------|--------|
| `ee/` | ❌ EXCLUDE | Enterprise code (already excluded) |
| `platform/` | ⚠️ PARTIAL | Core code YES, demo-portal NO |
| `migrations/core/` | ✅ INCLUDE | Community database schema |
| `migrations/enterprise/` | ❌ EXCLUDE | Enterprise migrations (already excluded) |
| `migrations/industry/` | ❌ EXCLUDE | Industry migrations (already excluded) |
| `docs/` | ✅ INCLUDE | Public documentation |
| `sdk/` | ✅ INCLUDE | Public SDKs |
| `examples/` | ✅ INCLUDE | Public examples |
| `tutorials/` | ✅ INCLUDE | Public tutorials |
| `tests/` | ✅ INCLUDE | Public tests |
| `.github/workflows/` | ⚠️ PARTIAL | Community workflows YES, deploy workflows NO |
| `config/` | ❌ EXCLUDE | AWS accounts, environment configs |
| `configs/` | ❌ EXCLUDE | Client-specific configs |
| `scripts/` | ❌ EXCLUDE | Internal deployment scripts |
| `technical-docs/` | ❌ EXCLUDE | Internal architecture docs |
| `client-workflows/` | ❌ EXCLUDE | Client-specific workflows |
| `demo-workflows/` | ❌ EXCLUDE | Internal demo workflows |
| `grafana/` | ❌ EXCLUDE | Internal monitoring configs |
| `docker/` | ⚠️ PARTIAL | docker-compose.yml YES, internal configs NO |
| `nginx/` | ❌ EXCLUDE | Internal nginx configs |
| `init-db/` | ❌ EXCLUDE | Internal database init |
| `code-docs/` | ❌ EXCLUDE | Internal code documentation |
| `archive/` | ❌ EXCLUDE | Internal archives |
| `.claude/` | ❌ EXCLUDE | Claude Code configs |

---

## Platform Directory Breakdown

| Path | Decision | Reason |
|------|----------|--------|
| `platform/agent/` | ✅ INCLUDE | Core agent (with Community stubs) |
| `platform/orchestrator/` | ✅ INCLUDE | Core orchestrator |
| `platform/connectors/` | ✅ INCLUDE | Connector framework + stubs |
| `platform/shared/` | ✅ INCLUDE | Shared utilities |
| `platform/cmd/` | ✅ INCLUDE | CLI tools |
| `platform/common/` | ✅ INCLUDE | Common utilities |
| `platform/database/` | ✅ INCLUDE | Database utilities |
| `platform/test/` | ✅ INCLUDE | Test utilities |
| `platform/demo-portal/` | ❌ EXCLUDE | Contains investor.html, advisor.html |
| `platform/monitoring/` | ❌ EXCLUDE | Internal monitoring |
| `platform/observability/` | ❌ EXCLUDE | Internal observability |
| `platform/scripts/` | ❌ EXCLUDE | Internal scripts |
| `platform/archive/` | ❌ EXCLUDE | Internal archives |
| `platform/go.mod` | ✅ INCLUDE | Go module definition |
| `platform/go.sum` | ✅ INCLUDE | Go dependencies |
| `platform/*.md` | ✅ INCLUDE | Public documentation |
| `platform/deploy-all-demos.sh` | ❌ EXCLUDE | Internal deployment |
| `platform/brand-system.css` | ❌ EXCLUDE | Brand assets |

---

## GitHub Workflows

| Workflow | Decision | Reason |
|----------|----------|--------|
| `sync-community-repo.yml` | ❌ EXCLUDE | Internal sync process |
| `accept-community-pr.yml` | ❌ EXCLUDE | Internal contribution process |
| `deploy-*.yml` | ❌ EXCLUDE | Internal deployment |
| `build-*.yml` | ❌ EXCLUDE | Internal build |
| `test.yml` | ✅ INCLUDE | Public CI testing |
| `lint.yml` | ✅ INCLUDE | Public linting |
| `release.yml` | ✅ INCLUDE | Public releases |

---

## Files to Exclude (Patterns)

```
# Enterprise code
ee/

# Internal configurations
config/
configs/
client-workflows/
demo-workflows/

# Internal documentation
technical-docs/
code-docs/
archive/

# Internal scripts
scripts/

# Internal infrastructure
grafana/
nginx/
init-db/
docker/

# Platform internals
platform/demo-portal/
platform/monitoring/
platform/observability/
platform/scripts/
platform/archive/
platform/deploy-all-demos.sh
platform/brand-system.css

# Migrations (keep only core)
migrations/enterprise/
migrations/industry/

# Claude Code configs
.claude/

# Internal workflows
.github/workflows/deploy-*.yml
.github/workflows/build-*.yml
.github/workflows/sync-community-repo.yml
.github/workflows/accept-community-pr.yml
.github/workflows/update-stack.yml
.github/workflows/delete-stack.yml
.github/workflows/setup-*.yml
.github/workflows/manage-*.yml
```

---

## What SHOULD Be in Community

```
# Core platform
platform/agent/
platform/orchestrator/
platform/connectors/
platform/shared/
platform/cmd/
platform/common/
platform/database/
platform/test/
platform/go.mod
platform/go.sum
platform/ARCHITECTURE_SUMMARY.md
platform/BACKEND_ARCHITECTURE_AND_TESTING_GUIDE.md
platform/FILE_MANIFEST.md

# SDKs
sdk/

# Public docs
docs/

# Examples and tutorials
examples/
tutorials/

# Tests
tests/

# Core migrations only
migrations/core/

# Root files
README.md
LICENSE
CONTRIBUTING.md
SECURITY.md
CODE_OF_CONDUCT.md
Makefile
docker-compose.yml (simplified version)
.gitignore
.golangci.yml

# Community workflows only
.github/workflows/test.yml
.github/workflows/lint.yml
.github/workflows/release.yml
.github/ISSUE_TEMPLATE/
.github/PULL_REQUEST_TEMPLATE.md
```

---

## Recommended Sync Exclusions

Add these to `sync-community-repo.yml`:

```yaml
rsync -av \
  --exclude='ee/' \
  --exclude='.git' \
  --exclude='.claude/' \
  --exclude='config/' \
  --exclude='configs/' \
  --exclude='scripts/' \
  --exclude='technical-docs/' \
  --exclude='client-workflows/' \
  --exclude='demo-workflows/' \
  --exclude='grafana/' \
  --exclude='nginx/' \
  --exclude='init-db/' \
  --exclude='docker/' \
  --exclude='code-docs/' \
  --exclude='archive/' \
  --exclude='migrations/enterprise/' \
  --exclude='migrations/industry/' \
  --exclude='platform/demo-portal/' \
  --exclude='platform/monitoring/' \
  --exclude='platform/observability/' \
  --exclude='platform/scripts/' \
  --exclude='platform/archive/' \
  --exclude='platform/deploy-all-demos.sh' \
  --exclude='platform/brand-system.css' \
  --exclude='.github/workflows/deploy-*.yml' \
  --exclude='.github/workflows/build-*.yml' \
  --exclude='.github/workflows/sync-community-repo.yml' \
  --exclude='.github/workflows/accept-community-pr.yml' \
  --exclude='.github/workflows/update-stack.yml' \
  --exclude='.github/workflows/delete-stack.yml' \
  --exclude='.github/workflows/setup-*.yml' \
  --exclude='.github/workflows/manage-*.yml' \
  --exclude='axonflow-worktree-*' \
  --exclude='*.pem' \
  --exclude='*.key' \
  --exclude='.env*' \
  . /tmp/oss-sync/
```
