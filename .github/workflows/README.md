# GitHub Actions Workflows

This document describes all GitHub Actions workflows in the AxonFlow repository.

## Quick Reference

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| [build.yml](#buildyml) | Push/Merge Queue | Build Docker images |
| [test.yml](#testyml) | Push/PR | Run test suites |
| [lint.yml](#lintyml) | Push/PR | Code linting |
| [commit-lint.yml](#commit-lintyml) | PR | Validate commit messages |
| [security.yml](#securityyml) | Push/PR/Merge Queue/Schedule | Security scanning |
| [release.yml](#releaseyml) | Push tag | Create releases |

## Merge Queue Optimization

We use GitHub's merge queue to optimize CI costs while maintaining code quality.

### How It Works

| Phase | Workflows Run | Docker Builds? |
|-------|---------------|----------------|
| **PR Created/Updated** | test, lint, security (no Docker), commit-lint | ❌ No |
| **PR Enters Merge Queue** | build, security (with Docker) | ✅ Yes |
| **Merged to Main** | build (pushes to ECR) | ✅ Yes + Push |

### Cost Savings

- **83% reduction** in Docker build jobs (merge queue)
- **50% reduction** in test jobs (consolidated from 7 to 3)
- **80% reduction** in lint jobs (consolidated from 6 to 1)
- **30% reduction** in build triggers (smarter path filters)
- Docker builds only run when PR is actually ready to merge
- Main stays clean: if build fails in merge queue, PR is rejected

### Job Consolidation

**Test Suite** (7 → 3 jobs):
- `unit-tests`: All module tests in sequence (orchestrator, agent, connectors, shared)
- `race-detector`: Race condition detection (separate due to -race overhead)
- `integration-tests`: Integration and E2E tests (after unit tests pass)

**Lint** (6 → 1 job):
- `golangci-lint`: All modules sequentially (agent, orchestrator, connectors, shared, sdk)

**Path Filters** for builds:
- Only trigger on: `*.go`, `go.mod/sum`, Dockerfiles, migrations, grafana
- Ignore: `*_test.go`, `testdata/**`, `*.md`, `docs/**`

### Required Branch Protection Settings

To enable merge queue, configure branch protection for `main` and `develop`:

1. Go to **Settings → Branches → Branch protection rules**
2. Select or create rule for `main`
3. Enable these settings:
   - ✅ **Require a pull request before merging**
   - ✅ **Require status checks to pass before merging**
     - Required checks: `Test Summary`, `Lint Summary`, `Security Scan Summary`
   - ✅ **Require merge queue**
     - Merge method: Squash and merge
     - Build concurrency: 5
     - Minimum/Maximum group size: 1/5
   - ✅ **Required checks for merge queue**
     - Add: `Build Summary`

4. Repeat for `develop` branch

### CLI Setup (Alternative)

```bash
# Enable merge queue via GitHub CLI
gh api repos/{owner}/{repo}/rulesets -X POST -f name="main-protection" \
  -f target="branch" \
  -f enforcement="active" \
  --json conditions='{"ref_name":{"include":["refs/heads/main"]}}' \
  --json rules='[{"type":"merge_queue","parameters":{"merge_method":"squash"}}]'
```

---

## Deployment Workflows Reference

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| [deploy-platform.yml](#deploy-platformyml) | Manual | Deploy AxonFlow platform (new stacks) |
| [deploy-application.yml](#deploy-applicationyml) | Manual | Deploy application updates to existing stacks |
| [deploy-infrastructure.yml](#deploy-infrastructureyml) | Manual | Deploy infrastructure-only changes |
| [deploy-clients.yml](#deploy-clientsyml) | Manual | Deploy client applications |
| [update-stack.yml](#update-stackyml) | Manual | Update existing CloudFormation stacks |
| [manage-load-testing.yml](#manage-load-testingyml) | Manual | Manage load testing infrastructure lifecycle |
| [build-client-images.yml](#build-client-imagesyml) | Manual/Push | Build client Docker images |
| [provision-client-infrastructure.yml](#provision-client-infrastructureyml) | Manual | Provision new client infrastructure |
| [setup-backend-dns.yml](#setup-backend-dnsyml) | Manual | Configure backend DNS records |
| [setup-client-dns-ssl.yml](#setup-client-dns-sslyml) | Manual | Configure client DNS and SSL |
| [setup-invpc-acm-ssl.yml](#setup-invpc-acm-sslyml) | Manual | Configure in-VPC ACM SSL certificates |
| [update-documentation.yml](#update-documentationyml) | Push | Update documentation |

---

## CI/CD Workflows

### build.yml
**Trigger:** Push to main/develop, Merge Queue

Builds Docker images for all AxonFlow components:
- Agent (with enterprise overlay)
- Orchestrator (with enterprise overlay)
- Prometheus
- Grafana

**Merge Queue Behavior:**
- On `merge_group`: Builds images but doesn't push (validation only)
- On `push`: Builds and pushes images to ECR
- If merge queue build fails, PR is rejected (main stays clean)

### test.yml
**Trigger:** Push to main/develop, Pull Requests (path-filtered)

Runs comprehensive test suites in 3 consolidated jobs:
- **Unit Tests**: Orchestrator, Agent, Connectors, Shared (with coverage thresholds)
- **Race Detector**: Concurrency safety validation
- **Integration Tests**: E2E testing (runs after unit tests pass)

Coverage thresholds enforced:
- Orchestrator: 72%
- Agent: 74%
- Connectors: 66%

### lint.yml
**Trigger:** Push to main/develop, Pull Requests (path-filtered)

Code quality checks in 1 consolidated job:
- Go linting with golangci-lint v2.0.2
- Runs sequentially on: agent, orchestrator, connectors, shared, sdk

### commit-lint.yml
**Trigger:** Pull Requests

Validates commit messages follow conventional commit format.

### security.yml
**Trigger:** Push, Pull Requests, Merge Queue, Scheduled (daily)

Security scanning with Trivy:
- **Filesystem Scan:** Vulnerable dependencies in go.mod, package.json (always runs)
- **Config Scan:** Misconfigurations in Dockerfiles, YAML (always runs)
- **Secret Scan:** Accidentally committed secrets (always runs)
- **Docker Image Scans:** Agent and Orchestrator images (merge queue/push only)

**Merge Queue Behavior:**
- On `pull_request`: Runs filesystem, config, secret scans (no Docker scans)
- On `merge_group`: Runs all scans including Docker image scans
- Docker scans are informational (continue-on-error: true)

### release.yml
**Trigger:** Push tags matching `v*`

Creates GitHub releases with:
- Changelog generation
- Asset uploads
- Docker image tagging

---

## Deployment Workflows

### deploy-platform.yml
**Trigger:** Manual (`workflow_dispatch`)

Deploys a new AxonFlow platform stack via CloudFormation.

**Inputs:**
- `environment` - Target environment (staging, production, etc.)
- `deploy_type` - internal or marketplace
- `region` - AWS region
- Various stack parameters

**Use when:** Creating a new deployment from scratch.

### deploy-application.yml
**Trigger:** Manual (`workflow_dispatch`)

Deploys application updates to existing stacks (container/code changes).

**Inputs:**
- `environment` - Target environment
- `component` - Which component to deploy (all, orchestrator, agent, etc.)

**Use when:** Deploying code changes without infrastructure modifications.

### deploy-infrastructure.yml
**Trigger:** Manual (`workflow_dispatch`)

Deploys infrastructure-only changes.

**Inputs:**
- `environment` - Target environment
- `component` - Infrastructure component

**Use when:** Infrastructure changes that don't require full stack update.

### update-stack.yml
**Trigger:** Manual (`workflow_dispatch`)

Updates existing CloudFormation stacks with new templates while preserving all parameter values.

**Inputs:**
- `environment` - Target environment (staging, production, etc.)
- `stack_name` - Optional stack name override (auto-detects if empty)
- `template_version` - Optional template version/commit (defaults to HEAD)
- `dry_run` - Preview changes without applying (default: true)

**Features:**
- **Dry-run mode** - Creates change set to preview modifications
- **UsePreviousValue** - Preserves all existing parameter values
- **Production approval** - Requires manual approval for production environments
- **Change tracking** - Shows exactly what resources will be modified/replaced

**Use when:** CloudFormation template changes need to be applied to existing stacks without modifying parameters.

**Example:**
```bash
# Preview changes (dry-run)
gh workflow run update-stack.yml \
  -f environment=staging-healthcare-india \
  -f dry_run=true

# Apply changes
gh workflow run update-stack.yml \
  -f environment=staging-healthcare-india \
  -f dry_run=false
```

### deploy-clients.yml
**Trigger:** Manual (`workflow_dispatch`)

Deploys client-specific applications.

**Inputs:**
- `client` - Client identifier
- `environment` - Target environment

### manage-load-testing.yml
**Trigger:** Manual (`workflow_dispatch`)

Manages load testing infrastructure lifecycle with three modes:

**Modes:**
1. **Enable** - Prepare environment for load testing
   - Suspends auto-scaling (prevents scale-down during tests)
   - Scales services to test capacity (e.g., 5 agents + 10 orchestrators)
   - Saves original configuration for restoration
   - Calls deploy-application.yml with custom replica counts

2. **Disable** - Restore normal operation
   - Re-enables auto-scaling
   - Waits for services to scale down (up to 15 minutes)
   - Verifies replica counts return to baseline

3. **Status** - Show current state
   - Reports auto-scaling status
   - Shows current vs baseline replica counts
   - Displays who enabled load testing and when

**Inputs:**
- `mode` - enable, disable, or status (required)
- `environment` - staging or staging-healthcare-india (required)
- `agent_count` - Agent replicas for testing (default: 5)
- `orchestrator_count` - Orchestrator replicas for testing (default: 10)
- `timeout_minutes` - Max wait time for scale-down (default: 15)
- `dry_run` - Preview changes without executing (default: false)

**Safety Features:**
- State saved to GitHub Artifacts for rollback
- Timeout protection prevents indefinite waits
- Dry-run mode for testing workflow logic
- Baseline verification ensures proper restoration

**Example:**
```bash
# Enable load testing (scale up)
gh workflow run manage-load-testing.yml \
  -f mode=enable \
  -f environment=staging \
  -f agent_count=5 \
  -f orchestrator_count=10

# Run your load tests...

# Disable load testing (scale down)
gh workflow run manage-load-testing.yml \
  -f mode=disable \
  -f environment=staging

# Check status anytime
gh workflow run manage-load-testing.yml \
  -f mode=status \
  -f environment=staging
```

**Use when:** Running load tests that require temporarily increased capacity without permanently modifying config files.

---

## Infrastructure Workflows

### build-client-images.yml
**Trigger:** Manual, Push to specific paths

Builds Docker images for client applications.

### provision-client-infrastructure.yml
**Trigger:** Manual (`workflow_dispatch`)

Provisions new client infrastructure including:
- EC2 instances
- Networking
- Security groups
- IAM roles

### setup-backend-dns.yml
**Trigger:** Manual (`workflow_dispatch`)

Configures DNS records for backend services in Route 53.

### setup-client-dns-ssl.yml
**Trigger:** Manual (`workflow_dispatch`)

Configures client DNS and SSL certificates:
- Route 53 records
- Let's Encrypt SSL via Certbot

### setup-invpc-acm-ssl.yml
**Trigger:** Manual (`workflow_dispatch`)

Configures in-VPC SSL using AWS Certificate Manager:
- ACM certificate provisioning
- ALB HTTPS listener configuration
- Certificate validation

---

## Documentation Workflows

### update-documentation.yml
**Trigger:** Push to main (docs paths)

Automatically updates documentation when changes are pushed.

---

## Workflow Relationships

```
New Deployment:
  deploy-platform.yml → (creates stack)
                      → setup-invpc-acm-ssl.yml (optional SSL)
                      → setup-backend-dns.yml (optional DNS)

Code Updates:
  build.yml → deploy-application.yml

Infrastructure Updates:
  update-stack.yml (template changes, preserves params)
  deploy-infrastructure.yml (targeted infra changes)

Load Testing:
  manage-load-testing.yml (enable) → run tests → manage-load-testing.yml (disable)

Client Onboarding:
  provision-client-infrastructure.yml
    → build-client-images.yml
    → deploy-clients.yml
    → setup-client-dns-ssl.yml
```

---

## Environment Matrix

| Environment | Region | Account | Approval Required |
|-------------|--------|---------|-------------------|
| staging | ap-south-1 | 686831565523 | No |
| staging-healthcare-india | ap-south-1 | 686831565523 | No |
| production | us-east-1 | 686831565523 | Yes |
| production-us | us-east-1 | 686831565523 | Yes |
| production-healthcare-us | us-east-1 | 686831565523 | Yes |
| production-banking-india | ap-south-1 | 686831565523 | Yes |
