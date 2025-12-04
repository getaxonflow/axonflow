# GitHub Actions Workflows

This document describes all GitHub Actions workflows in the AxonFlow repository.

## Quick Reference

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| [build.yml](#buildyml) | Push/PR | Build and test all components |
| [test.yml](#testyml) | Push/PR | Run test suites |
| [lint.yml](#lintyml) | Push/PR | Code linting |
| [commit-lint.yml](#commit-lintyml) | PR | Validate commit messages |
| [security.yml](#securityyml) | Push/PR/Schedule | Security scanning |
| [release.yml](#releaseyml) | Push tag | Create releases |
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
**Trigger:** Push to any branch, Pull Requests

Builds all AxonFlow components:
- Backend services (Go)
- Frontend applications (Node.js)
- Docker images
- Runs unit tests

### test.yml
**Trigger:** Push to any branch, Pull Requests

Runs comprehensive test suites:
- Unit tests
- Integration tests
- End-to-end tests

### lint.yml
**Trigger:** Push to any branch, Pull Requests

Code quality checks:
- Go linting (golangci-lint)
- TypeScript/JavaScript linting (ESLint)
- Formatting validation

### commit-lint.yml
**Trigger:** Pull Requests

Validates commit messages follow conventional commit format.

### security.yml
**Trigger:** Push, Pull Requests, Scheduled (daily)

Security scanning:
- Dependency vulnerability scanning
- Secret detection
- SAST analysis

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
