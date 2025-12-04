# AxonFlow 2-Environment Deployment Setup

**Created:** November 13, 2025
**Status:** Production-Ready
**Version:** 1.0

---

## Overview

AxonFlow supports 2 environments with clear separation and purpose:

| Environment | Purpose | Replicas | Resources | Cost |
|-------------|---------|----------|-----------|------|
| **Staging** | Testing new features | 2+2 | 512 CPU, 1GB RAM | ~$50/month |
| **Production** | Serving customers | 10+5 | 1024 CPU, 2GB RAM | ~$500/month |

Both environments use the **same ECR repositories** with different image tags for clear separation.

---

## Architecture

```
AWS Account: 686831565523 (Internal)
Region: eu-central-1

ECR Repositories (Shared):
├─ axonflow-agent
│  ├─ 1.0.12 (used by both environments)
│  ├─ d610ae1 (current production on central-1, central-2)
│  ├─ 0b5c593 (current on healthcare, ecommerce)
│  └─ marketplace-fixed (current on loadtest)
│
└─ axonflow-orchestrator
   ├─ 1.0.12
   ├─ marketplace-fixed
   └─ ...

Environments:
├─ Staging (config/environments/staging.yaml)
│  ├─ 2 agents (512 CPU, 1GB RAM)
│  ├─ 2 orchestrators (512 CPU, 1GB RAM)
│  ├─ db.t3.small, 20GB, single-AZ
│  └─ Internet-facing ALB (for testing)
│
└─ Production (config/environments/production.yaml)
   ├─ 10 agents (1024 CPU, 2GB RAM)
   ├─ 5 orchestrators (1024 CPU, 2GB RAM)
   ├─ db.t3.medium, 100GB, multi-AZ
   └─ Internal ALB (same-VPC only)
```

---

## Quick Start

### 1. Build Images for Staging

```bash
# Navigate to project root
cd /Users/saurabhjain/Development/axonflow

# Build agent for staging (uses git hash as tag)
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging

# Build orchestrator for staging
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment staging

# Result: Images tagged with git hash (e.g., abc1234)
```

### 2. Pre-Flight Validation

```bash
# Verify everything is ready before deployment
bash scripts/deployment/preflight-check.sh staging abc1234

# This checks:
# - AWS account matches config
# - ECR images exist and are pullable
# - VPC configuration is valid
# - CloudFormation template is valid
```

### 3. Deploy to Staging

```bash
bash scripts/deployment/deploy.sh --environment staging --version abc1234

# Monitor deployment
bash scripts/deployment/monitor.sh --environment staging --watch
```

### 4. Build and Deploy to Production

```bash
# Build with semantic version
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment production --tag v1.0.13

# Pre-flight check
bash scripts/deployment/preflight-check.sh production v1.0.13

# Deploy (requires manual approval in CI/CD)
bash scripts/deployment/deploy.sh --environment production --version v1.0.13
```

---

## Configuration Files

### Staging Configuration

**File:** `config/environments/staging.yaml`

```yaml
name: staging
description: Internal testing environment
account: internal
region: eu-central-1

deployment:
  type: ecs-fargate
  stack_name_prefix: axonflow-staging

  vpc:
    id: vpc-01421090ce66fa833
    public_subnets:
      - subnet-054d22ba89b9b7263
      - subnet-0ffd1b9596fe786eb

  load_balancer:
    scheme: internet-facing  # Testing access

  database:
    instance_class: db.t3.small
    allocated_storage: 20
    multi_az: false
    backup_retention_days: 3

containers:
  registry_account: "686831565523"
  registry_region: eu-central-1
  registry_prefix: ""  # Use base repository names

  agent:
    replicas: 2
    cpu: 512
    memory: 1024

  orchestrator:
    replicas: 2
    cpu: 512
    memory: 1024

monitoring:
  cloudwatch_logs_retention_days: 7
```

### Production Configuration

**File:** `config/environments/production.yaml`

```yaml
name: production
description: Production environment for customers
account: internal
region: eu-central-1

deployment:
  type: ecs-fargate
  stack_name_prefix: axonflow-production

  vpc:
    id: vpc-01421090ce66fa833
    public_subnets:
      - subnet-0b52b0df7e1078147
      - subnet-003f426e36e0dd74b
    private_subnets:
      - subnet-00e6cd460df819784
      - subnet-036b2741125fce3cc

  load_balancer:
    scheme: internal  # Same-VPC only

  database:
    instance_class: db.t3.medium
    allocated_storage: 100
    multi_az: true  # High availability
    backup_retention_days: 30

containers:
  registry_account: "686831565523"
  registry_region: eu-central-1
  registry_prefix: ""  # Use base repository names

  agent:
    replicas: 10
    cpu: 1024
    memory: 2048

  orchestrator:
    replicas: 5
    cpu: 1024
    memory: 2048

monitoring:
  cloudwatch_logs_retention_days: 90
```

---

## Image Tagging Strategy

### Current Strategy (Working in Production)

```
Git-based tags (development/testing):
  - 0b5c593 (deployed to healthcare, ecommerce)
  - d610ae1 (deployed to central-1, central-2)
  - abc1234 (new development builds)

Semantic versions (releases):
  - 1.0.12 (current release)
  - v1.0.13 (next release)

Descriptive tags (fixes/features):
  - marketplace-fixed (deployed to loadtest)
  - amadeus-fix
  - mcp-routing-fix
```

### Best Practices

1. **Staging:** Use git hash tags (transient, for testing)
2. **Production:** Use semantic versions (immutable, for releases)
3. **Hotfixes:** Use descriptive tags (clear purpose)

---

## Build Script Usage

### Basic Usage (Backward Compatible)

```bash
# Old way (still works) - uses git hash
bash scripts/multi-tenant/build-agent-ecr.sh

# Old way with custom tag
bash scripts/multi-tenant/build-agent-ecr.sh --tag my-custom-tag
```

### Environment-Aware Usage (New)

```bash
# Build for staging (reads config/environments/staging.yaml)
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging

# Build for production with semantic version
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13

# Both agent and orchestrator
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment staging
```

### What the Build Script Does

1. **Reads configuration** from `config/environments/{env}.yaml`
2. **Builds Docker image** with `--platform linux/amd64` (AWS requirement)
3. **Tags image** with specified tag (or git hash)
4. **Pushes to ECR** in configured account and region
5. **Verifies** image is accessible

---

## Pre-Flight Validation

**Purpose:** Catch configuration errors in 5 minutes vs 3-hour CloudFormation timeout

### What It Checks

1. ✅ Configuration file exists
2. ✅ AWS account matches config (prevents wrong account deployment)
3. ✅ ECR images exist for specified version
4. ✅ Images are pullable (tests permissions)
5. ✅ VPC configuration is valid
6. ✅ CloudFormation template is syntactically correct

### Usage

```bash
bash scripts/deployment/preflight-check.sh <environment> <version>

# Examples:
bash scripts/deployment/preflight-check.sh staging abc1234
bash scripts/deployment/preflight-check.sh production v1.0.13
```

### Example Output

```
[16:24:18] ===========================================
[16:24:18] Pre-Flight Validation
[16:24:18] ===========================================
[16:24:18] Environment: staging
[16:24:18] Version: 1.0.12
[16:24:18] ===========================================

[16:24:18] ✅ Configuration file exists
[16:24:18] ✅ AWS credentials valid (Account: 686831565523)
[16:24:19] ✅ Agent image exists: axonflow-agent:1.0.12
[16:24:20] ✅ Orchestrator image exists: axonflow-orchestrator:1.0.12
[16:24:22] ✅ Images are pullable
[16:24:26] ✅ VPC configuration valid
[16:24:26] ✅ CloudFormation template valid

[16:24:26] ✅ All pre-flight checks passed!
```

---

## Deployment Workflow

### Full Staging Deployment

```bash
# 1. Build images
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment staging
# Note the git hash tag (e.g., abc1234)

# 2. Pre-flight validation (5 minutes)
bash scripts/deployment/preflight-check.sh staging abc1234

# 3. Deploy (20-30 minutes)
bash scripts/deployment/deploy.sh --environment staging --version abc1234

# 4. Monitor deployment
bash scripts/deployment/monitor.sh --environment staging --watch

# 5. Verify health
bash scripts/deployment/lib/health.sh
check_ecs_health staging
```

### Full Production Deployment

```bash
# 1. Build with semantic version
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment production --tag v1.0.13

# 2. Pre-flight validation
bash scripts/deployment/preflight-check.sh production v1.0.13

# 3. Deploy (requires manual approval in CI/CD)
bash scripts/deployment/deploy.sh --environment production --version v1.0.13

# 4. Monitor deployment
bash scripts/deployment/monitor.sh --environment production --watch

# 5. Verify health
bash scripts/deployment/lib/health.sh
check_ecs_health production
```

---

## Platform Requirements

### Docker Build Platform

All images **MUST** be built with `--platform linux/amd64`:

```bash
docker build --platform linux/amd64 ...
```

**Why:**
- AWS ECS runs on AMD64 architecture
- M-series Macs are ARM64 by default
- Build scripts already handle this correctly

**Buildx Support:**
- ✅ Buildx is installed: `github.com/docker/buildx v0.25.0-desktop.1`
- ✅ Used automatically when `--platform` flag is specified
- ✅ No additional configuration needed

---

## AWS Account Architecture

### Internal Account (686831565523)

**Purpose:** Testing, demos, development
**Region:** eu-central-1 (primary)
**ECR Registry:** `686831565523.dkr.ecr.eu-central-1.amazonaws.com`

**What Lives Here:**
- All ECR repositories (axonflow-agent, axonflow-orchestrator, etc.)
- Central instances (63.178.85.84, 3.69.67.115)
- Demo clients (healthcare, ecommerce, support, travel)
- Customer portal infrastructure
- All test/dev stacks

### Marketplace Account (709825985650)

**Purpose:** AWS Marketplace container repository
**Region:** us-east-1 (AWS Marketplace requirement)
**ECR Registry:** `709825985650.dkr.ecr.us-east-1.amazonaws.com/axonflow`

**Important:**
- This is a **separate account** managed by AWS Marketplace
- Region MUST be `us-east-1` (not configurable)
- Used only for marketplace customer deployments
- See `technical-docs/AWS_ACCOUNT_ARCHITECTURE.md` for details

---

## Troubleshooting

### Image Not Found Error

```bash
❌ Agent image not found: axonflow-agent:1.0.13
```

**Solution:**
```bash
# Build the image first
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging --tag 1.0.13
```

### AWS Account Mismatch

```bash
❌ AWS account mismatch!
  Expected: 686831565523
  Current: 709825985650
```

**Solution:**
```bash
# Check your AWS credentials
aws configure list

# Verify active account
aws sts get-caller-identity

# See technical-docs/AWS_ACCOUNT_ARCHITECTURE.md
```

### VPC Not Found

```bash
❌ VPC not found: vpc-01421090ce66fa833
```

**Solution:**
```bash
# List available VPCs
aws ec2 describe-vpcs --region eu-central-1 --query 'Vpcs[*].[VpcId,CidrBlock]' --output table

# Update config/environments/{env}.yaml with correct VPC ID
```

### CloudFormation Stack Fails After 3 Hours

**Prevention:** Always run pre-flight validation first!

```bash
# Before deployment, ALWAYS run:
bash scripts/deployment/preflight-check.sh <environment> <version>

# This catches 90% of errors in 5 minutes vs 3-hour timeout
```

---

## Best Practices

### 1. Always Run Pre-Flight Validation

```bash
# NEVER skip this step
bash scripts/deployment/preflight-check.sh staging abc1234
```

**Saves:** 3 hours of CloudFormation timeout waiting

### 2. Use Environment-Aware Builds

```bash
# New way (config-driven)
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging

# Not: hardcoded values
```

### 3. Tag Production Releases Properly

```bash
# Production: Use semantic versions
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13

# Staging: Use git hashes (automatic)
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging
```

### 4. Monitor Deployments

```bash
# Don't just fire and forget
bash scripts/deployment/monitor.sh --environment staging --watch

# Check health after deployment
bash scripts/deployment/lib/health.sh
```

### 5. Read Documentation First

**Before any AWS operation:**
1. `technical-docs/AWS_ACCOUNT_ARCHITECTURE.md` - Account setup
2. `technical-docs/DEPLOYMENT_SCRIPTS_REFERENCE.md` - Script reference
3. `docs/deployment/RUNBOOK.md` - Operational procedures

---

## Related Documentation

- `technical-docs/AWS_ACCOUNT_ARCHITECTURE.md` - Two-account architecture
- `technical-docs/DEPLOYMENT_SCRIPTS_REFERENCE.md` - All deployment scripts
- `docs/deployment/README.md` - Complete deployment guide
- `docs/deployment/RUNBOOK.md` - Operational runbook
- `.claude/principles.md` - Development principles

---

## Change Log

| Date | Version | Changes |
|------|---------|---------|
| 2025-11-13 | 1.0 | Initial 2-environment setup documentation |
| 2025-11-12 | - | Phase 1 deployment infrastructure complete |

---

**This documentation reflects the actual production system as of November 13, 2025.**
