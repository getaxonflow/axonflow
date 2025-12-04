# AxonFlow Deployment Guide

## Overview

This guide covers deploying AxonFlow to your infrastructure using the world-class deployment system built with configuration-driven automation, comprehensive health checks, and automatic rollback.

## Documentation Index

**Quick Links:**
- [Cost Analysis](COST_ANALYSIS.md) - ECS Fargate cost breakdown and optimization strategies
- [Implementation Roadmap](IMPLEMENTATION_ROADMAP.md) - 6-week deployment plan with HA testing
- [Configuration Reference](#configuration-reference) - Environment and account configuration
- [Deployment Scripts](#deployment-scripts) - Script usage and workflows
- [Operations Runbook](RUNBOOK.md) - Day-to-day operations and troubleshooting

## Prerequisites

### Required Tools

- **AWS CLI** v2.x or later
- **Docker** 20.x or later
- **yq** v4.x or later (YAML processor)
- **Git** 2.x or later
- **Bash** 3.x or later (macOS compatible)

### Installation

```bash
# macOS
brew install awscli docker yq git

# Ubuntu/Debian
sudo apt-get install awscli docker.io yq git

# Verify installations
aws --version
docker --version
yq --version
git --version
```

### AWS Credentials

Configure AWS credentials for your target account:

```bash
# Configure default profile (internal account)
aws configure

# Or configure specific profile
aws configure --profile marketplace
```

## Quick Start

### 1. Build and Push Images

Build Docker images and push to ECR:

```bash
./scripts/deployment/build-and-push.sh --environment staging
```

### 2. Deploy

Deploy to your environment:

```bash
./scripts/deployment/deploy.sh --environment staging
```

### 3. Monitor

Monitor deployment progress:

```bash
./scripts/deployment/monitor.sh --environment staging --watch
```

## Deployment Environments

### Staging Environment

**Purpose:** Internal testing and validation

**Configuration:** `config/environments/staging.yaml`

**Resources:**
- Agent replicas: 2
- Orchestrator replicas: 2
- AWS Account: 686831565523 (internal)
- Region: eu-central-1

**Usage:**
```bash
./scripts/deployment/build-and-push.sh --environment staging
./scripts/deployment/deploy.sh --environment staging
```

### Production Environment

**Purpose:** Production workloads

**Configuration:** `config/environments/production.yaml`

**Resources:**
- Agent replicas: 10
- Orchestrator replicas: 5
- AWS Account: 686831565523 (internal)
- Region: eu-central-1

**Usage:**
```bash
./scripts/deployment/build-and-push.sh --environment production --version v1.0.12
./scripts/deployment/deploy.sh --environment production --version v1.0.12
```

### Marketplace Test Environment

**Purpose:** AWS Marketplace testing

**Configuration:** `config/environments/marketplace-test.yaml`

**Resources:**
- AWS Account: 709825985650 (marketplace)
- Region: us-east-1 (AWS Marketplace requirement)

**Usage:**
```bash
# Switch to marketplace AWS profile
export AWS_PROFILE=marketplace

./scripts/deployment/build-and-push.sh --environment marketplace-test
./scripts/deployment/deploy.sh --environment marketplace-test
```

## Deployment Scripts

### build-and-push.sh

Build Docker images and push to ECR.

**Usage:**
```bash
./scripts/deployment/build-and-push.sh --environment <env> [OPTIONS]
```

**Options:**
- `--environment, -e <env>` - Environment to build for (required)
- `--version, -v <tag>` - Image version/tag (default: git hash)
- `--component, -c <name>` - Component to build (agent, orchestrator, dashboard, all)
- `--skip-build` - Skip building images (push only)
- `--skip-push` - Skip pushing images (build only)
- `--cleanup` - Clean up old Docker images after push

**Examples:**
```bash
# Build and push all components
./scripts/deployment/build-and-push.sh --environment staging

# Build specific component
./scripts/deployment/build-and-push.sh --environment staging --component agent

# Build without pushing
./scripts/deployment/build-and-push.sh --environment staging --skip-push

# Push existing images
./scripts/deployment/build-and-push.sh --environment staging --skip-build
```

### deploy.sh

Deploy AxonFlow infrastructure to AWS.

**Usage:**
```bash
./scripts/deployment/deploy.sh --environment <env> [OPTIONS]
```

**Options:**
- `--environment, -e <env>` - Environment to deploy to (required)
- `--version, -v <tag>` - Image version/tag (default: auto-detect)
- `--dry-run` - Validate configuration without deploying

**Examples:**
```bash
# Deploy to staging
./scripts/deployment/deploy.sh --environment staging

# Deploy specific version to production
./scripts/deployment/deploy.sh --environment production --version v1.0.12

# Validate configuration
./scripts/deployment/deploy.sh --environment staging --dry-run
```

### monitor.sh

Monitor deployment progress and health.

**Usage:**
```bash
./scripts/deployment/monitor.sh --environment <env> [OPTIONS]
```

**Options:**
- `--environment, -e <env>` - Environment to monitor (required)
- `--stack <name>` - Stack name to monitor (default: latest)
- `--watch, -w` - Watch mode (auto-refresh)
- `--interval, -i <seconds>` - Refresh interval (default: 30)

**Examples:**
```bash
# Monitor latest deployment
./scripts/deployment/monitor.sh --environment staging

# Watch mode with auto-refresh
./scripts/deployment/monitor.sh --environment staging --watch

# Custom refresh interval
./scripts/deployment/monitor.sh --environment staging --watch --interval 10
```

### rolling-deploy.sh

Deploy to multiple instances with rolling updates.

**Usage:**
```bash
./scripts/deployment/rolling-deploy.sh --environment <env> --component <name> --version <tag> [OPTIONS]
```

**Options:**
- `--environment, -e <env>` - Environment to deploy to (required)
- `--component, -c <name>` - Component to deploy (required)
- `--version, -v <tag>` - Image version/tag (required)
- `--type, -t <type>` - Deployment type (rolling, canary, blue-green)
- `--canary-percent <n>` - Canary percentage (default: 10)
- `--health-interval <sec>` - Health check interval (default: 30)

**Examples:**
```bash
# Rolling deployment
./scripts/deployment/rolling-deploy.sh --environment staging --component agent --version v1.0.12

# Canary deployment
./scripts/deployment/rolling-deploy.sh --environment production --component agent --version v1.0.12 --type canary

# Blue-green deployment
./scripts/deployment/rolling-deploy.sh --environment production --component orchestrator --version v1.0.12 --type blue-green
```

## Deployment Workflows

### Standard Deployment Workflow

```
1. Build and Push
   └─> build-and-push.sh --environment staging

2. Deploy
   └─> deploy.sh --environment staging

3. Monitor
   └─> monitor.sh --environment staging --watch

4. Verify Health
   └─> Automated health checks run
   └─> Manual verification if needed

5. (If Failure) Rollback
   └─> Automatic rollback triggers
   └─> Or manual: source lib/rollback.sh && auto_rollback staging <stack>
```

### Rolling Deployment Workflow

```
1. Build and Push
   └─> build-and-push.sh --environment production

2. Rolling Deploy
   └─> rolling-deploy.sh --environment production --component agent --version v1.0.12

3. Monitor Progress
   └─> Deployment proceeds instance by instance
   └─> Health checks between each instance

4. Verify Complete
   └─> All instances updated
   └─> All health checks passing
```

### Canary Deployment Workflow

```
1. Build and Push
   └─> build-and-push.sh --environment production --version v1.0.12

2. Canary Deploy (10% of instances)
   └─> rolling-deploy.sh --environment production --component agent --version v1.0.12 --type canary

3. Monitor Metrics
   └─> Watch latency, error rates
   └─> Compare to baseline

4. Full Rollout (if canary successful)
   └─> rolling-deploy.sh --environment production --component agent --version v1.0.12
```

## Configuration

### Environment Configuration

Location: `config/environments/<environment>.yaml`

**Structure:**
```yaml
name: staging
description: Internal testing environment
account: internal
region: eu-central-1

deployment:
  type: ecs-fargate  # or ec2-multi-instance
  stack_name_prefix: axonflow-staging
  vpc:
    id: vpc-xxx
    public_subnets: [subnet-xxx, subnet-yyy]
    private_subnets: [subnet-aaa, subnet-bbb]
  pricing_tier: Professional
  load_balancer:
    scheme: internal
  create_vpc_endpoints: true

containers:
  registry_account: "686831565523"
  registry_region: eu-central-1
  registry_prefix: axonflow-test
  image_tag_strategy: git-hash  # or semantic-version
  agent:
    replicas: 2
  orchestrator:
    replicas: 2

license:
  key: AXON-ENT-xxx-xxx-xxx
```

### Account Configuration

Location: `config/accounts/<account>.yaml`

**Structure:**
```yaml
name: internal
account_id: "686831565523"
description: Internal AxonFlow testing and development
default_region: eu-central-1

ecr:
  test_registry:
    name: axonflow-test
    full_uri: 686831565523.dkr.ecr.eu-central-1.amazonaws.com/axonflow-test
  prod_registry:
    name: axonflow-prod
    full_uri: 686831565523.dkr.ecr.eu-central-1.amazonaws.com/axonflow-prod

vpcs:
  default:
    id: vpc-xxx
    public_subnets: [subnet-xxx, subnet-yyy]
    private_subnets: [subnet-aaa, subnet-bbb]

aws_profile: default
```

## Health Checks

### Automated Health Checks

The deployment system performs comprehensive health checks:

1. **CloudFormation Stack Status**
   - Stack creation/update complete
   - No failed resources

2. **RDS Database**
   - Database available
   - Endpoint accessible

3. **Application Load Balancer**
   - ALB active
   - Target groups healthy

4. **ECS Services**
   - Running count matches desired count
   - All tasks healthy
   - No deployment failures

### Manual Health Verification

```bash
# Check comprehensive health
source scripts/deployment/lib/health.sh
source scripts/deployment/lib/config-parser.sh

load_environment_config staging
load_account_config $(env_config '.account')

comprehensive_health_check "axonflow-staging-20251112-153045"
```

## Rollback

### Automatic Rollback

Rollback triggers automatically on:
- CloudFormation stack creation failure
- CloudFormation stack update failure
- Health check failure after deployment
- ECS service deployment failure

### Manual Rollback

```bash
# Source rollback library
source scripts/deployment/lib/rollback.sh
source scripts/deployment/lib/config-parser.sh

# Load configuration
load_environment_config production
load_account_config $(env_config '.account')

# Execute rollback
auto_rollback production "axonflow-production-20251112-153045"
```

### List Rollback Points

```bash
source scripts/deployment/lib/rollback.sh
list_rollback_points production
```

## Troubleshooting

### Deployment Failed

**Check logs:**
```bash
./scripts/deployment/monitor.sh --environment staging
```

**Check CloudFormation events:**
```bash
aws cloudformation describe-stack-events \
  --stack-name <stack-name> \
  --region eu-central-1
```

**Check ECS service:**
```bash
source scripts/deployment/lib/health.sh
check_ecs_service_health "<stack-name>" "agent-service"
```

### Images Not Found in ECR

**Verify image was pushed:**
```bash
source scripts/deployment/lib/push.sh
list_ecr_images agent 20
```

**Rebuild and push:**
```bash
./scripts/deployment/build-and-push.sh --environment staging
```

### Account Mismatch

**Error:** "Account mismatch detected"

**Solution:** Configure correct AWS credentials
```bash
export AWS_PROFILE=marketplace
# Or
aws configure --profile marketplace
```

### Health Checks Failing

**Check service status:**
```bash
source scripts/deployment/lib/health.sh
comprehensive_health_check "<stack-name>"
```

**Check logs:**
```bash
aws logs tail /ecs/<stack-name>/agent --follow --region eu-central-1
```

## Best Practices

### Version Tagging

**Development:**
- Use git hash: Auto-detected by deployment scripts
- Example: `09e1f57`

**Production:**
- Use semantic versioning: `--version v1.0.12`
- Tag releases in git: `git tag v1.0.12`

### Deployment Safety

1. **Always deploy to staging first**
   ```bash
   ./scripts/deployment/deploy.sh --environment staging
   ```

2. **Test thoroughly in staging**
   - Run smoke tests
   - Verify all features
   - Check logs for errors

3. **Use dry-run to validate configuration**
   ```bash
   ./scripts/deployment/deploy.sh --environment production --dry-run
   ```

4. **Monitor production deployment**
   ```bash
   ./scripts/deployment/monitor.sh --environment production --watch
   ```

### Rollback Strategy

- **Automatic rollback enabled by default**
- Rollback state saved before every deployment
- 30-day rollback history maintained
- Manual rollback available if needed

## CI/CD Integration

### GitLab CI/CD

Pipeline configuration: `.gitlab-ci.yml`

**Stages:**
1. Validate (syntax, YAML)
2. Build (Docker images)
3. Test (unit, integration)
4. Deploy Staging (automatic on main)
5. Deploy Production (manual approval)

**Usage:**
```bash
# Push to main branch triggers staging deployment
git push origin main

# Create tag for production deployment
git tag v1.0.12
git push origin v1.0.12

# Manual approval required for production
```

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review deployment logs
3. Check CloudFormation events
4. Contact DevOps team

## Additional Resources

- **Technical Documentation:** `technical-docs/`
- **Architecture Overview:** `technical-docs/DEPLOYMENT_SCRIPTS_REFERENCE.md`
- **AWS Accounts:** `technical-docs/AWS_ACCOUNT_ARCHITECTURE.md`
- **Principles:** `.claude/principles.md`
