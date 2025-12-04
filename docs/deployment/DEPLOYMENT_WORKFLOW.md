# AxonFlow Deployment Workflow - Complete Guide

**Version:** 1.0
**Date:** November 13, 2025
**Status:** Production-Ready

---

## Complete End-to-End Staging Deployment

### Step 1: Build Images (5 minutes)

```bash
cd /Users/saurabhjain/Development/axonflow

# Build agent for staging
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging

# Build orchestrator for staging
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment staging

# Note the git hash tag (e.g., 20d3b6c)
TAG=$(git rev-parse --short HEAD)
echo "Built images with tag: $TAG"
```

**What happens:**
- Reads config from `config/environments/staging.yaml`
- Builds with `--platform linux/amd64` (AWS requirement)
- Pushes to `686831565523.dkr.ecr.eu-central-1.amazonaws.com/axonflow-agent:$TAG`
- Pushes to `686831565523.dkr.ecr.eu-central-1.amazonaws.com/axonflow-orchestrator:$TAG`

### Step 2: Pre-Flight Validation (8 seconds)

```bash
bash scripts/deployment/preflight-check.sh staging $TAG
```

**What it validates:**
- ✅ Configuration file exists
- ✅ AWS account matches (686831565523)
- ✅ ECR images exist and are pullable
- ✅ VPC configuration is valid
- ✅ CloudFormation template is syntactically correct

**If any check fails:** Fix the issue before deploying (saves 3 hours!)

### Step 3: Dry-Run Deployment (10 seconds)

```bash
bash scripts/deployment/deploy.sh --environment staging --version $TAG --dry-run
```

**What it shows:**
- Stack name (timestamped)
- All CloudFormation parameters
- ECR registry URL
- Image tags
- Replica counts

**Review the parameters carefully!**

### Step 4: Actual Deployment (20-30 minutes)

```bash
bash scripts/deployment/deploy.sh --environment staging --version $TAG
```

**What happens:**
1. Loads configuration from `config/environments/staging.yaml`
2. Validates AWS account and region
3. Checks ECR access
4. Shows deployment summary
5. **Asks for confirmation** (type 'yes')
6. Creates CloudFormation stack
7. Saves stack name to `/tmp/current-deployment-stack.txt`

**CloudFormation creates:**
- VPC security groups
- Application Load Balancer (internet-facing)
- RDS PostgreSQL database (db.t3.small)
- ECS Fargate cluster
- 2 agent tasks (512 CPU, 1GB RAM)
- 2 orchestrator tasks (512 CPU, 1GB RAM)
- CloudWatch log groups (7-day retention)

### Step 5: Monitor Deployment (Real-time)

```bash
# Get stack name
STACK_NAME=$(cat /tmp/current-deployment-stack.txt)

# Watch stack events
aws cloudformation describe-stack-events \
    --stack-name $STACK_NAME \
    --region eu-central-1 \
    --query 'StackEvents[*].[Timestamp,ResourceStatus,ResourceType,ResourceStatusReason]' \
    --output table

# Or use the monitor script (if available)
bash scripts/deployment/monitor.sh --environment staging --watch
```

**Expected timeline:**
- 0-5 min: Creating VPC resources (security groups, subnets)
- 5-10 min: Creating RDS database
- 10-15 min: Creating ECS cluster and services
- 15-20 min: ECS tasks starting, pulling images
- 20-25 min: Tasks running, health checks passing
- 25-30 min: Stack CREATE_COMPLETE

### Step 6: Verify Health (2 minutes)

```bash
# Get stack outputs
aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --region eu-central-1 \
    --query 'Stacks[0].Outputs'

# Get load balancer URL
LB_URL=$(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --region eu-central-1 \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerURL`].OutputValue' \
    --output text)

# Test agent health
curl -k "https://${LB_URL}/agent/health"
# Expected: {"status":"healthy"}

# Test orchestrator health
curl -k "https://${LB_URL}/orchestrator/health"
# Expected: {"status":"healthy"}

# Check ECS service status
aws ecs describe-services \
    --cluster ${STACK_NAME}-ECSCluster \
    --services ${STACK_NAME}-agent-service ${STACK_NAME}-orchestrator-service \
    --region eu-central-1 \
    --query 'services[*].[serviceName,runningCount,desiredCount]' \
    --output table
# Expected: Both services show runningCount == desiredCount
```

---

## Complete End-to-End Production Deployment

### Step 1: Build Images with Semantic Version (5 minutes)

```bash
cd /Users/saurabhjain/Development/axonflow

# Choose semantic version
VERSION="v1.0.13"

# Build agent
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag $VERSION

# Build orchestrator
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment production --tag $VERSION
```

### Step 2: Pre-Flight Validation (8 seconds)

```bash
bash scripts/deployment/preflight-check.sh production $VERSION
```

### Step 3: Dry-Run Review (10 seconds)

```bash
bash scripts/deployment/deploy.sh --environment production --version $VERSION --dry-run
```

**Review carefully:**
- 10 agent replicas, 5 orchestrator replicas
- db.t3.medium, multi-AZ database
- Internal load balancer (not internet-facing)
- 90-day log retention

### Step 4: Production Deployment (30-40 minutes)

```bash
bash scripts/deployment/deploy.sh --environment production --version $VERSION
```

**Production considerations:**
- Larger resources (takes longer to provision)
- Multi-AZ database (additional setup time)
- More replicas (more tasks to start)

### Step 5: Monitor and Verify

Same as staging, but expect longer deployment time due to:
- Multi-AZ RDS database setup
- More ECS tasks to start and stabilize

---

## Rollback Procedure

### If Deployment Fails

```bash
STACK_NAME=$(cat /tmp/current-deployment-stack.txt)

# Check stack status
aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --region eu-central-1 \
    --query 'Stacks[0].[StackStatus,StackStatusReason]'

# If ROLLBACK_COMPLETE or CREATE_FAILED, delete stack
aws cloudformation delete-stack \
    --stack-name $STACK_NAME \
    --region eu-central-1

# Wait for deletion
aws cloudformation wait stack-delete-complete \
    --stack-name $STACK_NAME \
    --region eu-central-1

# Review failure reason
aws cloudformation describe-stack-events \
    --stack-name $STACK_NAME \
    --region eu-central-1 \
    --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]' \
    --output table
```

### Common Failure Reasons

1. **CannotPullContainerError**
   - Cause: ECR images don't exist or wrong tag
   - Fix: Run pre-flight validation, rebuild images
   - Prevention: Always run `preflight-check.sh` first

2. **VPC/Subnet Not Found**
   - Cause: Wrong VPC ID in config
   - Fix: Update `config/environments/{env}.yaml`
   - Prevention: Validate config before deployment

3. **Database Password Too Short**
   - Cause: DB password < 8 characters
   - Fix: Update password in deploy.sh
   - Prevention: Use strong passwords (12+ chars)

---

## Best Practices

### 1. Always Run Pre-Flight Validation

```bash
# NEVER skip this step
bash scripts/deployment/preflight-check.sh <environment> <version>
```

**Why:** Catches 90% of errors in 8 seconds vs 30-minute rollback

### 2. Test in Staging First

```bash
# Build and deploy to staging
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging
TAG=$(git rev-parse --short HEAD)
bash scripts/deployment/preflight-check.sh staging $TAG
bash scripts/deployment/deploy.sh --environment staging --version $TAG

# After successful staging deployment and testing, promote to production
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13
bash scripts/deployment/preflight-check.sh production v1.0.13
bash scripts/deployment/deploy.sh --environment production --version v1.0.13
```

### 3. Use Semantic Versioning for Production

```bash
# Staging: Git hashes (transient)
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging
# Creates: axonflow-agent:20d3b6c

# Production: Semantic versions (immutable)
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13
# Creates: axonflow-agent:v1.0.13
```

### 4. Save Stack Names for Reference

```bash
# Deployment automatically saves to /tmp/current-deployment-stack.txt
# For multiple environments, save separately:

STACK_NAME=$(cat /tmp/current-deployment-stack.txt)
echo "$STACK_NAME" > /tmp/staging-stack-$(date +%Y%m%d).txt
```

### 5. Monitor Deployment Progress

```bash
# Don't just fire and forget
# Watch the deployment:

STACK_NAME=$(cat /tmp/current-deployment-stack.txt)

# Real-time events
watch -n 5 "aws cloudformation describe-stack-events \
    --stack-name $STACK_NAME \
    --region eu-central-1 \
    --max-items 10 \
    --query 'StackEvents[*].[Timestamp,ResourceStatus,ResourceType]' \
    --output table"
```

---

## Troubleshooting

### Error: "AWS account mismatch"

```bash
# Check current account
aws sts get-caller-identity

# Expected: 686831565523
# If different, check your AWS credentials
aws configure list
```

### Error: "ECR images not found"

```bash
# Check if images exist
aws ecr describe-images \
    --repository-name axonflow-agent \
    --image-ids imageTag=1.0.12 \
    --region eu-central-1

# If not found, build them
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging --tag 1.0.12
```

### Error: "Stack creation timeout"

This shouldn't happen if you run pre-flight validation. If it does:

```bash
# Check stack events for failure reason
aws cloudformation describe-stack-events \
    --stack-name $STACK_NAME \
    --region eu-central-1 \
    --query 'StackEvents[?contains(ResourceStatus, `FAILED`)]' \
    --output table

# Common causes:
# 1. ECS tasks can't pull images (check ECR access)
# 2. RDS can't start (check subnet configuration)
# 3. Security group issues (check VPC configuration)
```

---

## Complete Workflow Summary

### Staging (Development/Testing)

```bash
# 1. Build
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment staging
TAG=$(git rev-parse --short HEAD)

# 2. Validate
bash scripts/deployment/preflight-check.sh staging $TAG

# 3. Dry-run
bash scripts/deployment/deploy.sh --environment staging --version $TAG --dry-run

# 4. Deploy
bash scripts/deployment/deploy.sh --environment staging --version $TAG

# 5. Monitor
STACK_NAME=$(cat /tmp/current-deployment-stack.txt)
aws cloudformation wait stack-create-complete --stack-name $STACK_NAME --region eu-central-1

# 6. Verify
LB_URL=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --region eu-central-1 \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerURL`].OutputValue' --output text)
curl -k "https://${LB_URL}/agent/health"
```

### Production (Customer-Facing)

```bash
# 1. Build with semantic version
VERSION="v1.0.13"
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag $VERSION
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment production --tag $VERSION

# 2. Validate
bash scripts/deployment/preflight-check.sh production $VERSION

# 3. Review dry-run carefully
bash scripts/deployment/deploy.sh --environment production --version $VERSION --dry-run

# 4. Deploy (with approval)
bash scripts/deployment/deploy.sh --environment production --version $VERSION

# 5. Monitor closely
STACK_NAME=$(cat /tmp/current-deployment-stack.txt)
watch -n 10 "aws cloudformation describe-stacks --stack-name $STACK_NAME --region eu-central-1 \
    --query 'Stacks[0].[StackStatus,Outputs]'"

# 6. Comprehensive verification
# Check all services, endpoints, health checks, logs
```

---

## Related Documentation

- **Quick Reference:** `docs/deployment/QUICK_REFERENCE.md`
- **Complete Setup Guide:** `docs/deployment/2_ENVIRONMENT_SETUP.md`
- **AWS Account Architecture:** `technical-docs/AWS_ACCOUNT_ARCHITECTURE.md`
- **Deployment Scripts Reference:** `technical-docs/DEPLOYMENT_SCRIPTS_REFERENCE.md`

---

**Last Updated:** November 13, 2025
**Tested With:** Staging environment, images 1.0.12
**Status:** Production-ready
