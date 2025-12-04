# AxonFlow Deployment - Quick Reference

**For detailed information, see:** `docs/deployment/2_ENVIRONMENT_SETUP.md`

---

## Staging Deployment (One-Liner)

```bash
# Build, validate, deploy
cd /Users/saurabhjain/Development/axonflow && \
bash scripts/multi-tenant/build-agent-ecr.sh --environment staging && \
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment staging && \
TAG=$(git rev-parse --short HEAD) && \
bash scripts/deployment/preflight-check.sh staging $TAG && \
bash scripts/deployment/deploy.sh --environment staging --version $TAG
```

## Production Deployment (Manual Steps)

```bash
# 1. Build with version
bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13
bash scripts/multi-tenant/build-orchestrator-ecr.sh --environment production --tag v1.0.13

# 2. Validate
bash scripts/deployment/preflight-check.sh production v1.0.13

# 3. Deploy (requires approval)
bash scripts/deployment/deploy.sh --environment production --version v1.0.13
```

---

## Common Commands

| Task | Command |
|------|---------|
| **Build for staging** | `bash scripts/multi-tenant/build-agent-ecr.sh --environment staging` |
| **Build for production** | `bash scripts/multi-tenant/build-agent-ecr.sh --environment production --tag v1.0.13` |
| **Pre-flight check** | `bash scripts/deployment/preflight-check.sh staging abc1234` |
| **Deploy** | `bash scripts/deployment/deploy.sh --environment staging --version abc1234` |
| **Monitor** | `bash scripts/deployment/monitor.sh --environment staging --watch` |
| **Check health** | `source scripts/deployment/lib/health.sh && check_ecs_health staging` |
| **Rollback** | `source scripts/deployment/lib/rollback.sh && auto_rollback staging stack-name` |

---

## Environment Comparison

| Aspect | Staging | Production |
|--------|---------|------------|
| **Replicas** | 2 agents, 2 orch | 10 agents, 5 orch |
| **CPU/Memory** | 512/1024 | 1024/2048 |
| **Database** | t3.small, single-AZ | t3.medium, multi-AZ |
| **Load Balancer** | Internet-facing | Internal |
| **Logs** | 7 days | 90 days |
| **Tagging** | Git hash | Semantic version |
| **Cost** | ~$50/month | ~$500/month |

---

## Troubleshooting (Quick Fixes)

| Error | Quick Fix |
|-------|-----------|
| **Image not found** | `bash scripts/multi-tenant/build-agent-ecr.sh --environment staging --tag <version>` |
| **AWS account mismatch** | Check: `aws sts get-caller-identity` - See `AWS_ACCOUNT_ARCHITECTURE.md` |
| **VPC not found** | Verify VPC ID in `config/environments/{env}.yaml` |
| **Stack timeout** | **Always run pre-flight first!** `bash scripts/deployment/preflight-check.sh` |

---

## Pre-Flight Validation (Always Run First!)

```bash
bash scripts/deployment/preflight-check.sh <environment> <version>
```

**Catches 90% of errors in 5 minutes vs 3-hour CloudFormation timeout**

---

## AWS Account Info

- **Internal (686831565523):** eu-central-1 - All testing/dev/production
- **Marketplace (709825985650):** us-east-1 only - AWS Marketplace only

**See:** `technical-docs/AWS_ACCOUNT_ARCHITECTURE.md`

---

## Help Commands

```bash
# Build script help
bash scripts/multi-tenant/build-agent-ecr.sh --help

# Deploy script help
bash scripts/deployment/deploy.sh --help

# Monitor script help
bash scripts/deployment/monitor.sh --help
```

---

**Full Documentation:** `docs/deployment/2_ENVIRONMENT_SETUP.md`
