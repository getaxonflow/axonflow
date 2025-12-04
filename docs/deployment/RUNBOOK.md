# AxonFlow Operations Runbook

## Table of Contents

1. [Deployment Procedures](#deployment-procedures)
2. [Rollback Procedures](#rollback-procedures)
3. [Incident Response](#incident-response)
4. [Monitoring](#monitoring)
5. [Maintenance](#maintenance)
6. [Emergency Contacts](#emergency-contacts)

## Deployment Procedures

### Decoupled Deployments (ADR-006)

As of November 2025, AxonFlow uses a decoupled deployment architecture that separates:
- **Application Deployments** (2-5 minutes): Updates code only via ECS API
- **Infrastructure Deployments** (20-40 minutes): Full CloudFormation updates

#### When to Use Application-Only Deployment
- Bug fixes and patches
- Feature updates that don't require infrastructure changes
- Configuration changes within existing infrastructure
- Regular version updates

```bash
# Via GitHub Actions
gh workflow run deploy-application.yml \
  -f environment=production \
  -f region=eu-central-1 \
  -f services=all

# Via Customer Portal API
curl -X POST https://portal.example.com/api/v1/deployments/upgrade \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"service": "all", "force_new_deployment": true}'
```

#### When to Use Infrastructure Deployment
- New resource requirements (RDS instance size, new services)
- VPC/networking changes
- Security group modifications
- Initial deployments

```bash
# Full deployment (Infrastructure + Application)
gh workflow run deploy-platform.yml \
  -f environment=production
```

---

### Standard Production Deployment

**Prerequisites:**
- [ ] Code merged to main branch
- [ ] All tests passing in CI/CD
- [ ] Staging deployment successful
- [ ] Change approval obtained
- [ ] Deployment window scheduled

**Steps:**

1. **Pre-Deployment Checks** (15 minutes)
   ```bash
   # Verify current production health
   ./scripts/deployment/monitor.sh --environment production

   # Check rollback points available
   source scripts/deployment/lib/rollback.sh
   list_rollback_points production

   # Verify images exist in ECR
   source scripts/deployment/lib/push.sh
   list_ecr_images agent
   list_ecr_images orchestrator
   ```

2. **Build and Push** (10 minutes)
   ```bash
   # Build and push production images
   ./scripts/deployment/build-and-push.sh \
     --environment production \
     --version v1.0.12 \
     --cleanup

   # Verify images pushed
   source scripts/deployment/lib/push.sh
   list_ecr_images agent | grep v1.0.12
   list_ecr_images orchestrator | grep v1.0.12
   ```

3. **Deploy** (30 minutes)
   ```bash
   # Deploy to production
   ./scripts/deployment/deploy.sh \
     --environment production \
     --version v1.0.12

   # Note the stack name from output
   # Example: axonflow-production-20251112-153045
   ```

4. **Monitor Deployment** (30 minutes)
   ```bash
   # Watch deployment progress
   ./scripts/deployment/monitor.sh \
     --environment production \
     --watch \
     --interval 30

   # In separate terminal, tail logs
   STACK_NAME="axonflow-production-20251112-153045"
   aws logs tail /ecs/${STACK_NAME}/agent --follow --region eu-central-1
   ```

5. **Health Verification** (15 minutes)
   ```bash
   # Comprehensive health check
   source scripts/deployment/lib/health.sh
   source scripts/deployment/lib/config-parser.sh

   load_environment_config production
   load_account_config $(env_config '.account')

   comprehensive_health_check "axonflow-production-20251112-153045"

   # Expected output: ✅ All Health Checks Passed
   ```

6. **Smoke Tests** (15 minutes)
   ```bash
   # Get ALB DNS name
   aws cloudformation describe-stacks \
     --stack-name axonflow-production-20251112-153045 \
     --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerDNS`].OutputValue' \
     --output text

   # Test health endpoint
   curl -k https://<alb-dns>/health

   # Expected: {"status": "healthy"}
   ```

7. **Post-Deployment** (10 minutes)
   ```bash
   # Document deployment
   echo "Deployment: v1.0.12" >> /tmp/deployment-log.txt
   echo "Stack: axonflow-production-20251112-153045" >> /tmp/deployment-log.txt
   echo "Time: $(date)" >> /tmp/deployment-log.txt
   echo "Status: SUCCESS" >> /tmp/deployment-log.txt

   # Notify team
   echo "✅ Production deployment v1.0.12 complete"
   ```

**Total Time:** ~2 hours (including buffer)

**Success Criteria:**
- [ ] CloudFormation stack: CREATE_COMPLETE or UPDATE_COMPLETE
- [ ] All ECS services: Running count = Desired count
- [ ] RDS database: Available
- [ ] ALB: Active with healthy targets
- [ ] Health endpoints: Returning 200 OK
- [ ] Smoke tests: All passing
- [ ] Logs: No error spikes

---

### Rolling Deployment to EC2 Instances

**Use Case:** Deploying to multi-instance EC2 setup

**Steps:**

1. **Pre-Deployment**
   ```bash
   # Verify instances healthy
   source scripts/deployment/lib/multi-instance.sh
   source scripts/deployment/lib/config-parser.sh

   load_environment_config production
   INSTANCES=$(get_environment_instances)

   get_deployment_progress agent "$INSTANCES"
   ```

2. **Execute Rolling Deployment**
   ```bash
   ./scripts/deployment/rolling-deploy.sh \
     --environment production \
     --component agent \
     --version v1.0.12 \
     --type rolling \
     --health-interval 60
   ```

3. **Monitor Progress**
   - Watch script output for per-instance status
   - Automatic rollback triggers on failure
   - Health checks run between each instance

**Success Criteria:**
- [ ] All instances updated successfully
- [ ] All health checks passing
- [ ] No automatic rollbacks triggered

---

### Customer Portal Upgrade API

**Use Case:** Triggering deployments via Customer Portal API (for automated or self-service upgrades)

**Endpoints:**
```
POST /api/v1/deployments/upgrade        - Trigger upgrade
GET  /api/v1/deployments/upgrade/{id}   - Get upgrade status
GET  /api/v1/deployments/upgrades       - List upgrade history
GET  /api/v1/deployments/versions       - Get available versions
```

**Steps:**

1. **Authenticate and Get Session Token**
   ```bash
   # Login via Customer Portal
   TOKEN=$(curl -X POST https://portal.example.com/api/v1/auth/login \
     -d '{"email":"admin@company.com","password":"..."}' \
     -H "Content-Type: application/json" | jq -r '.token')
   ```

2. **Trigger Upgrade**
   ```bash
   # Upgrade all services
   curl -X POST https://portal.example.com/api/v1/deployments/upgrade \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "service": "all",
       "force_new_deployment": true
     }'

   # Upgrade single service
   curl -X POST https://portal.example.com/api/v1/deployments/upgrade \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "service": "agent",
       "force_new_deployment": false
     }'
   ```

3. **Monitor Upgrade Status**
   ```bash
   # Get upgrade status by ID
   UPGRADE_ID="upgrade-2025-1125-143000-abc123"
   curl https://portal.example.com/api/v1/deployments/upgrade/$UPGRADE_ID \
     -H "Authorization: Bearer $TOKEN"

   # Expected response:
   # {
   #   "success": true,
   #   "upgrade_id": "upgrade-2025-1125-143000-abc123",
   #   "status": "SUCCESS",
   #   "services": [
   #     {"service_name": "agent", "status": "SUCCESS", "desired_count": 2, "running_count": 2}
   #   ]
   # }
   ```

4. **View Upgrade History**
   ```bash
   curl "https://portal.example.com/api/v1/deployments/upgrades?page=1&page_size=10" \
     -H "Authorization: Bearer $TOKEN"
   ```

**Valid Service Values:**
- `agent` - AxonFlow Agent service
- `orchestrator` - AxonFlow Orchestrator service
- `customer-portal` - Customer Portal service
- `all` - All services

**Success Criteria:**
- [ ] Upgrade initiated (returns upgrade_id)
- [ ] All services reach RUNNING state
- [ ] Health endpoints return 200 OK
- [ ] Desired count = Running count

---

### Canary Deployment

**Use Case:** Testing new version on subset of production traffic

**Steps:**

1. **Deploy Canary (10% of instances)**
   ```bash
   ./scripts/deployment/rolling-deploy.sh \
     --environment production \
     --component agent \
     --version v1.0.13 \
     --type canary \
     --canary-percent 10
   ```

2. **Monitor Metrics** (1-2 hours)
   - Compare latency: Canary vs Baseline
   - Compare error rates: Canary vs Baseline
   - Monitor logs for anomalies

   ```bash
   # Check canary instance health
   source scripts/deployment/lib/multi-instance.sh
   check_instance_health <canary-instance-id> agent
   ```

3. **Decision Point**

   **If metrics good → Full rollout:**
   ```bash
   ./scripts/deployment/rolling-deploy.sh \
     --environment production \
     --component agent \
     --version v1.0.13 \
     --type rolling
   ```

   **If issues detected → Rollback canary:**
   ```bash
   # Rollback canary instances
   source scripts/deployment/lib/rollback.sh
   auto_rollback production ""
   ```

---

## Rollback Procedures

### Automatic Rollback

**Triggers:**
- CloudFormation stack creation failure
- Health check failure
- ECS service deployment failure

**Process:**
- Automatic rollback initiated
- Previous deployment state restored
- Notification sent

**Monitor automatic rollback:**
```bash
# Watch rollback progress
./scripts/deployment/monitor.sh --environment production --watch
```

---

### Manual Rollback

**Scenario:** Need to rollback due to discovered issue

**Steps:**

1. **Assess Situation** (5 minutes)
   ```bash
   # Check current deployment status
   ./scripts/deployment/monitor.sh --environment production

   # Review available rollback points
   source scripts/deployment/lib/rollback.sh
   list_rollback_points production
   ```

2. **Execute Rollback** (10 minutes)
   ```bash
   source scripts/deployment/lib/rollback.sh
   source scripts/deployment/lib/config-parser.sh

   load_environment_config production
   load_account_config $(env_config '.account')

   # Get current stack name
   STACK_NAME=$(cat /tmp/current-deployment-stack.txt)

   # Execute rollback
   auto_rollback production "$STACK_NAME"
   ```

3. **Verify Rollback** (15 minutes)
   ```bash
   # Check health after rollback
   comprehensive_health_check "$STACK_NAME"

   # Verify previous version running
   aws ecs describe-services \
     --cluster ${STACK_NAME}-cluster \
     --services ${STACK_NAME}-agent-service \
     --query 'services[0].taskDefinition' \
     --region eu-central-1
   ```

4. **Post-Rollback** (10 minutes)
   ```bash
   # Document rollback
   echo "Rollback executed" >> /tmp/deployment-log.txt
   echo "Reason: <reason>" >> /tmp/deployment-log.txt
   echo "Time: $(date)" >> /tmp/deployment-log.txt

   # Notify team
   echo "⚠️  Production rolled back - investigating issue"
   ```

**Total Time:** ~40 minutes

---

## Incident Response

### High Error Rate

**Severity:** P1 (Critical)

**Detection:**
- CloudWatch alarms triggered
- Error rate > 5%
- Customer reports

**Response:**

1. **Immediate Assessment** (2 minutes)
   ```bash
   # Check deployment status
   ./scripts/deployment/monitor.sh --environment production

   # Check logs for errors
   STACK_NAME=$(cat /tmp/current-deployment-stack.txt)
   aws logs tail /ecs/${STACK_NAME}/agent --since 5m --region eu-central-1 | grep ERROR
   ```

2. **Determine Cause** (5 minutes)
   - Recent deployment? → Consider rollback
   - Database issues? → Check RDS health
   - Downstream service issues? → Check integrations

3. **Mitigate** (10 minutes)

   **If recent deployment:**
   ```bash
   # Execute immediate rollback
   source scripts/deployment/lib/rollback.sh
   auto_rollback production "$STACK_NAME"
   ```

   **If infrastructure issue:**
   - Scale up resources if needed
   - Investigate root cause
   - Apply fix

4. **Verify Resolution** (5 minutes)
   ```bash
   # Check error rate normalized
   # Monitor logs for continued errors
   # Verify customer reports resolved
   ```

---

### Service Down

**Severity:** P0 (Critical)

**Detection:**
- All health checks failing
- ALB targets unhealthy
- Service unavailable

**Response:**

1. **Immediate Assessment** (1 minute)
   ```bash
   ./scripts/deployment/monitor.sh --environment production
   ```

2. **Check Infrastructure** (3 minutes)
   ```bash
   # CloudFormation
   aws cloudformation describe-stacks \
     --stack-name $STACK_NAME \
     --region eu-central-1 \
     --query 'Stacks[0].StackStatus'

   # ECS Services
   source scripts/deployment/lib/health.sh
   check_all_ecs_services "$STACK_NAME"

   # RDS
   check_rds_health "$STACK_NAME"
   ```

3. **Mitigate** (5 minutes)

   **If ECS services down:**
   ```bash
   # Force new deployment
   aws ecs update-service \
     --cluster ${STACK_NAME}-cluster \
     --service ${STACK_NAME}-agent-service \
     --force-new-deployment \
     --region eu-central-1
   ```

   **If database down:**
   ```bash
   # Check RDS status
   aws rds describe-db-instances \
     --db-instance-identifier ${STACK_NAME}-db \
     --region eu-central-1

   # If stopped, restart
   aws rds start-db-instance \
     --db-instance-identifier ${STACK_NAME}-db \
     --region eu-central-1
   ```

4. **Escalate if Needed**
   - Contact AWS support
   - Engage on-call engineer
   - Notify management

---

### Slow Response Times

**Severity:** P2 (High)

**Detection:**
- P95 latency > 100ms
- Customer complaints
- CloudWatch metrics

**Response:**

1. **Identify Bottleneck** (10 minutes)
   ```bash
   # Check database connections
   # Check ECS task count vs desired
   # Review CloudWatch metrics
   ```

2. **Scale Resources** (15 minutes)
   ```bash
   # Increase agent replicas
   aws ecs update-service \
     --cluster ${STACK_NAME}-cluster \
     --service ${STACK_NAME}-agent-service \
     --desired-count 15 \
     --region eu-central-1

   # Monitor improvement
   # Check latency metrics
   ```

3. **Investigate Root Cause**
   - Review recent changes
   - Check for resource constraints
   - Analyze slow queries

---

## Monitoring

### Key Metrics

**ECS Services:**
- Running task count
- Desired task count
- CPU utilization
- Memory utilization

**Database:**
- Connection count
- Query latency
- Disk utilization
- CPU utilization

**Load Balancer:**
- Request count
- Target response time
- Healthy target count
- 4xx/5xx errors

### Monitoring Commands

```bash
# Real-time monitoring
./scripts/deployment/monitor.sh --environment production --watch

# Health summary
source scripts/deployment/lib/health.sh
get_health_summary "$STACK_NAME"

# Deployment progress
source scripts/deployment/lib/multi-instance.sh
get_deployment_progress agent "$INSTANCES"
```

### CloudWatch Dashboards

**Location:** AWS Console → CloudWatch → Dashboards

**Key Dashboards:**
- **AxonFlow-Production-Overview:** High-level health metrics
- **AxonFlow-Production-Detailed:** Per-service metrics
- **AxonFlow-Database:** RDS metrics

---

## Maintenance

### Weekly Maintenance

**Schedule:** Every Sunday 02:00-04:00 UTC

**Tasks:**
1. Review rollback points, cleanup old states
2. Check disk usage on instances
3. Review logs for warnings
4. Update dependencies if needed

```bash
# Cleanup old rollback states
source scripts/deployment/lib/rollback.sh
cleanup_rollback_states production 30

# Cleanup old Docker images
./scripts/deployment/build-and-push.sh --environment production --cleanup
```

### Monthly Maintenance

**Tasks:**
1. Review and update security patches
2. Database maintenance (VACUUM, ANALYZE)
3. Review CloudWatch logs retention
4. Update deployment scripts if needed
5. Review and update documentation

---

## Emergency Contacts

**On-Call Engineer:** [Contact info]
**DevOps Lead:** [Contact info]
**AWS Support:** [Support plan details]

**Escalation Path:**
1. On-Call Engineer (0-15 minutes)
2. DevOps Lead (15-30 minutes)
3. CTO (30+ minutes, P0 only)

---

## Appendix

### Common Commands Reference

```bash
# Quick health check
./scripts/deployment/monitor.sh -e production

# Force rollback
source scripts/deployment/lib/rollback.sh && auto_rollback production "$STACK_NAME"

# Check logs
aws logs tail /ecs/${STACK_NAME}/agent --follow --region eu-central-1

# Scale service
aws ecs update-service --cluster ${STACK_NAME}-cluster --service ${STACK_NAME}-agent-service --desired-count 15 --region eu-central-1

# List rollback points
source scripts/deployment/lib/rollback.sh && list_rollback_points production
```

### Deployment Checklist

- [ ] Pre-deployment checks complete
- [ ] Build and push successful
- [ ] Deployment executed
- [ ] Health checks passing
- [ ] Smoke tests passing
- [ ] Monitoring active
- [ ] Team notified
- [ ] Documentation updated

### Rollback Checklist

- [ ] Issue identified and documented
- [ ] Rollback decision made
- [ ] Rollback executed
- [ ] Health verified post-rollback
- [ ] Team notified
- [ ] Incident report created
- [ ] Root cause analysis scheduled
