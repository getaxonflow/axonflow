# AWS Marketplace Metering - Customer FAQ

**Last Updated:** November 11, 2025

---

## Billing & Pricing

### Q: How am I billed for AxonFlow?

**A:** AxonFlow uses a simple, transparent **node-hour** pricing model.

- **Node:** A container processing AI requests
- **Hour:** Billing calculated hourly (prorated to the minute)
- **Automatic:** Metered and billed through AWS Marketplace

**Example:**
- Running 5 nodes for 1 full hour = 5 node-hours
- Running 10 nodes for 30 minutes = 5 node-hours (10 × 0.5)

### Q: What are the pricing tiers?

**A:** AxonFlow offers three pricing tiers:

| Tier | Price per Node-Hour | Best For |
|------|---------------------|----------|
| **Professional** | $0.10 | Small teams (< 10 nodes) |
| **Enterprise** | $0.08 | Medium teams (10-50 nodes) |
| **Enterprise Plus** | $0.06 | Large teams (50+ nodes) |

**Volume discounts available** - contact sales@getaxonflow.com

### Q: How much will I pay per month?

**A:** Your monthly cost depends on how many nodes you run and for how long.

**Example Scenarios:**

**Constant 5 nodes (Professional tier):**
```
5 nodes × 24 hours/day × 30 days = 3,600 node-hours/month
3,600 × $0.10 = $360/month
```

**Peak scaling (Professional tier):**
```
Business hours (10 nodes): 10 × 10 hours × 22 weekdays = 2,200 node-hours
Off-hours (2 nodes): 2 × 14 hours × 22 weekdays = 616 node-hours
Weekends (2 nodes): 2 × 24 hours × 8 days = 384 node-hours

Total: 3,200 node-hours × $0.10 = $320/month
```

**Cost savings tip:** Scale down nodes during off-peak hours to reduce costs.

### Q: When am I billed?

**A:** Billing works through AWS Marketplace:

1. **Hourly metering:** AxonFlow reports usage every hour
2. **AWS aggregation:** AWS Marketplace aggregates your usage
3. **Monthly invoice:** You receive one consolidated AWS bill
4. **Payment:** Same as your other AWS services (no separate payment)

**Billing appears on your regular AWS invoice** under "AWS Marketplace Subscriptions"

### Q: Can I see my usage in real-time?

**A:** Yes! View your usage in two places:

**1. AWS Marketplace Console:**
- Go to: AWS Console → AWS Marketplace → Manage Subscriptions
- Select: AxonFlow AI Governance Platform
- View: Current month usage, cost estimates

**2. AxonFlow Dashboard:** (Coming Q1 2026)
- Real-time node count
- Hourly usage trends
- Cost projections
- Budget alerts

### Q: Are there any hidden fees?

**A:** No. You only pay for:
- ✅ AxonFlow node-hours (metered usage)
- ✅ AWS infrastructure (EC2, RDS, ALB - standard AWS pricing)

**NOT included in AxonFlow pricing** (billed separately by AWS):
- Compute: ECS Fargate tasks
- Database: RDS PostgreSQL
- Networking: Load Balancer, NAT Gateway
- Storage: EBS volumes, S3 buckets

**Tip:** Use AWS Cost Explorer to see complete breakdown.

---

## How Metering Works

### Q: What exactly is being metered?

**A:** AxonFlow meters **active nodes** (containers processing AI requests).

**Active node = A container that:**
- ✅ Is running and healthy
- ✅ Has sent a heartbeat in the last 5 minutes
- ✅ Is ready to process AI requests

**Inactive nodes (NOT metered):**
- ❌ Stopped containers
- ❌ Containers in failed state
- ❌ Containers without recent heartbeat

### Q: How often is metering performed?

**A:** **Every hour, on the hour** (00:00, 01:00, 02:00, etc.)

**Example Timeline:**
```
15:00 - Metering runs → 5 active nodes → Billed for 5 node-hours
16:00 - Metering runs → 3 active nodes → Billed for 3 node-hours
17:00 - Metering runs → 8 active nodes → Billed for 8 node-hours

Total billed: 16 node-hours (5 + 3 + 8)
```

**Important:** Metering is **automatic** - you don't need to do anything.

### Q: What happens if I scale up/down mid-hour?

**A:** Metering captures the **current state at the top of each hour**.

**Example:**
```
14:00 - Metering runs → 5 nodes → Billed 5 node-hours
14:30 - You scale up to 10 nodes
15:00 - Metering runs → 10 nodes → Billed 10 node-hours

Result: You're billed for 5 node-hours (14:00-15:00) and 10 node-hours (15:00-16:00)
```

**Tip:** For cost optimization, scale changes at the top of the hour (00 minutes).

### Q: Can I verify the metered usage?

**A:** Yes! Metering is transparent and verifiable:

**1. Database Query** (if you have database access):
```sql
SELECT
    DATE(timestamp) as day,
    SUM(quantity) as total_node_hours,
    ROUND(SUM(quantity) * 0.10, 2) as estimated_cost_usd
FROM marketplace_usage_records
WHERE timestamp >= DATE_TRUNC('month', NOW())
GROUP BY DATE(timestamp)
ORDER BY day DESC;
```

**2. AWS Marketplace Console:**
- View detailed usage reports
- Download CSV exports
- Compare with your node deployment logs

**3. CloudWatch Logs:**
- Metering events logged every hour
- Search for: "Metered X nodes"

### Q: What if metering fails?

**A:** AxonFlow has built-in reliability:

**Automatic Retry:**
- 5 retry attempts with exponential backoff
- Retries queued if all attempts fail
- Automatic retry every 24 hours

**You're protected:**
- ❌ Failed metering = NO charge to you
- ✅ Only successful metering records are billed
- ✅ Failed records are retried automatically

**Customer impact:** None! Metering failures are handled transparently.

---

## Data Privacy & Security

### Q: What data does metering collect?

**A:** Metering collects **ONLY operational data** - no customer content.

**Collected:**
- ✅ Number of active nodes (e.g., "5 nodes")
- ✅ Timestamp (e.g., "2025-11-11 15:00 UTC")
- ✅ AWS request ID (for billing reconciliation)

**NOT Collected:**
- ❌ Customer data or content
- ❌ API request payloads
- ❌ User information
- ❌ Personally Identifiable Information (PII)
- ❌ Business logic or workflows

**GDPR Compliance:** Metering data contains **zero PII** - fully compliant.

### Q: Is my data secure?

**A:** Yes. Metering uses industry-standard security:

**In Transit:**
- ✅ TLS 1.3 encryption (HTTPS)
- ✅ AWS PrivateLink (VPC endpoint)
- ✅ No internet exposure

**At Rest:**
- ✅ Encrypted database (RDS encryption)
- ✅ Encrypted backups
- ✅ 90-day retention (compliance)

**Access Control:**
- ✅ IAM roles (least privilege)
- ✅ VPC isolation
- ✅ Audit logging (CloudTrail)

**Certifications:**
- SOC 2 Type II compliant
- HIPAA eligible
- GDPR compliant

### Q: Can I opt out of metering?

**A:** No - metering is required for AWS Marketplace billing.

**Why metering is required:**
1. **Accurate billing:** Only pay for what you use
2. **Transparency:** Verify usage at any time
3. **AWS requirement:** All marketplace products must meter usage

**Alternative:** Use self-hosted AxonFlow (contact sales@getaxonflow.com)

---

## Troubleshooting

### Q: I'm not seeing any charges. Is metering working?

**A:** If you're not being charged, check these items:

**1. Verify metering is enabled:**
```bash
# Check environment variables
aws ecs describe-task-definition \
  --task-definition axonflow-agent \
  --query 'taskDefinition.containerDefinitions[0].environment'

# Look for:
# ENABLE_MARKETPLACE_METERING=true
```

**2. Check agent logs:**
```bash
# Look for metering startup message
aws logs tail /ecs/axonflow-agent/agent --follow | grep -i metering

# Expected output:
# ✅ AWS Marketplace metering service started
# ✅ Metered 5 nodes to AWS Marketplace
```

**3. Verify active nodes:**
```bash
# Check if nodes are running
aws ecs list-tasks --cluster axonflow --desired-status RUNNING
```

**4. Check AWS Marketplace console:**
- Go to: AWS Console → Marketplace → Subscriptions
- Select: AxonFlow
- View: Usage records

**Still not seeing charges?**
- Contact AWS Support
- Or email: support@getaxonflow.com with your AWS account ID

### Q: My bill seems higher than expected. Why?

**A:** Higher bills usually have one of these causes:

**1. Node count misconfigured:**
```bash
# Check actual node count
aws ecs describe-service \
  --cluster axonflow \
  --service axonflow-agent-service \
  --query 'service.desiredCount'

# Compare with your expectation
```

**2. Auto-scaling enabled:**
- Check if ECS auto-scaling is configured
- Review scaling policies (CloudWatch alarms)
- Verify max node count setting

**3. Nodes not stopped:**
- Verify all dev/test environments are stopped
- Check for zombie containers

**4. Multiple deployments:**
- Ensure you're not running duplicate stacks
- Check all AWS regions (should only be in one)

**To reduce costs:**
- Scale down during off-hours
- Use smaller instance types (Fargate)
- Delete unused dev environments
- Enable auto-scaling to match demand

**Need help?** Email billing@getaxonflow.com with:
- AWS account ID
- Expected vs actual usage
- Time period in question

### Q: Metering failed. Will I still be charged?

**A:** **No - you're only charged for successful metering records.**

**What happens when metering fails:**
1. AxonFlow retries up to 5 times (automatic)
2. If all retries fail, record is marked FAILED
3. **FAILED records = NO charge**
4. AxonFlow retries again in 24 hours
5. If retry succeeds, you're billed for that hour

**Customer protection:**
- You're never double-billed
- Failed hours may not be billed (if retry also fails)
- AWS Marketplace prevents duplicate charges

**Check failed records:**
```sql
SELECT * FROM marketplace_usage_records WHERE status='FAILED';
```

**Contact support** if you see multiple consecutive failures.

---

## Features & Roadmap

### Q: Will metering affect performance?

**A:** **No** - metering has negligible performance impact.

**Technical details:**
- Runs in background goroutine (non-blocking)
- Executes only once per hour
- Database query takes < 50ms
- AWS API call takes < 200ms
- Total overhead: < 300ms per hour (0.008% of time)

**Your AI requests are NOT affected** - metering is completely independent.

### Q: What happens if my agent restarts?

**A:** **Metering resumes automatically** - no action needed.

**Restart sequence:**
1. Agent starts up
2. Metering service initializes (< 5 seconds)
3. Registers with AWS Marketplace
4. Resumes hourly metering

**Missed hours:**
- If agent was down during a metering cycle, that hour is NOT billed
- You only pay for hours when nodes were active
- No retroactive metering

**Example:**
```
14:00 - Metering succeeds → 5 nodes billed
14:30 - Agent crashes
14:45 - Agent restarts
15:00 - Metering succeeds → 5 nodes billed
```
**Result:** Billed for 14:00-15:00 and 15:00-16:00 (NOT billed for 15:00 hour since agent restarted mid-cycle)

### Q: Can I meter custom dimensions?

**A:** Not yet, but it's on the roadmap!

**Currently metered:**
- ✅ Active nodes (containers)

**Coming soon (Q2 2026):**
- ⏳ API calls per hour
- ⏳ LLM tokens consumed
- ⏳ Storage used (GB)
- ⏳ Custom metrics (via API)

**Enterprise customers:** Custom metering available now - contact sales@getaxonflow.com

### Q: Will you add real-time cost dashboards?

**A:** Yes! Planned for Q1 2026.

**Upcoming features:**
- Real-time node count graph
- Hourly cost breakdown
- Monthly cost projections
- Budget alerts (Slack, email, PagerDuty)
- Cost optimization recommendations
- Usage anomaly detection

**Early access:** Sign up at https://getaxonflow.com/beta

---

## Support

### Q: Who do I contact for billing issues?

**A:** Depends on the issue type:

**AWS Marketplace billing:**
- Contact: AWS Support
- Link: https://console.aws.amazon.com/support
- Covers: Invoice questions, payment issues, subscription management

**AxonFlow metering technical issues:**
- Contact: support@getaxonflow.com
- Response: < 24 hours (business days)
- Covers: Metering failures, usage discrepancies, configuration help

**Sales & pricing:**
- Contact: sales@getaxonflow.com
- Response: < 4 hours (business hours)
- Covers: Pricing tiers, volume discounts, custom contracts

### Q: Where can I see the metering source code?

**A:** AxonFlow metering is open-source!

**GitHub Repository:** https://github.com/getaxonflow/axonflow

**Key files:**
- `platform/agent/marketplace/metering.go` - Metering service
- `platform/agent/marketplace/metering_test.go` - Tests (66.7% coverage)
- `migrations/012_usage_metering.sql` - Database schema
- `technical-docs/AWS_MARKETPLACE_METERING.md` - Full technical docs

**Transparency:**
- ✅ Full source code available
- ✅ All metering logic visible
- ✅ Test coverage documented
- ✅ No hidden fees or logic

**Community:** Join our Slack at https://getaxonflow.com/slack

### Q: Can I get a usage report?

**A:** Yes! Multiple ways to get usage reports:

**1. AWS Marketplace Console:**
- Go to: AWS Console → Marketplace → Subscriptions → AxonFlow
- Download: Monthly usage CSV

**2. Database Query** (if you have access):
```sql
SELECT
    DATE(timestamp) as date,
    quantity as node_hours,
    status
FROM marketplace_usage_records
WHERE timestamp >= DATE_TRUNC('month', NOW())
ORDER BY date ASC;
```

**3. Email Request:**
- Send to: support@getaxonflow.com
- Include: AWS account ID, time period
- Receive: CSV export within 24 hours

**4. API** (Coming Q2 2026):
- RESTful API for usage data
- Webhook notifications
- Real-time metrics

---

## Additional Resources

**Documentation:**
- Technical Docs: `technical-docs/AWS_MARKETPLACE_METERING.md`
- Deployment Guide: `technical-docs/MARKETPLACE_DEPLOYMENT_CHECKLIST.md`
- Monitoring Queries: `/tmp/metering_monitoring_queries.sql`

**AWS Resources:**
- [AWS Marketplace Metering Service](https://docs.aws.amazon.com/marketplace/latest/userguide/metering-service.html)
- [Container Products on AWS Marketplace](https://docs.aws.amazon.com/marketplace/latest/userguide/container-products.html)

**AxonFlow Resources:**
- Website: https://getaxonflow.com
- Documentation: https://docs.getaxonflow.com
- Community: https://getaxonflow.com/slack
- Support: support@getaxonflow.com

---

**Have more questions?**

📧 **Email:** support@getaxonflow.com
💬 **Slack:** https://getaxonflow.com/slack
📞 **Sales:** +1 (555) 123-4567

**We're here to help!** Average response time < 24 hours.
