# AWS Bedrock Setup Guide

**For:** AxonFlow Enterprise Edition
**Purpose:** Configure AWS Bedrock as LLM provider for HIPAA-compliant deployments
**Audience:** DevOps engineers, system administrators

---

## Overview

AWS Bedrock provides serverless access to foundation models from leading AI providers (Anthropic, Meta, Amazon, Mistral) through a unified API. AxonFlow integrates with Bedrock using the new Provider interface (Phase 1) for enterprise customers requiring HIPAA compliance.

**Key Benefits:**
- ✅ HIPAA eligible when used with BAA
- ✅ No model hosting infrastructure required
- ✅ AWS-native security (IAM, VPC endpoints, encryption)
- ✅ Multiple model support (Claude, Titan, Llama, Mistral)
- ✅ Cost-effective pay-per-token pricing

---

## Prerequisites

### 1. AWS Account Requirements

- AWS account with Bedrock enabled
- Bedrock available in your region (us-east-1, us-west-2, eu-central-1, ap-southeast-1)
- IAM permissions to enable model access

### 2. Enable Bedrock Model Access

**IMPORTANT:** Models require one-time access approval.

**Steps:**
1. Open AWS Console → Bedrock → Model access
2. Click "Modify model access"
3. Select models to enable:
   - ✅ Anthropic Claude 3.5 Sonnet (recommended)
   - ✅ Anthropic Claude 3 Haiku (cost-effective)
   - ✅ Meta Llama 3 70B (open-source alternative)
   - ✅ Amazon Titan Text Express
4. Submit request (instant approval for most models)

**Verify access:**
```bash
aws bedrock list-foundation-models \
  --region us-east-1 \
  --query 'modelSummaries[?modelId==`anthropic.claude-3-5-sonnet-20240620-v1:0`]'
```

If you see model details, access is granted.

---

## Setup Methods

### Option 1: AWS Marketplace Deployment (Recommended)

**For customers deploying via AWS Marketplace CloudFormation.**

#### Step 1: Configure CloudFormation Parameters

When launching the AxonFlow stack, set:

```yaml
# Enable Bedrock
BedrockRegion: us-east-1
BedrockModel: anthropic.claude-3-5-sonnet-20240620-v1:0

# Disable other providers (optional)
OPENAI_API_KEY: ""  # Empty = disabled
```

#### Step 2: IAM Permissions (Automatic)

CloudFormation automatically creates IAM policy with Bedrock permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream"
  ],
  "Resource": "arn:aws:bedrock:*::foundation-model/*"
}
```

#### Step 3: Deploy

CloudFormation completes in 15-20 minutes. Orchestrator auto-configures for Bedrock.

---

### Option 2: Self-Hosted Deployment

**For customers deploying in own infrastructure (ECS, EC2, Docker).**

#### Step 1: Create IAM Policy

Create `bedrock-access-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
        "arn:aws:bedrock:*::foundation-model/meta.llama3-70b-instruct-v1:0"
      ]
    }
  ]
}
```

**Create policy:**
```bash
aws iam create-policy \
  --policy-name AxonFlowBedrockAccess \
  --policy-document file://bedrock-access-policy.json
```

#### Step 2: Attach Policy to Role

**ECS Task Role:**
```bash
aws iam attach-role-policy \
  --role-name AxonFlowTaskExecutionRole \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/AxonFlowBedrockAccess
```

**EC2 Instance Role:**
```bash
aws iam attach-role-policy \
  --role-name AxonFlowEC2Role \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/AxonFlowBedrockAccess
```

#### Step 3: Configure Environment Variables

Set these in your deployment environment:

```bash
# Bedrock Configuration
export LLM_BEDROCK_ENABLED=true
export LLM_BEDROCK_REGION=us-east-1
export LLM_BEDROCK_MODEL=anthropic.claude-3-5-sonnet-20240620-v1:0

# Optional: VPC Endpoint for private access
export LLM_BEDROCK_ENDPOINT_URL=https://vpce-xxxxx.bedrock-runtime.us-east-1.vpce.amazonaws.com
```

**Docker Compose Example:**
```yaml
version: '3.8'
services:
  orchestrator:
    image: axonflow/orchestrator:latest
    environment:
      - LLM_BEDROCK_ENABLED=true
      - LLM_BEDROCK_REGION=us-east-1
      - LLM_BEDROCK_MODEL=anthropic.claude-3-5-sonnet-20240620-v1:0
      - AWS_REGION=us-east-1
    volumes:
      - ~/.aws:/root/.aws:ro  # AWS credentials
```

#### Step 4: Verify Connection

Test Bedrock integration:

```bash
curl -X POST http://localhost:8082/v1/complete \
  -H "Authorization: Bearer YOUR_LICENSE_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is the capital of France?",
    "provider": "bedrock",
    "model": "anthropic.claude-3-5-sonnet-20240620-v1:0"
  }'
```

**Expected Response:**
```json
{
  "content": "The capital of France is Paris.",
  "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
  "latency_ms": 245,
  "tokens": {
    "prompt": 8,
    "completion": 6,
    "total": 14
  }
}
```

---

## Supported Models

### Anthropic Claude Models (Recommended)

| Model | Model ID | Use Case | Cost (per 1M tokens) |
|-------|----------|----------|----------------------|
| **Claude 3.5 Sonnet** | `anthropic.claude-3-5-sonnet-20240620-v1:0` | Complex reasoning, code | Input: $3.00<br>Output: $15.00 |
| **Claude 3 Haiku** | `anthropic.claude-3-haiku-20240307-v1:0` | High throughput, fast | Input: $0.25<br>Output: $1.25 |
| **Claude 3 Opus** | `anthropic.claude-3-opus-20240229-v1:0` | Highest accuracy | Input: $15.00<br>Output: $75.00 |

**Recommendation:** Start with Claude 3.5 Sonnet for balanced performance/cost.

### Meta Llama Models

| Model | Model ID | Use Case | Cost (per 1M tokens) |
|-------|----------|----------|----------------------|
| **Llama 3 70B** | `meta.llama3-70b-instruct-v1:0` | Open-source, coding | Input/Output: $0.99 |
| **Llama 3 8B** | `meta.llama3-8b-instruct-v1:0` | Budget-friendly | Input/Output: $0.30 |

**Recommendation:** Llama 3 70B for cost-sensitive workloads.

### Amazon Titan Models

| Model | Model ID | Use Case | Cost (per 1M tokens) |
|-------|----------|----------|----------------------|
| **Titan Text Express** | `amazon.titan-text-express-v1` | General purpose | Input/Output: $0.20 |

### Mistral AI Models

| Model | Model ID | Use Case | Cost (per 1M tokens) |
|-------|----------|----------|----------------------|
| **Mistral Large** | `mistral.mistral-large-2402-v1:0` | Multilingual | Input: $8.00<br>Output: $24.00 |
| **Mixtral 8x7B** | `mistral.mixtral-8x7b-instruct-v0:1` | Efficient MoE | Input: $0.45<br>Output: $0.70 |

---

## VPC Endpoint Setup (HIPAA Compliance)

**Use Case:** Private Bedrock access without internet gateway (required for HIPAA, PCI DSS).

### Step 1: Create VPC Endpoint

```bash
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxxxx \
  --service-name com.amazonaws.us-east-1.bedrock-runtime \
  --route-table-ids rtb-xxxxx \
  --subnet-ids subnet-xxxxx subnet-yyyyy \
  --security-group-ids sg-xxxxx
```

### Step 2: Security Group Rules

```bash
# Allow HTTPS from Orchestrator
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 443 \
  --source-group sg-orchestrator
```

### Step 3: Configure Orchestrator

```bash
export LLM_BEDROCK_ENDPOINT_URL=https://vpce-xxxxx.bedrock-runtime.us-east-1.vpce.amazonaws.com
```

**Benefits:**
- ✅ Traffic stays within AWS network (no internet exposure)
- ✅ Lower latency (~100ms reduction)
- ✅ HIPAA/PCI DSS compliance

---

## Configuration Examples

### Healthcare Use Case (HIPAA Compliant)

```yaml
# config/environments/healthcare.yaml
BedrockRegion: us-east-1
BedrockModel: anthropic.claude-3-5-sonnet-20240620-v1:0

# VPC endpoint for private access
BedrockEndpointURL: https://vpce-xxxxx.bedrock-runtime.us-east-1.vpce.amazonaws.com

# Enable audit logging
AuditLogRetentionDays: 2555  # 7 years (HIPAA requirement)
```

### Cost-Optimized Use Case

```yaml
# Use cheaper Llama 3 70B for most queries
BedrockRegion: us-east-1
BedrockModel: meta.llama3-70b-instruct-v1:0

# Can override per-request for complex queries
# client.query({ model: "anthropic.claude-3-5-sonnet-20240620-v1:0" })
```

### Multi-Region Setup

```yaml
# Primary region
BedrockRegion: us-east-1
BedrockModel: anthropic.claude-3-5-sonnet-20240620-v1:0

# Failover region (if us-east-1 fails)
BedrockFailoverRegion: us-west-2
```

---

## Troubleshooting

### Issue 1: "Access Denied" Error

**Symptom:**
```
AccessDeniedException: You don't have access to the model
```

**Solutions:**

1. **Check Model Access:**
```bash
aws bedrock list-foundation-models --region us-east-1
```
If model not listed, enable in Bedrock console.

2. **Verify IAM Permissions:**
```bash
aws iam get-role-policy --role-name AxonFlowTaskExecutionRole --policy-name BedrockAccess
```
Ensure `bedrock:InvokeModel` permission exists.

3. **Check Region:**
```bash
# Bedrock not available in all regions
aws bedrock list-foundation-models --region us-east-1  # ✅
aws bedrock list-foundation-models --region us-east-2  # ❌ May not work
```

### Issue 2: High Latency (>1 second)

**Symptom:** Bedrock calls taking >1 second.

**Solutions:**

1. **Use VPC Endpoint:**
   - Without: Internet → NAT → Bedrock (500-1000ms)
   - With: Private → Bedrock (150-300ms)

2. **Switch to Faster Model:**
   - Claude 3.5 Sonnet: 300-500ms
   - Claude 3 Haiku: 150-250ms (2x faster)

3. **Check Region Proximity:**
```bash
# Deploy Orchestrator in same region as Bedrock
# Bad: Orchestrator in eu-central-1, Bedrock in us-east-1 (+100ms)
# Good: Both in us-east-1 (<10ms overhead)
```

### Issue 3: Rate Limiting

**Symptom:**
```
ThrottlingException: Rate exceeded
```

**Solutions:**

1. **Check Quotas:**
```bash
aws service-quotas get-service-quota \
  --service-code bedrock \
  --quota-code L-xxxxx
```

**Default Limits:**
- Claude 3.5 Sonnet: 10,000 tokens/min
- Claude 3 Haiku: 20,000 tokens/min

2. **Request Quota Increase:**
- AWS Console → Service Quotas → Bedrock
- Typically approved in 1-2 business days

3. **Implement Backoff:**
AxonFlow automatically retries with exponential backoff.

### Issue 4: Invalid Model Response

**Symptom:** Unexpected or malformed responses.

**Solutions:**

1. **Check Model Version:**
```bash
# ❌ Bad: Old model
anthropic.claude-3-sonnet-20240229-v1:0

# ✅ Good: Latest
anthropic.claude-3-5-sonnet-20240620-v1:0
```

2. **Enable Debug Logging:**
```bash
export LOG_LEVEL=debug
# View full Bedrock request/response in logs
```

3. **Validate Model ID:**
```bash
aws bedrock list-foundation-models --region us-east-1 \
  --query 'modelSummaries[*].modelId'
```

---

## Security Best Practices

### 1. IAM Least Privilege

Only grant necessary permissions:

```json
{
  "Effect": "Allow",
  "Action": "bedrock:InvokeModel",
  "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0"
}
```

**DON'T** grant:
- `bedrock:*` (too broad)
- `bedrock:DeleteModel` (dangerous)
- `bedrock:CreateModelCustomizationJob` (not needed)

### 2. VPC Endpoint for Private Access

Route Bedrock traffic through VPC (no internet exposure).

### 3. Enable CloudTrail Logging

```bash
aws cloudtrail create-trail \
  --name bedrock-api-audit \
  --s3-bucket-name bedrock-audit-logs
```

**Logs:**
- Who invoked API (IAM user/role)
- When (timestamp)
- Which model
- Token count
- Source IP

### 4. PII Filtering

AxonFlow automatically filters PII before sending to Bedrock:

```yaml
policies:
  - name: pii-filter
    type: content_filter
    filters:
      - type: pii_detection
        action: redact
        entities: [SSN, CREDIT_CARD, EMAIL, PHONE]
```

### 5. Encryption

- **In Transit:** HTTPS (TLS 1.2+) - ✅ Default
- **At Rest:** Bedrock stores no data - ✅ Stateless
- **Audit Logs:** Encrypt with KMS - ✅ Recommended

---

## HIPAA Compliance Checklist

For healthcare deployments:

- [ ] Sign BAA with AWS (Console → Artifact → Agreements)
- [ ] Enable CloudTrail logging (audit trail requirement)
- [ ] Use VPC endpoint (no internet exposure)
- [ ] Configure PII filtering in AxonFlow
- [ ] Set audit log retention to 7 years (2555 days)
- [ ] Enable KMS encryption for audit logs
- [ ] Deploy in HIPAA-eligible region (us-east-1, us-west-2)
- [ ] Document security controls for compliance audit

---

## Cost Optimization

### Strategy 1: Model Selection

| Use Case | Model | Reasoning |
|----------|-------|-----------|
| High-volume support | Claude 3 Haiku | 10x cheaper, 80% accuracy |
| Code generation | Claude 3.5 Sonnet | Best coding performance |
| Data extraction | Llama 3 70B | Structured output, low cost |
| Medical diagnosis | Claude 3 Opus | Highest accuracy, worth premium |

### Strategy 2: Request Optimization

```bash
# ❌ Bad: Sending full document (100K tokens)
prompt: "Summarize: [entire 100K token document]"

# ✅ Good: Sending summary (5K tokens)
prompt: "Summarize: [5K token summary]"

# Cost savings: 95%
```

### Strategy 3: Budget Policies

```yaml
policies:
  - name: daily-budget-limit
    type: budget
    limits:
      daily_cost_usd: 100
    action: deny
```

---

## Migration from OpenAI

### Step 1: Update Configuration

```yaml
# Before (OpenAI)
OPENAI_API_KEY: sk-xxxxx

# After (Bedrock)
BedrockRegion: us-east-1
BedrockModel: anthropic.claude-3-5-sonnet-20240620-v1:0
```

### Step 2: Model Mapping

| OpenAI Model | Bedrock Equivalent | Cost Savings |
|--------------|-------------------|--------------|
| `gpt-4-turbo` | Claude 3.5 Sonnet | 55% cheaper |
| `gpt-4` | Claude 3 Opus | Similar cost |
| `gpt-3.5-turbo` | Claude 3 Haiku | 96% cheaper |

### Step 3: Test with Shadow Mode

```bash
# Run both providers in parallel
export LLM_SHADOW_MODE=true
export LLM_PRIMARY_PROVIDER=openai
export LLM_SHADOW_PROVIDER=bedrock
export LLM_SHADOW_SAMPLE_RATE=0.10  # 10% traffic

# Monitor CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AxonFlow/LLMShadowMode \
  --metric-name SimilarityScore
```

### Step 4: Gradual Rollout

```yaml
# Week 1: 10% Bedrock, 90% OpenAI
routing_weights: {openai: 0.9, bedrock: 0.1}

# Week 2: 50% Bedrock, 50% OpenAI
routing_weights: {openai: 0.5, bedrock: 0.5}

# Week 3: 100% Bedrock
routing_weights: {bedrock: 1.0}
```

---

## Support

### AxonFlow Support
- **Documentation:** https://docs.getaxonflow.com
- **Email:** support@getaxonflow.com
- **Slack:** https://axonflow-community.slack.com

### AWS Bedrock Support
- **Documentation:** https://docs.aws.amazon.com/bedrock/
- **Support:** AWS Support Console (Business/Enterprise plans)
- **Forums:** https://repost.aws/tags/bedrock

---

**Last Updated:** November 24, 2025
**AxonFlow Version:** v1.1.0 (Track 2 Phase 3)
**Tested with:** AWS Bedrock (November 2025 API version)

