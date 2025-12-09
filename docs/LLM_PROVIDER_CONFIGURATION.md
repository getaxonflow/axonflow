# LLM Provider Configuration Guide

## Table of Contents
- [Overview](#overview)
- [LLM Providers](#llm-providers)
  - [Available Providers](#available-providers)
  - [OpenAI Configuration](#openai-configuration)
  - [AWS Bedrock Configuration](#aws-bedrock-configuration)
  - [Ollama Configuration](#ollama-configuration)
  - [Provider Selection](#provider-selection)
- [Connector Deployment Configuration](#connector-deployment-configuration)
  - [EnabledConnectors Parameter](#enabledconnectors-parameter)
  - [Available Connectors](#available-connectors)
  - [Deployment Examples](#deployment-examples)
- [LLM Providers](#llm-providers)
  - [AWS Bedrock](#aws-bedrock)
  - [OpenAI](#openai)
  - [Anthropic](#anthropic)
- [Shadow Mode](#shadow-mode)
  - [What is Shadow Mode?](#what-is-shadow-mode)
  - [When to Use Shadow Mode](#when-to-use-shadow-mode)
  - [Configuration](#configuration)
  - [Metrics](#metrics)
  - [Best Practices](#best-practices)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)

---

## Overview

AxonFlow supports multiple LLM providers for multi-agent orchestration. Shadow Mode allows you to safely test a new LLM provider alongside your current production provider before fully switching over.

---

## LLM Providers

AxonFlow Enterprise Edition supports multiple LLM providers to meet diverse operational, compliance, and cost requirements.

### Available Providers

| Provider | Type | Use Cases | Availability |
|----------|------|-----------|--------------|
| **OpenAI** | Cloud API | General purpose, rapid development | OSS + Enterprise |
| **AWS Bedrock** | Cloud API (AWS) | HIPAA compliance, data residency, enterprise | Enterprise Only |
| **Ollama** | Self-hosted | Air-gapped, on-premise, cost optimization | Enterprise Only |

### OpenAI Configuration

**Use Cases**:
- General purpose LLM access
- Rapid prototyping and development
- Access to latest GPT models

**Configuration**:

```yaml
# config/environments/development.yaml
LLM_PROVIDER: openai
LLM_OPENAI_ENABLED: true
LLM_OPENAI_API_KEY: sk-proj-...
LLM_OPENAI_MODEL: gpt-4
```

**Environment Variables**:

```bash
export LLM_PROVIDER=openai
export LLM_OPENAI_ENABLED=true
export LLM_OPENAI_API_KEY=sk-proj-...
export LLM_OPENAI_MODEL=gpt-4  # or gpt-4-turbo, gpt-3.5-turbo
```

**Supported Models**:
- `gpt-4` - Highest quality, most capable
- `gpt-4-turbo` - Faster, cost-effective
- `gpt-3.5-turbo` - Budget-friendly, fast

**Documentation**: [OpenAI API Docs](https://platform.openai.com/docs)

---

### AWS Bedrock Configuration

**Use Cases**:
- HIPAA-compliant healthcare applications
- Financial services with data residency requirements
- Government/defense with AWS GovCloud
- Enterprise with existing AWS infrastructure

**Configuration**:

```yaml
# config/environments/healthcare.yaml
LLM_PROVIDER: bedrock
LLM_BEDROCK_ENABLED: true
LLM_BEDROCK_REGION: us-east-1
LLM_BEDROCK_MODEL: anthropic.claude-3-5-sonnet-20240620-v1:0
```

**Environment Variables**:

```bash
export LLM_PROVIDER=bedrock
export LLM_BEDROCK_ENABLED=true
export LLM_BEDROCK_REGION=us-east-1
export LLM_BEDROCK_MODEL=anthropic.claude-3-5-sonnet-20240620-v1:0

# AWS credentials (IAM role preferred)
export AWS_REGION=us-east-1
# Or use IAM role attached to ECS task/EC2 instance
```

**Supported Model Families**:
- **Anthropic Claude**: `anthropic.claude-3-5-sonnet-20240620-v1:0` (recommended)
- **Meta Llama**: `meta.llama3-70b-instruct-v1:0`
- **Amazon Titan**: `amazon.titan-text-express-v1`
- **Mistral AI**: `mistral.mistral-large-2402-v1:0`

**IAM Permissions Required**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel"
      ],
      "Resource": "arn:aws:bedrock:*:*:model/*"
    }
  ]
}
```

**Key Features**:
- ✅ VPC endpoint support for private access
- ✅ HIPAA compliance when configured properly
- ✅ Data residency (stays in AWS region)
- ✅ No data used for training
- ✅ Enterprise SLAs

**Documentation**: See [BEDROCK_SETUP.md](./BEDROCK_SETUP.md) for complete setup guide.

---

### Ollama Configuration

**Use Cases**:
- Air-gapped environments (government, defense, classified networks)
- On-premise deployments with data sovereignty requirements
- Cost optimization (no per-token fees)
- Local development without API costs
- Custom fine-tuned models

**Configuration**:

```yaml
# config/environments/airgap.yaml
LLM_PROVIDER: ollama
LLM_OLLAMA_ENABLED: true
LLM_OLLAMA_BASE_URL: http://ollama.internal.axonflow.com:11434
LLM_OLLAMA_MODEL: llama3.1
LLM_OLLAMA_TIMEOUT: 120s
```

**Environment Variables**:

```bash
export LLM_PROVIDER=ollama
export LLM_OLLAMA_ENABLED=true
export LLM_OLLAMA_BASE_URL=http://localhost:11434  # or http://ollama-server:11434
export LLM_OLLAMA_MODEL=llama3.1  # or mistral, codellama, etc.
export LLM_OLLAMA_TIMEOUT=60s
```

**Docker Compose Example**:

```yaml
# docker-compose.yaml
services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama-data:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]

  axonflow-orchestrator:
    image: axonflow/orchestrator:latest
    depends_on:
      - ollama
    environment:
      - LLM_PROVIDER=ollama
      - LLM_OLLAMA_BASE_URL=http://ollama:11434
      - LLM_OLLAMA_MODEL=llama3.1

volumes:
  ollama-data:
```

**Supported Models**:
- **Llama 3.1**: `llama3.1` (8B, general purpose)
- **Llama 3.1 70B**: `llama3.1:70b` (high accuracy)
- **Mistral**: `mistral` (efficient, multilingual)
- **Code Llama**: `codellama` (code generation)
- **Neural Chat**: `neural-chat` (conversational)

**Pull Models**:

```bash
# Pull models to Ollama server
docker exec ollama ollama pull llama3.1
docker exec ollama ollama pull mistral
docker exec ollama ollama pull llama3.1:70b

# List installed models
docker exec ollama ollama list
```

**Key Features**:
- ✅ Zero external dependencies
- ✅ Complete data privacy
- ✅ No per-token costs
- ✅ GPU acceleration support
- ✅ Air-gap compatible
- ✅ Custom model deployment

**Documentation**: See [OLLAMA_SETUP.md](./OLLAMA_SETUP.md) for complete setup guide.

---

### Provider Selection

**Decision Matrix**:

| Requirement | Recommended Provider |
|-------------|----------------------|
| HIPAA compliance | AWS Bedrock |
| Air-gapped network | Ollama |
| Lowest latency | OpenAI (global CDN) |
| Lowest cost (high volume) | Ollama (self-hosted) |
| Lowest cost (low volume) | OpenAI (pay-per-use) |
| Data residency (AWS) | AWS Bedrock |
| Data residency (on-prem) | Ollama |
| Latest models | OpenAI |
| No internet access | Ollama |
| Rapid prototyping | OpenAI |
| Custom fine-tuned models | Ollama |

**Multi-Provider Strategy**:

```yaml
# Development
LLM_PROVIDER: ollama  # Free, fast iteration

# Staging
LLM_PROVIDER: openai  # Test with production-like provider

# Production (Healthcare)
LLM_PROVIDER: bedrock  # HIPAA-compliant

# Production (Government)
LLM_PROVIDER: ollama  # Air-gapped
```

---

## Connector Deployment Configuration

### EnabledConnectors Parameter

AxonFlow uses an array-based `EnabledConnectors` parameter to control which MCP connector secrets are injected into ECS containers. This enables:

- ✅ **OSS Deployments**: Deploy with no connectors (empty string)
- ✅ **Partial Deployments**: Enable only specific connectors
- ✅ **Enterprise Deployments**: Enable all connectors

**Key Benefits:**
- Scales to 50+ connectors with a single parameter
- No redeployment needed to add connectors dynamically
- Pre-flight validation checks only enabled connector secrets

### Available Connectors

| Connector ID | Purpose | Secrets Count | Fields |
|--------------|---------|---------------|--------|
| `amadeus` | Travel API (flights, hotels, airports) | 2 | api_key, api_secret |
| `salesforce` | CRM integration | 4 | client_id, client_secret, username, password |
| `slack` | Team messaging | 1 | bot_token |
| `snowflake` | Data warehouse | 6 | account, username, warehouse, database, schema, role |
| `openai` | Server-side LLM provider | 1 | api_key |
| `anthropic` | Server-side LLM provider | 1 | api_key |
| `client-openai` | Client-side LLM provider | 1 | api_key |
| `client-anthropic` | Client-side LLM provider | 1 | api_key |

### Deployment Examples

**OSS Deployment (No Connectors):**
```yaml
# config/environments/staging.yaml
EnabledConnectors: ""
```

**Travel Demo (Amadeus + OpenAI):**
```yaml
# config/environments/travel.yaml
EnabledConnectors: "amadeus,openai"
```

**E-commerce Demo (Salesforce + Anthropic):**
```yaml
# config/environments/ecommerce.yaml
EnabledConnectors: "salesforce,anthropic"
```

**Full Production (All Connectors):**
```yaml
# config/environments/production-us.yaml
EnabledConnectors: "amadeus,salesforce,slack,snowflake,openai,anthropic,client-openai,client-anthropic"
```

**Dynamic Addition:**
Connectors can be added after deployment by:
1. Creating the connector secret in AWS Secrets Manager
2. Updating the `EnabledConnectors` config
3. Restarting ECS services (no stack update needed)

---

## LLM Providers

AxonFlow supports multiple LLM providers through a unified Provider interface. Providers can be used standalone or combined with multi-provider routing for load balancing and failover.

### AWS Bedrock

**For:** Enterprise Edition (HIPAA-compliant deployments)

AWS Bedrock provides serverless access to foundation models from Anthropic, Meta, Amazon, and Mistral through a unified API.

**Key Features:**
- ✅ HIPAA eligible when used with BAA
- ✅ Multiple model families (Claude, Llama, Titan, Mistral)
- ✅ AWS-native security (IAM, VPC endpoints)
- ✅ No infrastructure management

**Configuration:**

```yaml
# config/environments/healthcare.yaml
BedrockRegion: us-east-1
BedrockModel: anthropic.claude-3-5-sonnet-20240620-v1:0
```

**Environment Variables:**
```bash
export LLM_BEDROCK_ENABLED=true
export LLM_BEDROCK_REGION=us-east-1
export LLM_BEDROCK_MODEL=anthropic.claude-3-5-sonnet-20240620-v1:0
```

**Supported Models:**
- `anthropic.claude-3-5-sonnet-20240620-v1:0` (recommended)
- `anthropic.claude-3-haiku-20240307-v1:0` (cost-effective)
- `anthropic.claude-3-opus-20240229-v1:0` (highest accuracy)
- `meta.llama3-70b-instruct-v1:0` (open-source)
- `amazon.titan-text-express-v1` (AWS native)
- `mistral.mistral-large-2402-v1:0` (multilingual)

**IAM Permissions Required:**
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

**Use Cases:**
- Healthcare (HIPAA compliance required)
- Financial services (SOC 2 compliance)
- Government (AWS FedRAMP certified)
- Cost optimization (50-90% cheaper than OpenAI)

**Full Setup Guide:** See `docs/BEDROCK_SETUP.md`

### OpenAI

**For:** OSS and Enterprise Edition

OpenAI GPT models for general-purpose AI tasks.

**Configuration:**
```yaml
# config/environments/staging.yaml
EnabledConnectors: "openai"
```

**Environment Variables:**
```bash
export OPENAI_API_KEY=sk-xxxxx
```

**Supported Models:**
- `gpt-4-turbo` (general purpose)
- `gpt-4` (complex reasoning)
- `gpt-3.5-turbo` (fast, cost-effective)

### Anthropic

**For:** OSS and Enterprise Edition

Anthropic Claude models optimized for safety and helpfulness.

**Configuration:**
```yaml
# config/environments/staging.yaml
EnabledConnectors: "anthropic"
```

**Environment Variables:**
```bash
export ANTHROPIC_API_KEY=sk-ant-xxxxx
```

**Supported Models:**
- `claude-3-opus-20240229` (highest intelligence)
- `claude-3-sonnet-20240229` (balanced)
- `claude-3-haiku-20240307` (fast)

---

## Shadow Mode

### What is Shadow Mode?

Shadow Mode runs two LLM providers in parallel:
- **Primary Provider**: Your current production provider (e.g., OpenAI)
- **Shadow Provider**: The new provider you want to test (e.g., AWS Bedrock)

**Key Characteristics:**
- ✅ **Non-blocking**: Shadow requests run in background goroutines
- ✅ **Safe**: Always returns primary response (shadow doesn't affect production)
- ✅ **Configurable**: Sample rate controls what % of traffic is shadowed
- ✅ **Observable**: Metrics published to CloudWatch for analysis

### When to Use Shadow Mode

**Recommended Use Cases:**
1. **Provider Migration**: Testing Bedrock before migrating from OpenAI
2. **Cost Optimization**: Comparing Ollama (free) vs OpenAI (paid)
3. **Performance Testing**: Evaluating latency and response quality
4. **Compliance**: Testing HIPAA-compliant Bedrock before go-live

**Example Scenario:**
```
Current:  100% traffic → OpenAI (production)
Goal:     100% traffic → AWS Bedrock (lower cost, data residency)
Strategy: Shadow Mode for 7 days → Verify quality → Switch
```

### Configuration

#### Environment Variables

```bash
# Enable shadow mode
export LLM_SHADOW_MODE=true

# Primary provider (current production)
export LLM_PRIMARY_PROVIDER=openai
export OPENAI_API_KEY=sk-...

# Shadow provider (testing)
export LLM_SHADOW_PROVIDER=bedrock
export BEDROCK_REGION=us-east-1
export BEDROCK_MODEL=anthropic.claude-3-sonnet-20240229-v1:0

# Sample rate (0.0-1.0)
export LLM_SHADOW_SAMPLE_RATE=0.10  # Shadow 10% of requests
```

#### Sample Rate Guidelines

| Rate | Usage | Traffic Volume | Cost Impact |
|------|-------|----------------|-------------|
| `0.01` | Initial testing | 1% | Minimal |
| `0.10` | Standard testing | 10% | Low (~10% increase) |
| `0.50` | Aggressive testing | 50% | Medium (~50% increase) |
| `1.00` | Full comparison | 100% | High (~100% increase) |

**Recommendation**: Start with 10% (0.10) for 7 days.

### Metrics

Shadow Mode publishes the following CloudWatch metrics:

#### Namespace
`AxonFlow/LLMShadowMode`

#### Metrics

| Metric | Unit | Dimensions | Description |
|--------|------|------------|-------------|
| `ShadowRequests` | Count | PrimaryProvider, ShadowProvider | Total shadow requests executed |
| `BothSucceeded` | Count | PrimaryProvider, ShadowProvider | Both providers returned successfully |
| `BothFailed` | Count | PrimaryProvider, ShadowProvider | Both providers failed |
| `OnlyPrimaryFailed` | Count | PrimaryProvider, ShadowProvider | Primary failed, shadow succeeded |
| `OnlyShadowFailed` | Count | PrimaryProvider, ShadowProvider | Shadow failed, primary succeeded |
| `LatencyDiff` | Milliseconds | PrimaryProvider, ShadowProvider | Latency difference (shadow - primary) |
| `ContentSimilarity` | Percent | PrimaryProvider, ShadowProvider | Response similarity (0-100%) |
| `TokenCountDiff` | Count | PrimaryProvider, ShadowProvider | Token count difference |

#### Example CloudWatch Insights Query

```sql
fields @timestamp, LatencyDiff, ContentSimilarity
| filter ShadowProvider = "bedrock"
| stats
    avg(LatencyDiff) as avg_latency_diff_ms,
    pct(LatencyDiff, 50) as p50_latency_diff,
    pct(LatencyDiff, 95) as p95_latency_diff,
    pct(LatencyDiff, 99) as p99_latency_diff,
    avg(ContentSimilarity) as avg_similarity,
    min(ContentSimilarity) as min_similarity
by bin(5m)
```

### Best Practices

#### 1. Gradual Rollout

```
Week 1: Shadow 10% of traffic (LLM_SHADOW_SAMPLE_RATE=0.10)
Week 2: Review metrics → If good, shadow 50% (0.50)
Week 3: Review metrics → If good, shadow 100% (1.00)
Week 4: Switch to new provider (disable shadow mode)
```

#### 2. Exit Criteria for Production Switch

Before switching from shadow to primary, verify:

- ✅ **Error Rate**: Shadow provider error rate <5%
- ✅ **Similarity**: Content similarity >90%
- ✅ **Latency**: Shadow latency within 2x of primary (or acceptable)
- ✅ **Cost**: Total cost (primary + shadow testing) acceptable
- ✅ **Duration**: Tested for at least 7 days

#### 3. Monitor CloudWatch Alarms

Set up alarms for:

```yaml
# High shadow error rate
Metric: OnlyShadowFailed / ShadowRequests
Threshold: > 5%
Action: Investigate shadow provider issues

# Low content similarity
Metric: ContentSimilarity
Threshold: < 85%
Action: Review prompt engineering or model selection

# High latency degradation
Metric: LatencyDiff
Threshold: P95 > 2000ms
Action: Evaluate if latency acceptable for use case
```

#### 4. Cost Management

Shadow mode **doubles LLM costs** during testing (primary + shadow).

**Cost Optimization Tips:**
- Use sample rate (10% = 10% cost increase)
- Set `LLM_SHADOW_MODE=false` when not actively testing
- Use cheaper shadow provider (e.g., Ollama = $0)
- Test during off-peak hours if possible

---

## Multi-Provider Routing

AxonFlow Enterprise Edition supports multi-provider routing to distribute LLM requests across multiple providers for load balancing, cost optimization, and high availability.

### Routing Strategies

**Available Strategies:**

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `round_robin` | Distributes requests evenly across all healthy providers | Balanced load distribution |
| `weighted` | Routes traffic based on configured weights | Gradual migration, A/B testing |
| `cost_optimized` | Routes to cheapest provider first, failover to more expensive | Cost optimization |

### Round Robin Strategy

**Configuration:**
```yaml
# config/environments/development.yaml
llm:
  routing_strategy: round_robin
  providers:
    openai:
      enabled: true
      model: gpt-4
      cost: 0.03
    bedrock:
      enabled: true
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
      cost: 0.01
    ollama:
      enabled: true
      endpoint: http://ollama:11434
      model: llama3.1:70b
      cost: 0.0
```

**Behavior:**
- Request 1 → OpenAI
- Request 2 → Bedrock
- Request 3 → Ollama
- Request 4 → OpenAI (cycle repeats)

**Best For:**
- Equal load distribution
- Testing multiple providers simultaneously
- Development environments

### Weighted Strategy

**Configuration:**
```yaml
# config/environments/production-us.yaml
llm:
  routing_strategy: weighted
  providers:
    openai:
      enabled: true
      model: gpt-4
      weight: 50  # 50% of traffic
      cost: 0.03
    bedrock:
      enabled: true
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
      weight: 30  # 30% of traffic
      cost: 0.01
    ollama:
      enabled: true
      endpoint: http://ollama:11434
      model: llama3.1:70b
      weight: 20  # 20% of traffic
      cost: 0.0
```

**Behavior:**
- 50 out of 100 requests → OpenAI
- 30 out of 100 requests → Bedrock
- 20 out of 100 requests → Ollama

**Best For:**
- Gradual provider migration (start 10%, increase to 100%)
- A/B testing new providers
- Cost optimization (route more to cheaper providers)
- Canary deployments

**Example Migration:**
```yaml
# Week 1: 10% on new provider
openai: 90, bedrock: 10

# Week 2: Increase to 30%
openai: 70, bedrock: 30

# Week 3: 50/50 split
openai: 50, bedrock: 50

# Week 4: Complete migration
bedrock: 100
```

### Cost Optimized Strategy

**Configuration:**
```yaml
# config/environments/cost-optimization.yaml
llm:
  routing_strategy: cost_optimized
  providers:
    ollama:
      enabled: true
      endpoint: http://ollama:11434
      model: llama3.1:70b
      cost: 0.0  # Free (self-hosted)
    bedrock:
      enabled: true
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
      cost: 0.01  # $0.01 per 1K tokens
    openai:
      enabled: true
      model: gpt-4
      cost: 0.03  # $0.03 per 1K tokens
```

**Behavior:**
- All requests try Ollama first (cost: $0)
- If Ollama fails → Try Bedrock (cost: $0.01)
- If Bedrock fails → Try OpenAI (cost: $0.03)

**Best For:**
- Maximizing cost savings
- Using free self-hosted LLM with cloud fallback
- Development environments (Ollama local, fallback to cloud)

**Cost Savings Example:**
```
Without cost optimization (OpenAI only):
1M tokens × $0.03 = $30

With cost optimization (80% Ollama, 15% Bedrock, 5% OpenAI):
800K tokens × $0 = $0
150K tokens × $0.01 = $1.50
50K tokens × $0.03 = $1.50
Total: $3 (90% cost reduction)
```

---

## Health Checking and Failover

### Circuit Breaker Pattern

AxonFlow implements circuit breaker pattern for automatic failover when providers fail.

**Circuit Breaker States:**

| State | Description | Behavior |
|-------|-------------|----------|
| **Closed** | Provider healthy | All requests sent to provider |
| **Open** | Provider failing | No requests sent, immediate failover |
| **Half-Open** | Recovery testing | Limited requests to test recovery |

**Configuration:**
```yaml
llm:
  failover:
    enabled: true
    max_retries: 3  # Try up to 3 providers before failing
    failure_threshold: 5  # Open circuit after 5 consecutive failures
    recovery_timeout: 30s  # Wait 30s before trying half-open
    health_check_interval: 30s  # Check provider health every 30s
```

**Health States:**

| State | Description | Action |
|-------|-------------|--------|
| **Healthy** | 0-2 consecutive failures | Provider available for routing |
| **Degraded** | 3-4 consecutive failures | Provider deprioritized, still available |
| **Unhealthy** | 5+ consecutive failures | Circuit breaker open, provider skipped |

### Automatic Failover

**Scenario: Provider Failure During Request**

```yaml
# Configuration
llm:
  routing_strategy: weighted
  providers:
    openai: {weight: 50}
    bedrock: {weight: 30}
    ollama: {weight: 20}
  failover:
    enabled: true
    max_retries: 3
```

**Request Flow:**
1. Request routed to OpenAI (selected by weighted routing)
2. OpenAI returns 500 Internal Server Error
3. AxonFlow automatically retries with Bedrock
4. Bedrock succeeds → Response returned to client
5. OpenAI failure recorded (consecutive failures: 1)

**After 5 Consecutive Failures:**
1. OpenAI circuit breaker opens → State: Unhealthy
2. All future requests skip OpenAI
3. Traffic redistributed: Bedrock 60%, Ollama 40%
4. After 30s: Try 1 request to OpenAI (half-open state)
5. If succeeds → Circuit breaker closes → OpenAI back to 50%

### Monitoring Failover Events

**CloudWatch Metrics:**
- `ProviderFailures` - Count of failures per provider
- `CircuitBreakerState` - Current circuit breaker state (0=closed, 1=open)
- `FailoverEvents` - Count of automatic failovers
- `ProviderLatency` - P50, P95, P99 latency per provider

**CloudWatch Logs:**
```json
{
  "event": "provider_failure",
  "provider": "openai",
  "error": "timeout after 30s",
  "consecutive_failures": 3,
  "health_state": "degraded"
}

{
  "event": "automatic_failover",
  "from_provider": "openai",
  "to_provider": "bedrock",
  "request_id": "req-abc123",
  "failover_latency_ms": 45
}

{
  "event": "circuit_breaker_opened",
  "provider": "openai",
  "consecutive_failures": 5,
  "recovery_timeout_seconds": 30
}
```

---

## Environment-Specific Configurations

### Healthcare (HIPAA Compliance)

**Configuration:** `config/environments/healthcare.yaml`

```yaml
llm:
  # Single provider strategy (no failover outside HIPAA boundary)
  routing_strategy: single

  providers:
    # Bedrock is HIPAA-compliant when configured with VPC endpoints
    bedrock:
      enabled: true
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
      vpc_endpoint: true  # Required for HIPAA
      weight: 100
      cost: 0.01

    # External providers disabled for HIPAA compliance
    openai:
      enabled: false

    ollama:
      enabled: false
```

**Key Requirements:**
- ✅ VPC endpoints (no internet traffic)
- ✅ Data residency in us-east-1
- ✅ AWS BAA (Business Associate Agreement) signed
- ✅ CloudWatch logs encrypted with KMS
- ✅ No data leaves HIPAA boundary

### Air-Gapped Government

**Configuration:** `config/environments/airgap-gov.yaml`

```yaml
llm:
  # Single provider strategy (no external connectivity)
  routing_strategy: single

  providers:
    # Ollama self-hosted (air-gapped approved)
    ollama:
      enabled: true
      endpoint: http://ollama.internal:11434
      model: llama3.1:70b
      gpu_enabled: true
      weight: 100
      cost: 0.0

    # External providers disabled (no internet)
    bedrock:
      enabled: false
      reason: "No AWS API access in air-gapped environment"

    openai:
      enabled: false
      reason: "No internet access in air-gapped environment"
```

**Deployment Requirements:**
- ✅ No external internet access
- ✅ Self-hosted Ollama on customer infrastructure
- ✅ GPU acceleration (NVIDIA A100/H100)
- ✅ Models pre-loaded during installation
- ✅ Compliance: FedRAMP, NIST-800-53, DoD-IL5

### Production Multi-Provider (Cost Optimization)

**Configuration:** `config/environments/production-us.yaml`

```yaml
llm:
  # Weighted routing for cost optimization and gradual migration
  routing_strategy: weighted

  providers:
    # OpenAI (primary, highest quality)
    openai:
      enabled: true
      model: gpt-4
      weight: 50  # 50% of traffic
      cost: 0.03

    # Bedrock (secondary, HIPAA-ready)
    bedrock:
      enabled: true
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
      weight: 30  # 30% of traffic
      cost: 0.01

    # Ollama (tertiary, cost optimization)
    ollama:
      enabled: true
      endpoint: http://ollama:11434
      model: llama3.1:70b
      weight: 20  # 20% of traffic
      cost: 0.0

  # Automatic failover configuration
  failover:
    enabled: true
    max_retries: 3
    failure_threshold: 5
    recovery_timeout: 30s
    health_check_interval: 30s
```

**Expected Cost Savings:**
```
All OpenAI (baseline):
1M tokens × $0.03 = $30/day = $900/month

Multi-provider (50% OpenAI, 30% Bedrock, 20% Ollama):
500K × $0.03 = $15
300K × $0.01 = $3
200K × $0 = $0
Total: $18/day = $540/month (40% savings)
```

---

## Usage Examples

### Example 1: Testing AWS Bedrock

**Scenario**: Migrate from OpenAI to Bedrock for HIPAA compliance

```bash
# Enable shadow mode
export LLM_SHADOW_MODE=true
export LLM_PRIMARY_PROVIDER=openai
export LLM_SHADOW_PROVIDER=bedrock
export LLM_SHADOW_SAMPLE_RATE=0.10

# Primary provider config
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4

# Shadow provider config
export BEDROCK_REGION=us-east-1
export BEDROCK_MODEL=anthropic.claude-3-sonnet-20240229-v1:0

# Start orchestrator
./orchestrator
```

**Expected Logs:**
```
[Shadow] ✅ Both succeeded | Primary: openai, Shadow: bedrock | Latency diff: +125ms | Similarity: 94.5% | Token diff: -5
[Shadow] Metrics published to CloudWatch: AxonFlow/LLMShadowMode/*
```

### Example 2: Testing Self-Hosted Ollama

**Scenario**: Reduce costs by testing free Ollama

```bash
# Enable shadow mode
export LLM_SHADOW_MODE=true
export LLM_PRIMARY_PROVIDER=openai
export LLM_SHADOW_PROVIDER=ollama
export LLM_SHADOW_SAMPLE_RATE=0.20  # 20% sample

# Primary provider config
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4

# Shadow provider config (self-hosted)
export OLLAMA_ENDPOINT=http://ollama-server:11434
export OLLAMA_MODEL=llama3.1:70b

# Start orchestrator
./orchestrator
```

### Example 3: Disabling Shadow Mode

```bash
# Disable shadow mode (production)
export LLM_SHADOW_MODE=false
export LLM_PRIMARY_PROVIDER=bedrock  # Now using Bedrock as primary

# No shadow configuration needed
export BEDROCK_REGION=us-east-1
export BEDROCK_MODEL=anthropic.claude-3-sonnet-20240229-v1:0

# Start orchestrator
./orchestrator
```

---

## Troubleshooting

### Issue: Shadow requests not running

**Symptoms:**
- `ShadowRequests` metric shows 0
- No shadow logs in CloudWatch

**Solutions:**
1. Verify `LLM_SHADOW_MODE=true` is set
2. Check sample rate: `LLM_SHADOW_SAMPLE_RATE` should be >0
3. Ensure shadow provider is configured (API keys, endpoints)
4. Check orchestrator logs for shadow provider initialization errors

---

### Issue: High shadow error rate

**Symptoms:**
- `OnlyShadowFailed` metric >10%
- Logs show repeated shadow provider failures

**Solutions:**
1. **AWS Bedrock**: Check IAM permissions, model availability in region
2. **Ollama**: Verify endpoint reachable, model downloaded
3. **OpenAI/Anthropic**: Validate API key, check rate limits
4. Review CloudWatch logs for specific error messages

---

### Issue: Low content similarity

**Symptoms:**
- `ContentSimilarity` metric <80%
- Responses look very different

**Root Causes:**
1. **Different models**: GPT-4 vs Llama produce different styles
2. **Temperature**: Different default temperatures
3. **Prompt engineering**: Model-specific prompt optimizations needed

**Solutions:**
1. Review actual responses in logs
2. Adjust prompts for shadow provider
3. Set consistent temperature: `Temperature=0.7` for both
4. Accept some variance (85%+ is usually fine)

---

### Issue: Shadow provider very slow

**Symptoms:**
- `LatencyDiff` metric very high (>5000ms)
- P99 latency unacceptable for production

**Solutions:**
1. **AWS Bedrock**: Use provisioned throughput for consistent latency
2. **Ollama**: Ensure sufficient GPU resources
3. **OpenAI**: Check network path, use dedicated tenancy
4. Accept higher latency if cost savings justify it

---

### Issue: Metrics not appearing in CloudWatch

**Symptoms:**
- No metrics in CloudWatch console
- Logs show "Failed to publish metrics"

**Solutions:**
1. Verify IAM role has `cloudwatch:PutMetricData` permission
2. Check AWS region: Metrics published to orchestrator's region
3. Verify namespace: `AxonFlow/LLMShadowMode`
4. Wait 1-2 minutes for metrics to appear (CloudWatch delay)

---

## Next Steps

1. **Enable Shadow Mode**: Set environment variables
2. **Monitor Metrics**: Create CloudWatch dashboard
3. **Analyze Results**: Review similarity, latency, errors for 7 days
4. **Make Decision**: Switch to shadow provider if metrics acceptable
5. **Disable Shadow Mode**: Set `LLM_SHADOW_MODE=false` after switch

---

## Runtime Provider Management

In addition to environment variable configuration, AxonFlow supports runtime provider management through:

### REST API

The orchestrator exposes a full REST API for provider CRUD operations:

```bash
# List all providers
curl -X GET http://localhost:8080/api/v1/llm-providers

# Create a new provider
curl -X POST http://localhost:8080/api/v1/llm-providers \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-anthropic",
    "type": "anthropic",
    "api_key": "sk-ant-...",
    "model": "claude-3-sonnet-20240229",
    "enabled": true,
    "priority": 1
  }'

# Update routing weights
curl -X PUT http://localhost:8080/api/v1/llm-providers/routing \
  -H "Content-Type: application/json" \
  -d '{"weights": {"my-anthropic": 70, "my-openai": 30}}'
```

See [LLM Provider Architecture](./LLM_PROVIDER_ARCHITECTURE.md#rest-api-reference) for full API documentation.

### Customer Portal (Enterprise)

Enterprise customers can manage LLM providers through the Customer Portal UI:

- **Add/Edit/Delete** providers with a visual interface
- **Configure routing** weights and priorities
- **Monitor health** status of all providers
- **View usage metrics** and cost estimates

Access the Customer Portal at your deployment URL (e.g., `https://portal.your-domain.com/llm-providers`).

---

**For more information:**
- [LLM Provider Architecture](./LLM_PROVIDER_ARCHITECTURE.md) - Technical architecture and REST API reference
- [MCP Connectors Guide](../technical-docs/MCP_CONNECTORS.md) - Connect to external data sources
- [AWS Bedrock Configuration](./BEDROCK_SETUP.md)
- [Ollama Self-Hosted Setup](./OLLAMA_SETUP.md)
- [Architecture Overview](../technical-docs/ARCHITECTURE.md)
