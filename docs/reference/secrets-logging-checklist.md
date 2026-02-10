# AWS Secrets Manager - Deployment Checklist

**Version:** 1.1

**Last Updated:** February 2026

**Platform Version:** v4.2.0

**Purpose:** Pre-deployment validation checklist for AWS Secrets Manager secrets

---

## Critical Issue: JSON Format Requirement

**Root Cause of Nov 23 Staging Failure:**
- CloudFormation uses `:field::` syntax to extract fields from secrets (e.g., `:password::`)
- ECS Secrets Manager integration requires secrets to be JSON objects
- Plain text secrets cause container crashes during secret injection phase
- Containers crash BEFORE application starts → no logs written
- Health checks fail → ECS circuit breaker triggers → deployment fails

**Example:**
```yaml
# CloudFormation task definition
Secrets:
  - Name: DATABASE_PASSWORD
    ValueFrom: !Sub '${DBPasswordSecret}:password::'  # Expects JSON with "password" field
```

**Requirements:**
- ✅ **CORRECT:** `{"password": "your-password-here"}`
- ❌ **WRONG:** `your-password-here` (plain text)

---

## Pre-Deployment Checklist

### Step 1: List All Required Secrets

**Database Passwords (Required for all environments):**
- [ ] `axonflow/{environment}/database-password` - Main database admin password
- [ ] `axonflow/{environment}/database-app-password` - Application user password

**Connector Credentials (Optional, environment-specific):**
- [ ] `axonflow/{environment}/amadeus-credentials` - Travel API credentials
- [ ] `axonflow/{environment}/salesforce-credentials` - CRM credentials
- [ ] `axonflow/{environment}/slack-credentials` - Slack integration
- [ ] `axonflow/{environment}/snowflake-credentials` - Data warehouse credentials

**LLM Provider Credentials (Required for production, optional for staging):**
- [ ] `axonflow/{environment}/openai-credentials` - OpenAI API credentials
- [ ] `axonflow/{environment}/anthropic-credentials` - Anthropic API credentials
- [ ] `axonflow/{environment}/client-openai-credentials` - Client OpenAI credentials
- [ ] `axonflow/{environment}/client-anthropic-credentials` - Client Anthropic credentials
- [ ] `axonflow/{environment}/azure-openai-credentials` - Azure OpenAI credentials
- [ ] `axonflow/{environment}/google-credentials` - Google Gemini API credentials

### Step 2: Verify Secrets Exist

```bash
# List secrets for environment
ENVIRONMENT=staging  # or production
REGION=eu-central-1  # or us-east-1, ap-south-1

aws secretsmanager list-secrets \
  --region "$REGION" \
  --query "SecretList[?contains(Name, 'axonflow/$ENVIRONMENT')].Name" \
  --output table
```

### Step 3: Verify JSON Format (CRITICAL)

**For each secret, verify it's valid JSON:**

```bash
# Check database password
SECRET_NAME="axonflow/staging/database-password"
REGION="eu-central-1"

# Get secret value and validate JSON
aws secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --region "$REGION" \
  --query SecretString \
  --output text | jq .

# Should output:
# {
#   "password": "your-password-here"
# }
```

**Common Issues:**

❌ **Plain Text Secret:**
```bash
$ aws secretsmanager get-secret-value ... | jq .
parse error: Invalid numeric literal at line 1, column 1
```

✅ **Valid JSON Secret:**
```bash
$ aws secretsmanager get-secret-value ... | jq .
{
  "password": "CPzepXqCplGh3eTnibB3"
}
```

### Step 4: Verify Required JSON Fields

**Database passwords must have `password` field:**
```json
{
  "password": "your-password-here"
}
```

**Connector credentials must have all required fields:**

```json
// Amadeus
{
  "api_key": "...",
  "api_secret": "..."
}

// Salesforce
{
  "client_id": "...",
  "client_secret": "...",
  "instance_url": "...",
  "username": "...",
  "password": "..."
}

// Slack
{
  "bot_token": "xoxb-..."
}

// Snowflake
{
  "account": "...",
  "username": "...",
  "warehouse": "...",
  "database": "...",
  "schema": "...",
  "role": "..."
}

// OpenAI
{
  "api_key": "sk-..."
}

// Anthropic
{
  "api_key": "sk-ant-..."
}

// Azure OpenAI
{
  "endpoint": "https://your-resource.cognitiveservices.azure.com",
  "api_key": "...",
  "deployment_name": "gpt-4o-mini"
}

// Google Gemini
{
  "api_key": "..."
}
```

### Step 5: Credential Encryption (v4.1.0+)

As of Platform v4.1.0, connector credentials stored in the database are encrypted at rest using **AES-256-GCM**. This applies to all connector configurations registered via the orchestrator API.

**How it works:**
- The `CredentialEncryptor` uses AES-256-GCM with a cached cipher for performance
- Credentials in `ConnectorConfigDB` are tagged `json:"-"` to prevent accidental serialization
- The encryption key is derived from the `AXONFLOW_CREDENTIAL_ENCRYPTION_KEY` environment variable
- Credential fields are auto-detected via `hasCredentials()` which checks for keys like `api_key`, `api_secret`, `client_secret`, `password`, `bot_token`, `private_key`, and others

**Required environment variable:**
```bash
export AXONFLOW_CREDENTIAL_ENCRYPTION_KEY="your-32-byte-base64-encoded-key"
```

**Generate a key:**
```bash
openssl rand -base64 32
```

**Checklist:**
- [ ] `AXONFLOW_CREDENTIAL_ENCRYPTION_KEY` is set in all environments
- [ ] Key is stored in AWS Secrets Manager (not in plaintext config files)
- [ ] Key is the same across all services in a given environment (orchestrator + agent)
- [ ] Key rotation plan documented (re-encrypt existing credentials after rotation)

> **Important:** If `AXONFLOW_CREDENTIAL_ENCRYPTION_KEY` is not set, the platform will refuse to start. This is a hard requirement as of v4.1.0.

### Step 6: Fix Plain Text Secrets

**If a secret is plain text, convert to JSON:**

```bash
# Get current value
SECRET_NAME="axonflow/staging/database-password"
REGION="eu-central-1"
PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --region "$REGION" \
  --query SecretString \
  --output text)

# Convert to JSON
aws secretsmanager update-secret \
  --secret-id "$SECRET_NAME" \
  --secret-string "{\"password\":\"$PASSWORD\"}" \
  --region "$REGION"

# Verify
aws secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --region "$REGION" \
  --query SecretString \
  --output text | jq .
```

### Step 7: Verify CloudWatch Log Groups Exist

**Log groups must exist BEFORE deployment:**

```bash
ENVIRONMENT=staging
REGION=eu-central-1

# Check if log groups exist
aws logs describe-log-groups \
  --region "$REGION" \
  --log-group-name-prefix "/ecs/axonflow-${ENVIRONMENT}"
```

**If missing, CloudFormation will create them during deployment.**

### Step 8: Verify TaskExecutionRole Permissions

**Check IAM role has Secrets Manager permissions:**

```bash
# Find TaskExecutionRole from existing stack or CloudFormation template
ROLE_NAME="ecsTaskExecutionRole"  # or your custom role name

# Check Secrets Manager permissions
aws iam list-attached-role-policies --role-name "$ROLE_NAME"
aws iam list-role-policies --role-name "$ROLE_NAME"

# Should have:
# - AmazonECSTaskExecutionRolePolicy (managed policy)
# - Custom policy with secretsmanager:GetSecretValue
```

---

## Quick Validation Script

**Save as `scripts/validate-secrets.sh`:**

```bash
#!/bin/bash
set -e

ENVIRONMENT=$1
REGION=$2

if [[ -z "$ENVIRONMENT" ]] || [[ -z "$REGION" ]]; then
    echo "Usage: $0 <environment> <region>"
    echo "Example: $0 staging eu-central-1"
    exit 1
fi

echo "Validating secrets for $ENVIRONMENT in $REGION..."
echo ""

SECRETS=(
    "axonflow/$ENVIRONMENT/database-password"
    "axonflow/$ENVIRONMENT/database-app-password"
)

FAILED=0

for SECRET in "${SECRETS[@]}"; do
    echo "Checking $SECRET..."

    # Check if secret exists
    if ! aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" >/dev/null 2>&1; then
        echo "❌ SECRET MISSING: $SECRET"
        ((FAILED++))
        continue
    fi

    # Check if JSON is valid
    if ! aws secretsmanager get-secret-value --secret-id "$SECRET" --region "$REGION" --query SecretString --output text | jq . >/dev/null 2>&1; then
        echo "❌ INVALID JSON: $SECRET (plain text detected)"
        ((FAILED++))
        continue
    fi

    echo "✅ OK: $SECRET"
done

echo ""
if [[ $FAILED -eq 0 ]]; then
    echo "✅ All secrets valid!"
    exit 0
else
    echo "❌ $FAILED secrets failed validation"
    exit 1
fi
```

**Usage:**
```bash
chmod +x scripts/validate-secrets.sh
./scripts/validate-secrets.sh staging eu-central-1
```

---

## Common Issues & Solutions

### Issue 1: Container Crashes with No Logs

**Symptoms:**
- ECS circuit breaker triggers after 3-4 container restarts
- CloudWatch log streams exist but have 0 bytes
- No application logs written

**Root Cause:**
- Plain text secret instead of JSON
- ECS fails during secret injection (before app starts)

**Solution:**
- Verify secret format: `aws secretsmanager get-secret-value ... | jq .`
- Convert to JSON if needed (Step 5 above)

### Issue 2: "pq: password is required" Error

**Symptoms:**
- Agent service fails during database migrations
- Error in logs: "pq: password is required"

**Root Cause:**
- `dblink` extension trying to connect without password
- Session variable not set correctly

**Solution:**
- Verify migration 017 uses session variables correctly
- Check agent sets `app.db_password` before running migrations

### Issue 3: Secrets Manager Permission Denied

**Symptoms:**
- Container crash with: "AccessDeniedException"
- CloudWatch logs show secret fetch failure

**Root Cause:**
- TaskExecutionRole missing Secrets Manager permissions

**Solution:**
```bash
# Add Secrets Manager permissions to execution role
aws iam put-role-policy \
  --role-name ecsTaskExecutionRole \
  --policy-name SecretsManagerAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "secretsmanager:GetSecretValue"
        ],
        "Resource": "arn:aws:secretsmanager:*:*:secret:axonflow/*"
      }
    ]
  }'
```

---

## Environment-Specific Checklists

### Staging (eu-central-1)

**Required Secrets:**
- [x] axonflow/staging/database-password (JSON format verified)
- [x] axonflow/staging/database-app-password (JSON format verified)
- [x] axonflow/staging/openai-credentials (JSON format verified)
- [x] axonflow/staging/anthropic-credentials (JSON format verified)
- [x] axonflow/staging/amadeus-credentials (JSON format verified)
- [x] axonflow/staging/salesforce-credentials (JSON format verified)
- [x] axonflow/staging/slack-credentials (JSON format verified)
- [x] axonflow/staging/snowflake-credentials (JSON format verified)

### Production (eu-central-1)

**Required Secrets:**
- [x] axonflow/production/database-password (JSON format verified)
- [x] axonflow/production/database-app-password (JSON format verified)
- [ ] axonflow/production/openai-credentials (MISSING - need to create)
- [ ] axonflow/production/anthropic-credentials (MISSING - need to create)
- [x] axonflow/production/amadeus-credentials (JSON format verified)

**Note:** Production has plain text `-api-key` secrets but CloudFormation references `-credentials`

### Production US (us-east-1)

**Status:** Active (axonflow-production-us stack)

**Required Secrets:**
- [x] axonflow/production/database-password (JSON format verified)
- [x] axonflow/production/database-app-password (JSON format verified)
- [x] axonflow/production/openai-credentials (JSON format verified)
- [x] axonflow/production/anthropic-credentials (JSON format verified)
- [x] axonflow/production/credential-encryption-key (JSON format verified)

### Production India (ap-south-1)

**Status:** Active (axonflow-production-banking-india stack)

**Required Secrets:**
- [x] axonflow/production/database-password (JSON format verified)
- [x] axonflow/production/database-app-password (JSON format verified)
- [x] axonflow/production/credential-encryption-key (JSON format verified)

> **Note:** Use `./scripts/sync-secrets.sh --sync-from us-east-1 --environment production` to synchronize secrets across regions. Verify `private_key` fields are present in connector credentials after sync.

---

## References

- CloudFormation Template: `platform/aws-marketplace/cloudformation-ecs-fargate.yaml`
- Secret Creation Script: `scripts/create-secrets.sh`
- Deployment Guide: `technical-docs/DEPLOYMENT_QUICK_REFERENCE.md`
- AWS Docs: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data-secrets.html

---

## Last Verified

- **Date:** February 2026
- **Verified By:** AxonFlow Team
- **Platform Version:** v4.2.0
- **Status:** All active regions validated (us-east-1 production, ap-south-1 production, eu-central-1 staging). Credential encryption (AES-256-GCM) verified operational.
