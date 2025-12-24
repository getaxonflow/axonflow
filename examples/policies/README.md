# Policy Management Examples

Examples demonstrating policy CRUD operations using the AxonFlow SDKs.

## Overview

These examples show how to:
- Create custom detection policies
- List and filter policies
- Test regex patterns before deployment
- Manage policy lifecycle

## SDKs Covered

| SDK | Directory | Language |
|-----|-----------|----------|
| [TypeScript](./typescript/) | `typescript/` | TypeScript/Node.js |
| [Python](./python/) | `python/` | Python 3.10+ |
| [Go](./go/) | `go/` | Go 1.21+ |
| [Java](./java/) | `java/` | Java 17+ |

## Quick Start

### 1. Start AxonFlow

```bash
docker compose up -d
```

### 2. Choose Your SDK

**TypeScript:**
```bash
cd typescript
npm install
npm run create
```

**Python:**
```bash
cd python
pip install -r requirements.txt
python create_custom_policy.py
```

**Go:**
```bash
cd go
go run create_custom_policy.go
```

**Java:**
```bash
cd java
mvn compile exec:java -Pcreate
```

## Examples in Each SDK

| Example | Description |
|---------|-------------|
| `create-custom-policy` | Create a custom tenant-tier policy |
| `list-and-filter` | List policies with filters and pagination |
| `test-pattern` | Test regex patterns before saving |

## Policy Concepts

### Policy Types

| Type | Description | Location |
|------|-------------|----------|
| Static | Pattern-based (regex) rules | Agent (port 8080) |
| Dynamic | Condition-based rules | Orchestrator (port 8081) |

### Policy Tiers

| Tier | Scope | Editable |
|------|-------|----------|
| System | Platform-wide | No (read-only) |
| Organization | All tenants in org | Enterprise only |
| Tenant | Single tenant | Yes |

### Policy Categories

| Category | Description |
|----------|-------------|
| `security-sqli` | SQL injection detection |
| `security-admin` | Privilege escalation |
| `pii-global` | Global PII patterns |
| `pii-us` | US-specific (SSN, etc.) |
| `pii-eu` | EU-specific (GDPR) |
| `pii-india` | India-specific (Aadhaar, PAN) |
| `custom` | User-defined |

## Enterprise Examples

See [`/ee/examples/policies/`](../../ee/examples/policies/) for:
- Organization-tier policies
- System policy overrides
- Version history

## Industry Examples

See [`/ee/examples/industry/`](../../ee/examples/industry/) for:
- Banking (SWIFT, credit cards, IBAN)
- Healthcare (MRN, DEA, NPI, HIPAA)
- India Compliance (GSTIN, DL, Passport)

## Related Documentation

- [Policy Architecture ADR](../../technical-docs/architecture-decisions/ADR-018-policy-system-architecture.md)
- [Static Policies API](../../docs/api/agent-api.yaml)
- [Dynamic Policies API](../../docs/api/orchestrator-api.yaml)
