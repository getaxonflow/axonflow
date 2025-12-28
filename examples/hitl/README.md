# Human-in-the-Loop (HITL) Examples

This directory contains examples demonstrating the `require_approval` policy action, which triggers Human-in-the-Loop (HITL) workflows for AI oversight.

## What is `require_approval`?

The `require_approval` action pauses request execution and creates an approval request in the HITL queue, requiring human review before proceeding.

### Behavior by Edition

| Edition | Behavior |
|---------|----------|
| **Enterprise** | Full HITL queue with human review workflow |
| **Community** | Auto-approves immediately (upgrade path) |

## Use Cases

- **EU AI Act Article 14**: Human oversight for high-risk AI decisions
- **SEBI AI/ML Circular**: High-value transaction oversight for financial services
- **RBI FREE-AI**: Human review for sensitive banking operations
- **Admin Access**: Require approval for privileged operations

## Prerequisites

1. **AxonFlow running locally**:
   ```bash
   docker compose up -d
   ```

2. **SDK installed** (see language-specific instructions below)

## Examples

### TypeScript

```bash
cd typescript
npm install
npm run example
```

### Python

```bash
cd python
pip install -r requirements.txt
python require_approval_policy.py
```

### Go

```bash
cd go
go run require_approval_policy.go
```

### Java

```bash
cd java
mvn compile exec:java
```

## Example Output

```
AxonFlow HITL - require_approval Policy Example
============================================================

1. Creating HITL oversight policy...
   Created policy: e7f11860-774e-479e-a285-28a4c973ad36
   Name: High-Value Transaction Oversight
   Action: require_approval
   Tier: tenant

2. Testing pattern with sample inputs...

   Test results:
   ✓ HITL: "Transfer amount $5,000,000 to account..."
   ✓ HITL: "Transaction value ₹10,00,00,000..."
   ✓ HITL: "Total: €2500000..."
   ✗ PASS: "Payment of $500 completed..."
   ✗ PASS: "Amount: $999999..."

3. Creating admin access oversight policy...
   Created: Admin Access Detection
   Action: require_approval

4. Listing all HITL policies...
   Found 2 HITL policies:
   - High-Value Transaction Oversight (high)
   - Admin Access Detection (critical)

5. Cleaning up test policies...
   Deleted test policies

============================================================
Example completed successfully!

Note: In Community Edition, require_approval auto-approves.
Upgrade to Enterprise for full HITL queue functionality.
```

## Policy Actions Reference

| Action | Description | Priority |
|--------|-------------|----------|
| `block` | Immediately block request | Highest (5) |
| `require_approval` | Pause for human approval | High (4) |
| `redact` | Mask sensitive content | Medium (3) |
| `warn` | Log warning, allow request | Low (2) |
| `log` | Audit only | Lowest (1) |

## Related Documentation

- [Policy Overview](/docs/policies/overview)
- [EU AI Act Compliance](/docs/compliance/eu-ai-act)
- [SEBI AI/ML Compliance](/docs/compliance/sebi)
