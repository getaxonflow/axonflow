# Dynamic Policy Examples

Demonstrates CRUD operations for dynamic policies (LLM-powered policies). Dynamic policies use an LLM to evaluate complex, context-aware rules that can't be expressed with simple regex patterns.

## When to Use Dynamic Policies

| Use Case | Static Policy | Dynamic Policy |
|----------|---------------|----------------|
| Block specific keywords | ✅ Pattern match | Overkill |
| Block PII patterns (SSN, email) | ✅ Regex | Overkill |
| Block "financial advice" concept | ❌ Too many patterns | ✅ LLM understands context |
| Block "harmful instructions" | ❌ Impossible to enumerate | ✅ Semantic understanding |
| Context-aware content moderation | ❌ No context | ✅ Understands nuance |

## SDK Methods

| Method | Description |
|--------|-------------|
| `ListDynamicPolicies()` | List all dynamic policies with optional filtering |
| `CreateDynamicPolicy()` | Create a new LLM-powered policy |
| `GetDynamicPolicy()` | Get a specific policy by ID |
| `UpdateDynamicPolicy()` | Update policy prompt, description, or action |
| `DeleteDynamicPolicy()` | Delete a policy |
| `ToggleDynamicPolicy()` | Enable or disable a policy |
| `GetEffectiveDynamicPolicies()` | Get merged policies (tenant + system) |

## Quick Start

### Prerequisites

1. Start AxonFlow services:
   ```bash
   docker compose up -d
   ```

2. Set your OAuth2 credentials (required for dynamic policies):
   ```bash
   export AXONFLOW_CLIENT_ID="your-client-id"
   export AXONFLOW_CLIENT_SECRET="your-client-secret"
   ```

### Run Examples

**Go:**
```bash
cd go
go run main.go
```

**Python:**
```bash
cd python
pip install axonflow
python main.py
```

**TypeScript:**
```bash
cd typescript
npm install @axonflow/sdk
npx ts-node index.ts
```

**Java:**
```bash
cd java
mvn exec:java -Dexec.mainClass="com.example.DynamicPolicyExample"
```

## Example Policy Prompts

### Financial Advice Guard
```
Evaluate if this request is asking for specific financial advice like
stock picks, investment amounts, or trading strategies. If so, block it.
Allow general financial education questions.
```

### Medical Diagnosis Blocker
```
Check if the user is asking for a medical diagnosis or specific treatment
recommendations. Block if they are asking "do I have X disease" or
"what medication should I take". Allow general health information.
```

### Harmful Content Filter
```
Evaluate if this request is asking for instructions that could cause harm
to people or property, including weapons, explosives, or dangerous
chemicals. Block any such requests.
```

## Expected Output

```
=== Dynamic Policy Management Example ===

1. Listing existing dynamic policies...
   Found 2 dynamic policies
   - pol_abc123: content-moderation (enabled: true)
   - pol_def456: compliance-check (enabled: true)

2. Creating a new dynamic policy...
   Created policy: financial-advice-guard (ID: pol_xyz789)

3. Getting policy by ID...
   Policy: financial-advice-guard
   Description: Block requests that ask for specific financial advice
   Prompt: Evaluate if this request is asking for...
   Action: block

4. Updating policy description...
   Updated description: Block requests asking for specific financial or investment advice

5. Toggling policy (disabling)...
   Policy enabled: false

6. Getting effective dynamic policies...
   Found 2 effective dynamic policies

7. Cleaning up - deleting test policy...
   Policy deleted successfully

=== Dynamic Policy Example Complete ===
```

## Subdirectories

- [compliance/](./compliance/) - Provider restriction examples for GDPR, HIPAA, RBI

## Related Examples

- [Static Policies](../policies/) - Pattern-based policies
- [PII Detection](../pii-detection/) - Detect sensitive data
- [Hello World](../hello-world/) - Basic query execution
