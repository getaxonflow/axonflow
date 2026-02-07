# Code Governance Examples

These examples demonstrate AxonFlow's Code Governance feature - automatic detection and auditing of LLM-generated code.

## What is Code Governance?

When an LLM generates code in response to a user query, AxonFlow automatically:

1. **Detects** code blocks in the response
2. **Identifies** the programming language
3. **Categorizes** the code type (function, class, script, etc.)
4. **Counts** potential security issues (secrets, unsafe patterns)
5. **Logs** metadata for audit and compliance

## Examples by Language

| Language | Directory | Description |
|----------|-----------|-------------|
| Python | `python/` | Async SDK example with code artifact detection |
| TypeScript | `typescript/` | TypeScript SDK with policyInfo access |
| Go | `go/` | Go SDK demonstrating raw response parsing |
| Java | `java/` | Java SDK with Map-based artifact extraction |

## Prerequisites

- AxonFlow Agent running on localhost:8080 (or configured via environment)
- OpenAI or Anthropic API key configured in AxonFlow
- Language-specific SDK installed

## Running the Examples

### Python

```bash
cd python
cp .env.example .env  # Edit with your settings
pip install -r requirements.txt
python main.py
```

### TypeScript

```bash
cd typescript
cp .env.example .env  # Edit with your settings
npm install
npm start
```

### Go

```bash
cd go
export AXONFLOW_AGENT_URL=http://localhost:8080
go run main.go
```

### Java

```bash
cd java
export AXONFLOW_AGENT_URL=http://localhost:8080
mvn compile exec:java
```

## Code Artifact Response

Each example shows how to access the `code_artifact` field in the response:

```json
{
  "policy_info": {
    "code_artifact": {
      "is_code_output": true,
      "language": "python",
      "code_type": "function",
      "size_bytes": 245,
      "line_count": 12,
      "secrets_detected": 0,
      "unsafe_patterns": 0
    }
  }
}
```

## Use Cases

- **Compliance Auditing**: Track all AI-generated code for regulatory compliance
- **Security Monitoring**: Alert on unsafe patterns before deployment
- **Usage Analytics**: Build dashboards for AI code generation metrics
- **Policy Enforcement**: Block code with secrets or dangerous patterns

## Documentation

See the full [Code Governance documentation](https://docs.getaxonflow.com/docs/features/code-governance) for more details.
