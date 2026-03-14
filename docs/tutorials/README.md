# AxonFlow Tutorials

Step-by-step tutorials for getting started with AxonFlow.

## Tutorials

| Tutorial | Time | Difficulty | Description |
|----------|------|------------|-------------|
| [Build Your First Agent](./01-first-agent-10-minutes.md) | 10 min | Beginner | Create an agent, send a query, and see sub-10ms policy evaluation |
| [LLM Integration](./02-llm-integration.md) | 15 min | Intermediate | Route queries through AWS Bedrock, OpenAI, or Anthropic with policy enforcement |

## Prerequisites

- **Go 1.25+**, **Python 3.9+**, **Node.js 18+**, or **Java 17+** (tutorials include examples in multiple languages)
- **Docker** and **Docker Compose** (for local development)
- An AxonFlow SDK for your language of choice (see below)

## SDKs

All SDKs are at v4.1.0.

| Language | Package | Repository |
|----------|---------|------------|
| Go | `github.com/getaxonflow/axonflow-sdk-go/v4` | [axonflow-sdk-go](https://github.com/getaxonflow/axonflow-sdk-go) |
| Python | `axonflow` (PyPI) | [axonflow-sdk-python](https://github.com/getaxonflow/axonflow-sdk-python) |
| Java | `com.getaxonflow.sdk` (Maven Central) | [axonflow-sdk-java](https://github.com/getaxonflow/axonflow-sdk-java) |
| TypeScript | `@axonflow/sdk` (npm) | [axonflow-sdk-typescript](https://github.com/getaxonflow/axonflow-sdk-typescript) |

### Install

```bash
# Go
go get github.com/getaxonflow/axonflow-sdk-go/v4

# Python
pip3 install axonflow==4.1.0

# Java (Maven)
# Add to pom.xml:
#   <dependency>
#     <groupId>com.getaxonflow</groupId>
#     <artifactId>axonflow-sdk</artifactId>
#     <version>4.1.0</version>
#   </dependency>

# TypeScript
npm install @axonflow/sdk
```

## Related Documentation

- [Getting Started Guide](../getting-started.md) -- Deploy AxonFlow locally or on AWS
- [Local Development](../guides/local-development.md) -- Docker Compose setup for development
- [SDK Documentation](../sdk/README.md) -- Detailed SDK API reference
- [API Specifications](../api/) -- OpenAPI specs for the Agent and Orchestrator APIs
- [SDK Feature Coverage](../SDK_FEATURE_COVERAGE.md) -- Full method coverage matrix across all SDKs

## Guides

Beyond the step-by-step tutorials above, the [guides](../guides/) directory covers:

- Policy authoring with Rego
- MCP connector configuration
- Multi-Agent Parallel (MAP) execution
- PII detection and redaction
- RBAC and access control
- Production deployment

---

Last Updated: March 2026
