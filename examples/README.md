# AxonFlow Examples

**Production-ready examples for common use cases** - Get started quickly with complete, tested code.

---

## Available Examples

| Example | Description | Complexity | Time to Deploy |
|---------|-------------|------------|----------------|
| [hello-world](./hello-world/) | Simplest possible example (30 lines) | Beginner | 5 minutes |
| healthcare-assistant | HIPAA-compliant medical AI assistant | Advanced | 30 minutes |
| ecommerce-recommendations | Product recommendation engine | Intermediate | 20 minutes |
| customer-support | Automated support chatbot | Intermediate | 20 minutes |
| travel | Multi-agent travel planning | Advanced | 30 minutes |

---

## Quick Start

### 1. Hello World (Recommended First Step)

The absolute minimum code to use AxonFlow:

```bash
cd hello-world/typescript
npm install
npm start
```

See [hello-world/README.md](./hello-world/README.md) for details.

---

## Prerequisites

All examples require:
1. **AxonFlow deployed** - See [Getting Started Guide](https://docs.getaxonflow.com/docs/getting-started)
2. **License key** - From CloudFormation Outputs
3. **Agent endpoint** - From CloudFormation Outputs
4. **Node.js 18+** or **Go 1.21+**

---

## Example Structure

Each example follows this structure:

```
example-name/
├── README.md           # Complete documentation
├── typescript/         # TypeScript implementation
│   ├── package.json
│   ├── index.ts
│   └── .env.example
└── go/                 # Go implementation
    ├── go.mod
    ├── main.go
    └── .env.example
```

---

## Running Examples

### General Steps

```bash
# 1. Clone repository
git clone https://github.com/axonflow/axonflow
cd axonflow/examples/[example-name]

# 2. Choose language
cd typescript  # or: cd go

# 3. Configure
cp .env.example .env
# Edit .env with your credentials

# 4. Install dependencies
npm install    # or: go mod download

# 5. Run
npm start      # or: go run main.go
```

---

## Examples by Industry

### Healthcare
- **[healthcare-assistant](./healthcare-assistant/)** - HIPAA-compliant medical AI
  - Patient record access
  - PII detection and redaction
  - Role-based access control
  - Complete audit trail

### Retail / E-commerce
- **[ecommerce-recommendations](./ecommerce-recommendations/)** - Product recommendations
  - Collaborative filtering
  - Real-time personalization
  - Inventory management
  - Dynamic pricing

### Customer Support
- **[customer-support](./customer-support/)** - Automated support
  - Ticket automation
  - Knowledge base search
  - Escalation workflows
  - Multi-language support

### Travel
- **[travel](./travel/)** - AI travel assistant
  - Flight and hotel search
  - Multi-agent coordination (MAP)
  - MCP connector integration
  - LLM-powered itineraries

---

## Examples by Complexity

### Beginner
Start here if you're new to AxonFlow:
- **[hello-world](./hello-world/)** - 30 lines, 5 minutes

### Intermediate
After mastering the basics:
- **[ecommerce-recommendations](./ecommerce-recommendations/)** - 20 minutes
- **[customer-support](./customer-support/)** - 20 minutes

### Advanced
For production deployments:
- **[healthcare-assistant](./healthcare-assistant/)** - HIPAA compliance, RBAC
- **[travel](./travel/)** - MAP, MCP, service identity

---

## Examples by Features

### Policy Enforcement
All examples demonstrate policy enforcement. Highlights:
- **[healthcare-assistant](./healthcare-assistant/)** - HIPAA minimum necessary rule
- **[ecommerce-recommendations](./ecommerce-recommendations/)** - Dynamic pricing policies

### MCP Connectors
Connect to real data sources:
- **[travel](./travel/)** - Amadeus API (flights, hotels)
- **[healthcare-assistant](./healthcare-assistant/)** - FHIR/EHR integration
- **[customer-support](./customer-support/)** - Zendesk, Salesforce

### Multi-Agent Parallel (MAP)
Execute multiple agents in parallel:
- **[travel](./travel/)** - 5 agents in parallel (flights + hotels + activities + weather + restaurants)

### LLM Integration
Connect to AWS Bedrock, OpenAI, or Anthropic:
- **[travel](./travel/)** - Claude for itinerary generation
- **[customer-support](./customer-support/)** - GPT-4 for response generation

---

## Configuration

All examples use environment variables for configuration:

```bash
# Required for all examples
AXONFLOW_ENDPOINT=https://your-agent-endpoint
AXONFLOW_LICENSE_KEY=AXON-V2-xxx-yyy
AXONFLOW_ORG_ID=my-org

# Optional: MCP connector credentials
SALESFORCE_CLIENT_ID=xxx
SALESFORCE_CLIENT_SECRET=yyy
SNOWFLAKE_ACCOUNT=xxx
SNOWFLAKE_USERNAME=yyy
```

**Security Note:** Never commit `.env` files to git. Always use `.env.example` as a template.

---

## Testing Examples

Each example includes tests:

```bash
# TypeScript
npm test

# Go
go test ./...
```

---

## Customizing Examples

All examples are MIT licensed and can be freely customized for your use case:

1. **Fork the repository**
2. **Modify for your needs**
3. **Deploy to production**
4. **Contribute back** (optional)

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

## Support

**Questions about examples?**

- **Email:** support@getaxonflow.com
- **Documentation:** https://docs.getaxonflow.com
- **GitHub Issues:** https://github.com/axonflow/axonflow/issues
- **Examples Documentation:** https://docs.getaxonflow.com/docs/examples/overview

---

## Contributing

We welcome contributions! To add a new example:

1. Follow the standard structure (typescript/ and go/ subdirectories)
2. Include comprehensive README.md
3. Add .env.example files
4. Include tests
5. Update this README
6. Submit pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

---

## License

All examples are licensed under MIT License. See [LICENSE](../LICENSE) for details.

---

**Ready to get started?** Begin with [hello-world](./hello-world/) and build your first AxonFlow agent in 5 minutes! 🚀
