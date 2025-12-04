# Serko Demo FAQ & Talking Points

**Purpose:** Prepared answers for anticipated questions during/after the Serko VP Infrastructure demo
**Audience:** VP Infrastructure, Engineering Leadership
**Focus Areas:** Technical Architecture, EU AI Act, Deployment, Integration, Security

---

## Technical Architecture

### Q: "How does AxonFlow actually intercept AI requests?"

**Short Answer:**
> "AxonFlow acts as a proxy layer between your application and AI providers. You replace your AI endpoint URL with AxonFlow's endpoint, and we forward requests after policy evaluation."

**Detailed Answer:**
> "There are three integration patterns:
> 1. **SDK Integration** - Our Go, Python, or Node.js SDKs wrap your existing AI client with policy enforcement built in
> 2. **Proxy Mode** - Point your AI requests to our endpoint instead of directly to OpenAI/Claude
> 3. **Gateway Mode** - Deploy AxonFlow as a network gateway that intercepts traffic transparently
>
> Most customers start with SDK integration for maximum control, then evaluate Gateway Mode for legacy applications."

### Q: "What's the latency impact?"

**Short Answer:**
> "Sub-30 milliseconds at the 95th percentile. You saw this in the demo - our audit logs showed 20-25ms for policy evaluation."

**Detailed Answer:**
> "Our policy engine is written in Go with hot-path optimizations. We evaluate policies in parallel, not sequentially, so adding more policies doesn't linearly increase latency.

> For context:
> - p50 latency: ~15ms
> - p95 latency: ~25ms
> - p99 latency: ~40ms
>
> This is negligible compared to AI inference time (typically 1-5 seconds). Your users won't notice the governance layer."

### Q: "What happens if AxonFlow is unavailable?"

**Short Answer:**
> "You can configure fail-open or fail-closed behavior. Most customers use fail-open with enhanced logging."

**Detailed Answer:**
> "AxonFlow supports three failure modes:
> 1. **Fail-open** - If AxonFlow is unreachable, requests proceed directly to the AI provider. All requests are logged locally and reconciled later.
> 2. **Fail-closed** - If AxonFlow is unreachable, requests are blocked. Used in high-security environments.
> 3. **Degraded mode** - Essential policies only, skip non-critical evaluations.
>
> Our SLA is 99.9% uptime for SaaS, and In-VPC deployments inherit your infrastructure's availability."

---

## EU AI Act Compliance

### Q: "Which EU AI Act articles does AxonFlow address?"

**Short Answer:**
> "Articles 10, 13, 14, and 17 primarily - covering data governance, transparency, human oversight, and record-keeping."

**Detailed Answer:**
> "Here's the mapping:
>
> | Article | Requirement | AxonFlow Feature |
> |---------|-------------|------------------|
> | Article 10 | Data governance & quality | PII redaction, data minimization policies |
> | Article 13 | Transparency | Complete audit trail, decision logging |
> | Article 14 | Human oversight | Alert policies, manual approval workflows |
> | Article 17 | Quality management | Compliance dashboards, export for audits |
>
> We also support GDPR Articles 44-50 for cross-border data transfers, which you saw in the passport redaction scenario."

### Q: "Is AxonFlow itself certified for EU AI Act compliance?"

**Short Answer:**
> "The EU AI Act doesn't certify vendors - it places obligations on deployers. AxonFlow is a tool that helps you meet those obligations."

**Detailed Answer:**
> "EU AI Act compliance is about demonstrable practices, not vendor certifications. What we provide:
> - **Technical documentation** showing how our features map to each article
> - **Audit-ready exports** in formats regulators expect
> - **Deployment guides** for data residency requirements
> - **Legal opinion** (from Clifford Chance) on our architecture's compliance posture
>
> Your compliance team should still do their own assessment, but we make that assessment straightforward."

### Q: "How do you handle the 'high-risk' classification for AI systems?"

**Short Answer:**
> "Travel booking AI likely falls under 'limited risk' rather than 'high risk' under EU AI Act classification. But AxonFlow supports both postures."

**Detailed Answer:**
> "High-risk AI systems under Annex III are things like biometric identification, credit scoring, and employment screening. Travel recommendations are generally 'limited risk.'
>
> However, financial decisions (like €8,500 bookings) can trigger human oversight requirements. AxonFlow lets you:
> 1. Define what constitutes 'high value' in your context
> 2. Automatically flag those requests
> 3. Create audit trails proving human oversight was available
>
> Better to over-comply than under-comply during the enforcement ramp-up period."

---

## Deployment & Infrastructure

### Q: "Can we deploy in our own VPC?"

**Short Answer:**
> "Yes. In-VPC deployment means AxonFlow runs in your AWS/GCP/Azure account. Zero data leaves your infrastructure."

**Detailed Answer:**
> "In-VPC deployment includes:
> - Terraform/CloudFormation templates for provisioning
> - Auto-scaling group configuration
> - Integration with your existing monitoring (Datadog, New Relic, CloudWatch)
> - Private subnet deployment with no public endpoints
> - License key activation (no phone-home except license validation)
>
> We recommend starting with SaaS for POC to prove value quickly, then migrating to In-VPC for production if your security team requires it."

### Q: "What about data residency? We need EU-only data processing."

**Short Answer:**
> "Our EU region (Frankfurt, eu-central-1) guarantees all data stays within EU. No replication outside EU."

**Detailed Answer:**
> "For EU data residency:
> - **SaaS EU Region**: Hosted in AWS Frankfurt. All data, logs, and backups are EU-only.
> - **In-VPC**: You control the region. Deploy in eu-central-1, eu-west-1, or any EU AWS region.
>
> Our architecture ensures:
> - Policy evaluation happens regionally
> - Audit logs are stored regionally
> - No cross-region data transfer
> - GDPR data processing agreement included in Enterprise contracts"

### Q: "How does this integrate with our existing observability stack?"

**Short Answer:**
> "We support Prometheus metrics export, OpenTelemetry traces, and webhook notifications to your alerting systems."

**Detailed Answer:**
> "Integration points:
> - **Metrics**: Prometheus `/metrics` endpoint with latency, request counts, policy triggers
> - **Logs**: JSON structured logs compatible with ELK, Splunk, Datadog
> - **Traces**: OpenTelemetry spans for each policy evaluation
> - **Alerts**: Webhooks to Slack, PagerDuty, or custom endpoints
>
> In-VPC deployments can also push to CloudWatch Logs and CloudWatch Metrics natively."

---

## Integration & SDK

### Q: "Which AI providers do you support?"

**Short Answer:**
> "OpenAI, Claude (Anthropic), Azure OpenAI, Google Vertex AI, Cohere, and any custom HTTP endpoint."

**Detailed Answer:**
> "We have native connectors for:
> - OpenAI (GPT-4, GPT-4o, GPT-3.5)
> - Anthropic (Claude 3.5 Sonnet, Claude 3 Opus, Claude 2)
> - Azure OpenAI (same models, Azure-hosted)
> - Google Vertex AI (Gemini Pro, PaLM 2)
> - Cohere (Command, Embed)
> - AWS Bedrock (Claude, Titan)
>
> For custom models (self-hosted, fine-tuned), we support any HTTP endpoint that accepts JSON requests."

### Q: "What does SDK integration look like?"

**Short Answer:**
> "Typically 5-10 lines of code change. You initialize our client with your existing AI client, and all requests go through AxonFlow."

**Detailed Answer:**
> "Here's a Go example:
>
> ```go
> // Before
> client := openai.NewClient(apiKey)
> resp, err := client.CreateChatCompletion(ctx, req)
>
> // After
> axClient := axonflow.NewClient(axonflowKey, axonflow.WithRegion("eu"))
> client := axClient.WrapOpenAI(openai.NewClient(apiKey))
> resp, err := client.CreateChatCompletion(ctx, req)
> ```
>
> Same API, same types, same error handling - just routed through AxonFlow."

### Q: "How do we define custom policies?"

**Short Answer:**
> "YAML-based policy language or UI builder. Policies define conditions and actions - what to match and what to do."

**Detailed Answer:**
> "Policy example:
>
> ```yaml
> name: high_value_transaction_alert
> description: Require human oversight for transactions over €5,000
> conditions:
>   - field: request.metadata.booking_value
>     operator: greater_than
>     value: 5000
>   - field: request.metadata.currency
>     operator: equals
>     value: EUR
> actions:
>   - type: alert
>     message: 'High-value transaction requires review'
>     eu_article: 'Article 14 - Human Oversight'
>   - type: log
>     level: warning
> ```
>
> Policies can also be created in our UI with a drag-and-drop builder. We'll show this in the technical deep-dive."

---

## Security & Compliance

### Q: "Are you SOC 2 certified?"

**Short Answer:**
> "Yes - SOC 2 Type II certified. Happy to share the report under NDA."

**Detailed Answer:**
> "Our SOC 2 Type II report covers:
> - Security (primary focus)
> - Availability
> - Confidentiality
>
> Report available under NDA. We also maintain:
> - ISO 27001 (in progress)
> - GDPR DPA available
> - Penetration testing annually (report available under NDA)"

### Q: "Does AxonFlow see our API keys?"

**Short Answer:**
> "In SDK mode, yes - but they're encrypted at rest and in transit. In Gateway mode, keys can be injected at the edge, never stored."

**Detailed Answer:**
> "Key handling options:
> 1. **SDK Mode**: Keys passed through AxonFlow, encrypted with AES-256, never logged
> 2. **Gateway Mode**: Keys stored in your secrets manager (AWS Secrets Manager, Vault), injected at forwarding time
> 3. **In-VPC**: Keys never leave your infrastructure
>
> We recommend Gateway Mode or In-VPC for maximum security posture."

### Q: "How do you handle data retention?"

**Short Answer:**
> "Configurable per customer. Default is 90 days for audit logs, but you can extend to 7 years for compliance."

**Detailed Answer:**
> "Retention configuration:
> - **Audit logs**: Default 90 days, configurable up to 7 years
> - **Request/response content**: Optional, can be disabled entirely or limited to metadata only
> - **Metrics**: 30 days hot, 1 year cold storage
>
> For EU AI Act, we recommend 7-year retention on audit logs since the regulation references ongoing compliance evidence requirements."

---

## Pricing & Commercials

### Q: "What's the pricing model?"

**Short Answer:**
> "Per-request pricing with volume tiers. Enterprise starts at custom minimums with committed spend discounts."

**Detailed Answer:**
> "Pricing tiers:
> - **Starter**: Pay-as-you-go, $X per 1,000 requests
> - **Growth**: $X/month includes Y requests, then $X per 1,000
> - **Enterprise**: Custom pricing based on volume commitment
>
> In-VPC adds a platform fee but eliminates per-request costs. For a company at Serko's scale, Enterprise with In-VPC is typically most cost-effective."

### Q: "Is there a free trial?"

**Short Answer:**
> "Yes - 14-day free trial with full features. No credit card required. EU region available."

**Detailed Answer:**
> "Trial includes:
> - Full feature access (all policy types, audit exports)
> - EU region for data residency testing
> - 100,000 requests included
> - Slack support during trial
>
> Most customers convert trial to paid within 2 weeks of starting integration."

---

## Competitive Questions

### Q: "How are you different from LangChain/LlamaIndex guardrails?"

**Short Answer:**
> "Those are client-side libraries. AxonFlow is an enterprise platform with audit trails, compliance dashboards, and team management."

**Detailed Answer:**
> "Key differences:
>
> | Feature | LangChain Guardrails | AxonFlow |
> |---------|---------------------|----------|
> | Architecture | Client-side library | Centralized platform |
> | Audit trail | Build your own | Built-in, export-ready |
> | Policy management | Code changes | YAML/UI, no deploys |
> | Multi-tenant | DIY | Native support |
> | Compliance reporting | None | EU AI Act dashboards |
> | Support | Community | Enterprise SLA |
>
> LangChain is great for prototyping. AxonFlow is for production enterprise deployments."

### Q: "Why not build this ourselves?"

**Short Answer:**
> "You could, but it's 6-12 months of engineering time for a non-differentiating capability. We're production-ready today."

**Detailed Answer:**
> "Build vs. buy considerations:
>
> **Build:**
> - 6-12 months to production
> - 2-3 engineers ongoing maintenance
> - Compliance expertise required
> - Distraction from core product
>
> **Buy (AxonFlow):**
> - Production in 1-2 weeks
> - No ongoing maintenance
> - Compliance expertise included
> - Focus on your core business
>
> The question is: is AI governance a differentiator for Serko, or is it table stakes? For most companies, it's table stakes - don't build table stakes."

---

## Serko-Specific Questions

### Q: "How would this work with our Amadeus integration?"

**Short Answer:**
> "AxonFlow sits between your application and AI providers, not between you and Amadeus. Amadeus data that flows to AI would be governed."

**Detailed Answer:**
> "Architecture with Amadeus:
>
> ```
> User Request
>      |
> Serko App --> Amadeus API (flights, hotels)
>      |
> Serko App --> AxonFlow --> Claude/OpenAI (recommendations)
>      |
> Response to User
> ```
>
> AxonFlow governs the AI layer. Amadeus data like booking values and PII that you send to AI for processing would be subject to our policies."

### Q: "Can you handle our request volume?"

**Short Answer:**
> "Yes. We process millions of requests per day across customers. Sub-30ms latency at scale."

**Detailed Answer:**
> "Scale characteristics:
> - Horizontal auto-scaling
> - 100,000+ requests/second capacity
> - Regional isolation (EU traffic stays in EU)
>
> For POC, we'll set up dedicated capacity in EU region. For production, we'll right-size based on your actual traffic patterns during evaluation."

---

## Closing Talking Points

### If They're Interested

> "Great. Here's what I recommend as next steps:
> 1. **Technical deep-dive** - 60 minutes with your engineering team next week
> 2. **POC setup** - We can have you integrated with staging in 5 days
> 3. **Security review** - I'll send over our SOC 2 report and architecture docs today"

### If They Need More Information

> "Completely understand. I'll send over:
> - Detailed architecture documentation
> - EU AI Act compliance mapping
> - Customer case studies from similar travel companies
>
> What would be most valuable for your evaluation?"

### If They're Skeptical

> "I appreciate the directness. What would you need to see to feel confident this could work for Serko? I'm happy to arrange a technical deep-dive, provide reference customers, or set up a proof-of-concept in your environment."

---

*Prepared for Serko VP Infrastructure Demo - December 2025*
