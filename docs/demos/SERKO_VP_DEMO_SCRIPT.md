# Serko VP Infrastructure Demo Script

**Audience:** VP Infrastructure & Engineering Leadership
**Duration:** 35 minutes (time-boxed)
**Focus:** EU AI Act Compliance for Travel Platforms
**Date Created:** December 3, 2025

---

## Pre-Demo Checklist

- [ ] Browser tabs open: Travel Demo, Customer Portal, AxonFlow Docs
- [ ] Demo mode verified working (run both scenarios once)
- [ ] Customer Portal shows recent audit data
- [ ] Backup screenshots ready (see SERKO_DEMO_ENVIRONMENT_CHECKLIST.md)
- [ ] Video recording enabled (optional)

---

## Demo Timeline Overview

| Time | Section | Duration | Key Message |
|------|---------|----------|-------------|
| 0:00 | Introduction | 3 min | AxonFlow solves EU AI Act compliance for AI-powered travel |
| 0:03 | Normal Travel Flow | 5 min | Show baseline user experience |
| 0:08 | Scenario 1: High-Value | 5 min | Article 14 human oversight in action |
| 0:13 | Customer Portal - Audit | 5 min | Complete audit trail for regulators |
| 0:18 | Scenario 2: Cross-Border PII | 5 min | GDPR + AI Act data minimization |
| 0:23 | Audit Trail - PII | 3 min | Prove PII was never exposed to AI |
| 0:26 | Compliance Dashboard | 3 min | Real-time compliance posture |
| 0:29 | Deployment Options | 3 min | SaaS vs In-VPC flexibility |
| 0:32 | Q&A Buffer | 3 min | Address immediate questions |

---

## Section 1: Introduction (3 minutes)

**Objective:** Set context and establish the problem we solve

### Opening Statement (30 seconds)

> "Thank you for your time today. I'm going to show you how AxonFlow enables travel platforms to deploy AI features while maintaining full EU AI Act and GDPR compliance - without slowing down your engineering teams."

### The Problem (1 minute)

> "Travel platforms face a unique challenge with EU AI Act compliance:
> - **Article 14** requires human oversight for high-risk AI decisions affecting consumers
> - **GDPR Articles 44-50** mandate data minimization for cross-border transfers
> - **Article 10** requires data governance for AI training and processing
>
> For a platform like Serko, every booking involves AI recommendations, cross-border data flows, and high-value transactions. Manual compliance is impossible at scale."

### The Solution (1 minute)

> "AxonFlow sits between your application and your AI providers - Claude, OpenAI, or internal models. It enforces compliance policies in real-time with sub-30ms latency. Today I'll show you exactly how this works with two scenarios specifically relevant to travel."

### Transition

> "Let me start by showing you the normal user experience, then we'll enable our EU AI Act demo mode."

---

## Section 2: Normal Travel Flow (5 minutes)

**Objective:** Establish baseline UX before showing policy enforcement

### Navigation Steps

1. **Open Travel Demo**
   - URL: `https://travel-eu.getaxonflow.com`
   - Expected: AxonFlow Travel homepage with trip planning form

2. **Enter Basic Trip Details**
   - Destination: "Barcelona, Spain"
   - Days: 5
   - Budget: Moderate
   - Click: "Plan My Trip"

3. **Show AI Response**
   - Expected: Itinerary generated in 5-15 seconds
   - Point out: Task execution details, duration metrics

### Talking Points

> "This is a standard AI-powered trip planning experience. The user enters their preferences, our multi-agent system queries flight availability, hotel options, and local activities, then synthesizes a personalized itinerary."

> "What you don't see is that every step of this process is being governed by AxonFlow. But for normal requests, there's zero friction - the policies are transparent."

### Click: "Plan Another Trip"

**Transition to Demo Mode**

> "Now let me show you what happens when we enable our EU AI Act compliance scenarios. I'm going to toggle Demo Mode to show you two specific policy enforcements."

---

## Section 3: Scenario 1 - High-Value Transaction (5 minutes)

**Objective:** Demonstrate EU AI Act Article 14 human oversight

### Navigation Steps

1. **Enable Demo Mode**
   - Locate toggle in top-right header: "Demo Mode"
   - Click toggle ON
   - Expected: Toggle shows "EU AI Act Demo Mode"

2. **Select Demo User**
   - Expected: Two user cards appear (Sarah Thompson, James Wilson)
   - Click: **Sarah Thompson** card
   - Read aloud her profile:
     - Role: Corporate Travel Manager
     - Company: TechGlobal NZ
     - Scenario: "High-Value Transaction Oversight"

3. **Review Pre-Filled Trip**
   - Destination: Paris, France (pre-filled, greyed out)
   - Days: 7 (pre-filled)
   - Budget: Luxury (pre-filled)
   - Note the "Ready to demonstrate" banner

4. **Execute Scenario**
   - Click: "Execute High-Value Transaction Oversight Scenario"
   - Watch: Loading spinner, "AxonFlow is analyzing this request..."

5. **Show Policy Enforcement Result**
   - Expected: Green checkmark with policy enforcement details
   - Highlight:
     - Action: **ALERT**
     - Policy: `eu_ai_act_high_value_transaction`
     - Message: "Transaction value €8,500 exceeds €5,000 threshold. Manual approval required"
     - EU Article: "Article 14 - Human Oversight"

### Talking Points

> "Sarah is booking a €8,500 first-class trip. Under EU AI Act Article 14, AI systems making decisions with significant financial impact require human oversight."

> "AxonFlow detected this is a high-value transaction and automatically flagged it for manual approval. The booking still proceeded - we don't block the user - but we created an audit trail showing this required human review."

> "This is exactly what regulators want to see: the AI made a recommendation, but a human has the opportunity to override it before the transaction completes."

**Transition**

> "Now let me show you how this appears in your compliance dashboard - the audit trail that proves Article 14 compliance to regulators."

---

## Section 4: Customer Portal - Audit Trail (5 minutes)

**Objective:** Show complete audit trail for regulatory compliance

### Navigation Steps

1. **Open Customer Portal**
   - URL: `https://app.getaxonflow.com`
   - Login if prompted (demo credentials)
   - Navigate: Click "Audit Logs" in sidebar

2. **Show Compliance Summary**
   - Expected: Dashboard showing:
     - Total Requests
     - Allowed / Blocked / Modified counts
     - Block Rate percentage
     - Average Latency

3. **Filter for Recent Activity**
   - Set date range: Today
   - Expected: Sarah Thompson's transaction visible

4. **Expand Transaction Details**
   - Find the entry with action "Alerted"
   - Click to expand (or hover)
   - Show:
     - Timestamp
     - User: sarah-thompson
     - Policy: High-Value Transaction Oversight
     - Latency: ~25ms
     - Full query context

5. **Demonstrate Export**
   - Click: "Export CSV" button
   - Explain: "This CSV can be provided directly to auditors"

### Talking Points

> "This is your compliance command center. Every AI request, every policy enforcement, every human override - it's all logged here with full context."

> "Notice the latency - 25 milliseconds. AxonFlow enforces compliance without impacting user experience. Your users never feel the governance layer."

> "The export functionality is critical for audits. When a regulator asks 'show me all high-value transactions flagged for human review in Q4', you click one button."

**Transition**

> "Now let me show you our second scenario - this one involves cross-border data flows and PII protection."

---

## Section 5: Scenario 2 - Cross-Border PII (5 minutes)

**Objective:** Demonstrate GDPR + EU AI Act Article 10 data minimization

### Navigation Steps

1. **Return to Travel Demo**
   - URL: `https://travel-eu.getaxonflow.com`
   - Or switch browser tab

2. **Click "Plan Another Trip"**
   - Resets form while keeping Demo Mode active

3. **Select Second Demo User**
   - Click: **James Wilson** card
   - Read aloud his profile:
     - Role: Sales Director
     - Company: Kiwi Exports Ltd
     - Scenario: "Cross-Border PII Minimization"

4. **Review Pre-Filled Trip**
   - Destination: Frankfurt, Germany (pre-filled)
   - Days: 5 (pre-filled)
   - Budget: Moderate (pre-filled)
   - Note: Passport number LA987654 is included

5. **Execute Scenario**
   - Click: "Execute Cross-Border PII Minimization Scenario"
   - Watch: Loading spinner

6. **Show Policy Enforcement Result**
   - Expected: Green checkmark with policy enforcement details
   - Highlight:
     - Action: **REDACT**
     - Policy: `eu_gdpr_cross_border_pii`
     - Message: "Passport number redacted to LA****54 before AI processing"
     - EU Article: "GDPR Articles 44-50 + EU AI Act Article 10"

### Talking Points

> "James is a New Zealand passport holder booking travel to the EU. His passport number LA987654 is required for the booking, but under GDPR, unnecessary PII shouldn't be exposed to AI systems."

> "Watch what happens - AxonFlow automatically redacted the passport number to LA****54 before it reached the AI. The AI never saw the full passport number."

> "This is data minimization in action. The booking completes normally, but we've provably reduced the PII exposure footprint."

**Transition**

> "Let me show you how this redaction appears in the audit log - proof that the AI never processed the full passport number."

---

## Section 6: Audit Trail - PII Redaction (3 minutes)

**Objective:** Prove PII was redacted before AI processing

### Navigation Steps

1. **Return to Customer Portal Audit Logs**
   - Refresh the page or navigate to Audit Logs

2. **Filter by Action: Modified**
   - Use Action dropdown, select "Modified"
   - Expected: James Wilson's redacted request visible

3. **Show Redaction Evidence**
   - Find entry with:
     - Action: "Modified"
     - Policy: "Cross-Border PII Minimization"
   - Expand to show:
     - Original query (truncated/masked in UI)
     - Modified query (with LA****54)

### Talking Points

> "This audit entry proves to any regulator that the passport number was redacted BEFORE AI processing. The timestamp, the policy name, the before/after - it's all here."

> "For GDPR audits, this is gold. You can prove you implemented data minimization, not just claim you did."

---

## Section 7: Compliance Dashboard (3 minutes)

**Objective:** Show real-time compliance posture

### Navigation Steps

1. **Navigate to Compliance Summary**
   - Return to top of Audit page
   - Or navigate to dedicated Compliance tab (if available)

2. **Show Key Metrics**
   - Point out:
     - Total requests processed
     - Policy enforcement breakdown
     - Average latency (emphasize <30ms)
     - Top triggered policies

3. **Show Top Policies**
   - Expected: List showing most-triggered policies
   - Point out: Both demo policies appear here

### Talking Points

> "This dashboard gives you real-time visibility into your AI compliance posture. You can see at a glance how many requests are being governed, what policies are triggering most often, and crucially - that latency stays under 30 milliseconds."

> "For a company like Serko processing thousands of AI requests per minute, this visibility is essential. You can't manage what you can't measure."

---

## Section 8: Deployment Options (3 minutes)

**Objective:** Address infrastructure and data residency concerns

### Talking Points (No Navigation Required)

> "AxonFlow offers two deployment models:
>
> **1. SaaS (Multi-tenant)**
> - Fastest time to value - integrate in days
> - EU region (Frankfurt) available for data residency
> - SOC 2 Type II certified
> - Ideal for: Initial deployment, testing, smaller workloads
>
> **2. In-VPC (Enterprise)**
> - Deployed in your AWS/GCP/Azure account
> - Zero data leaves your infrastructure
> - Same features, same APIs, your control
> - Ideal for: Regulated industries, large scale, maximum control
>
> Both models offer the same policy engine, the same audit capabilities, and the same compliance guarantees."

> "For a company like Serko with strict data residency requirements, I'd recommend starting with our EU SaaS region for initial POC, then evaluating In-VPC for production based on your infrastructure team's assessment."

---

## Section 9: Q&A Buffer (3 minutes)

**Objective:** Address immediate questions

### Common Questions Prepared

| Question | Quick Answer |
|----------|--------------|
| "What's the latency impact?" | Sub-30ms p95. We showed this in the audit logs - typical is 20-25ms. |
| "How do we define custom policies?" | YAML-based policy language or UI builder. We'll show this in a follow-up session. |
| "Can we try this in a POC?" | Yes - 14-day free trial with EU region, no credit card required. |
| "What AI providers do you support?" | Claude (Anthropic), OpenAI, Azure OpenAI, Cohere, and any custom endpoint. |
| "SOC 2 certification?" | Yes - Type II. Happy to share our audit report under NDA. |

### Closing Statement

> "Thank you for your time today. I've demonstrated two specific EU AI Act scenarios - human oversight for high-value transactions and data minimization for cross-border PII. Both are directly relevant to Serko's use cases."

> "Next steps I'd recommend:
> 1. **Technical deep-dive** - 60 minutes with your engineering team on SDK integration
> 2. **POC setup** - Get you running in your staging environment within a week
> 3. **Security review** - Share our SOC 2 report and architecture documentation"

> "Is there anything else you'd like to see, or shall we schedule that technical session?"

---

## Fallback Procedures

### If Travel Demo is Down

1. Open backup screenshots (prepare these before the demo)
2. Walk through screenshots explaining each step
3. State: "The demo environment is experiencing an issue. Let me show you recorded screenshots that demonstrate the same flow."

### If Customer Portal is Down

1. Show sample audit export CSV (prepare this before the demo)
2. Explain: "This is a sample export showing the audit format. The live demo is temporarily unavailable."

### If Demo Mode Doesn't Trigger

1. Try clearing browser cache and refreshing
2. If still failing, use screenshots
3. Explain: "The demo scenarios require our EU staging environment. Let me show you recorded evidence instead."

### If Questions Go Off-Script

1. Acknowledge the question
2. Note it for follow-up
3. Say: "That's an excellent question. I want to give you a thorough answer, so let me note that for our technical follow-up session."

---

## Post-Demo Actions

1. **Send follow-up email within 2 hours**
   - Thank you
   - Summary of what was shown
   - Links to documentation
   - Proposed next steps with calendar link

2. **Schedule technical deep-dive within 1 week**

3. **Provide SOC 2 report under NDA if requested**

4. **Log demo in CRM with notes**

---

## Technical URLs Reference

| Resource | URL |
|----------|-----|
| Travel Demo (Production) | https://travel-eu.getaxonflow.com |
| Customer Portal | https://app.getaxonflow.com |
| Documentation | https://docs.getaxonflow.com |
| SDK Reference | https://docs.getaxonflow.com/sdk |
| EU AI Act Guide | https://docs.getaxonflow.com/compliance/eu-ai-act |

---

*Generated for Serko VP Infrastructure Demo - December 2025*
