# Video Tutorial Script: Adding LLM Integration to AxonFlow

**Target Duration:** 12:00 minutes
**Difficulty:** Intermediate
**Audience:** Developers who completed "First Agent" tutorial
**Prerequisites:** AxonFlow deployed, first agent working, AWS Bedrock access

---

## Video Outline

### Opening (0:00 - 0:45)

**Hook:** "Take your AxonFlow agent from simple queries to AI-powered responses with AWS Bedrock, OpenAI, or Claude."

**Visual:** Split screen showing:
- Left: Static response ("The capital is Paris")
- Right: AI-generated response (rich, contextual paragraph)

**Talking Points:**
- "Add AI capabilities to your agent in minutes"
- "Support for AWS Bedrock, OpenAI, and Anthropic Claude"
- "Policy enforcement on AI responses"
- "Production-ready error handling"

**Screen:**
- Show AxonFlow logo
- Show "LLM Integration" title
- Demo preview: AI-generated product description

**On-Screen Text:**
```
Adding LLM Integration
• AWS Bedrock ✓
• OpenAI ✓
• Anthropic Claude ✓
• With Policy Enforcement
```

---

### Part 1: Choose Your LLM Provider (0:45 - 2:00)

**Talking Points:**
"AxonFlow supports three major LLM providers. Let's compare them."

**Visual:** Table comparison

**On-Screen Table:**
```
| Provider      | Best For          | Cost    | Latency |
|---------------|-------------------|---------|---------|
| AWS Bedrock   | AWS customers     | Low     | 2-5s    |
| OpenAI        | Best quality      | Medium  | 1-3s    |
| Anthropic     | Long context      | Medium  | 2-4s    |
```

**Voiceover:**
"AWS Bedrock is perfect if you're already on AWS - it's cost-effective and no external API keys needed. OpenAI gives you GPT-4 for best quality. Anthropic Claude excels at long context and reasoning. For this tutorial, we'll use AWS Bedrock with Claude, but the pattern works for all providers."

**B-roll:** Quick clips of AWS Bedrock console, OpenAI playground, Claude interface

---

### Part 2: Setup AWS Bedrock (2:00 - 4:00)

**Talking Points:**
"First, we need to enable model access in AWS Bedrock."

**Screen Recording:** AWS Console

**Steps:**
1. Navigate to AWS Bedrock console
2. Click "Model access" in left sidebar
3. Click "Enable specific models"
4. Select "Anthropic Claude 3 Sonnet"
5. Click "Save changes"
6. Wait for "Access granted" status

**Voiceover:**
"In the AWS console, go to Amazon Bedrock, click Model access, and enable Anthropic Claude 3 Sonnet. This takes about 30 seconds. You'll see 'Access granted' when it's ready."

**On-Screen Callouts:**
- Arrow pointing to "Model access"
- Arrow pointing to "Claude 3 Sonnet"
- Highlight "Access granted" in green

**Checkpoint (on-screen):**
```
✓ AWS Bedrock console open
✓ Model access enabled
✓ Claude 3 Sonnet - Access granted
Ready to code!
```

---

### Part 3: Update Your Code (4:00 - 7:00)

**Talking Points:**
"Now let's modify our agent to use Bedrock. We only need to add one parameter."

**Screen:** Code editor (VS Code)

**Starting Code (show for 2 seconds):**
```typescript
const response = await client.executeQuery({
  query: 'What is the capital of France?',
  policy: policyContent
});
```

**Voiceover:**
"Here's our original code. To add LLM integration, we just add an 'llm' parameter."

**Type the new code:**
```typescript
const response = await client.executeQuery({
  query: 'Generate a professional product description for wireless noise-canceling headphones',
  policy: policyContent,
  llm: {
    provider: 'aws-bedrock',
    model: 'anthropic.claude-3-sonnet-20240229-v1:0',
    temperature: 0.7,
    max_tokens: 500
  }
});
```

**Voiceover while typing:**
"We change the query to something that needs AI generation - like creating a product description. Then we add the llm configuration. The provider is 'aws-bedrock', the model is Claude 3 Sonnet, temperature controls creativity, and max_tokens limits the response length."

**On-Screen Callouts:**
- Highlight `provider: 'aws-bedrock'` → "LLM provider"
- Highlight `model:` → "Specific model version"
- Highlight `temperature: 0.7` → "0.0 = deterministic, 1.0 = creative"
- Highlight `max_tokens: 500` → "Response length limit"

**Pause for 3 seconds to let viewers see the complete code**

---

### Part 4: Add Policy for LLM Responses (7:00 - 9:00)

**Talking Points:**
"Here's where AxonFlow shines - we can enforce policies on LLM responses."

**Show policy code:**
```rego
package axonflow.policy

# Allow LLM queries with content filtering
allow {
    input.llm.provider in ["aws-bedrock", "openai", "anthropic"]
    not contains_inappropriate_content
}

# Block responses containing sensitive topics
contains_inappropriate_content {
    sensitive_topics := ["violence", "illegal", "harmful"]
    some topic in sensitive_topics
    contains(lower(input.query), topic)
}

# Rate limiting for expensive LLM calls
deny["LLM rate limit exceeded"] {
    llm_calls_last_hour := count_llm_calls(input.context.user_id)
    llm_calls_last_hour > 100
}

# Cost control
deny["Token limit exceeded"] {
    input.llm.max_tokens > 1000
}
```

**Voiceover:**
"This policy allows LLM queries from approved providers, blocks sensitive content, implements rate limiting to control costs, and limits token usage. This is how you deploy AI safely in production."

**Animated Diagram:**
```
Query → Policy Check → LLM → Response → Policy Check → User
        ↓                                    ↓
      Block if:                          Block if:
      - Sensitive topic                  - Inappropriate content
      - Rate limited                     - Too long
      - Too expensive                    - Contains PII
```

**On-Screen Text:**
```
Policy Enforcement:
✓ Content filtering
✓ Rate limiting
✓ Cost control
✓ PII detection
Safe AI in production!
```

---

### Part 5: Run and See AI in Action (9:00 - 10:30)

**Talking Points:**
"Let's run our AI-powered agent!"

**Terminal:**
```bash
npx ts-node index.ts
```

**Show output (slowly, with highlight effect):**
```
🔌 Connecting to AxonFlow...
✅ Connected

📤 Generating product description...
⏱️  Generating... (2.3s)

✅ AI Response:

Introducing our premium wireless noise-canceling headphones - the perfect blend
of cutting-edge technology and superior comfort. Experience crystal-clear audio
with advanced active noise cancellation that adapts to your environment.

With 30-hour battery life, Bluetooth 5.0 connectivity, and plush memory foam
ear cushions, these headphones are engineered for all-day wear. The intuitive
touch controls and built-in voice assistant integration make them perfect for
work, travel, or leisure.

Whether you're focusing in a busy office or relaxing on a long flight, these
headphones deliver an immersive audio experience that transports you to your
own private concert hall.

📊 Stats:
- Latency: 2,347ms (LLM generation)
- Policy Check: 4ms ✓
- Tokens Used: 187 / 500
- Cost: ~$0.002
```

**Voiceover:**
"And there's our AI-generated product description! Notice it took about 2 seconds for the LLM to generate the response, but the policy check was still just 4 milliseconds. AxonFlow tracked the token usage and estimated cost automatically."

**Celebration Visual:**
- Confetti animation
- "🎉 AI-Powered Agent Working!"
- Highlight the professional quality of the response

---

### Part 6: Multiple LLM Providers (10:30 - 11:15)

**Talking Points:**
"You can easily switch between providers - just change one line."

**Visual:** Side-by-side code comparison

**AWS Bedrock:**
```typescript
llm: {
  provider: 'aws-bedrock',
  model: 'anthropic.claude-3-sonnet-20240229-v1:0'
}
```

**OpenAI:**
```typescript
llm: {
  provider: 'openai',
  model: 'gpt-4',
  api_key: process.env.OPENAI_API_KEY
}
```

**Anthropic Direct:**
```typescript
llm: {
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  api_key: process.env.ANTHROPIC_API_KEY
}
```

**Voiceover:**
"Switching providers is this easy. AWS Bedrock uses your AWS credentials automatically. For OpenAI or Anthropic direct, you just add your API key. The rest of your code stays exactly the same."

**On-Screen Text:**
```
Switch Providers Easily:
• AWS Bedrock (no API key needed)
• OpenAI (need API key)
• Anthropic (need API key)

Same code, different provider!
```

---

### Part 7: Production Best Practices (11:15 - 11:45)

**Talking Points:**
"Before going to production, follow these best practices."

**Visual:** Checklist animation

**On-Screen Checklist:**
```
Production Checklist:
✓ Set max_tokens to prevent runaway costs
✓ Implement rate limiting (per user/org)
✓ Add content filtering policies
✓ Monitor token usage and costs
✓ Use environment variables for API keys
✓ Set up CloudWatch alarms
✓ Test with various prompts
✓ Handle LLM timeouts gracefully
```

**Voiceover:**
"Always set max tokens to control costs. Implement rate limiting per user or organization. Add content filtering policies to block inappropriate content. Monitor your usage in CloudWatch. Never hardcode API keys - use environment variables. And always test with edge cases before deploying."

**Quick B-roll:** CloudWatch dashboard showing LLM metrics

---

### Closing (11:45 - 12:00)

**Talking Points:**
"Congratulations! Your AxonFlow agent is now AI-powered with enterprise-grade policy enforcement."

**Visual:**
- Show the complete code one more time
- Fade to AxonFlow logo
- Call-to-action

**On-Screen Text:**
```
✅ You Added LLM Integration!

What's Next:
• Connect to your database (next tutorial)
• Use MCP connectors
• Multi-Agent Parallel execution
• Deploy to production

docs.getaxonflow.com
support@getaxonflow.com

Subscribe for Part 3: Database Integration →
```

**Voiceover:**
"In the next tutorial, we'll connect to your database with MCP connectors. Subscribe to not miss it. Thanks for watching!"

---

## Code Examples

### Complete TypeScript Example

```typescript
import { AxonFlowClient } from '@axonflow/sdk';
import * as fs from 'fs';

const client = new AxonFlowClient({
  endpoint: process.env.AXONFLOW_ENDPOINT!,
  licenseKey: process.env.AXONFLOW_LICENSE_KEY!,
  organizationId: 'my-org'
});

async function generateWithLLM() {
  // Load policy
  const policy = fs.readFileSync('llm-policy.rego', 'utf-8');

  try {
    console.log('🔌 Connecting to AxonFlow...');
    console.log('✅ Connected\n');

    console.log('📤 Generating product description...');
    const startTime = Date.now();

    // Execute query with LLM
    const response = await client.executeQuery({
      query: 'Generate a professional product description for wireless noise-canceling headphones',
      policy: policy,
      llm: {
        provider: 'aws-bedrock',
        model: 'anthropic.claude-3-sonnet-20240229-v1:0',
        temperature: 0.7,
        max_tokens: 500
      },
      context: {
        user_id: 'marketing-team',
        purpose: 'product_description',
        timestamp: new Date().toISOString()
      }
    });

    const elapsedTime = Date.now() - startTime;

    console.log(`⏱️  Generating... (${(elapsedTime / 1000).toFixed(1)}s)\n`);
    console.log('✅ AI Response:\n');
    console.log(response.result);
    console.log('\n📊 Stats:');
    console.log(`- Latency: ${elapsedTime}ms (LLM generation)`);
    console.log(`- Policy Check: ${response.metadata.latency_ms}ms ✓`);
    console.log(`- Tokens Used: ${response.metadata.tokens_used} / ${response.metadata.max_tokens}`);
    console.log(`- Cost: ~$${(response.metadata.estimated_cost).toFixed(4)}`);

  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
}

generateWithLLM();
```

### Complete Go Example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	client, err := axonflow.NewClient(axonflow.Config{
		Endpoint:       os.Getenv("AXONFLOW_ENDPOINT"),
		LicenseKey:     os.Getenv("AXONFLOW_LICENSE_KEY"),
		OrganizationID: "my-org",
	})
	if err != nil {
		log.Fatal("Failed to create client:", err)
	}

	// Load policy
	policy, err := os.ReadFile("llm-policy.rego")
	if err != nil {
		log.Fatal("Failed to read policy:", err)
	}

	fmt.Println("🔌 Connecting to AxonFlow...")
	fmt.Println("✅ Connected\n")

	fmt.Println("📤 Generating product description...")
	startTime := time.Now()

	// Execute query with LLM
	response, err := client.ExecuteQuery(context.Background(), &axonflow.QueryRequest{
		Query:  "Generate a professional product description for wireless noise-canceling headphones",
		Policy: string(policy),
		LLM: &axonflow.LLMConfig{
			Provider:    "aws-bedrock",
			Model:       "anthropic.claude-3-sonnet-20240229-v1:0",
			Temperature: 0.7,
			MaxTokens:   500,
		},
		Context: map[string]interface{}{
			"user_id":   "marketing-team",
			"purpose":   "product_description",
			"timestamp": time.Now().Format(time.RFC3339),
		},
	})
	if err != nil {
		log.Fatal("❌ Error:", err)
	}

	elapsedTime := time.Since(startTime)

	fmt.Printf("⏱️  Generating... (%.1fs)\n\n", elapsedTime.Seconds())
	fmt.Println("✅ AI Response:\n")
	fmt.Println(response.Result)
	fmt.Println("\n📊 Stats:")
	fmt.Printf("- Latency: %dms (LLM generation)\n", elapsedTime.Milliseconds())
	fmt.Printf("- Policy Check: %dms ✓\n", response.Metadata.LatencyMS)
	fmt.Printf("- Tokens Used: %d / %d\n", response.Metadata.TokensUsed, response.Metadata.MaxTokens)
	fmt.Printf("- Cost: ~$%.4f\n", response.Metadata.EstimatedCost)
}
```

### Policy File (llm-policy.rego)

```rego
package axonflow.policy

import future.keywords

# Allow LLM queries with proper configuration
default allow = false

allow {
    input.llm.provider in ["aws-bedrock", "openai", "anthropic"]
    input.llm.max_tokens <= 1000
    not contains_inappropriate_content
    not rate_limit_exceeded
}

# Content filtering
contains_inappropriate_content {
    sensitive_topics := ["violence", "illegal", "harmful", "explicit"]
    some topic in sensitive_topics
    contains(lower(input.query), topic)
}

# Rate limiting (100 LLM calls per hour per user)
rate_limit_exceeded {
    # In production, query external rate limit service
    false  # Placeholder - implement with Redis or DynamoDB
}

# Cost control
deny["Token limit exceeded - max 1000 tokens allowed"] {
    input.llm.max_tokens > 1000
}

# Audit logging
log_llm_usage {
    metadata := {
        "llm_provider": input.llm.provider,
        "llm_model": input.llm.model,
        "tokens_requested": input.llm.max_tokens,
        "user_id": input.context.user_id,
        "purpose": input.context.purpose,
        "timestamp": input.context.timestamp
    }
}
```

---

## Production Notes

### Pre-Production Checklist

- [ ] AWS Bedrock access enabled
- [ ] Test with all three providers
- [ ] Record at 1080p minimum
- [ ] Prepare example prompts
- [ ] Test policy enforcement
- [ ] Verify costs in AWS console

### Screen Recording Tips

**Terminal Output:**
- Use colored output for better visibility
- Add timestamps to show LLM latency
- Show token usage and cost estimation
- Highlight policy enforcement messages

**Code Editor:**
- Use syntax highlighting for Rego policies
- Show before/after comparison
- Add inline comments for clarity

### B-roll Suggestions

- AWS Bedrock console (model selection)
- CloudWatch logs showing LLM calls
- Cost dashboard in AWS
- Token usage graphs
- Multiple LLM responses side-by-side

---

## Distribution & SEO

**Title:** "Add AI to Your App in 10 Minutes | AWS Bedrock + AxonFlow Tutorial"

**Description:**
"Learn how to integrate AWS Bedrock, OpenAI, or Claude with AxonFlow for enterprise-grade AI applications. Includes policy enforcement, cost control, and production best practices. Complete code examples in TypeScript and Go."

**Tags:** aws bedrock, claude ai, openai, llm integration, ai development, typescript tutorial, go tutorial, policy enforcement

**Thumbnail:** Split screen showing code and AI-generated output

---

## Maintenance

**Update Triggers:**
- New LLM provider support
- SDK version changes
- AWS Bedrock model updates
- Policy syntax changes

**Review Schedule:** Quarterly
**Last Updated:** November 11, 2025
**Next Review:** February 11, 2026

---

**Ready for production!** This tutorial teaches LLM integration with real-world best practices. 🎬
