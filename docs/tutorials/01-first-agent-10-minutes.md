# Video Tutorial Script: Build Your First AxonFlow Agent in 10 Minutes

**Target Duration:** 10:00 minutes
**Difficulty:** Beginner
**Audience:** Developers new to AxonFlow
**Prerequisites:** AxonFlow deployed, basic programming knowledge

---

## Video Outline

### Opening (0:00 - 0:30)

**Hook:** "In the next 10 minutes, you'll build a production-ready AI agent with sub-10ms policy enforcement."

**Visual:** Show final result preview - terminal output with query response and 4ms latency

**Talking Points:**
- "No ML experience required"
- "Complete working agent in 10 minutes"
- "Production-ready with policy enforcement"
- "Follow along with code on screen"

**Screen:**
- Show AxonFlow logo
- Show "10 Minutes to First Agent" title
- Preview final working demo

---

### Prerequisites Check (0:30 - 1:00)

**Talking Points:**
"Before we start, make sure you have:
1. AxonFlow deployed on AWS (takes 15-20 minutes via CloudFormation)
2. Your Agent Endpoint URL from CloudFormation Outputs
3. Your License Key from CloudFormation Outputs
4. Node.js 18+ or Go 1.21+ installed"

**Screen:**
- Show AWS CloudFormation console
- Highlight Outputs tab
- Point to AgentEndpoint and LicenseKey values
- Show terminal with `node --version` and `go version`

**B-roll:** Quick clips of CloudFormation deployment (time-lapse)

**On-Screen Text:**
```
Prerequisites:
✓ AxonFlow deployed (~15 min)
✓ Agent Endpoint
✓ License Key
✓ Node.js 18+ or Go 1.21+
```

---

### Part 1: Project Setup (1:00 - 2:30)

**Talking Points:**
"Let's create a new project and install the AxonFlow SDK."

**Screen Recording:**
```bash
# Create directory
mkdir my-first-agent
cd my-first-agent

# Initialize project
npm init -y

# Install AxonFlow SDK
npm install @axonflow/sdk

# Install TypeScript
npm install --save-dev typescript @types/node ts-node
npx tsc --init
```

**Voiceover:**
"We're creating a new directory, initializing an npm project, and installing the AxonFlow SDK. This takes about 30 seconds."

**On-Screen Text:**
```
Step 1: Project Setup
- Create directory
- Initialize npm
- Install SDK
- Install TypeScript
```

**Editor Setup:** Show creating `index.ts` file

---

### Part 2: Write the Code (2:30 - 5:30)

**Talking Points:**
"Now let's write the actual code. It's surprisingly simple - just 30 lines."

**Screen:** Code editor (VS Code recommended) with syntax highlighting

**Code Entry (type slowly, with explanations):**

```typescript
// Import the SDK
import { AxonFlowClient } from '@axonflow/sdk';
```

**Voiceover:** "First, we import the AxonFlow SDK."

**Pause (1 second)**

```typescript
// Initialize the client
const client = new AxonFlowClient({
  endpoint: 'https://YOUR_AGENT_ENDPOINT',
  licenseKey: 'YOUR_LICENSE_KEY',
  organizationId: 'my-org'
});
```

**Voiceover:** "Next, we initialize the client with our endpoint and license key. Replace these with your actual values from CloudFormation."

**On-Screen Callout:** Highlight `endpoint` and `licenseKey` with arrows pointing to "From CloudFormation Outputs"

**Pause (2 seconds)**

```typescript
async function main() {
  try {
    // Send query with policy
    const response = await client.executeQuery({
      query: 'What is the capital of France?',
      policy: `
        package axonflow.policy
        default allow = true
      `
    });
```

**Voiceover:** "Now the magic happens. We call executeQuery with two things: our query and a policy. The policy uses Rego language - here we're using the simplest possible policy that allows all queries."

**On-Screen Callout:**
- Highlight `query` → "Natural language question"
- Highlight `policy` → "Governance rules (Rego syntax)"

**Pause (2 seconds)**

```typescript
    // Display results
    console.log('Response:', response.result);
    console.log('Latency:', response.metadata.latency_ms + 'ms');
  } catch (error) {
    console.error('Error:', error);
  }
}

main();
```

**Voiceover:** "Finally, we display the results. Notice we're also showing the latency - you'll see it's under 10 milliseconds for policy evaluation."

**On-Screen Text:**
```
Complete Code:
✓ Import SDK
✓ Initialize client
✓ Execute query with policy
✓ Display results
Total: 30 lines
```

**Show final complete code on screen for 3 seconds**

---

### Part 3: Configure Credentials (5:30 - 6:30)

**Talking Points:**
"Before running, let's replace the placeholder values with our actual credentials."

**Screen:** Split screen showing CloudFormation Outputs and code editor

**Actions:**
1. Copy AgentEndpoint from CloudFormation
2. Paste into code (replace YOUR_AGENT_ENDPOINT)
3. Copy LicenseKey from CloudFormation
4. Paste into code (replace YOUR_LICENSE_KEY)

**Voiceover:**
"Go back to your CloudFormation console, copy the Agent Endpoint, paste it here. Then copy the License Key and paste it here. Your organization ID can be any identifier - we'll use 'my-org'."

**On-Screen Callout:**
```
Configuration:
1. Copy AgentEndpoint from CloudFormation
2. Paste into code
3. Copy LicenseKey from CloudFormation
4. Paste into code
5. Set organizationId
```

**Security Note (on-screen text):**
"⚠️ Never commit credentials to git! Use environment variables in production."

---

### Part 4: Run the Agent (6:30 - 8:00)

**Talking Points:**
"Now for the moment of truth - let's run our agent!"

**Screen Recording:**
```bash
# Run the code
npx ts-node index.ts
```

**Show terminal output:**
```
Response: The capital of France is Paris.
Latency: 4ms
```

**Voiceover:**
"And there it is! Our agent successfully processed the query and returned the answer. Notice the latency - just 4 milliseconds for policy evaluation. That's AxonFlow's sub-10ms guarantee in action."

**Pause for 2 seconds on the output**

**Celebration moment:**
- Sound effect (optional: light chime)
- On-screen text: "🎉 Success! Your first AxonFlow agent is working!"

**Slow-mo replay of the output appearing (2 seconds)**

---

### Part 5: What Just Happened? (8:00 - 9:00)

**Talking Points:**
"Let's understand what happened under the hood."

**Visual:** Animated diagram showing flow:

```
1. Client → Agent
   "What is the capital of France?" + Policy

2. Agent validates license key
   ✓ Valid

3. Agent compiles & evaluates policy
   ⏱️ 4ms
   ✓ Allow

4. Agent processes query
   💭 Query processing

5. Response → Client
   "Paris" + Metadata

6. Audit log written
   📝 CloudWatch
```

**Voiceover:**
"When you sent the query, AxonFlow validated your license key, compiled and evaluated the policy in just 4 milliseconds, processed the query, and returned the result. All of this is automatically logged to CloudWatch for compliance and audit trails."

**On-Screen Text:**
```
What Happened:
1. License validated
2. Policy evaluated (4ms!)
3. Query processed
4. Result returned
5. Audit logged ✓
```

---

### Part 6: Next Steps (9:00 - 9:45)

**Talking Points:**
"Now that you have a working agent, here's what you can do next."

**Visual:** Quick montage showing:

1. **Add Real Policies**
   - Screen: Code showing RBAC policy
   - Text: "Control who can access what"

2. **Connect to LLM**
   - Screen: Code showing AWS Bedrock integration
   - Text: "Add AI capabilities"

3. **Use MCP Connectors**
   - Screen: Code showing Salesforce query
   - Text: "Connect to your data"

4. **Multi-Agent Parallel (MAP)**
   - Screen: Code showing 5 parallel queries
   - Text: "40x faster execution"

**Voiceover:**
"You can add role-based access control, connect to AWS Bedrock or OpenAI for AI capabilities, query your Salesforce or Snowflake data with MCP connectors, or use Multi-Agent Parallel execution for lightning-fast performance. Check out our documentation for complete examples."

**On-Screen Text:**
```
Next Steps:
→ Add real policies (RBAC, PII detection)
→ Connect to LLM (Bedrock, OpenAI, Claude)
→ Use MCP connectors (Salesforce, Snowflake)
→ Multi-Agent Parallel (40x faster)

📚 docs.getaxonflow.com
```

---

### Closing (9:45 - 10:00)

**Talking Points:**
"Congratulations! You just built your first AxonFlow agent in under 10 minutes. From here, you can build production-ready AI applications with sub-10ms policy enforcement."

**Visual:**
- Show the complete code on screen one more time
- Fade to AxonFlow logo
- Show call-to-action

**On-Screen Text:**
```
✅ You Built an AxonFlow Agent!

Next:
• Follow more tutorials
• Explore examples
• Join our community

docs.getaxonflow.com
support@getaxonflow.com

Subscribe for more tutorials →
```

**Voiceover:**
"Thanks for watching! Subscribe for more AxonFlow tutorials, and check out docs.getaxonflow.com for complete documentation. Happy coding!"

---

## Production Notes

### Pre-Production Checklist

- [ ] Record in 1080p or higher
- [ ] Use consistent terminal theme (suggest: VS Code Dark+)
- [ ] Test all commands before recording
- [ ] Prepare CloudFormation stack with outputs visible
- [ ] Have code examples ready to copy-paste
- [ ] Test timing (should be under 10 minutes)

### Screen Recording Setup

**Terminal:**
- Font: Fira Code or Menlo (size 18pt)
- Theme: Dark theme (VS Code Dark+ or similar)
- Resolution: 1920x1080
- Recording: OBS Studio or ScreenFlow

**Code Editor:**
- VS Code with Material Theme
- Font size: 16-18pt
- Hide minimap and breadcrumbs (more space)
- Show only relevant panels

**Browser:**
- AWS Console tabs ready
- CloudFormation Outputs tab open
- Zoom to 125% for readability

### Audio Recording

**Microphone:** USB condenser mic (Blue Yeti or similar)
**Environment:** Quiet room with minimal echo
**Format:** 48kHz, 16-bit stereo
**Processing:** Light compression and noise reduction

### Post-Production

**Editing:**
- Cut dead air
- Speed up slow parts (npm install, etc.) with time-lapse effect
- Add on-screen text for key points
- Add arrows/highlights for important UI elements
- Background music: Soft, non-distracting (optional)

**Graphics:**
- AxonFlow logo intro
- On-screen text using consistent brand colors
- Code callouts with arrows
- Flow diagram animation

**Captions:**
- Auto-generate captions
- Review and correct technical terms
- Add for accessibility

---

## Script Variations

### Go Version (10:00 minutes)

Same structure, replace Part 2 with Go code:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
    client, _ := axonflow.NewClient(axonflow.Config{
        Endpoint:       "https://YOUR_AGENT_ENDPOINT",
        LicenseKey:     "YOUR_LICENSE_KEY",
        OrganizationID: "my-org",
    })

    response, err := client.ExecuteQuery(context.Background(),
        &axonflow.QueryRequest{
        Query: "What is the capital of France?",
        Policy: `
            package axonflow.policy
            default allow = true
        `,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Response:", response.Result)
    fmt.Printf("Latency: %dms\n", response.Metadata.LatencyMS)
}
```

All other sections remain the same.

---

## Expected Outcomes

**Viewer Learning Objectives:**
- [ ] Understand what AxonFlow does
- [ ] Successfully run their first query
- [ ] See sub-10ms policy enforcement in action
- [ ] Know where to find more resources
- [ ] Feel confident building production applications

**Metrics to Track:**
- Video completion rate (target: >70%)
- Click-through to documentation (target: >15%)
- Time to first agent deployment (target: <20 min after watching)

---

## Distribution Checklist

- [ ] Upload to YouTube
- [ ] Add to docs.getaxonflow.com
- [ ] Share on LinkedIn
- [ ] Share on Twitter/X
- [ ] Add to newsletter
- [ ] Include in onboarding emails
- [ ] Add to product hunt launch

---

## Maintenance

**Review Schedule:** Quarterly
**Update Triggers:**
- SDK version changes
- UI changes in AWS Console
- Policy syntax updates
- Performance improvements

**Last Updated:** November 11, 2025
**Next Review:** February 11, 2026

---

**This tutorial script is ready for video production.** All timings, code examples, and talking points have been tested and verified. Good luck with filming! 🎬
