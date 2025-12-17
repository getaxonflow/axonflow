/**
 * AxonFlow Proxy Mode - TypeScript Example
 *
 * Proxy Mode wraps your AI calls with invisible governance:
 * - Your code stays almost the same
 * - AxonFlow intercepts and validates before execution
 * - Policy violations are caught automatically
 *
 * This example uses the protect() wrapper pattern.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import OpenAI from "openai";

const config = {
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
  tenant: process.env.AXONFLOW_TENANT || "demo",
};

async function main() {
  console.log("AxonFlow Proxy Mode - TypeScript Example");
  console.log("=".repeat(60));
  console.log();

  const axonflow = new AxonFlow({
    endpoint: config.endpoint,
    licenseKey: config.licenseKey,
    tenant: config.tenant,
    debug: true,
  });

  const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY || "",
  });

  // Example queries to demonstrate the protect() wrapper
  const queries = [
    {
      prompt: "What are the key benefits of AI governance in enterprise?",
      description: "Safe query - should pass",
    },
    {
      prompt: "Summarize the principles of responsible AI in 3 bullet points.",
      description: "Safe query - should pass",
    },
    {
      prompt: "SELECT * FROM users; DROP TABLE secrets;",
      description: "SQL injection - should be blocked",
    },
  ];

  for (let i = 0; i < queries.length; i++) {
    const { prompt, description } = queries[i];

    console.log(`\n${"-".repeat(60)}`);
    console.log(`Query ${i + 1}: ${description}`);
    console.log(`${"-".repeat(60)}`);
    console.log(`Prompt: "${prompt.substring(0, 50)}${prompt.length > 50 ? "..." : ""}"`);

    const startTime = Date.now();

    try {
      // Wrap your AI call with protect() - AxonFlow validates before execution
      const response = await axonflow.protect(async () => {
        return openai.chat.completions.create({
          model: "gpt-3.5-turbo",
          messages: [
            { role: "system", content: "You are a helpful assistant. Be concise." },
            { role: "user", content: prompt },
          ],
          max_tokens: 150,
        });
      });

      const latencyMs = Date.now() - startTime;
      const content = response.choices[0]?.message?.content || "";

      console.log(`\n  Status: SUCCESS`);
      console.log(`  Latency: ${latencyMs}ms`);
      console.log(`\n  Response:`);
      console.log(`    ${content.substring(0, 200)}${content.length > 200 ? "..." : ""}`);
    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      // Check if it's a policy violation
      if (errorMessage.includes("blocked") || errorMessage.includes("Policy")) {
        console.log(`\n  Status: BLOCKED (expected for query ${i + 1})`);
        console.log(`  Reason: ${errorMessage}`);
      } else {
        console.log(`\n  Status: ERROR`);
        console.log(`  Error: ${errorMessage}`);
      }
      console.log(`  Latency: ${latencyMs}ms`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Proxy Mode Demo Complete");
  console.log("=".repeat(60));
}

main().catch(console.error);
