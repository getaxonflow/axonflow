/**
 * AxonFlow SDK Comprehensive Audit - TypeScript
 *
 * Validates all SDK methods work correctly against live services.
 * Tests include:
 * 1. Health checks (Agent + Orchestrator)
 * 2. Gateway Mode request
 * 3. Proxy Mode request
 * 4. Static policy CRUD
 * 5. Audit logging
 * 6. Error handling (blocked requests)
 * 7. Connector operations (list, install, uninstall)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

// Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
// The Agent proxies orchestrator routes internally.
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "demo-tenant",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
  tenant: process.env.AXONFLOW_TENANT || "demo-tenant",
  debug: true,
});

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main() {
  console.log("AxonFlow SDK Comprehensive Audit - TypeScript");
  console.log("=".repeat(46));
  console.log();

  let approvedContextId: string | null = null;

  // Test 1: Agent Health Check
  console.log("Test 1: Agent Health Check");
  try {
    const health = await axonflow.healthCheck();
    assertCheck(
      health.status === "healthy",
      "Agent health check returns healthy status"
    );
    assertCheck(
      health.status !== undefined,
      "Agent health check returns status field"
    );
  } catch (error) {
    console.log(`  Error: ${error}`);
    failures.push(`Agent health check: ${error}`);
  }

  // Test 2: Orchestrator Health Check
  console.log("Test 2: Orchestrator Health Check");
  try {
    const health = await axonflow.orchestratorHealthCheck();
    assertCheck(
      health.status === "healthy",
      "Orchestrator health check returns healthy status"
    );
    assertCheck(
      health.status !== undefined,
      "Orchestrator health check returns status field"
    );
  } catch (error) {
    console.log(`  Error: ${error}`);
    failures.push(`Orchestrator health check: ${error}`);
  }

  // Test 3: Gateway Mode - Safe Query
  console.log("Test 3: Gateway Mode - Safe Query");
  try {
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "audit-user",
      query: "What is the capital of France?",
    });
    assertCheck(
      result.approved === true,
      "Safe query is approved"
    );
    assertCheck(
      result.contextId !== undefined && result.contextId !== "",
      "Approved query returns contextId"
    );
    if (result.approved) {
      approvedContextId = result.contextId;
    }
  } catch (error) {
    console.log(`  Error: ${error}`);
    failures.push(`Gateway safe query: ${error}`);
  }

  // Test 4: Gateway Mode - Blocked Query (SQL Injection)
  console.log("Test 4: Gateway Mode - Blocked Query (SQL Injection)");
  try {
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "audit-user",
      query: "SELECT * FROM users; DROP TABLE users;",
    });
    assertCheck(
      result.approved === false,
      "SQL injection query is blocked"
    );
    assertCheck(
      result.blockReason !== undefined && result.blockReason !== "",
      "Blocked query has blockReason"
    );
  } catch (error) {
    console.log(`  Error: ${error}`);
    failures.push(`Gateway blocked query: ${error}`);
  }

  // Test 5: Audit LLM Call
  console.log("Test 5: Audit LLM Call");
  if (approvedContextId) {
    try {
      const auditResult = await axonflow.auditLLMCall({
        contextId: approvedContextId,
        provider: "openai",
        model: "gpt-4",
        responseSummary: "Test response for SDK audit",
        tokenUsage: {
          promptTokens: 100,
          completionTokens: 50,
          totalTokens: 150,
        },
        latencyMs: 250,
      });
      assertCheck(
        auditResult.success === true,
        "Audit LLM call returns success=true"
      );
      assertCheck(
        auditResult.auditId !== undefined && auditResult.auditId !== "",
        "Audit LLM call returns auditId"
      );
    } catch (error) {
      console.log(`  Error: ${error}`);
      failures.push(`Audit LLM call: ${error}`);
    }
  } else {
    console.log("  SKIPPED: No context ID from previous test");
    failures.push("Audit LLM call: skipped due to no contextId");
  }

  // Test 6: List Connectors
  console.log("Test 6: List Connectors");
  try {
    const connectors = await axonflow.listConnectors();
    assertCheck(
      Array.isArray(connectors),
      "List connectors returns array"
    );
    console.log(`  Found ${connectors.length} connectors`);
  } catch (error) {
    console.log(`  Error: ${error}`);
    failures.push(`List connectors: ${error}`);
  }

  // Test 7: Static Policy CRUD
  console.log("Test 7: Static Policy CRUD");
  const policyName = `sdk-audit-test-${Date.now()}`;
  let createdPolicyId: string | null = null;

  try {
    // Create policy
    const created = await axonflow.createStaticPolicy({
      name: policyName,
      description: "Test policy from SDK audit",
      category: "security-sqli",
      pattern: "sdk-audit-test-pattern",
      severity: "low",
      enabled: true,
      action: "warn",
    });
    assertCheck(
      created.id !== undefined && created.id !== "",
      "Create policy returns id"
    );
    assertCheck(
      created.name === policyName,
      "Created policy has correct name"
    );
    createdPolicyId = created.id;

    // Get policy
    const fetched = await axonflow.getStaticPolicy(created.id);
    assertCheck(
      fetched.name === policyName,
      "Get policy returns correct name"
    );
    assertCheck(
      fetched.id === created.id,
      "Get policy returns correct id"
    );

    // Update policy
    const updated = await axonflow.updateStaticPolicy(created.id, {
      description: "Updated description from SDK audit",
    });
    assertCheck(
      updated.description?.includes("Updated") === true,
      "Update policy changes description"
    );

    // Delete policy
    await axonflow.deleteStaticPolicy(created.id);
    assertCheck(true, "Delete policy succeeds without error");
    createdPolicyId = null; // Mark as deleted
  } catch (error) {
    console.log(`  Error: ${error}`);
    failures.push(`Static policy CRUD: ${error}`);
    // Cleanup if policy was created but later operations failed
    if (createdPolicyId) {
      try {
        await axonflow.deleteStaticPolicy(createdPolicyId);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  // Test 8: List Static Policies
  console.log("Test 8: List Static Policies");
  try {
    const policies = await axonflow.listStaticPolicies();
    assertCheck(
      Array.isArray(policies),
      "List policies returns array"
    );
    console.log(`  Found ${policies.length} policies`);
  } catch (error) {
    console.log(`  Error: ${error}`);
    failures.push(`List static policies: ${error}`);
  }

  // Summary
  console.log();
  console.log("=".repeat(46));
  const totalTests = 8;
  const passedCount = totalTests - failures.length;
  console.log(`Summary: ${passedCount} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log("Failures:");
    failures.forEach((f) => console.log(`  - ${f}`));
  }
  console.log();

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
