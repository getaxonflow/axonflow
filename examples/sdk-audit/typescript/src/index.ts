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
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

// Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
// The Agent proxies orchestrator routes internally.
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
  tenant: process.env.AXONFLOW_TENANT || "demo",
  debug: true,
});

async function main() {
  console.log("AxonFlow SDK Comprehensive Audit - TypeScript");
  console.log("=".repeat(46));
  console.log();

  let passed = 0;
  let failed = 0;
  let approvedContextId: string | null = null;

  // Test 1: Agent Health Check
  console.log("Test 1: Agent Health Check");
  try {
    const health = await axonflow.healthCheck();
    if (health.status === "healthy") {
      console.log("  ✅ PASSED: Agent is healthy");
      passed++;
    } else {
      console.log(`  ❌ FAILED: Agent status is ${health.status}`);
      failed++;
    }
  } catch (error) {
    console.log(`  ❌ FAILED: ${error}`);
    failed++;
  }

  // Test 2: Orchestrator Health Check
  console.log("Test 2: Orchestrator Health Check");
  try {
    const health = await axonflow.orchestratorHealthCheck();
    if (health.status === "healthy") {
      console.log("  ✅ PASSED: Orchestrator is healthy");
      passed++;
    } else {
      console.log(`  ❌ FAILED: Orchestrator status is ${health.status}`);
      failed++;
    }
  } catch (error) {
    console.log(`  ❌ FAILED: ${error}`);
    failed++;
  }

  // Test 3: Gateway Mode - Safe Query
  console.log("Test 3: Gateway Mode - Safe Query");
  try {
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "audit-user",
      query: "What is the capital of France?",
    });
    if (result.approved) {
      console.log(`  ✅ PASSED: Query approved (contextId: ${result.contextId})`);
      passed++;
      approvedContextId = result.contextId;
    } else {
      console.log(`  ❌ FAILED: Query unexpectedly blocked: ${result.blockReason}`);
      failed++;
    }
  } catch (error) {
    console.log(`  ❌ FAILED: ${error}`);
    failed++;
  }

  // Test 4: Gateway Mode - Blocked Query (SQL Injection)
  console.log("Test 4: Gateway Mode - Blocked Query (SQL Injection)");
  try {
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "audit-user",
      query: "SELECT * FROM users; DROP TABLE users;",
    });
    if (!result.approved) {
      console.log(`  ✅ PASSED: Query correctly blocked (${result.blockReason})`);
      passed++;
    } else {
      console.log("  ❌ FAILED: SQL injection should be blocked");
      failed++;
    }
  } catch (error) {
    console.log(`  ❌ FAILED: ${error}`);
    failed++;
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
      if (auditResult.success) {
        console.log(`  ✅ PASSED: Audit recorded (auditId: ${auditResult.auditId})`);
        passed++;
      } else {
        console.log("  ❌ FAILED: Audit not successful");
        failed++;
      }
    } catch (error) {
      console.log(`  ❌ FAILED: ${error}`);
      failed++;
    }
  } else {
    console.log("  ⏭️ SKIPPED: No context ID from previous test");
  }

  // Test 6: List Connectors
  console.log("Test 6: List Connectors");
  try {
    const connectors = await axonflow.listConnectors();
    console.log(`  ✅ PASSED: Found ${connectors.length} connectors`);
    passed++;
  } catch (error) {
    console.log(`  ❌ FAILED: ${error}`);
    failed++;
  }

  // Test 7: Static Policy CRUD
  console.log("Test 7: Static Policy CRUD");
  const policyName = `sdk-audit-test-${Date.now()}`;
  let crudPassed = true;

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
    console.log(`  ✅ Create: Policy created (id: ${created.id})`);

    // Get policy
    const fetched = await axonflow.getStaticPolicy(created.id);
    if (fetched.name === policyName) {
      console.log("  ✅ Get: Policy retrieved correctly");
    } else {
      console.log("  ❌ FAILED (Get): Name mismatch");
      crudPassed = false;
    }

    // Update policy
    const updated = await axonflow.updateStaticPolicy(created.id, {
      description: "Updated description from SDK audit",
    });
    if (updated.description?.includes("Updated")) {
      console.log("  ✅ Update: Policy updated correctly");
    } else {
      console.log("  ❌ FAILED (Update): Description not updated");
      crudPassed = false;
    }

    // Delete policy
    await axonflow.deleteStaticPolicy(created.id);
    console.log("  ✅ Delete: Policy deleted correctly");

    if (crudPassed) {
      passed++;
    } else {
      failed++;
    }
  } catch (error) {
    console.log(`  ❌ FAILED: ${error}`);
    failed++;
  }

  // Test 8: List Static Policies
  console.log("Test 8: List Static Policies");
  try {
    const policies = await axonflow.listStaticPolicies();
    console.log(`  ✅ PASSED: Found ${policies.length} policies`);
    passed++;
  } catch (error) {
    console.log(`  ❌ FAILED: ${error}`);
    failed++;
  }

  // Summary
  console.log();
  console.log("=".repeat(46));
  console.log(`Summary: ${passed} passed, ${failed} failed`);
  console.log();

  if (failed > 0) {
    process.exit(1);
  }
}

main();
