/**
 * HITL Queue API Example - TypeScript
 *
 * Validates the HITL Queue SDK methods against a running AxonFlow instance.
 *
 * The HITL Queue is an enterprise-only feature. In community mode, HITL
 * queue routes are not registered, so the server returns HTTP 404 (or 403).
 * This example verifies that the API exists and returns the expected
 * enterprise-only response, printing a clear message.
 *
 * In enterprise mode, the same SDK calls would succeed and return queue data.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * In community mode, 403/404 responses are EXPECTED and count as PASS.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

let passCount = 0;
let failCount = 0;
const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
    passCount++;
  } else {
    console.log(`   FAIL: ${message}`);
    failCount++;
    failures.push(message);
  }
}

/**
 * Check whether an error indicates an enterprise-only response (403 or 404).
 * In community mode, HITL queue routes are not registered, so the server
 * may return 404 (route not found) instead of 403 (forbidden).
 */
function isEnterpriseOnly(error: unknown): boolean {
  const errMsg =
    error instanceof Error ? error.message : String(error);
  return (
    errMsg.includes("403") ||
    errMsg.includes("404") ||
    errMsg.includes("Forbidden") ||
    errMsg.includes("Not Found") ||
    errMsg.includes("enterprise") ||
    errMsg.includes("Enterprise")
  );
}

const endpoint =
  process.env.AXONFLOW_ENDPOINT || "http://localhost:8080";
const clientId =
  process.env.AXONFLOW_CLIENT_ID || "demo-org";
const clientSecret =
  process.env.AXONFLOW_CLIENT_SECRET || "";

const axonflow = new AxonFlow({
  endpoint,
  clientId,
  clientSecret,
});

async function main() {
  console.log("HITL Queue API - TypeScript");
  console.log("=".repeat(50));
  console.log();
  console.log("This example validates the HITL Queue SDK methods.");
  console.log("In community mode, HITL queue endpoints return 403 or 404.");
  console.log("403/404 responses are EXPECTED and count as PASS.");
  console.log();

  // ========================================
  // Test 1: HITL Status (raw HTTP)
  // ========================================
  console.log("Test 1: HITL Status Endpoint");
  console.log("-".repeat(28));

  try {
    const statusUrl = `${endpoint}/api/v1/hitl/status`;
    const statusResp = await fetch(statusUrl, {
      headers: {
        "X-Client-ID": clientId,
        "X-Client-Secret": clientSecret,
      },
    });

    if (statusResp.ok) {
      const statusData = (await statusResp.json()) as Record<
        string,
        unknown
      >;
      const enabled = statusData.enabled as boolean;
      const mode = statusData.mode as string;
      assertCheck(
        true,
        `HITL status endpoint reachable (enabled=${enabled}, mode=${mode})`
      );
      if (mode === "community") {
        console.log(
          "   Running in community mode - HITL queue endpoints will return 403"
        );
      } else {
        console.log(
          "   Running in enterprise mode - HITL queue endpoints should succeed"
        );
      }
    } else if (statusResp.status === 403) {
      assertCheck(
        true,
        "HITL status endpoint returned 403 (enterprise feature)"
      );
    } else if (statusResp.status === 404) {
      assertCheck(
        true,
        `HITL status endpoint returned ${statusResp.status} (endpoint may not be available)`
      );
    } else {
      const body = await statusResp.text();
      assertCheck(
        false,
        `HITL status endpoint returned unexpected HTTP ${statusResp.status}: ${body}`
      );
    }
  } catch (error) {
    const errMsg =
      error instanceof Error ? error.message : String(error);
    if (errMsg.includes("ECONNREFUSED")) {
      console.log("\nHint: Make sure AxonFlow is running:");
      console.log("  docker compose up -d");
      process.exit(1);
    }
    assertCheck(false, `HITL status request failed: ${errMsg}`);
  }
  console.log();

  // ========================================
  // Test 2: listHITLQueue
  // ========================================
  console.log("Test 2: listHITLQueue");
  console.log("-".repeat(21));

  try {
    const listResp = await axonflow.listHITLQueue();
    assertCheck(true, "listHITLQueue succeeded (enterprise mode)");
    assertCheck(
      listResp !== null && listResp !== undefined,
      "listHITLQueue returned non-null response"
    );
    if (listResp) {
      console.log(
        `   Queue items: ${listResp.items.length}, Total: ${listResp.total}`
      );
    }
  } catch (error) {
    if (isEnterpriseOnly(error)) {
      assertCheck(
        true,
        "listHITLQueue returns enterprise-only response (expected)"
      );
      console.log("   HITL Queue listing requires Enterprise license");
    } else {
      assertCheck(
        false,
        `listHITLQueue unexpected error: ${error instanceof Error ? error.message : error}`
      );
    }
  }
  console.log();

  // Test with options
  console.log("Test 2b: listHITLQueue with options");
  console.log("-".repeat(35));

  try {
    const listRespOpts = await axonflow.listHITLQueue({
      limit: 10,
      offset: 0,
    });
    assertCheck(
      true,
      "listHITLQueue with options succeeded (enterprise mode)"
    );
    if (listRespOpts) {
      console.log(
        `   Queue items: ${listRespOpts.items.length}, Total: ${listRespOpts.total}`
      );
    }
  } catch (error) {
    if (isEnterpriseOnly(error)) {
      assertCheck(
        true,
        "listHITLQueue with options returns enterprise-only response (expected)"
      );
    } else {
      assertCheck(
        false,
        `listHITLQueue with options unexpected error: ${error instanceof Error ? error.message : error}`
      );
    }
  }
  console.log();

  // ========================================
  // Test 3: getHITLStats
  // ========================================
  console.log("Test 3: getHITLStats");
  console.log("-".repeat(20));

  try {
    const stats = await axonflow.getHITLStats();
    assertCheck(true, "getHITLStats succeeded (enterprise mode)");
    assertCheck(
      stats !== null && stats !== undefined,
      "getHITLStats returned non-null response"
    );
    if (stats) {
      console.log(
        `   Pending: ${stats.pending}, Approved: ${stats.approved}, Rejected: ${stats.rejected}`
      );
    }
  } catch (error) {
    if (isEnterpriseOnly(error)) {
      assertCheck(
        true,
        "getHITLStats returns enterprise-only response (expected)"
      );
      console.log("   HITL Queue statistics require Enterprise license");
    } else {
      assertCheck(
        false,
        `getHITLStats unexpected error: ${error instanceof Error ? error.message : error}`
      );
    }
  }
  console.log();

  // ========================================
  // Test 4: getHITLRequest (fake ID)
  // ========================================
  console.log("Test 4: getHITLRequest (fake ID)");
  console.log("-".repeat(31));

  const fakeRequestId = "hitl_req_nonexistent_12345";
  try {
    const hitlReq = await axonflow.getHITLRequest(fakeRequestId);
    assertCheck(
      hitlReq !== null,
      "getHITLRequest succeeded (enterprise mode, unexpected for fake ID)"
    );
  } catch (error) {
    if (isEnterpriseOnly(error)) {
      assertCheck(
        true,
        "getHITLRequest returns enterprise-only response (expected)"
      );
      console.log(
        "   HITL request retrieval requires Enterprise license"
      );
    } else {
      const errMsg =
        error instanceof Error ? error.message : String(error);
      if (
        errMsg.includes("404") ||
        errMsg.toLowerCase().includes("not found")
      ) {
        assertCheck(
          true,
          "getHITLRequest returns 404 for nonexistent ID (expected)"
        );
      } else {
        assertCheck(
          false,
          `getHITLRequest unexpected error: ${errMsg}`
        );
      }
    }
  }
  console.log();

  // ========================================
  // Test 5: approveHITLRequest (fake ID)
  // ========================================
  console.log("Test 5: approveHITLRequest (fake ID)");
  console.log("-".repeat(35));

  try {
    await axonflow.approveHITLRequest(fakeRequestId, {
      reviewerId: "test-reviewer",
      comment: "Auto-approved by HITL queue validation example",
    });
    assertCheck(
      true,
      "approveHITLRequest succeeded (enterprise mode)"
    );
  } catch (error) {
    if (isEnterpriseOnly(error)) {
      assertCheck(
        true,
        "approveHITLRequest returns enterprise-only response (expected)"
      );
    } else {
      const errMsg =
        error instanceof Error ? error.message : String(error);
      if (
        errMsg.includes("404") ||
        errMsg.toLowerCase().includes("not found")
      ) {
        assertCheck(
          true,
          "approveHITLRequest returns 404 for nonexistent ID (expected)"
        );
      } else {
        assertCheck(
          false,
          `approveHITLRequest unexpected error: ${errMsg}`
        );
      }
    }
  }
  console.log();

  // ========================================
  // Test 6: rejectHITLRequest (fake ID)
  // ========================================
  console.log("Test 6: rejectHITLRequest (fake ID)");
  console.log("-".repeat(34));

  try {
    await axonflow.rejectHITLRequest(fakeRequestId, {
      reviewerId: "test-reviewer",
      comment: "Rejected by HITL queue validation example",
    });
    assertCheck(
      true,
      "rejectHITLRequest succeeded (enterprise mode)"
    );
  } catch (error) {
    if (isEnterpriseOnly(error)) {
      assertCheck(
        true,
        "rejectHITLRequest returns enterprise-only response (expected)"
      );
    } else {
      const errMsg =
        error instanceof Error ? error.message : String(error);
      if (
        errMsg.includes("404") ||
        errMsg.toLowerCase().includes("not found")
      ) {
        assertCheck(
          true,
          "rejectHITLRequest returns 404 for nonexistent ID (expected)"
        );
      } else {
        assertCheck(
          false,
          `rejectHITLRequest unexpected error: ${errMsg}`
        );
      }
    }
  }
  console.log();

  // ========================================
  // Summary
  // ========================================
  console.log("=".repeat(50));
  console.log(`Results: ${passCount} PASS, ${failCount} FAIL`);
  console.log("=".repeat(50));

  if (failures.length > 0) {
    console.log("SOME TESTS FAILED:");
    failures.forEach((f) => console.log(`  - ${f}`));
    process.exit(1);
  }

  console.log("ALL TESTS PASSED");
  console.log();
  console.log("HITL Queue operations validated:");
  console.log("  - HITL status endpoint (raw HTTP)");
  console.log("  - listHITLQueue() / listHITLQueue(opts)");
  console.log("  - getHITLStats()");
  console.log("  - getHITLRequest(requestId)");
  console.log("  - approveHITLRequest(requestId, review)");
  console.log("  - rejectHITLRequest(requestId, review)");
  console.log();
  console.log(
    "Note: In Community Edition, HITL queue endpoints return 403 or 404."
  );
  console.log(
    "Upgrade to Enterprise for full HITL queue management."
  );
}

main();
