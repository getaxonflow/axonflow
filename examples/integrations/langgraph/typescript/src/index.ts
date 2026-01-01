/**
 * LangGraph + AxonFlow Integration Example (TypeScript SDK)
 *
 * This example demonstrates how to add AxonFlow governance to LangGraph-style
 * stateful agent workflows. LangGraph uses graph-based orchestration with nodes
 * and edges for building complex agent systems.
 *
 * Features demonstrated:
 * - Graph-based workflow with governed nodes
 * - Policy enforcement at each node transition
 * - State management across the workflow
 * - PII detection and SQL injection blocking
 * - Audit logging for compliance
 *
 * Requirements:
 * - AxonFlow running locally (docker compose up)
 * - Node.js 18+
 *
 * Usage:
 *     npm install
 *     npm start
 */

import { AxonFlow } from "@axonflow/sdk";

// =============================================================================
// Types - LangGraph-style state and graph structures
// =============================================================================

interface GraphState {
  messages: Array<{ role: string; content: string }>;
  currentNode: string;
  metadata: Record<string, unknown>;
}

interface NodeResult {
  nextNode: string | null;
  state: GraphState;
  blocked?: boolean;
  blockReason?: string;
}

type NodeFunction = (state: GraphState, axonflow: AxonFlow) => Promise<NodeResult>;

// =============================================================================
// Configuration
// =============================================================================

const config = {
  agentUrl: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  tenant: process.env.AXONFLOW_TENANT || "langgraph-demo",
};

// =============================================================================
// Graph Nodes - Each node is governed by AxonFlow
// =============================================================================

/**
 * Input node - Validates and processes user input
 */
async function inputNode(state: GraphState, axonflow: AxonFlow): Promise<NodeResult> {
  const lastMessage = state.messages[state.messages.length - 1];
  const query = lastMessage?.content || "";

  console.log(`[Input Node] Processing: "${query.substring(0, 50)}..."`);

  try {
    // Check policy before processing
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "langgraph-user",
      query,
      context: {
        node: "input",
        workflow: "research-assistant",
        ...state.metadata,
      },
    });

    if (!result.approved) {
      console.log(`[Input Node] BLOCKED: ${result.blockReason}`);
      return {
        nextNode: null,
        state: { ...state, currentNode: "blocked" },
        blocked: true,
        blockReason: result.blockReason,
      };
    }

    // Store context ID for audit trail
    state.metadata.contextId = result.contextId;
    state.metadata.inputApproved = true;

    console.log(`[Input Node] ✓ Approved (Context: ${result.contextId.substring(0, 8)}...)`);

    return {
      nextNode: "router",
      state: { ...state, currentNode: "router" },
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.log(`[Input Node] BLOCKED: ${errorMsg}`);
    return {
      nextNode: null,
      state: { ...state, currentNode: "blocked" },
      blocked: true,
      blockReason: errorMsg,
    };
  }
}

/**
 * Router node - Determines which processing path to take
 */
async function routerNode(state: GraphState, axonflow: AxonFlow): Promise<NodeResult> {
  const lastMessage = state.messages[state.messages.length - 1];
  const query = lastMessage?.content?.toLowerCase() || "";

  console.log(`[Router Node] Analyzing query intent...`);

  // Simple intent detection
  let nextNode: string;
  if (query.includes("search") || query.includes("find") || query.includes("look up")) {
    nextNode = "search";
  } else if (query.includes("analyze") || query.includes("compare")) {
    nextNode = "analyze";
  } else {
    nextNode = "respond";
  }

  console.log(`[Router Node] ✓ Routing to: ${nextNode}`);

  return {
    nextNode,
    state: { ...state, currentNode: nextNode, metadata: { ...state.metadata, route: nextNode } },
  };
}

/**
 * Search node - Handles search-type queries with governance
 */
async function searchNode(state: GraphState, axonflow: AxonFlow): Promise<NodeResult> {
  const lastMessage = state.messages[state.messages.length - 1];
  const query = lastMessage?.content || "";

  console.log(`[Search Node] Executing governed search...`);

  try {
    // Policy check for search operation
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "langgraph-user",
      query: `SEARCH: ${query}`,
      context: {
        node: "search",
        operation: "database_query",
        workflow: "research-assistant",
      },
    });

    if (!result.approved) {
      console.log(`[Search Node] BLOCKED: ${result.blockReason}`);
      return {
        nextNode: null,
        state: { ...state, currentNode: "blocked" },
        blocked: true,
        blockReason: result.blockReason,
      };
    }

    // Simulate search operation
    const searchResult = `[Search results for: ${query.substring(0, 30)}...]`;

    // Audit the operation
    await axonflow.auditLLMCall({
      contextId: result.contextId,
      responseSummary: searchResult,
      provider: "internal",
      model: "search-v1",
      tokenUsage: { promptTokens: 10, completionTokens: 20, totalTokens: 30 },
      latencyMs: 50,
    });

    state.messages.push({ role: "assistant", content: searchResult });
    console.log(`[Search Node] ✓ Search completed and audited`);

    return {
      nextNode: "respond",
      state: { ...state, currentNode: "respond" },
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.log(`[Search Node] BLOCKED: ${errorMsg}`);
    return {
      nextNode: null,
      state: { ...state, currentNode: "blocked" },
      blocked: true,
      blockReason: errorMsg,
    };
  }
}

/**
 * Analyze node - Handles analysis queries with governance
 */
async function analyzeNode(state: GraphState, axonflow: AxonFlow): Promise<NodeResult> {
  const lastMessage = state.messages[state.messages.length - 1];
  const query = lastMessage?.content || "";

  console.log(`[Analyze Node] Running governed analysis...`);

  try {
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "langgraph-user",
      query: `ANALYZE: ${query}`,
      context: {
        node: "analyze",
        operation: "data_analysis",
        workflow: "research-assistant",
      },
    });

    if (!result.approved) {
      console.log(`[Analyze Node] BLOCKED: ${result.blockReason}`);
      return {
        nextNode: null,
        state: { ...state, currentNode: "blocked" },
        blocked: true,
        blockReason: result.blockReason,
      };
    }

    // Simulate analysis
    const analysisResult = `[Analysis complete for: ${query.substring(0, 30)}...]`;

    await axonflow.auditLLMCall({
      contextId: result.contextId,
      responseSummary: analysisResult,
      provider: "internal",
      model: "analyzer-v1",
      tokenUsage: { promptTokens: 20, completionTokens: 40, totalTokens: 60 },
      latencyMs: 100,
    });

    state.messages.push({ role: "assistant", content: analysisResult });
    console.log(`[Analyze Node] ✓ Analysis completed and audited`);

    return {
      nextNode: "respond",
      state: { ...state, currentNode: "respond" },
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.log(`[Analyze Node] BLOCKED: ${errorMsg}`);
    return {
      nextNode: null,
      state: { ...state, currentNode: "blocked" },
      blocked: true,
      blockReason: errorMsg,
    };
  }
}

/**
 * Respond node - Generates final response with governance
 */
async function respondNode(state: GraphState, axonflow: AxonFlow): Promise<NodeResult> {
  console.log(`[Respond Node] Generating governed response...`);

  const contextSummary = state.messages.map((m) => m.content).join(" | ");

  try {
    const result = await axonflow.getPolicyApprovedContext({
      userToken: "langgraph-user",
      query: `RESPOND: ${contextSummary.substring(0, 200)}`,
      context: {
        node: "respond",
        operation: "response_generation",
        workflow: "research-assistant",
      },
    });

    if (!result.approved) {
      console.log(`[Respond Node] BLOCKED: ${result.blockReason}`);
      return {
        nextNode: null,
        state: { ...state, currentNode: "blocked" },
        blocked: true,
        blockReason: result.blockReason,
      };
    }

    // Simulate LLM response
    const response = "Based on my analysis, here are the key findings...";

    await axonflow.auditLLMCall({
      contextId: result.contextId,
      responseSummary: response,
      provider: "simulated",
      model: "gpt-4",
      tokenUsage: { promptTokens: 50, completionTokens: 100, totalTokens: 150 },
      latencyMs: 200,
    });

    state.messages.push({ role: "assistant", content: response });
    console.log(`[Respond Node] ✓ Response generated and audited`);

    return {
      nextNode: null,
      state: { ...state, currentNode: "complete" },
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.log(`[Respond Node] BLOCKED: ${errorMsg}`);
    return {
      nextNode: null,
      state: { ...state, currentNode: "blocked" },
      blocked: true,
      blockReason: errorMsg,
    };
  }
}

// =============================================================================
// Graph Execution Engine
// =============================================================================

class GovernedGraph {
  private nodes: Map<string, NodeFunction> = new Map();
  private axonflow: AxonFlow;

  constructor(axonflow: AxonFlow) {
    this.axonflow = axonflow;
    // Register nodes
    this.nodes.set("input", inputNode);
    this.nodes.set("router", routerNode);
    this.nodes.set("search", searchNode);
    this.nodes.set("analyze", analyzeNode);
    this.nodes.set("respond", respondNode);
  }

  async execute(initialState: GraphState): Promise<GraphState> {
    let currentNode = "input";
    let state = { ...initialState, currentNode };

    console.log("\n" + "=".repeat(60));
    console.log("Starting Graph Execution");
    console.log("=".repeat(60) + "\n");

    while (currentNode) {
      const nodeFunc = this.nodes.get(currentNode);
      if (!nodeFunc) {
        console.error(`Unknown node: ${currentNode}`);
        break;
      }

      const result = await nodeFunc(state, this.axonflow);
      state = result.state;

      if (result.blocked) {
        console.log(`\n⚠️  Workflow blocked at node "${currentNode}"`);
        console.log(`   Reason: ${result.blockReason}`);
        break;
      }

      currentNode = result.nextNode || "";
    }

    return state;
  }
}

// =============================================================================
// Test Cases
// =============================================================================

async function runTests(axonflow: AxonFlow): Promise<void> {
  const graph = new GovernedGraph(axonflow);

  // Test 1: Safe search query
  console.log("\n" + "=".repeat(60));
  console.log("[Test 1] Safe Search Query");
  console.log("=".repeat(60));

  await graph.execute({
    messages: [{ role: "user", content: "Search for best practices in AI safety" }],
    currentNode: "input",
    metadata: { testCase: "safe-search" },
  });

  // Test 2: Safe analysis query
  console.log("\n" + "=".repeat(60));
  console.log("[Test 2] Safe Analysis Query");
  console.log("=".repeat(60));

  await graph.execute({
    messages: [{ role: "user", content: "Analyze the trends in renewable energy adoption" }],
    currentNode: "input",
    metadata: { testCase: "safe-analysis" },
  });

  // Test 3: Query with PII (should be blocked)
  console.log("\n" + "=".repeat(60));
  console.log("[Test 3] Query with PII - Should be blocked");
  console.log("=".repeat(60));

  const piiResult = await graph.execute({
    messages: [{ role: "user", content: "Search for customer with SSN 123-45-6789" }],
    currentNode: "input",
    metadata: { testCase: "pii-detection" },
  });

  if (piiResult.currentNode === "blocked") {
    console.log("\n✓ PII correctly detected and blocked!");
  }

  // Test 4: SQL injection attempt (should be blocked)
  console.log("\n" + "=".repeat(60));
  console.log("[Test 4] SQL Injection - Should be blocked");
  console.log("=".repeat(60));

  const sqliResult = await graph.execute({
    messages: [{ role: "user", content: "Find users WHERE 1=1; DROP TABLE users;--" }],
    currentNode: "input",
    metadata: { testCase: "sql-injection" },
  });

  if (sqliResult.currentNode === "blocked") {
    console.log("\n✓ SQL injection correctly blocked!");
  }

  console.log("\n" + "=".repeat(60));
  console.log("All tests completed!");
  console.log("=".repeat(60) + "\n");
}

// =============================================================================
// Main Entry Point
// =============================================================================

async function main(): Promise<void> {
  console.log("LangGraph + AxonFlow Integration Example (TypeScript SDK)");
  console.log("=".repeat(60));

  // Health check
  console.log(`\nChecking AxonFlow at ${config.agentUrl}...`);

  const axonflow = new AxonFlow({
    endpoint: config.agentUrl,
    tenant: config.tenant,
  });

  try {
    const health = await axonflow.healthCheck();
    if (health.status !== "healthy") {
      console.error("AxonFlow is not healthy. Start it with: docker compose up -d");
      process.exit(1);
    }
    console.log(`Status: ${health.status}\n`);

    await runTests(axonflow);
  } catch (error) {
    console.error("Error connecting to AxonFlow:", error);
    console.error("\nMake sure AxonFlow is running: docker compose up -d");
    process.exit(1);
  }
}

main().catch(console.error);
