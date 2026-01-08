/**
 * AxonFlow Static Policy Management - TypeScript SDK (Comprehensive)
 *
 * This example demonstrates ALL static policy SDK methods:
 * - listStaticPolicies
 * - getStaticPolicy
 * - createStaticPolicy
 * - updateStaticPolicy
 * - deleteStaticPolicy
 * - toggleStaticPolicy
 * - testPattern
 * - getStaticPolicyVersions
 * - getEffectiveStaticPolicies
 *
 * Run with: npx ts-node index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from "@axonflow/sdk";

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

async function main(): Promise<void> {
  console.log("AxonFlow Static Policy Management - TypeScript SDK");
  console.log("===================================================");
  console.log();

  // Create AxonFlow client with OAuth2-style credentials
  // Note: As of SDK v3.0.0 (ADR-028), use clientId/clientSecret for authentication.
  // The Agent proxies orchestrator routes internally (ADR-026).
  const client = new AxonFlow({
    endpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
    clientId: getEnv("AXONFLOW_CLIENT_ID", "demo-tenant"),
    clientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    debug: true,
  });

  // Unique name for our test policy
  const policyName = `demo-custom-policy-${Date.now()}`;
  let policyId: string | null = null;

  try {
    // ========================================
    // 1. LIST STATIC POLICIES
    // ========================================
    console.log("1. listStaticPolicies - Listing all static policies...");
    try {
      const policies = await client.listStaticPolicies({ limit: 10 });
      console.log(`   Found ${policies.length} policies`);
      policies.slice(0, 3).forEach((p) => {
        const status = p.enabled ? "enabled" : "disabled";
        console.log(`   - ${p.name}: ${p.category} (${status})`);
      });
      if (policies.length > 3) {
        console.log(`   ... and ${policies.length - 3} more`);
      }
    } catch (e) {
      console.log(`   ERROR: ${e}`);
    }
    console.log();

    // ========================================
    // 2. LIST BY CATEGORY
    // ========================================
    console.log("2. listStaticPolicies - Filtering by category...");
    try {
      // Note: TypeScript SDK uses string literals for categories
      const sqliPolicies = await client.listStaticPolicies({
        category: "security-sqli",
        limit: 5,
      });
      console.log(`   Found ${sqliPolicies.length} SQL injection policies`);
      sqliPolicies.slice(0, 3).forEach((p) => {
        console.log(`   - ${p.name}: severity=${p.severity}`);
      });
    } catch (e) {
      console.log(`   ERROR: ${e}`);
    }
    console.log();

    // ========================================
    // 3. CREATE STATIC POLICY
    // ========================================
    console.log("3. createStaticPolicy - Creating a custom policy...");
    // Using 'code-secrets' category - appropriate for custom tenant policies
    // that detect sensitive patterns in generated code.
    try {
      const created = await client.createStaticPolicy({
        name: policyName,
        description: "Demo policy for SDK testing - detects test secrets in code",
        category: "code-secrets",
        tier: "tenant",
        pattern: "(?i)test_secret_\\d+",
        severity: "medium",
        enabled: true,
        action: "warn",
      });
      policyId = created.id;
      console.log(`   Created: ${created.name}`);
      console.log(`   ID: ${created.id}`);
      console.log(`   Category: ${created.category}`);
      console.log(`   Action: ${created.action}`);
    } catch (e) {
      console.log(`   ERROR: ${e}`);
      return;
    }
    console.log();

    // ========================================
    // 4. GET STATIC POLICY
    // ========================================
    console.log("4. getStaticPolicy - Retrieving policy by ID...");
    try {
      const retrieved = await client.getStaticPolicy(policyId);
      console.log(`   Retrieved: ${retrieved.name}`);
      console.log(`   Pattern: ${retrieved.pattern}`);
      console.log(`   Enabled: ${retrieved.enabled}`);
      console.log(`   Version: ${retrieved.version || 1}`);
    } catch (e) {
      console.log(`   ERROR: ${e}`);
    }
    console.log();

    // ========================================
    // 5. TEST PATTERN
    // ========================================
    console.log("5. testPattern - Testing regex pattern...");
    try {
      const testInputs = [
        "test_secret_123", // Should match
        "test_secret_abc", // Should NOT match (no digits)
        "TEST_SECRET_999", // Should match (case insensitive)
        "normal text", // Should NOT match
        "my test_secret_42 data", // Should match
      ];
      const result = await client.testPattern("(?i)test_secret_\\d+", testInputs);
      console.log(`   Pattern valid: ${result.valid}`);
      console.log("   Match results:");
      result.matches.forEach((match) => {
        const status = match.matched ? "MATCH" : "NO MATCH";
        console.log(`     [${status}] ${match.input}`);
      });
    } catch (e) {
      console.log(`   ERROR: ${e}`);
    }
    console.log();

    // ========================================
    // 6. UPDATE STATIC POLICY
    // ========================================
    console.log("6. updateStaticPolicy - Updating policy...");
    try {
      const updated = await client.updateStaticPolicy(policyId, {
        description: "Updated description - now with stricter severity",
        severity: "high",
        action: "block",
      });
      console.log(`   Updated: ${updated.name}`);
      console.log(`   New severity: ${updated.severity}`);
      console.log(`   New action: ${updated.action}`);
      console.log(`   New version: ${updated.version || 2}`);
    } catch (e) {
      console.log(`   ERROR: ${e}`);
    }
    console.log();

    // ========================================
    // 7. GET POLICY VERSIONS
    // ========================================
    console.log("7. getStaticPolicyVersions - Getting version history...");
    try {
      const versions = await client.getStaticPolicyVersions(policyId);
      console.log(`   Found ${versions.length} versions`);
      versions.forEach((v) => {
        console.log(`   - v${v.version}: ${v.changeType} at ${v.changedAt}`);
      });
    } catch (e) {
      console.log(`   Note: Version history may require Enterprise: ${e}`);
    }
    console.log();

    // ========================================
    // 8. TOGGLE STATIC POLICY
    // ========================================
    console.log("8. toggleStaticPolicy - Disabling policy...");
    try {
      let toggled = await client.toggleStaticPolicy(policyId, false);
      console.log(`   Policy: ${toggled.name}`);
      console.log(`   Enabled: ${toggled.enabled}`);
      console.log();

      console.log("   Enabling policy again...");
      toggled = await client.toggleStaticPolicy(policyId, true);
      console.log(`   Enabled: ${toggled.enabled}`);
    } catch (e) {
      console.log(`   ERROR: ${e}`);
    }
    console.log();

    // ========================================
    // 9. GET EFFECTIVE POLICIES
    // ========================================
    console.log("9. getEffectiveStaticPolicies - Getting effective policies...");
    try {
      const effective = await client.getEffectiveStaticPolicies({
        includeDisabled: false,
      });
      console.log(`   Found ${effective.length} effective policies`);
      const ourPolicy = effective.find((p) => p.id === policyId);
      if (ourPolicy) {
        console.log(`   Our policy is effective: ${ourPolicy.name}`);
      } else {
        console.log("   Our policy is not in the effective list (may be disabled)");
      }
    } catch (e) {
      console.log(`   ERROR: ${e}`);
    }
    console.log();

    // ========================================
    // 10. DELETE STATIC POLICY
    // ========================================
    console.log("10. deleteStaticPolicy - Cleaning up...");
    try {
      await client.deleteStaticPolicy(policyId);
      console.log(`   Deleted policy: ${policyName}`);
      policyId = null; // Mark as deleted
    } catch (e) {
      console.log(`   WARNING: Failed to delete policy: ${e}`);
    }
    console.log();

    console.log("===================================================");
    console.log("All 10 Static Policy SDK methods tested!");
    console.log();
    console.log("Methods demonstrated:");
    console.log("  1. listStaticPolicies()           - List with filtering");
    console.log("  2. listStaticPolicies(category)   - Filter by category");
    console.log("  3. createStaticPolicy()           - Create new policy");
    console.log("  4. getStaticPolicy()              - Get by ID");
    console.log("  5. testPattern()                  - Test regex pattern");
    console.log("  6. updateStaticPolicy()           - Update policy");
    console.log("  7. getStaticPolicyVersions()      - Version history");
    console.log("  8. toggleStaticPolicy()           - Enable/disable");
    console.log("  9. getEffectiveStaticPolicies()   - Effective policies");
    console.log(" 10. deleteStaticPolicy()           - Delete policy");
  } finally {
    // Cleanup if policy wasn't deleted
    if (policyId) {
      try {
        await client.deleteStaticPolicy(policyId);
        console.log(`\nCleanup: Deleted policy ${policyName}`);
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}

main().catch(console.error);
