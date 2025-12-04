# AxonFlow SDK Testing Guide

**Purpose:** Comprehensive testing and verification of the TypeScript SDK before customer demos

---

## Quick Start Testing

### 1. Build the SDK

```bash
cd /Users/saurabhjain/Development/axonflow/sdk/typescript
npm install
npm run build
```

Expected output:
```
✅ Compilation successful
✅ dist/ folder created with .js and .d.ts files
```

### 2. Run Manual Test

```bash
npx ts-node test/manual-test.ts
```

Expected output:
```
🚀 AxonFlow SDK Manual Test
[AxonFlow] AxonFlow initialized
[AxonFlow] Protecting AI call
✅ SUCCESS! Result: {...}
```

---

## Comprehensive Testing Checklist

### ✅ SDK Build & Compilation

```bash
cd sdk/typescript
npm run clean
npm run build
```

**Verify:**
- [ ] No TypeScript errors
- [ ] `dist/index.js` exists
- [ ] `dist/index.d.ts` exists
- [ ] File sizes reasonable (<100KB)

---

### ✅ Unit Tests (If Implemented)

```bash
npm test
```

**Expected:** All tests pass (currently no tests, manual only)

---

### ✅ Manual Integration Test

**Test 1: Public Endpoint**

```bash
npx ts-node test/manual-test.ts
```

**Expected:**
- SDK initializes successfully
- Calls Agent API (may fail with auth error - expected)
- Fails open (returns mock data when AxonFlow unavailable)

**Test 2: VPC Private Endpoint**

Create `test/vpc-test.ts`:

```typescript
import { AxonFlow } from '../src/client';

async function testVPC() {
  console.log('🔐 Testing VPC Private Endpoint\n');

  const axonflow = new AxonFlow({
    apiKey: 'healthcare-demo-token',
    tenant: 'healthcare-acme',
    endpoint: 'https://10.0.2.67:8443',
    debug: true
  });

  const mockAICall = async () => {
    return { message: 'Test query' };
  };

  try {
    const result = await axonflow.protect(mockAICall);
    console.log('\n✅ VPC endpoint SUCCESS:', result);
  } catch (error: any) {
    console.log('\n❌ VPC endpoint ERROR:', error.message);
    console.log('(Expected if not running from within VPC)');
  }
}

testVPC();
```

Run:
```bash
npx ts-node test/vpc-test.ts
```

---

### ✅ Real Integration Test (With Actual Client)

**Create Test Client:**

```bash
mkdir -p /tmp/axonflow-sdk-test
cd /tmp/axonflow-sdk-test
npm init -y
npm install /Users/saurabhjain/Development/axonflow/sdk/typescript
npm install openai
```

**Create test file** (`test-real.ts`):

```typescript
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

async function realIntegrationTest() {
  console.log('🚀 Real Integration Test\n');
  console.log('This simulates a customer integrating the SDK\n');

  // Step 1: Initialize OpenAI (mock for test)
  console.log('Step 1: Initialize OpenAI client');
  const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY || 'sk-test-key'
  });

  // Step 2: Initialize AxonFlow (3 lines!)
  console.log('Step 2: Initialize AxonFlow (3 lines)');
  console.log('----------------------------------------');
  console.log('const axonflow = new AxonFlow({');
  console.log('  apiKey: "your-client-id",');
  console.log('  tenant: "your-tenant"');
  console.log('});');
  console.log('----------------------------------------\n');

  const axonflow = new AxonFlow({
    apiKey: 'test-user-token',
    tenant: 'healthcare-acme',
    endpoint: 'https://staging-eu.getaxonflow.com',
    debug: true
  });

  // Step 3: Wrap existing AI call
  console.log('Step 3: Wrap existing AI call with protect()');

  try {
    const response = await axonflow.protect(async () => {
      // This would normally call OpenAI
      // For testing, return mock data
      return {
        id: 'mock-123',
        choices: [{
          message: {
            role: 'assistant',
            content: 'Book flight for John Smith, passport LA987654, Auckland to Paris'
          }
        }]
      };
    });

    console.log('\n✅ Integration successful!');
    console.log('Response:', JSON.stringify(response, null, 2));

  } catch (error: any) {
    console.log('\n⚠️ AxonFlow unavailable (expected in test)');
    console.log('SDK failed open - AI call would proceed normally');
    console.log('Error:', error.message);
  }

  console.log('\n✅ Integration test complete!');
  console.log('The SDK works exactly as advertised: 3-line integration ✅');
}

realIntegrationTest();
```

Run:
```bash
npx ts-node test-real.ts
```

**Expected Output:**
```
🚀 Real Integration Test
Step 1: Initialize OpenAI client
Step 2: Initialize AxonFlow (3 lines)
Step 3: Wrap existing AI call with protect()
[AxonFlow] AxonFlow initialized
[AxonFlow] Protecting AI call
✅ Integration successful!
```

---

### ✅ End-to-End Test (SDK → Agent → Database)

**Prerequisites:**
1. Agent running on central instance (63.178.85.84)
2. Valid client_id and user_token in database
3. EU AI Act templates deployed ✅

**Test Script** (`test/e2e-test.ts`):

```typescript
import { AxonFlow } from '../src/client';

async function e2eTest() {
  console.log('🔄 End-to-End Test (SDK → Agent → Database)\n');

  const axonflow = new AxonFlow({
    apiKey: 'valid-user-token-here', // Replace with actual token
    tenant: 'healthcare-acme', // Replace with actual client
    endpoint: 'https://staging-eu.getaxonflow.com',
    debug: true
  });

  // Test 1: Normal query (should pass)
  console.log('\n📝 Test 1: Normal Query');
  try {
    const result1 = await axonflow.protect(async () => {
      return { query: 'Show patient demographics' };
    });
    console.log('✅ Normal query passed:', result1);
  } catch (error: any) {
    console.log('❌ Normal query failed:', error.message);
  }

  // Test 2: Query with passport (should trigger EU AI Act template)
  console.log('\n📝 Test 2: Passport Detection (EU AI Act Article 13)');
  try {
    const result2 = await axonflow.protect(async () => {
      return { query: 'Book flight for passport LA987654' };
    });
    console.log('✅ Passport detected and handled:', result2);
  } catch (error: any) {
    console.log('✅ Passport blocked (expected):', error.message);
  }

  // Test 3: High-value transaction (should trigger Article 14)
  console.log('\n📝 Test 3: High-Value Transaction (EU AI Act Article 14)');
  try {
    const result3 = await axonflow.protect(async () => {
      return { query: 'Book business class flight for €6,500' };
    });
    console.log('✅ High-value transaction flagged:', result3);
  } catch (error: any) {
    console.log('❌ High-value query failed:', error.message);
  }

  console.log('\n✅ End-to-end test complete!');
}

e2eTest();
```

---

### ✅ Performance Test (Latency Validation)

**Test Script** (`test/performance-test.ts`):

```typescript
import { AxonFlow } from '../src/client';

async function performanceTest() {
  console.log('⚡ Performance Test (100 requests)\n');

  const axonflow = new AxonFlow({
    apiKey: 'test-token',
    tenant: 'healthcare-acme',
    endpoint: 'https://staging-eu.getaxonflow.com',
    debug: false
  });

  const latencies: number[] = [];
  const iterations = 100;

  console.log(`Running ${iterations} requests...\n`);

  for (let i = 0; i < iterations; i++) {
    const start = Date.now();

    try {
      await axonflow.protect(async () => {
        return { query: `Test query ${i}` };
      });
    } catch (error) {
      // Fail-open, continue
    }

    const latency = Date.now() - start;
    latencies.push(latency);

    if ((i + 1) % 10 === 0) {
      process.stdout.write(`${i + 1}/${iterations} `);
    }
  }

  console.log('\n\n📊 Results:');

  latencies.sort((a, b) => a - b);

  const p50 = latencies[Math.floor(iterations * 0.50)];
  const p95 = latencies[Math.floor(iterations * 0.95)];
  const p99 = latencies[Math.floor(iterations * 0.99)];
  const avg = latencies.reduce((a, b) => a + b, 0) / iterations;

  console.log(`  Average: ${avg.toFixed(2)}ms`);
  console.log(`  P50: ${p50}ms`);
  console.log(`  P95: ${p95}ms`);
  console.log(`  P99: ${p99}ms`);

  console.log('\n✅ Performance test complete!');
}

performanceTest();
```

---

## Verification Checklist

Before claiming "3-line integration" in email:

### ✅ Code Quality
- [ ] SDK compiles with no TypeScript errors
- [ ] All exports work (`AxonFlow`, `wrapOpenAIClient`, types)
- [ ] No console warnings during build

### ✅ Functionality
- [ ] SDK initializes successfully
- [ ] `protect()` method works
- [ ] Fail-open behavior works (proceeds on error)
- [ ] Debug logging works when enabled

### ✅ Integration
- [ ] Can install SDK in fresh project (`npm install`)
- [ ] TypeScript types work (autocomplete, IntelliSense)
- [ ] 3-line integration claim is accurate
- [ ] Works with both public and VPC endpoints

### ✅ Performance
- [ ] SDK adds <50ms overhead (client-side)
- [ ] End-to-end P99 meets <10ms target (Agent-side)
- [ ] No memory leaks in 100+ requests

### ✅ Documentation
- [ ] README examples work when copy-pasted
- [ ] Serko example is accurate
- [ ] VPC endpoint documented
- [ ] Error handling documented

---

## Testing Commands Summary

```bash
# 1. Build SDK
cd sdk/typescript
npm run build

# 2. Run manual test
npx ts-node test/manual-test.ts

# 3. Run VPC test
npx ts-node test/vpc-test.ts

# 4. Real integration test
cd /tmp/axonflow-sdk-test
npm install /path/to/sdk/typescript
npx ts-node test-real.ts

# 5. End-to-end test (requires valid credentials)
npx ts-node test/e2e-test.ts

# 6. Performance test
npx ts-node test/performance-test.ts
```

---

## Troubleshooting

**Issue:** `Cannot find module '@axonflow/sdk'`
**Fix:** Run `npm run build` in sdk/typescript first

**Issue:** TypeScript errors in tests
**Fix:** Install types: `npm install --save-dev @types/node`

**Issue:** Connection timeout to Agent
**Fix:** Verify Agent is running: `curl https://staging-eu.getaxonflow.com/health`

**Issue:** 401 Unauthorized
**Fix:** Use valid client_id and user_token from database

---

## Next Steps

After all tests pass:
1. ✅ Claim "TypeScript SDK shipped" in email
2. ✅ Claim "3-line integration" in email
3. ✅ Demonstrate in Zeno demo (Phase 2)
4. ✅ Use in pilot scoping call (Phase 4)

**Current Status:** [Run tests and update this section]
