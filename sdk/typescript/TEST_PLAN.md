# AxonFlow TypeScript SDK Test Plan

**Version:** 1.0.0
**Date:** September 30, 2025
**Environment:** EU Infrastructure (eu-central-1)
**Target:** 9.5ms P99 latency with <50KB bundle

## Executive Summary

This test plan ensures the AxonFlow SDK meets enterprise requirements for:
- **Performance:** 9.5ms P99 latency overhead
- **Reliability:** 99.99% availability with graceful fallback
- **Security:** Zero PII leakage, secure API handling
- **Compatibility:** Works across Node.js, React, Next.js, browsers
- **Scale:** Handles 1000+ RPS per customer

## Test Infrastructure

### EU AWS Setup (New)
```
Region: eu-central-1 (Frankfurt)
Account: dev@getaxonflow.com
Services:
- ECS Fargate: Agent/Orchestrator containers
- ALB: Load balancing with health checks
- RDS PostgreSQL: Multi-AZ for test data
- CloudWatch: Metrics and monitoring
- Route53: DNS for test endpoints
```

### Test Endpoints
```
Production: https://api.getaxonflow.com (EU)
Staging: https://staging-api.getaxonflow.com (EU)
Development: https://dev-api.getaxonflow.com (EU)
```

## 1. Unit Tests

### 1.1 Core Functionality
```typescript
// test/unit/client.test.ts
describe('AxonFlow Client', () => {
  test('initializes with API key', () => {
    const client = new AxonFlow({ apiKey: 'test-key' });
    expect(client).toBeDefined();
  });

  test('throws on missing API key', () => {
    expect(() => new AxonFlow({})).toThrow('API key required');
  });

  test('protect() wraps async functions', async () => {
    const client = new AxonFlow({ apiKey: 'test-key' });
    const result = await client.protect(async () => 'test');
    expect(result).toBe('test');
  });
});
```

### 1.2 PII Detection
```typescript
describe('PII Detection', () => {
  test('detects SSN patterns', () => {
    const hasSSN = detectPII('My SSN is 123-45-6789');
    expect(hasSSN).toBe(true);
  });

  test('detects credit card patterns', () => {
    const hasCard = detectPII('Card: 4111-1111-1111-1111');
    expect(hasCard).toBe(true);
  });

  test('detects passport patterns', () => {
    const hasPassport = detectPII('Passport: A12345678');
    expect(hasPassport).toBe(true);
  });
});
```

### 1.3 Policy Enforcement
```typescript
describe('Policy Engine', () => {
  test('applies rate limiting', async () => {
    const policy = { rate_limit: 10 };
    const enforcer = new PolicyEnforcer(policy);

    // Make 11 requests
    for (let i = 0; i < 11; i++) {
      const result = await enforcer.check();
      if (i < 10) expect(result).toBe(true);
      else expect(result).toBe(false);
    }
  });

  test('enforces content filters', () => {
    const policy = { block_keywords: ['malicious'] };
    const enforcer = new PolicyEnforcer(policy);

    expect(enforcer.check('normal request')).toBe(true);
    expect(enforcer.check('malicious request')).toBe(false);
  });
});
```

## 2. Integration Tests

### 2.1 API Integration
```typescript
describe('API Integration', () => {
  const client = new AxonFlow({
    apiKey: 'demo-key-serko',
    endpoint: 'https://staging-api.getaxonflow.com'
  });

  test('connects to Agent endpoint', async () => {
    const response = await client.testConnection();
    expect(response.status).toBe('healthy');
  });

  test('handles authentication', async () => {
    const invalidClient = new AxonFlow({
      apiKey: 'invalid-key',
      endpoint: 'https://staging-api.getaxonflow.com'
    });

    await expect(invalidClient.protect(() => fetch('/api')))
      .rejects.toThrow('Unauthorized');
  });

  test('redacts PII in requests', async () => {
    const response = await client.protect(async () => ({
      prompt: 'My SSN is 123-45-6789'
    }));

    expect(response.prompt).toBe('My SSN is [SSN_REDACTED]');
  });
});
```

### 2.2 OpenAI Integration
```typescript
describe('OpenAI Integration', () => {
  test('intercepts OpenAI calls', async () => {
    const openai = new OpenAI({ apiKey: process.env.OPENAI_KEY });
    const protectedOpenAI = wrapOpenAIClient(openai, axonflow);

    const response = await protectedOpenAI.chat.completions.create({
      model: 'gpt-4',
      messages: [{
        role: 'user',
        content: 'Process payment for card 4111-1111-1111-1111'
      }]
    });

    // Verify card was redacted before sending to OpenAI
    expect(response._axonflow_redacted).toContain('CARD_REDACTED');
  });
});
```

## 3. Performance Tests

### 3.1 Latency Benchmarks
```javascript
// test/performance/latency.bench.js
const ITERATIONS = 10000;
const TARGET_P99 = 9.5; // ms

async function benchmarkLatency() {
  const latencies = [];

  for (let i = 0; i < ITERATIONS; i++) {
    const start = process.hrtime.bigint();

    await axonflow.protect(async () => {
      // Minimal async operation
      return Promise.resolve('test');
    });

    const end = process.hrtime.bigint();
    const latencyMs = Number(end - start) / 1_000_000;
    latencies.push(latencyMs);
  }

  latencies.sort((a, b) => a - b);

  const p50 = latencies[Math.floor(ITERATIONS * 0.5)];
  const p95 = latencies[Math.floor(ITERATIONS * 0.95)];
  const p99 = latencies[Math.floor(ITERATIONS * 0.99)];

  console.log(`Latency P50: ${p50.toFixed(2)}ms`);
  console.log(`Latency P95: ${p95.toFixed(2)}ms`);
  console.log(`Latency P99: ${p99.toFixed(2)}ms`);

  assert(p99 < TARGET_P99, `P99 ${p99}ms exceeds target ${TARGET_P99}ms`);
}
```

### 3.2 Throughput Tests
```javascript
// test/performance/throughput.bench.js
async function benchmarkThroughput() {
  const duration = 60; // seconds
  const targetRPS = 1000;

  let requests = 0;
  let errors = 0;
  const startTime = Date.now();

  while (Date.now() - startTime < duration * 1000) {
    const promises = [];

    // Batch 100 concurrent requests
    for (let i = 0; i < 100; i++) {
      promises.push(
        axonflow.protect(() => fetch('/api/test'))
          .then(() => requests++)
          .catch(() => errors++)
      );
    }

    await Promise.all(promises);
  }

  const actualRPS = requests / duration;
  const errorRate = errors / (requests + errors);

  console.log(`Throughput: ${actualRPS} RPS`);
  console.log(`Error Rate: ${(errorRate * 100).toFixed(2)}%`);

  assert(actualRPS >= targetRPS, `RPS ${actualRPS} below target ${targetRPS}`);
  assert(errorRate < 0.001, `Error rate ${errorRate} exceeds 0.1%`);
}
```

### 3.3 Bundle Size Verification
```javascript
// test/performance/bundle.test.js
const fs = require('fs');
const zlib = require('zlib');

test('bundle size under 50KB', () => {
  const bundlePath = './dist/axonflow.min.js';
  const bundle = fs.readFileSync(bundlePath);
  const gzipped = zlib.gzipSync(bundle);

  const sizeKB = gzipped.length / 1024;
  console.log(`Bundle size: ${sizeKB.toFixed(2)}KB (gzipped)`);

  expect(sizeKB).toBeLessThan(50);
});
```

## 4. End-to-End Tests

### 4.1 Customer Scenarios

#### Serko Travel Booking Flow
```typescript
describe('Serko Travel Booking', () => {
  const axonflow = new AxonFlow({
    apiKey: 'demo-key-serko',
    environment: 'production'
  });

  test('complete booking flow with PII', async () => {
    // Step 1: Search flights
    const search = await axonflow.protect(async () =>
      openai.complete('Find flights AKL to SYD March 15')
    );
    expect(search).toBeDefined();

    // Step 2: Book with PII
    const booking = await axonflow.protect(async () =>
      openai.complete('Book for John Smith, passport A12345678, card 4111-1111-1111-1111')
    );

    // Verify PII was redacted
    expect(booking._axonflow_metadata.redacted).toContain('passport');
    expect(booking._axonflow_metadata.redacted).toContain('card');

    // Step 3: Verify audit trail
    const audit = await axonflow.getAuditLog(booking._axonflow_request_id);
    expect(audit.pii_redacted).toBe(true);
    expect(audit.policy_applied).toContain('travel_industry');
  });

  test('enforces corporate travel policy', async () => {
    const request = 'Book most expensive first-class ticket to London';

    const response = await axonflow.protect(async () =>
      openai.complete(request)
    );

    // Verify policy enforcement
    expect(response._axonflow_metadata.policy_modified).toBe(true);
    expect(response._axonflow_metadata.modification).toContain('economy');
  });
});
```

#### Msasa.ai Financial Processing
```typescript
describe('Msasa.ai Financial', () => {
  const axonflow = new AxonFlow({
    apiKey: 'demo-key-msasa',
    environment: 'production'
  });

  test('processes financial data securely', async () => {
    const request = 'Process transaction for account 1234567890, amount $10,000';

    const response = await axonflow.protect(async () =>
      openai.complete(request)
    );

    // Verify account masking
    expect(response._axonflow_metadata.masked).toContain('account');
    expect(response.content).toContain('****7890');

    // Verify compliance logging
    expect(response._axonflow_metadata.compliance).toContain('financial_services');
  });
});
```

## 5. Security Tests

### 5.1 API Key Security
```typescript
describe('API Key Security', () => {
  test('never sends API key in request body', async () => {
    const interceptor = jest.fn();
    global.fetch = interceptor;

    await axonflow.protect(() => fetch('/api'));

    const [url, options] = interceptor.mock.calls[0];
    expect(options.body).not.toContain('demo-key-serko');
  });

  test('uses Authorization header', async () => {
    const interceptor = jest.fn();
    global.fetch = interceptor;

    await axonflow.protect(() => fetch('/api'));

    const [url, options] = interceptor.mock.calls[0];
    expect(options.headers.Authorization).toBe('Bearer demo-key-serko');
  });
});
```

### 5.2 Data Privacy
```typescript
describe('Data Privacy', () => {
  test('no data leakage in errors', async () => {
    const sensitiveData = 'SSN: 123-45-6789';

    try {
      await axonflow.protect(() => {
        throw new Error(sensitiveData);
      });
    } catch (error) {
      expect(error.message).not.toContain('123-45-6789');
      expect(error.message).toContain('[REDACTED]');
    }
  });

  test('sanitizes logs', () => {
    const spy = jest.spyOn(console, 'log');

    axonflow.debug = true;
    axonflow.protect(() => 'Card: 4111-1111-1111-1111');

    expect(spy).not.toHaveBeenCalledWith(expect.stringContaining('4111'));
  });
});
```

## 6. Compatibility Tests

### 6.1 Node.js Versions
```yaml
# .github/workflows/compatibility.yml
strategy:
  matrix:
    node-version: [14, 16, 18, 20]

steps:
  - uses: actions/setup-node@v3
    with:
      node-version: ${{ matrix.node-version }}
  - run: npm test
```

### 6.2 Framework Compatibility
- **React:** 16.8+, 17.x, 18.x
- **Next.js:** 12.x, 13.x, 14.x
- **Vue:** 3.x
- **Angular:** 14+
- **Express:** 4.x
- **Fastify:** 4.x

### 6.3 Browser Compatibility
```javascript
// test/browser/compatibility.test.js
const browsers = ['chrome', 'firefox', 'safari', 'edge'];

browsers.forEach(browser => {
  test(`works in ${browser}`, async () => {
    const driver = await new Builder()
      .forBrowser(browser)
      .build();

    await driver.get('http://localhost:3000/test');

    const result = await driver.executeScript(() => {
      return window.axonflow.protect(() => Promise.resolve('test'));
    });

    expect(result).toBe('test');
    await driver.quit();
  });
});
```

## 7. Stress Tests

### 7.1 Memory Leak Detection
```javascript
// test/stress/memory.test.js
test('no memory leaks over 100k requests', async () => {
  const initialMemory = process.memoryUsage().heapUsed;

  for (let i = 0; i < 100000; i++) {
    await axonflow.protect(() => Promise.resolve(i));

    if (i % 10000 === 0) {
      global.gc(); // Force garbage collection
      const currentMemory = process.memoryUsage().heapUsed;
      const growth = (currentMemory - initialMemory) / 1024 / 1024; // MB

      console.log(`After ${i} requests: ${growth.toFixed(2)}MB growth`);
      expect(growth).toBeLessThan(50); // Max 50MB growth
    }
  }
});
```

### 7.2 Concurrent Request Handling
```javascript
test('handles 1000 concurrent requests', async () => {
  const promises = [];

  for (let i = 0; i < 1000; i++) {
    promises.push(
      axonflow.protect(() => fetch(`/api/test/${i}`))
    );
  }

  const results = await Promise.allSettled(promises);
  const successful = results.filter(r => r.status === 'fulfilled');

  expect(successful.length).toBeGreaterThan(990); // >99% success rate
});
```

## 8. Failure Mode Tests

### 8.1 Network Failures
```typescript
describe('Network Resilience', () => {
  test('fails open when AxonFlow unreachable', async () => {
    const client = new AxonFlow({
      apiKey: 'test-key',
      endpoint: 'https://unreachable.example.com',
      failOpen: true
    });

    const result = await client.protect(() => 'sensitive data');

    expect(result).toBe('sensitive data'); // Request proceeds
    expect(client.getLastError()).toContain('unreachable');
  });

  test('retries on transient failures', async () => {
    let attempts = 0;
    global.fetch = jest.fn(() => {
      attempts++;
      if (attempts < 3) throw new Error('Network error');
      return Promise.resolve({ ok: true });
    });

    await axonflow.protect(() => 'test');
    expect(attempts).toBe(3);
  });
});
```

### 8.2 Timeout Handling
```typescript
test('respects timeout configuration', async () => {
  const client = new AxonFlow({
    apiKey: 'test-key',
    timeout: 100 // 100ms
  });

  const slowOperation = () => new Promise(resolve =>
    setTimeout(resolve, 200)
  );

  await expect(client.protect(slowOperation))
    .rejects.toThrow('Timeout');
});
```

## 9. Regression Tests

### 9.1 Known Issues Database
```javascript
// test/regression/known-issues.test.js
const knownIssues = [
  {
    id: 'SDK-001',
    description: 'SSN pattern false positive on dates',
    test: () => {
      const result = detectPII('Born on 01-23-4567');
      expect(result).toBe(false); // Should not detect as SSN
    }
  },
  {
    id: 'SDK-002',
    description: 'Rate limit reset at minute boundary',
    test: async () => {
      // Test rate limit resets properly
    }
  }
];

knownIssues.forEach(issue => {
  test(`Regression: ${issue.id} - ${issue.description}`, issue.test);
});
```

## 10. Test Execution Plan

### Phase 1: Local Development (Day 1)
```bash
# Unit tests
npm run test:unit

# Integration tests with mock endpoints
npm run test:integration:mock
```

### Phase 2: EU Staging (Day 2-3)
```bash
# Deploy to EU staging
./scripts/deploy-sdk-demo.sh --region eu-central-1

# Integration tests against staging
npm run test:integration:staging

# Performance benchmarks
npm run test:performance
```

### Phase 3: Production Validation (Day 4-5)
```bash
# Limited production testing
npm run test:production:canary

# Full E2E customer scenarios
npm run test:e2e:serko
npm run test:e2e:msasa
```

### Phase 4: Load Testing (Day 6)
```bash
# Gradual load increase
npm run test:load:ramp

# Sustained load test (1 hour)
npm run test:load:sustained

# Stress test to find breaking point
npm run test:load:stress
```

## 11. Success Criteria

### Performance
- ✅ P99 latency < 9.5ms
- ✅ Throughput > 1000 RPS per customer
- ✅ Bundle size < 50KB gzipped
- ✅ Memory usage < 50MB after 100k requests

### Reliability
- ✅ 99.99% availability
- ✅ Graceful degradation when service unavailable
- ✅ Automatic retry with exponential backoff
- ✅ Circuit breaker pattern implementation

### Security
- ✅ 100% PII redaction accuracy
- ✅ No sensitive data in logs
- ✅ Secure API key handling
- ✅ HTTPS-only communication

### Compatibility
- ✅ Works in Node.js 14+
- ✅ Works in all modern browsers
- ✅ Framework agnostic
- ✅ TypeScript and JavaScript support

## 12. Test Automation

### CI/CD Pipeline
```yaml
# .github/workflows/sdk-tests.yml
name: SDK Test Suite

on:
  push:
    paths:
      - 'sdk/typescript/**'
  pull_request:
    paths:
      - 'sdk/typescript/**'

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: cd sdk/typescript && npm ci

      - name: Run unit tests
        run: npm run test:unit

      - name: Run integration tests
        run: npm run test:integration
        env:
          AXONFLOW_TEST_API_KEY: ${{ secrets.TEST_API_KEY }}

      - name: Check bundle size
        run: npm run test:bundle

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## 13. Test Reporting

### Dashboard Metrics
- Test pass rate by category
- Performance trends over time
- Bundle size tracking
- Compatibility matrix status

### Automated Alerts
- P99 latency exceeds 9.5ms
- Bundle size exceeds 50KB
- Test failure rate > 1%
- Security test failures (immediate)

## 14. Certification

Upon successful completion of all tests:

### AxonFlow SDK Certification
```
✅ Performance Certified: 9.5ms P99 latency
✅ Security Certified: Zero PII leakage
✅ Reliability Certified: 99.99% availability
✅ Compatibility Certified: All major frameworks
✅ Enterprise Ready: 1000+ RPS capacity

Certification Date: [Date]
Version: 1.0.0
Valid Until: [Date + 6 months]
```

---

**Test Plan Approved By:**
- Engineering Lead: _____________
- Security Lead: _____________
- Product Manager: _____________

**Next Review Date:** Q1 2026