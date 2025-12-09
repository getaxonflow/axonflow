/**
 * Gateway Mode Tests
 * Tests for getPolicyApprovedContext() and auditLLMCall() methods
 */

import { AxonFlow } from '../src/client';
import { PolicyApprovalResult, AuditResult, TokenUsage } from '../src/types';

// Mock fetch for testing
const mockFetch = jest.fn();
// @ts-ignore
global.fetch = mockFetch;

describe('Gateway Mode SDK', () => {
  let axonflow: AxonFlow;

  beforeAll(() => {
    axonflow = new AxonFlow({
      apiKey: 'test-api-key',
      endpoint: 'http://localhost:8080',
      tenant: 'test-tenant',
      debug: false
    });
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });

  beforeEach(() => {
    mockFetch.mockClear();
  });

  describe('getPolicyApprovedContext', () => {
    it('should return approved context when policy passes', async () => {
      const mockResponse = {
        context_id: 'ctx-123',
        approved: true,
        policies: ['hipaa-compliance'],
        approved_data: {
          patients: [{ id: 1, name: 'John Doe' }]
        },
        expires_at: new Date(Date.now() + 300000).toISOString()
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await axonflow.getPolicyApprovedContext({
        userToken: 'user-jwt',
        dataSources: ['postgres'],
        query: 'Find patients with diabetes'
      });

      expect(result.contextId).toBe('ctx-123');
      expect(result.approved).toBe(true);
      expect(result.policies).toContain('hipaa-compliance');
      expect(result.approvedData).toBeDefined();
      expect(result.approvedData?.patients).toHaveLength(1);
      expect(result.expiresAt).toBeInstanceOf(Date);
    });

    it('should return blocked context when policy fails', async () => {
      const mockResponse = {
        context_id: 'ctx-456',
        approved: false,
        policies: ['sql-injection-prevention'],
        block_reason: 'SQL injection detected',
        expires_at: new Date(Date.now() + 300000).toISOString()
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await axonflow.getPolicyApprovedContext({
        userToken: 'user-jwt',
        query: 'SELECT * FROM users UNION SELECT * FROM passwords'
      });

      expect(result.contextId).toBe('ctx-456');
      expect(result.approved).toBe(false);
      expect(result.blockReason).toBe('SQL injection detected');
    });

    it('should throw error on server error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: () => Promise.resolve('Server error')
      });

      await expect(
        axonflow.getPolicyApprovedContext({
          userToken: 'user-jwt',
          query: 'test query'
        })
      ).rejects.toThrow('Pre-check failed: 500 Internal Server Error');
    });

    it('should include rate limit info when present', async () => {
      const mockResponse = {
        context_id: 'ctx-789',
        approved: true,
        policies: [],
        expires_at: new Date(Date.now() + 300000).toISOString(),
        rate_limit: {
          limit: 100,
          remaining: 50,
          reset_at: new Date(Date.now() + 3600000).toISOString()
        }
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await axonflow.getPolicyApprovedContext({
        userToken: 'user-jwt',
        query: 'test query'
      });

      expect(result.rateLimitInfo).toBeDefined();
      expect(result.rateLimitInfo?.limit).toBe(100);
      expect(result.rateLimitInfo?.remaining).toBe(50);
      expect(result.rateLimitInfo?.resetAt).toBeInstanceOf(Date);
    });

    it('should send correct headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          context_id: 'ctx-test',
          approved: true,
          policies: [],
          expires_at: new Date().toISOString()
        })
      });

      await axonflow.getPolicyApprovedContext({
        userToken: 'user-jwt',
        query: 'test'
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/policy/pre-check',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-Client-Secret': 'test-api-key',
            'X-License-Key': 'test-api-key'
          })
        })
      );
    });
  });

  describe('auditLLMCall', () => {
    it('should successfully record audit', async () => {
      const mockResponse = {
        success: true,
        audit_id: 'audit-123'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const tokenUsage: TokenUsage = {
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150
      };

      const result = await axonflow.auditLLMCall(
        'ctx-123',
        'Found 5 patients with diabetes',
        'openai',
        'gpt-4',
        tokenUsage,
        250,
        { sessionId: 'session-123' }
      );

      expect(result.success).toBe(true);
      expect(result.auditId).toBe('audit-123');
    });

    it('should throw error on server error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: () => Promise.resolve('Server error')
      });

      const tokenUsage: TokenUsage = {
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150
      };

      await expect(
        axonflow.auditLLMCall(
          'ctx-123',
          'summary',
          'openai',
          'gpt-4',
          tokenUsage,
          100
        )
      ).rejects.toThrow('Audit failed: 500 Internal Server Error');
    });

    it('should send correct request body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true, audit_id: 'audit-456' })
      });

      const tokenUsage: TokenUsage = {
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150
      };

      await axonflow.auditLLMCall(
        'ctx-123',
        'summary text',
        'anthropic',
        'claude-3-sonnet',
        tokenUsage,
        350,
        { custom: 'metadata' }
      );

      const callArgs = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
      const body = JSON.parse(callArgs[1].body);

      expect(body.context_id).toBe('ctx-123');
      expect(body.client_id).toBe('test-tenant');
      expect(body.provider).toBe('anthropic');
      expect(body.model).toBe('claude-3-sonnet');
      expect(body.token_usage.prompt_tokens).toBe(100);
      expect(body.token_usage.completion_tokens).toBe(50);
      expect(body.token_usage.total_tokens).toBe(150);
      expect(body.latency_ms).toBe(350);
      expect(body.metadata).toEqual({ custom: 'metadata' });
    });
  });

  describe('Gateway Mode Integration', () => {
    it('should support full pre-check -> audit flow', async () => {
      // Mock pre-check response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          context_id: 'ctx-flow-test',
          approved: true,
          policies: ['hipaa'],
          approved_data: { data: 'test' },
          expires_at: new Date(Date.now() + 300000).toISOString()
        })
      });

      // Pre-check
      const preCheckResult = await axonflow.getPolicyApprovedContext({
        userToken: 'user-jwt',
        dataSources: ['postgres'],
        query: 'Find patient records'
      });

      expect(preCheckResult.approved).toBe(true);
      expect(preCheckResult.contextId).toBe('ctx-flow-test');

      // Mock audit response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: true,
          audit_id: 'audit-flow-test'
        })
      });

      // Audit
      const auditResult = await axonflow.auditLLMCall(
        preCheckResult.contextId,
        'Found 3 patient records',
        'openai',
        'gpt-4',
        { promptTokens: 200, completionTokens: 100, totalTokens: 300 },
        500
      );

      expect(auditResult.success).toBe(true);
      expect(auditResult.auditId).toBe('audit-flow-test');
    });
  });
});

describe('Type Definitions', () => {
  it('TokenUsage should have correct properties', () => {
    const usage: TokenUsage = {
      promptTokens: 100,
      completionTokens: 50,
      totalTokens: 150
    };

    expect(usage.promptTokens).toBe(100);
    expect(usage.completionTokens).toBe(50);
    expect(usage.totalTokens).toBe(150);
  });

  it('PolicyApprovalResult should have correct properties', () => {
    const result: PolicyApprovalResult = {
      contextId: 'ctx-123',
      approved: true,
      policies: ['policy1'],
      expiresAt: new Date()
    };

    expect(result.contextId).toBe('ctx-123');
    expect(result.approved).toBe(true);
    expect(result.policies).toContain('policy1');
    expect(result.expiresAt).toBeInstanceOf(Date);
  });

  it('AuditResult should have correct properties', () => {
    const result: AuditResult = {
      success: true,
      auditId: 'audit-123'
    };

    expect(result.success).toBe(true);
    expect(result.auditId).toBe('audit-123');
  });
});

describe('AxonFlow Client - Additional Methods', () => {
  let axonflow: AxonFlow;

  beforeAll(() => {
    axonflow = new AxonFlow({
      apiKey: 'test-api-key',
      endpoint: 'http://localhost:8080',
      tenant: 'test-tenant',
      debug: false
    });
  });

  beforeEach(() => {
    mockFetch.mockClear();
  });

  describe('listConnectors', () => {
    it('should return list of connectors', async () => {
      const mockConnectors = [
        { id: 'postgres', name: 'PostgreSQL', type: 'database' },
        { id: 'redis', name: 'Redis', type: 'cache' }
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockConnectors)
      });

      const result = await axonflow.listConnectors();

      expect(result).toHaveLength(2);
      expect(result[0].id).toBe('postgres');
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/connectors',
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('should throw error on failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });

      await expect(axonflow.listConnectors()).rejects.toThrow('Failed to list connectors');
    });
  });

  describe('installConnector', () => {
    it('should install connector successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true })
      });

      await expect(
        axonflow.installConnector({
          connector_id: 'postgres',
          name: 'my-postgres',
          tenant_id: 'tenant-1',
          options: {},
          credentials: { host: 'localhost' }
        })
      ).resolves.not.toThrow();

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/connectors/install',
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should throw error on failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: () => Promise.resolve('Invalid connector')
      });

      await expect(
        axonflow.installConnector({
          connector_id: 'invalid',
          name: 'test',
          tenant_id: 'tenant-1',
          options: {},
          credentials: {}
        })
      ).rejects.toThrow('Failed to install connector');
    });
  });

  describe('queryConnector', () => {
    it('should query connector successfully', async () => {
      const mockResponse = {
        success: true,
        data: [{ id: 1, name: 'test' }],
        metadata: { duration: '50ms' }
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await axonflow.queryConnector('postgres', 'SELECT * FROM users', { limit: 10 });

      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(1);
    });

    it('should throw error on failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: () => Promise.resolve('Query failed')
      });

      await expect(
        axonflow.queryConnector('postgres', 'SELECT * FROM users')
      ).rejects.toThrow('Connector query failed');
    });
  });

  describe('generatePlan', () => {
    it('should generate plan successfully', async () => {
      const mockResponse = {
        success: true,
        plan_id: 'plan-123',
        data: {
          steps: [{ id: 'step-1', name: 'Search', type: 'search' }],
          domain: 'travel',
          complexity: 2,
          parallel: false
        },
        metadata: {}
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await axonflow.generatePlan('Book a flight to Paris', 'travel');

      expect(result.planId).toBe('plan-123');
      expect(result.steps).toHaveLength(1);
      expect(result.domain).toBe('travel');
    });

    it('should throw error when generation fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: false,
          error: 'Invalid query'
        })
      });

      await expect(
        axonflow.generatePlan('invalid')
      ).rejects.toThrow('Plan generation failed');
    });

    it('should throw error on HTTP failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: () => Promise.resolve('Server error')
      });

      await expect(
        axonflow.generatePlan('Book a flight')
      ).rejects.toThrow('Plan generation failed');
    });
  });

  describe('executePlan', () => {
    it('should execute plan successfully', async () => {
      const mockResponse = {
        success: true,
        result: 'Flight booked successfully',
        metadata: {
          duration: '5s',
          step_results: { 'step-1': 'completed' }
        }
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await axonflow.executePlan('plan-123');

      expect(result.status).toBe('completed');
      expect(result.result).toBe('Flight booked successfully');
      expect(result.duration).toBe('5s');
    });

    it('should handle failed execution', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: false,
          error: 'Step failed'
        })
      });

      const result = await axonflow.executePlan('plan-123');

      expect(result.status).toBe('failed');
      expect(result.error).toBe('Step failed');
    });

    it('should throw error on HTTP failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: () => Promise.resolve('Server error')
      });

      await expect(
        axonflow.executePlan('plan-123')
      ).rejects.toThrow('Plan execution failed');
    });
  });

  describe('getPlanStatus', () => {
    it('should get plan status successfully', async () => {
      const mockResponse = {
        status: 'running',
        result: null,
        step_results: { 'step-1': 'in_progress' }
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await axonflow.getPlanStatus('plan-123');

      expect(result.planId).toBe('plan-123');
      expect(result.status).toBe('running');
    });

    it('should throw error on HTTP failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        text: () => Promise.resolve('Plan not found')
      });

      await expect(
        axonflow.getPlanStatus('invalid-plan')
      ).rejects.toThrow('Get plan status failed');
    });
  });

  describe('sandbox', () => {
    it('should create sandbox client with default key', () => {
      const sandbox = AxonFlow.sandbox();
      expect(sandbox).toBeInstanceOf(AxonFlow);
    });

    it('should create sandbox client with custom key', () => {
      const sandbox = AxonFlow.sandbox('custom-key');
      expect(sandbox).toBeInstanceOf(AxonFlow);
    });
  });
});

describe('AxonFlow Client - Debug Mode', () => {
  let axonflowDebug: AxonFlow;

  beforeAll(() => {
    axonflowDebug = new AxonFlow({
      apiKey: 'test-api-key',
      endpoint: 'http://localhost:8080',
      tenant: 'test-tenant',
      debug: true  // Enable debug mode
    });
  });

  beforeEach(() => {
    mockFetch.mockClear();
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should log debug info for getPolicyApprovedContext', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        context_id: 'ctx-debug',
        approved: true,
        policies: [],
        expires_at: new Date().toISOString()
      })
    });

    await axonflowDebug.getPolicyApprovedContext({
      userToken: 'token',
      query: 'test query'
    });

    expect(console.log).toHaveBeenCalled();
  });

  it('should log debug info for auditLLMCall', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ success: true, audit_id: 'audit-debug' })
    });

    await axonflowDebug.auditLLMCall(
      'ctx-123',
      'summary',
      'openai',
      'gpt-4',
      { promptTokens: 10, completionTokens: 5, totalTokens: 15 },
      100
    );

    expect(console.log).toHaveBeenCalled();
  });

  it('should log debug info for listConnectors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([])
    });

    await axonflowDebug.listConnectors();

    expect(console.log).toHaveBeenCalled();
  });
});
