import {
  AxonFlowConfig,
  AIRequest,
  GovernanceRequest,
  GovernanceResponse,
  ConnectorMetadata,
  ConnectorInstallRequest,
  ConnectorResponse,
  PlanResponse,
  PlanExecutionResponse,
  PreCheckRequest,
  PolicyApprovalResult,
  TokenUsage,
  AuditResult
} from './types';
import { OpenAIInterceptor } from './interceptors/openai';
import { AnthropicInterceptor } from './interceptors/anthropic';
import { BaseInterceptor } from './interceptors/base';
import { generateRequestId, debugLog } from './utils/helpers';

/**
 * Main AxonFlow client for invisible AI governance
 */
export class AxonFlow {
  private config: Required<AxonFlowConfig>;
  private interceptors: BaseInterceptor[] = [];

  constructor(config: AxonFlowConfig) {
    // Set defaults
    this.config = {
      apiKey: config.apiKey,
      endpoint: config.endpoint || 'https://staging-eu.getaxonflow.com',
      mode: config.mode || 'production',
      tenant: config.tenant || 'default',
      debug: config.debug || false,
      timeout: config.timeout || 30000,
      retry: config.retry || { enabled: true, maxAttempts: 3, delay: 1000 },
      cache: config.cache || { enabled: true, ttl: 60000 }
    };

    // Initialize interceptors
    this.interceptors = [
      new OpenAIInterceptor(),
      new AnthropicInterceptor()
    ];

    if (this.config.debug) {
      debugLog('AxonFlow initialized', { mode: this.config.mode, endpoint: this.config.endpoint });
    }
  }

  /**
   * Main method to protect AI calls with governance
   * @param aiCall The AI call to protect
   * @returns The AI response after governance
   */
  async protect<T = any>(aiCall: () => Promise<T>): Promise<T> {
    try {
      // Extract request details from the AI call
      const aiRequest = await this.extractRequest(aiCall);

      if (this.config.debug) {
        debugLog('Protecting AI call', { provider: aiRequest.provider, model: aiRequest.model });
      }

      // Create governance request
      const governanceRequest: GovernanceRequest = {
        requestId: generateRequestId(),
        timestamp: Date.now(),
        aiRequest,
        mode: this.config.mode,
        tenant: this.config.tenant
      };

      // Check policies with AxonFlow Agent
      const governanceResponse = await this.checkPolicies(governanceRequest);

      // If denied, throw error
      if (!governanceResponse.allowed) {
        const violation = governanceResponse.violations?.[0];
        throw new Error(`Request blocked by AxonFlow: ${violation?.description || 'Policy violation'}`);
      }

      // Execute the AI call (possibly with modifications)
      const modifiedCall = governanceResponse.modifiedRequest
        ? () => Promise.resolve(governanceResponse.modifiedRequest)
        : aiCall;

      const result = await modifiedCall();

      // Log audit trail
      await this.logAudit(governanceResponse);

      return result;
    } catch (error) {
      if (this.config.debug) {
        debugLog('Error in protect()', error);
      }

      // In production, fail open (allow the call) if AxonFlow is unavailable
      if (this.config.mode === 'production' && this.isAxonFlowError(error)) {
        console.warn('AxonFlow unavailable, failing open');
        return aiCall();
      }

      throw error;
    }
  }

  /**
   * Extract request details from an AI call
   */
  private async extractRequest(aiCall: Function): Promise<AIRequest> {
    // Try each interceptor to see if it can handle this call
    for (const interceptor of this.interceptors) {
      if (interceptor.canHandle(aiCall)) {
        return interceptor.extractRequest(aiCall);
      }
    }

    // Generic extraction if no specific interceptor matches
    return {
      provider: 'unknown',
      model: 'unknown',
      prompt: aiCall.toString(),
      parameters: {}
    };
  }

  /**
   * Check policies with AxonFlow Agent
   */
  private async checkPolicies(request: GovernanceRequest): Promise<GovernanceResponse> {
    const url = `${this.config.endpoint}/api/request`;

    // Transform SDK request to Agent API format
    const agentRequest = {
      query: request.aiRequest.prompt,
      user_token: this.config.apiKey,
      client_id: this.config.tenant,
      request_type: 'llm_chat',
      context: {
        provider: request.aiRequest.provider,
        model: request.aiRequest.model,
        parameters: request.aiRequest.parameters,
        requestId: request.requestId,
        mode: this.config.mode
      }
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(agentRequest),
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`AxonFlow API error: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const agentResponse = await response.json();

    // Transform Agent API response to SDK format
    return {
      requestId: request.requestId,
      allowed: !agentResponse.blocked,
      violations: agentResponse.blocked ? [{
        type: 'security',
        severity: 'high',
        description: agentResponse.block_reason || 'Request blocked by policy',
        policy: 'agent-policy',
        action: 'blocked'
      }] : [],
      modifiedRequest: agentResponse.data,
      policies: [],
      audit: {
        timestamp: Date.now(),
        duration: parseInt(agentResponse.policy_info?.processing_time?.replace('ms', '') || '0'),
        tenant: this.config.tenant
      }
    };
  }

  /**
   * Log audit trail
   */
  private async logAudit(response: GovernanceResponse): Promise<void> {
    // Audit logging is handled server-side by the Agent
    // Just log locally if debug mode is enabled
    if (this.config.debug) {
      debugLog('Request processed', {
        allowed: response.allowed,
        violations: response.violations?.length || 0,
        duration: response.audit.duration
      });
    }
  }

  /**
   * Check if an error is from AxonFlow (vs the AI provider)
   */
  private isAxonFlowError(error: any): boolean {
    return error?.message?.includes('AxonFlow') ||
           error?.message?.includes('governance') ||
           error?.message?.includes('fetch');
  }

  /**
   * Create a sandbox client for testing
   */
  static sandbox(apiKey: string = 'demo-key'): AxonFlow {
    return new AxonFlow({
      apiKey,
      mode: 'sandbox',
      endpoint: 'https://staging-eu.getaxonflow.com',
      debug: true
    });
  }

  /**
   * List all available MCP connectors from the marketplace
   */
  async listConnectors(): Promise<ConnectorMetadata[]> {
    const url = `${this.config.endpoint}/api/connectors`;

    const response = await fetch(url, {
      method: 'GET',
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      throw new Error(`Failed to list connectors: ${response.status} ${response.statusText}`);
    }

    const connectors = await response.json();

    if (this.config.debug) {
      debugLog('Listed connectors', { count: connectors.length });
    }

    return connectors;
  }

  /**
   * Install an MCP connector from the marketplace
   */
  async installConnector(request: ConnectorInstallRequest): Promise<void> {
    const url = `${this.config.endpoint}/api/connectors/install`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Secret': this.config.apiKey
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to install connector: ${response.status} ${response.statusText} - ${errorText}`);
    }

    if (this.config.debug) {
      debugLog('Connector installed', { name: request.name });
    }
  }

  /**
   * Execute a query against an installed MCP connector
   */
  async queryConnector(connectorName: string, query: string, params?: any): Promise<ConnectorResponse> {
    const agentRequest = {
      query,
      user_token: this.config.apiKey,
      client_id: this.config.tenant,
      request_type: 'mcp-query',
      context: {
        connector: connectorName,
        params: params || {}
      }
    };

    const url = `${this.config.endpoint}/api/request`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(agentRequest),
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Connector query failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const agentResponse = await response.json();

    if (this.config.debug) {
      debugLog('Connector query executed', { connector: connectorName });
    }

    return {
      success: agentResponse.success,
      data: agentResponse.data,
      error: agentResponse.error,
      meta: agentResponse.metadata
    };
  }

  /**
   * Generate a multi-agent execution plan from a natural language query
   */
  async generatePlan(query: string, domain?: string): Promise<PlanResponse> {
    const agentRequest = {
      query,
      user_token: this.config.apiKey,
      client_id: this.config.tenant,
      request_type: 'multi-agent-plan',
      context: domain ? { domain } : {}
    };

    const url = `${this.config.endpoint}/api/request`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(agentRequest),
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Plan generation failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const agentResponse = await response.json();

    if (!agentResponse.success) {
      throw new Error(`Plan generation failed: ${agentResponse.error}`);
    }

    if (this.config.debug) {
      debugLog('Plan generated', { planId: agentResponse.plan_id });
    }

    return {
      planId: agentResponse.plan_id,
      steps: agentResponse.data?.steps || [],
      domain: agentResponse.data?.domain || domain || 'generic',
      complexity: agentResponse.data?.complexity || 0,
      parallel: agentResponse.data?.parallel || false,
      metadata: agentResponse.metadata || {}
    };
  }

  /**
   * Execute a previously generated multi-agent plan
   */
  async executePlan(planId: string): Promise<PlanExecutionResponse> {
    const agentRequest = {
      query: '',
      user_token: this.config.apiKey,
      client_id: this.config.tenant,
      request_type: 'execute-plan',
      context: { plan_id: planId }
    };

    const url = `${this.config.endpoint}/api/request`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(agentRequest),
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Plan execution failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const agentResponse = await response.json();

    if (this.config.debug) {
      debugLog('Plan executed', { planId, success: agentResponse.success });
    }

    return {
      planId,
      status: agentResponse.success ? 'completed' : 'failed',
      result: agentResponse.result,
      stepResults: agentResponse.metadata?.step_results,
      error: agentResponse.error,
      duration: agentResponse.metadata?.duration
    };
  }

  /**
   * Get the status of a running or completed plan
   */
  async getPlanStatus(planId: string): Promise<PlanExecutionResponse> {
    const url = `${this.config.endpoint}/api/plans/${planId}`;

    const response = await fetch(url, {
      method: 'GET',
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Get plan status failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const status = await response.json();

    return {
      planId,
      status: status.status,
      result: status.result,
      stepResults: status.step_results,
      error: status.error,
      duration: status.duration
    };
  }

  // ===========================================================================
  // Gateway Mode SDK Methods
  // ===========================================================================
  // Gateway Mode allows clients to make LLM calls directly while still using
  // AxonFlow for policy enforcement and audit logging.
  //
  // Usage:
  //   1. Call getPolicyApprovedContext() before making LLM call
  //   2. Make LLM call directly to your provider (using returned approved data)
  //   3. Call auditLLMCall() after to record the call for compliance
  //
  // Example:
  //   const ctx = await axonflow.getPolicyApprovedContext({
  //     userToken: 'user-jwt',
  //     dataSources: ['postgres'],
  //     query: 'Find patients with diabetes'
  //   });
  //   if (!ctx.approved) throw new Error(ctx.blockReason);
  //
  //   const llmResp = await openai.chat.completions.create({...});  // Your LLM call
  //
  //   await axonflow.auditLLMCall({
  //     contextId: ctx.contextId,
  //     responseSummary: 'Found 5 patients',
  //     provider: 'openai',
  //     model: 'gpt-4',
  //     tokenUsage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
  //     latencyMs: 250
  //   });

  /**
   * Perform policy pre-check before making LLM call
   *
   * This is the first step in Gateway Mode. Call this before making your
   * LLM call to ensure policy compliance.
   *
   * @param request Pre-check request containing user token, query, and optional data sources
   * @returns PolicyApprovalResult with context ID and approved data (if any)
   *
   * @example
   * const result = await axonflow.getPolicyApprovedContext({
   *   userToken: 'user-jwt-token',
   *   dataSources: ['postgres', 'salesforce'],
   *   query: 'Find all patients with recent lab results'
   * });
   *
   * if (!result.approved) {
   *   throw new Error(`Request blocked: ${result.blockReason}`);
   * }
   *
   * // Use result.approvedData to build your LLM prompt
   * const prompt = buildPrompt(result.approvedData);
   */
  async getPolicyApprovedContext(request: PreCheckRequest): Promise<PolicyApprovalResult> {
    const url = `${this.config.endpoint}/api/policy/pre-check`;

    const body = {
      user_token: request.userToken,
      client_id: this.config.tenant,
      query: request.query,
      data_sources: request.dataSources || [],
      context: request.context || {}
    };

    if (this.config.debug) {
      debugLog('Gateway pre-check request', {
        query: request.query.substring(0, 50),
        dataSources: request.dataSources
      });
    }

    const startTime = Date.now();
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Secret': this.config.apiKey,
        'X-License-Key': this.config.apiKey
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.config.timeout)
    });

    const duration = Date.now() - startTime;

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Pre-check failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const data = await response.json();

    if (this.config.debug) {
      debugLog('Gateway pre-check complete', {
        contextId: data.context_id,
        approved: data.approved,
        duration
      });
    }

    return {
      contextId: data.context_id,
      approved: data.approved,
      approvedData: data.approved_data,
      policies: data.policies || [],
      rateLimitInfo: data.rate_limit ? {
        limit: data.rate_limit.limit,
        remaining: data.rate_limit.remaining,
        resetAt: new Date(data.rate_limit.reset_at)
      } : undefined,
      expiresAt: new Date(data.expires_at),
      blockReason: data.block_reason
    };
  }

  /**
   * Report LLM call details for audit logging
   *
   * This is the second step in Gateway Mode. Call this after making your
   * LLM call to record it in the audit trail.
   *
   * @param contextId Context ID from getPolicyApprovedContext()
   * @param responseSummary Brief summary of the LLM response (not full response)
   * @param provider LLM provider name
   * @param model Model name
   * @param tokenUsage Token counts from LLM response
   * @param latencyMs Time taken for LLM call in milliseconds
   * @param metadata Optional additional metadata
   * @returns AuditResult confirming the audit was recorded
   *
   * @example
   * const result = await axonflow.auditLLMCall(
   *   ctx.contextId,
   *   'Found 5 patients with recent lab results',
   *   'openai',
   *   'gpt-4',
   *   { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
   *   250,
   *   { sessionId: 'session-123' }
   * );
   */
  async auditLLMCall(
    contextId: string,
    responseSummary: string,
    provider: string,
    model: string,
    tokenUsage: TokenUsage,
    latencyMs: number,
    metadata?: Record<string, any>
  ): Promise<AuditResult> {
    const url = `${this.config.endpoint}/api/audit/llm-call`;

    const body = {
      context_id: contextId,
      client_id: this.config.tenant,
      response_summary: responseSummary,
      provider,
      model,
      token_usage: {
        prompt_tokens: tokenUsage.promptTokens,
        completion_tokens: tokenUsage.completionTokens,
        total_tokens: tokenUsage.totalTokens
      },
      latency_ms: latencyMs,
      metadata
    };

    if (this.config.debug) {
      debugLog('Gateway audit request', {
        contextId,
        provider,
        model,
        tokens: tokenUsage.totalTokens
      });
    }

    const startTime = Date.now();
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Secret': this.config.apiKey,
        'X-License-Key': this.config.apiKey
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.config.timeout)
    });

    const duration = Date.now() - startTime;

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Audit failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const data = await response.json();

    if (this.config.debug) {
      debugLog('Gateway audit complete', {
        auditId: data.audit_id,
        duration
      });
    }

    return {
      success: data.success,
      auditId: data.audit_id
    };
  }
}