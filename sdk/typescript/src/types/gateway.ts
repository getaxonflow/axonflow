/**
 * Gateway Mode Types
 *
 * Gateway Mode allows clients to make LLM calls directly while still using
 * AxonFlow for policy enforcement and audit logging.
 *
 * Usage:
 *   1. Call getPolicyApprovedContext() before making LLM call
 *   2. Make LLM call directly to your provider (using returned approved data)
 *   3. Call auditLLMCall() after to record the call for compliance
 */

/**
 * Request for policy pre-check before LLM call
 */
export interface PreCheckRequest {
  /**
   * JWT token for the user making the request
   */
  userToken: string;

  /**
   * Optional list of MCP connectors to fetch data from
   */
  dataSources?: string[];

  /**
   * The query/prompt that will be sent to the LLM
   */
  query: string;

  /**
   * Optional additional context for policy evaluation
   */
  context?: Record<string, any>;
}

/**
 * Result from policy pre-check
 */
export interface PolicyApprovalResult {
  /**
   * Context ID linking pre-check to audit
   */
  contextId: string;

  /**
   * Whether the request was approved by policies
   */
  approved: boolean;

  /**
   * Filtered data from connectors (if dataSources specified)
   */
  approvedData?: Record<string, any>;

  /**
   * Policies that were evaluated
   */
  policies: string[];

  /**
   * Rate limit information (if applicable)
   */
  rateLimitInfo?: RateLimitInfo;

  /**
   * When this context expires
   */
  expiresAt: Date;

  /**
   * Reason if request was blocked
   */
  blockReason?: string;
}

/**
 * Rate limit status information
 */
export interface RateLimitInfo {
  /**
   * Maximum requests allowed
   */
  limit: number;

  /**
   * Remaining requests in current window
   */
  remaining: number;

  /**
   * When the rate limit resets
   */
  resetAt: Date;
}

/**
 * Token usage tracking from LLM response
 */
export interface TokenUsage {
  /**
   * Number of prompt tokens used
   */
  promptTokens: number;

  /**
   * Number of completion tokens generated
   */
  completionTokens: number;

  /**
   * Total tokens (prompt + completion)
   */
  totalTokens: number;
}

/**
 * Request to audit an LLM call
 */
export interface AuditLLMCallRequest {
  /**
   * Context ID from getPolicyApprovedContext()
   */
  contextId: string;

  /**
   * Brief summary of the LLM response (not full response for privacy)
   */
  responseSummary: string;

  /**
   * LLM provider name
   */
  provider: 'openai' | 'anthropic' | 'bedrock' | 'ollama' | string;

  /**
   * Model name
   */
  model: string;

  /**
   * Token counts from LLM response
   */
  tokenUsage: TokenUsage;

  /**
   * Time taken for LLM call in milliseconds
   */
  latencyMs: number;

  /**
   * Optional additional metadata
   */
  metadata?: Record<string, any>;
}

/**
 * Result from audit recording
 */
export interface AuditResult {
  /**
   * Whether audit was recorded successfully
   */
  success: boolean;

  /**
   * Unique audit record ID
   */
  auditId: string;
}
