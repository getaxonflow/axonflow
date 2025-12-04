/**
 * Request types for AI calls
 */
export interface AIRequest {
  /**
   * The AI provider (openai, anthropic, etc.)
   */
  provider: string;

  /**
   * The model being used
   */
  model: string;

  /**
   * The prompt or messages
   */
  prompt: string | any[];

  /**
   * Request parameters (temperature, max_tokens, etc.)
   */
  parameters?: Record<string, any>;

  /**
   * User context for policy evaluation
   */
  context?: {
    userId?: string;
    sessionId?: string;
    metadata?: Record<string, any>;
  };

  /**
   * Original request for passthrough
   */
  originalRequest?: any;
}

export interface GovernanceRequest {
  /**
   * Unique request ID
   */
  requestId: string;

  /**
   * Timestamp
   */
  timestamp: number;

  /**
   * The AI request to govern
   */
  aiRequest: AIRequest;

  /**
   * Governance mode
   */
  mode: 'sandbox' | 'production';

  /**
   * Tenant identifier
   */
  tenant?: string;
}