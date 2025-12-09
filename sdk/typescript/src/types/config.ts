/**
 * Configuration options for the AxonFlow SDK
 */
export interface AxonFlowConfig {
  /**
   * Your AxonFlow API key
   */
  apiKey: string;

  /**
   * AxonFlow API endpoint (optional)
   * Default: https://api.axonflow.com
   */
  endpoint?: string;

  /**
   * Deployment mode
   * - sandbox: For testing with non-production data
   * - production: For production use
   * Default: production
   */
  mode?: 'sandbox' | 'production';

  /**
   * Tenant identifier for multi-tenant deployments
   */
  tenant?: string;

  /**
   * Enable debug logging
   * Default: false
   */
  debug?: boolean;

  /**
   * Request timeout in milliseconds
   * Default: 30000 (30 seconds)
   */
  timeout?: number;

  /**
   * Retry configuration
   */
  retry?: {
    enabled: boolean;
    maxAttempts?: number;
    delay?: number;
  };

  /**
   * Cache configuration for policy decisions
   */
  cache?: {
    enabled: boolean;
    ttl?: number; // Time to live in milliseconds
  };
}

export interface RetryConfig {
  enabled: boolean;
  maxAttempts: number;
  delay: number;
  backoff: boolean;
}

export interface CacheConfig {
  enabled: boolean;
  ttl: number;
  maxSize: number;
}