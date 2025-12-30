import { AIRequest } from '../types';

/**
 * Base interceptor interface for different AI providers
 *
 * @deprecated TypeScript interceptors are deprecated as of SDK v1.4.0 and will be removed in v2.0.0.
 * Modern LLM SDKs (OpenAI v4+, Anthropic v0.20+) use ES2022 private class fields which are
 * incompatible with JavaScript Proxy-based wrapping.
 *
 * Use Gateway Mode or Proxy Mode instead:
 * - Gateway Mode: https://docs.getaxonflow.com/docs/sdk/gateway-mode
 * - Proxy Mode: https://docs.getaxonflow.com/docs/sdk/proxy-mode
 */
export abstract class BaseInterceptor {
  /**
   * Check if this interceptor can handle the given AI call
   */
  abstract canHandle(aiCall: any): boolean;

  /**
   * Extract request details from the AI call
   */
  abstract extractRequest(aiCall: any): AIRequest;

  /**
   * Execute the AI call with modifications
   */
  abstract executeWithModifications(aiCall: any, modifications: any): Promise<any>;

  /**
   * Get the provider name
   */
  abstract getProvider(): string;
}