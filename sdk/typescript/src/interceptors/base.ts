import { AIRequest } from '../types';

/**
 * Base interceptor interface for different AI providers
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