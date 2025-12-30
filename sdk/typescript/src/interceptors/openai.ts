import { BaseInterceptor } from './base';
import { AIRequest } from '../types';

/**
 * Interceptor for OpenAI API calls
 *
 * @deprecated TypeScript interceptors are deprecated as of SDK v1.4.0 and will be removed in v2.0.0.
 * Use Gateway Mode or Proxy Mode instead. See https://docs.getaxonflow.com/docs/sdk/gateway-mode
 */
export class OpenAIInterceptor extends BaseInterceptor {
  canHandle(aiCall: any): boolean {
    // Check if this looks like an OpenAI call
    const callString = aiCall.toString();
    return callString.includes('openai') ||
           callString.includes('createCompletion') ||
           callString.includes('createChatCompletion') ||
           callString.includes('gpt');
  }

  extractRequest(aiCall: any): AIRequest {
    // Try to extract OpenAI-specific details
    // This is simplified - in production, we'd use more sophisticated parsing
    const callString = aiCall.toString();

    // Try to detect model
    let model = 'unknown';
    if (callString.includes('gpt-4')) {
      model = 'gpt-4';
    } else if (callString.includes('gpt-3.5')) {
      model = 'gpt-3.5-turbo';
    }

    return {
      provider: 'openai',
      model,
      prompt: callString,
      parameters: {
        // Would extract temperature, max_tokens, etc. in production
      }
    };
  }

  executeWithModifications(aiCall: any, modifications: any): Promise<any> {
    // Execute the call with any modifications from governance
    // In production, this would apply actual modifications
    return aiCall();
  }

  getProvider(): string {
    return 'openai';
  }
}

/**
 * Helper to wrap OpenAI client for easier interception
 *
 * @deprecated TypeScript interceptors are deprecated as of SDK v1.4.0 and will be removed in v2.0.0.
 * Modern LLM SDKs (OpenAI v4+, Anthropic v0.20+) use ES2022 private class fields which are
 * incompatible with JavaScript Proxy-based wrapping.
 *
 * Use Gateway Mode or Proxy Mode instead:
 * - Gateway Mode: https://docs.getaxonflow.com/docs/sdk/gateway-mode
 * - Proxy Mode: https://docs.getaxonflow.com/docs/sdk/proxy-mode
 */
export function wrapOpenAIClient(openaiClient: any, axonflow: any): any {
  console.warn(
    '[AxonFlow] DEPRECATION WARNING: wrapOpenAIClient is deprecated as of SDK v1.4.0 and will be removed in v2.0.0. ' +
    'Use Gateway Mode or Proxy Mode instead. See https://docs.getaxonflow.com/docs/sdk/gateway-mode'
  );
  // Create a proxy that intercepts method calls
  return new Proxy(openaiClient, {
    get(target, prop, receiver) {
      const original = Reflect.get(target, prop, receiver);

      // If it's a function that makes API calls
      if (typeof original === 'function' &&
          ['createCompletion', 'createChatCompletion', 'createEdit'].includes(prop.toString())) {

        return async (...args: any[]) => {
          // Protect the call with AxonFlow
          return axonflow.protect(() => original.apply(target, args));
        };
      }

      // For nested objects (like openai.chat.completions)
      if (typeof original === 'object' && original !== null) {
        return wrapOpenAIClient(original, axonflow);
      }

      return original;
    }
  });
}