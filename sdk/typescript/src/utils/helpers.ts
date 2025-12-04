/**
 * Generate a unique request ID
 */
export function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Debug logging helper
 */
export function debugLog(message: string, data?: any): void {
  console.log(`[AxonFlow] ${message}`, data ? JSON.stringify(data, null, 2) : '');
}

/**
 * Sleep helper for retry logic
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Check if running in browser vs Node.js
 */
export function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof window.document !== 'undefined';
}

/**
 * Check if running in Node.js
 */
export function isNode(): boolean {
  return typeof process !== 'undefined' && process.versions !== undefined && process.versions.node !== undefined;
}

/**
 * Safe JSON stringify that handles circular references
 */
export function safeStringify(obj: any): string {
  const seen = new WeakSet();
  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular]';
      }
      seen.add(value);
    }
    return value;
  });
}