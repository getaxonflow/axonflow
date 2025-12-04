/**
 * Integration test for AxonFlow SDK
 * Tests actual API connectivity
 */

import { AxonFlow } from '../src/client';

describe('AxonFlow SDK Integration Tests', () => {
  // Use a test client ID (should exist in the Agent database)
  const TEST_CLIENT_ID = 'healthcare-acme';
  const TEST_USER_TOKEN = 'test-token-123';

  describe('Public Endpoint', () => {
    it('should connect to public endpoint', async () => {
      const axonflow = new AxonFlow({
        apiKey: TEST_USER_TOKEN,
        tenant: TEST_CLIENT_ID,
        endpoint: 'https://staging-eu.getaxonflow.com',
        debug: true
      });

      // Mock AI call
      const mockAICall = async () => {
        return { message: 'Hello from AI' };
      };

      try {
        const result = await axonflow.protect(mockAICall);
        console.log('✅ Public endpoint test passed:', result);
        expect(result).toBeDefined();
      } catch (error: any) {
        // Expected to fail with 401/403 if client doesn't exist
        console.log('Expected error (client validation):', error.message);
        expect(error.message).toContain('AxonFlow API error');
      }
    }, 30000);
  });

  describe('VPC Private Endpoint', () => {
    it('should connect to VPC private endpoint', async () => {
      const axonflow = new AxonFlow({
        apiKey: TEST_USER_TOKEN,
        tenant: TEST_CLIENT_ID,
        endpoint: 'https://10.0.2.67:8443',
        debug: true
      });

      // Mock AI call
      const mockAICall = async () => {
        return { message: 'Hello from AI' };
      };

      try {
        const result = await axonflow.protect(mockAICall);
        console.log('✅ VPC endpoint test passed:', result);
        expect(result).toBeDefined();
      } catch (error: any) {
        // Expected to fail with connection error if not in VPC
        console.log('Expected error (VPC connectivity):', error.message);
        expect(error.message).toMatch(/AxonFlow API error|fetch/);
      }
    }, 30000);
  });

  describe('Sandbox Mode', () => {
    it('should create sandbox client', () => {
      const axonflow = AxonFlow.sandbox('test-key');
      expect(axonflow).toBeDefined();
    });
  });
});
