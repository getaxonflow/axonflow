/**
 * Unit tests for Workflow Control Plane SDK methods
 */

import { AxonFlow } from '../src/client';
import {
  CreateWorkflowRequest,
  StepGateRequest,
  WorkflowStatus,
  WorkflowSource,
  GateDecision,
  StepType
} from '../src/types';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch as any;

describe('AxonFlow Workflow Control Plane', () => {
  let axonflow: AxonFlow;

  beforeEach(() => {
    mockFetch.mockClear();
    axonflow = new AxonFlow({
      apiKey: 'test-api-key',
      tenant: 'test-tenant',
      endpoint: 'http://localhost:8080',
      debug: false
    });
  });

  describe('createWorkflow', () => {
    it('should create a workflow successfully', async () => {
      const mockResponse = {
        workflow_id: 'wf_123',
        workflow_name: 'test-workflow',
        source: 'langgraph',
        status: 'in_progress',
        created_at: '2026-01-17T00:00:00Z'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const request: CreateWorkflowRequest = {
        workflowName: 'test-workflow',
        source: 'langgraph',
        totalSteps: 5,
        metadata: { customerId: 'cust-123' }
      };

      const result = await axonflow.createWorkflow(request);

      expect(result.workflowId).toBe('wf_123');
      expect(result.workflowName).toBe('test-workflow');
      expect(result.source).toBe('langgraph');
      expect(result.status).toBe('in_progress');
      expect(result.createdAt).toBeInstanceOf(Date);

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/v1/workflows',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          }),
          body: JSON.stringify({
            workflow_name: 'test-workflow',
            source: 'langgraph',
            total_steps: 5,
            metadata: { customerId: 'cust-123' }
          })
        })
      );
    });

    it('should throw error when creation fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: async () => 'workflow_name is required'
      });

      await expect(axonflow.createWorkflow({ workflowName: '' }))
        .rejects.toThrow('Failed to create workflow: 400 Bad Request');
    });
  });

  describe('getWorkflow', () => {
    it('should get workflow status', async () => {
      const mockResponse = {
        workflow_id: 'wf_123',
        workflow_name: 'test-workflow',
        source: 'langgraph',
        status: 'in_progress',
        current_step_index: 2,
        total_steps: 5,
        started_at: '2026-01-17T00:00:00Z',
        steps: [
          {
            step_id: 'step-1',
            step_index: 1,
            step_name: 'Generate Code',
            step_type: 'llm_call',
            decision: 'allow',
            gate_checked_at: '2026-01-17T00:00:00Z'
          }
        ]
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await axonflow.getWorkflow('wf_123');

      expect(result.workflowId).toBe('wf_123');
      expect(result.currentStepIndex).toBe(2);
      expect(result.totalSteps).toBe(5);
      expect(result.steps).toHaveLength(1);
      expect(result.steps![0].stepId).toBe('step-1');
      expect(result.steps![0].decision).toBe('allow');
    });

    it('should throw error when workflow not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        text: async () => 'workflow not found'
      });

      await expect(axonflow.getWorkflow('wf_nonexistent'))
        .rejects.toThrow('Failed to get workflow: 404 Not Found');
    });
  });

  describe('stepGate', () => {
    it('should return allow decision', async () => {
      const mockResponse = {
        decision: 'allow',
        step_id: 'step-1',
        reason: null,
        policy_ids: []
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const request: StepGateRequest = {
        stepName: 'Generate Code',
        stepType: 'llm_call',
        model: 'gpt-4',
        provider: 'openai'
      };

      const result = await axonflow.stepGate('wf_123', 'step-1', request);

      expect(result.decision).toBe('allow');
      expect(result.stepId).toBe('step-1');
    });

    it('should return block decision with reason', async () => {
      const mockResponse = {
        decision: 'block',
        step_id: 'step-1',
        reason: 'Sensitive data detected in step input',
        policy_ids: ['policy-pii-block']
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const request: StepGateRequest = {
        stepName: 'Query Patient Data',
        stepType: 'tool_call',
        stepInput: { ssn: '123-45-6789' }
      };

      const result = await axonflow.stepGate('wf_123', 'step-2', request);

      expect(result.decision).toBe('block');
      expect(result.reason).toBe('Sensitive data detected in step input');
      expect(result.policyIds).toContain('policy-pii-block');
    });

    it('should return require_approval with approval URL', async () => {
      const mockResponse = {
        decision: 'require_approval',
        step_id: 'step-3',
        reason: 'High-risk operation requires approval',
        policy_ids: ['policy-high-risk'],
        approval_url: 'https://portal.axonflow.com/approve/step-3'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const request: StepGateRequest = {
        stepName: 'Delete User Data',
        stepType: 'tool_call'
      };

      const result = await axonflow.stepGate('wf_123', 'step-3', request);

      expect(result.decision).toBe('require_approval');
      expect(result.approvalUrl).toBe('https://portal.axonflow.com/approve/step-3');
    });
  });

  describe('markStepCompleted', () => {
    it('should mark step as completed', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({})
      });

      await axonflow.markStepCompleted('wf_123', 'step-1', {
        output: { result: 'Code generated successfully' }
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/v1/workflows/wf_123/steps/step-1/complete',
        expect.objectContaining({
          method: 'POST'
        })
      );
    });
  });

  describe('completeWorkflow', () => {
    it('should complete workflow successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({})
      });

      await axonflow.completeWorkflow('wf_123');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/v1/workflows/wf_123/complete',
        expect.objectContaining({
          method: 'POST'
        })
      );
    });

    it('should throw error when workflow is already terminal', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 409,
        statusText: 'Conflict',
        text: async () => 'workflow is in terminal state'
      });

      await expect(axonflow.completeWorkflow('wf_completed'))
        .rejects.toThrow('Failed to complete workflow: 409 Conflict');
    });
  });

  describe('abortWorkflow', () => {
    it('should abort workflow with reason', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({})
      });

      await axonflow.abortWorkflow('wf_123', 'User cancelled the operation');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/v1/workflows/wf_123/abort',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ reason: 'User cancelled the operation' })
        })
      );
    });
  });

  describe('resumeWorkflow', () => {
    it('should resume workflow after approval', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({})
      });

      await axonflow.resumeWorkflow('wf_123');

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/v1/workflows/wf_123/resume',
        expect.objectContaining({
          method: 'POST'
        })
      );
    });
  });

  describe('listWorkflows', () => {
    it('should list workflows with filters', async () => {
      const mockResponse = {
        workflows: [
          {
            workflow_id: 'wf_1',
            workflow_name: 'Workflow 1',
            source: 'langgraph',
            status: 'in_progress',
            current_step_index: 1,
            started_at: '2026-01-17T00:00:00Z'
          },
          {
            workflow_id: 'wf_2',
            workflow_name: 'Workflow 2',
            source: 'langgraph',
            status: 'in_progress',
            current_step_index: 2,
            started_at: '2026-01-17T00:00:00Z'
          }
        ],
        total: 2
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await axonflow.listWorkflows({
        status: 'in_progress',
        source: 'langgraph',
        limit: 10
      });

      expect(result.workflows).toHaveLength(2);
      expect(result.total).toBe(2);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/v1/workflows?status=in_progress&source=langgraph&limit=10',
        expect.any(Object)
      );
    });

    it('should list all workflows without filters', async () => {
      const mockResponse = {
        workflows: [],
        total: 0
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      });

      const result = await axonflow.listWorkflows();

      expect(result.workflows).toHaveLength(0);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/api/v1/workflows',
        expect.any(Object)
      );
    });
  });
});

describe('Workflow Types', () => {
  it('should export all workflow types', () => {
    // Type checking at compile time
    const status: WorkflowStatus = 'in_progress';
    const source: WorkflowSource = 'langgraph';
    const decision: GateDecision = 'allow';
    const stepType: StepType = 'llm_call';

    expect(status).toBe('in_progress');
    expect(source).toBe('langgraph');
    expect(decision).toBe('allow');
    expect(stepType).toBe('llm_call');
  });
});
