/**
 * Multi-Agent Planning (MAP) types for AxonFlow SDK
 */

export interface PlanStep {
  id: string;
  name: string;
  type: string;
  description: string;
  dependsOn: string[];
  agent: string;
  parameters: Record<string, any>;
}

export interface PlanResponse {
  planId: string;
  steps: PlanStep[];
  domain: string;
  complexity: number;
  parallel: boolean;
  metadata: Record<string, any>;
}

export interface PlanExecutionResponse {
  planId: string;
  status: 'running' | 'completed' | 'failed';
  result?: string;
  stepResults?: Record<string, any>;
  error?: string;
  duration?: string;
}
