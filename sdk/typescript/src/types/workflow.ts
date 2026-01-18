/**
 * Workflow Control Plane types for AxonFlow SDK
 *
 * The Workflow Control Plane provides governance gates for external orchestrators
 * like LangChain, LangGraph, and CrewAI. These types define the request/response
 * structures for registering workflows, checking step gates, and managing workflow
 * lifecycle.
 */

/**
 * Workflow status values
 */
export type WorkflowStatus = 'in_progress' | 'completed' | 'aborted' | 'failed';

/**
 * Source of the workflow (which orchestrator is running it)
 */
export type WorkflowSource = 'langgraph' | 'langchain' | 'crewai' | 'external';

/**
 * Gate decision values returned by step gate checks
 */
export type GateDecision = 'allow' | 'block' | 'require_approval';

/**
 * Approval status for steps requiring human approval
 */
export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

/**
 * Step type indicating what kind of operation the step performs
 */
export type StepType = 'llm_call' | 'tool_call' | 'connector_call' | 'human_task';

/**
 * Request to create a new workflow
 */
export interface CreateWorkflowRequest {
  /**
   * Human-readable name for the workflow
   */
  workflowName: string;

  /**
   * Source orchestrator running the workflow
   */
  source?: WorkflowSource;

  /**
   * Total number of steps in the workflow (if known)
   */
  totalSteps?: number;

  /**
   * Additional metadata for the workflow
   */
  metadata?: Record<string, any>;
}

/**
 * Response from creating a workflow
 */
export interface CreateWorkflowResponse {
  /**
   * Unique identifier for the workflow
   */
  workflowId: string;

  /**
   * Name of the workflow
   */
  workflowName: string;

  /**
   * Source orchestrator
   */
  source: WorkflowSource;

  /**
   * Current status (always 'in_progress' for new workflows)
   */
  status: WorkflowStatus;

  /**
   * When the workflow was created
   */
  createdAt: Date;
}

/**
 * Request to check if a step is allowed to proceed
 */
export interface StepGateRequest {
  /**
   * Human-readable name for the step
   */
  stepName?: string;

  /**
   * Type of step being executed
   */
  stepType: StepType;

  /**
   * Input data for the step (for policy evaluation)
   */
  stepInput?: Record<string, any>;

  /**
   * LLM model being used (if applicable)
   */
  model?: string;

  /**
   * LLM provider (if applicable)
   */
  provider?: string;
}

/**
 * Response from a step gate check
 */
export interface StepGateResponse {
  /**
   * The gate decision: allow, block, or require_approval
   */
  decision: GateDecision;

  /**
   * Unique step ID assigned by the system
   */
  stepId: string;

  /**
   * Reason for the decision (especially for block/require_approval)
   */
  reason?: string;

  /**
   * IDs of policies that matched and influenced the decision
   */
  policyIds?: string[];

  /**
   * URL to the approval portal (if decision is require_approval)
   */
  approvalUrl?: string;

  /**
   * All policies that were checked during evaluation (Issue #1021)
   */
  policiesEvaluated?: PolicyMatch[];

  /**
   * Policies that matched and contributed to the decision (Issue #1021)
   */
  policiesMatched?: PolicyMatch[];
}

/**
 * Information about a workflow step
 */
export interface WorkflowStepInfo {
  /**
   * Unique step identifier
   */
  stepId: string;

  /**
   * Step index in the workflow
   */
  stepIndex: number;

  /**
   * Step name
   */
  stepName?: string;

  /**
   * Step type
   */
  stepType: StepType;

  /**
   * Gate decision for this step
   */
  decision: GateDecision;

  /**
   * Reason for the decision
   */
  decisionReason?: string;

  /**
   * Approval status (if require_approval decision)
   */
  approvalStatus?: ApprovalStatus;

  /**
   * Who approved the step (if approved)
   */
  approvedBy?: string;

  /**
   * When the gate was checked
   */
  gateCheckedAt: Date;

  /**
   * When the step was completed
   */
  completedAt?: Date;
}

/**
 * Response containing workflow status
 */
export interface WorkflowStatusResponse {
  /**
   * Workflow ID
   */
  workflowId: string;

  /**
   * Workflow name
   */
  workflowName: string;

  /**
   * Source orchestrator
   */
  source: WorkflowSource;

  /**
   * Current status
   */
  status: WorkflowStatus;

  /**
   * Current step index (0-based)
   */
  currentStepIndex: number;

  /**
   * Total steps in the workflow (if known)
   */
  totalSteps?: number;

  /**
   * When the workflow started
   */
  startedAt: Date;

  /**
   * When the workflow completed (if completed)
   */
  completedAt?: Date;

  /**
   * List of steps in the workflow
   */
  steps?: WorkflowStepInfo[];
}

/**
 * Options for listing workflows
 */
export interface ListWorkflowsOptions {
  /**
   * Filter by workflow status
   */
  status?: WorkflowStatus;

  /**
   * Filter by source
   */
  source?: WorkflowSource;

  /**
   * Maximum number of results to return
   */
  limit?: number;

  /**
   * Offset for pagination
   */
  offset?: number;
}

/**
 * Response from listing workflows
 */
export interface ListWorkflowsResponse {
  /**
   * List of workflows
   */
  workflows: WorkflowStatusResponse[];

  /**
   * Total count (for pagination)
   */
  total: number;
}

/**
 * Request to mark a step as completed
 */
export interface MarkStepCompletedRequest {
  /**
   * Output data from the step
   */
  output?: Record<string, any>;

  /**
   * Additional metadata
   */
  metadata?: Record<string, any>;
}

/**
 * Request to abort a workflow
 */
export interface AbortWorkflowRequest {
  /**
   * Reason for aborting the workflow
   */
  reason?: string;
}

/**
 * Policy match information
 */
export interface PolicyMatch {
  /**
   * Policy ID that matched
   */
  policyId: string;

  /**
   * Policy name
   */
  policyName: string;

  /**
   * Action taken by the policy
   */
  action: string;

  /**
   * Reason for the match
   */
  reason?: string;
}
