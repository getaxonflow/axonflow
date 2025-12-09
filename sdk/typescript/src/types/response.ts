/**
 * Response types from AxonFlow governance
 */
export interface GovernanceResponse {
  /**
   * Request ID for tracking
   */
  requestId: string;

  /**
   * Whether the request is allowed
   */
  allowed: boolean;

  /**
   * Modified request (if any modifications were made)
   */
  modifiedRequest?: any;

  /**
   * Applied policies
   */
  policies: PolicyDecision[];

  /**
   * Audit information
   */
  audit: {
    timestamp: number;
    duration: number;
    tenant?: string;
  };

  /**
   * Any violations detected
   */
  violations?: Violation[];

  /**
   * The AI response (after governance)
   */
  aiResponse?: any;
}

export interface PolicyDecision {
  /**
   * Policy ID
   */
  id: string;

  /**
   * Policy name
   */
  name: string;

  /**
   * Decision (allow, deny, modify)
   */
  decision: 'allow' | 'deny' | 'modify';

  /**
   * Reason for the decision
   */
  reason?: string;

  /**
   * Modifications applied
   */
  modifications?: any[];
}

export interface Violation {
  /**
   * Type of violation
   */
  type: 'pii' | 'security' | 'cost' | 'rate_limit' | 'content' | 'other';

  /**
   * Severity
   */
  severity: 'low' | 'medium' | 'high' | 'critical';

  /**
   * Description
   */
  description: string;

  /**
   * Policy that was violated
   */
  policy: string;

  /**
   * Action taken
   */
  action: 'blocked' | 'redacted' | 'logged' | 'allowed';
}