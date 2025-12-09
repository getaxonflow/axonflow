/**
 * Policy-related types
 */
export interface Policy {
  /**
   * Policy ID
   */
  id: string;

  /**
   * Policy name
   */
  name: string;

  /**
   * Policy type
   */
  type: 'static' | 'dynamic';

  /**
   * Is the policy enabled?
   */
  enabled: boolean;

  /**
   * Policy rules
   */
  rules: PolicyRule[];

  /**
   * Priority (lower numbers = higher priority)
   */
  priority: number;
}

export interface PolicyRule {
  /**
   * Rule condition
   */
  condition: {
    field: string;
    operator: 'equals' | 'contains' | 'regex' | 'greater' | 'less';
    value: any;
  };

  /**
   * Action to take if condition matches
   */
  action: 'allow' | 'deny' | 'redact' | 'modify' | 'log';

  /**
   * Optional message
   */
  message?: string;
}