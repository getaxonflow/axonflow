/**
 * MAS FEAT Compliance Types
 *
 * Types for the Monetary Authority of Singapore FEAT (Fairness, Ethics,
 * Accountability, Transparency) compliance module.
 */

// ===========================================================================
// Enums
// ===========================================================================

export type MaterialityClassification = 'high' | 'medium' | 'low';
export type SystemStatus = 'draft' | 'active' | 'suspended' | 'retired';
export type FEATAssessmentStatus = 'pending' | 'in_progress' | 'completed' | 'approved' | 'rejected';
export type KillSwitchStatus = 'enabled' | 'disabled' | 'triggered';
export type FEATPillar = 'fairness' | 'ethics' | 'accountability' | 'transparency';
export type AISystemUseCase =
  | 'credit_scoring'
  | 'robo_advisory'
  | 'insurance_underwriting'
  | 'trading_algorithm'
  | 'aml_cft'
  | 'customer_service'
  | 'fraud_detection'
  | 'other';

// ===========================================================================
// AI System Registry
// ===========================================================================

export interface RegisterSystemRequest {
  /** Unique system identifier */
  systemId: string;
  /** Human-readable system name */
  systemName: string;
  /** System description */
  description?: string;
  /** Primary use case category */
  useCase: AISystemUseCase;
  /** Owning team */
  ownerTeam: string;
  /** Technical owner email */
  technicalOwner?: string;
  /** Business owner email */
  businessOwner?: string;
  /** Customer impact rating (1-5) */
  customerImpact: number;
  /** Model complexity rating (1-5) */
  modelComplexity: number;
  /** Human reliance rating (1-5) */
  humanReliance: number;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

export interface UpdateSystemRequest {
  systemName?: string;
  description?: string;
  ownerTeam?: string;
  technicalOwner?: string;
  businessOwner?: string;
  customerImpact?: number;
  modelComplexity?: number;
  humanReliance?: number;
  metadata?: Record<string, any>;
}

export interface AISystemRegistry {
  id: string;
  orgId: string;
  systemId: string;
  systemName: string;
  description?: string;
  useCase: AISystemUseCase;
  ownerTeam: string;
  technicalOwner?: string;
  businessOwner?: string;
  customerImpact: number;
  modelComplexity: number;
  humanReliance: number;
  materiality: MaterialityClassification;
  status: SystemStatus;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
}

export interface RegistrySummary {
  totalSystems: number;
  activeSystems: number;
  highMaterialityCount: number;
  mediumMaterialityCount: number;
  lowMaterialityCount: number;
  byUseCase: Record<string, number>;
  byStatus: Record<string, number>;
}

export interface ListSystemsOptions {
  status?: SystemStatus;
  useCase?: AISystemUseCase;
  materiality?: MaterialityClassification;
  limit?: number;
  offset?: number;
}

// ===========================================================================
// FEAT Assessments
// ===========================================================================

export interface CreateAssessmentRequest {
  /** System ID to assess */
  systemId: string;
  /** Assessment type */
  assessmentType?: 'initial' | 'periodic' | 'ad_hoc';
  /** List of assessor emails */
  assessors?: string[];
}

export interface UpdateAssessmentRequest {
  /** Fairness pillar score (0-100) */
  fairnessScore?: number;
  /** Ethics pillar score (0-100) */
  ethicsScore?: number;
  /** Accountability pillar score (0-100) */
  accountabilityScore?: number;
  /** Transparency pillar score (0-100) */
  transparencyScore?: number;
  /** Fairness assessment details */
  fairnessDetails?: Record<string, any>;
  /** Ethics assessment details */
  ethicsDetails?: Record<string, any>;
  /** Accountability assessment details */
  accountabilityDetails?: Record<string, any>;
  /** Transparency assessment details */
  transparencyDetails?: Record<string, any>;
  /** Assessment findings */
  findings?: string[];
  /** Recommendations */
  recommendations?: string[];
  /** Assessor list */
  assessors?: string[];
}

export interface FEATAssessment {
  id: string;
  orgId: string;
  systemId: string;
  assessmentType: string;
  status: FEATAssessmentStatus;
  assessmentDate: Date;
  validUntil?: Date;
  fairnessScore?: number;
  ethicsScore?: number;
  accountabilityScore?: number;
  transparencyScore?: number;
  overallScore?: number;
  fairnessDetails?: Record<string, any>;
  ethicsDetails?: Record<string, any>;
  accountabilityDetails?: Record<string, any>;
  transparencyDetails?: Record<string, any>;
  findings?: string[];
  recommendations?: string[];
  assessors?: string[];
  approvedBy?: string;
  approvedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
}

export interface ApproveAssessmentRequest {
  approvedBy: string;
  comments?: string;
}

export interface RejectAssessmentRequest {
  rejectedBy: string;
  reason: string;
}

export interface ListAssessmentsOptions {
  systemId?: string;
  status?: FEATAssessmentStatus;
  limit?: number;
  offset?: number;
}

// ===========================================================================
// Kill Switch
// ===========================================================================

export interface KillSwitch {
  id: string;
  orgId: string;
  systemId: string;
  status: KillSwitchStatus;
  accuracyThreshold?: number;
  biasThreshold?: number;
  errorRateThreshold?: number;
  autoTriggerEnabled: boolean;
  triggeredAt?: Date;
  triggeredBy?: string;
  triggeredReason?: string;
  restoredAt?: Date;
  restoredBy?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConfigureKillSwitchRequest {
  /** Minimum accuracy threshold (0-1) */
  accuracyThreshold?: number;
  /** Maximum bias threshold (0-1) */
  biasThreshold?: number;
  /** Maximum error rate threshold (0-1) */
  errorRateThreshold?: number;
  /** Enable automatic triggering */
  autoTriggerEnabled?: boolean;
}

export interface CheckKillSwitchRequest {
  /** Current model accuracy (0-1) */
  accuracy: number;
  /** Current bias score (0-1) */
  biasScore?: number;
  /** Current error rate (0-1) */
  errorRate?: number;
}

export interface TriggerKillSwitchRequest {
  reason: string;
  triggeredBy?: string;
}

export interface RestoreKillSwitchRequest {
  reason: string;
  restoredBy?: string;
}

export interface DisableKillSwitchRequest {
  reason?: string;
}

export interface KillSwitchEvent {
  id: string;
  killSwitchId: string;
  eventType: 'created' | 'enabled' | 'disabled' | 'triggered' | 'restored' | 'configured';
  eventData?: Record<string, any>;
  createdBy?: string;
  createdAt: Date;
}
