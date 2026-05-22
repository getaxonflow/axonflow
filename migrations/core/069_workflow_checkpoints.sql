-- Migration 069: Workflow step-gate checkpoints
--
-- Creates automatic checkpoints at every step-gate boundary, capturing the
-- full decision and policy context for safe resume. This is the foundation for
-- the "policy-aware checkpointing" feature — not arbitrary snapshots, but
-- governance-aware resume boundaries.
--
-- Resume requires the FULL original context (step_name, model, provider,
-- tool_context, user_id, client_id) because policies may match on any of
-- these fields. Storing a partial snapshot would produce different decisions
-- on resume for the wrong reason.
--
-- Tier behavior:
--   Community:  checkpoints created and readable (GET /checkpoints), no resume
--   Evaluation: resume from last checkpoint only
--   Enterprise: resume from any checkpoint

CREATE TABLE IF NOT EXISTS workflow_checkpoints (
    id BIGSERIAL PRIMARY KEY,

    -- References the workflow this checkpoint belongs to. CASCADE ensures
    -- checkpoints are cleaned up when a workflow is deleted.
    workflow_id VARCHAR(255) NOT NULL REFERENCES workflows(workflow_id) ON DELETE CASCADE,

    -- Step identity and position
    step_id VARCHAR(255) NOT NULL,
    step_index INTEGER NOT NULL,
    step_type VARCHAR(100),
    step_name VARCHAR(255),

    -- Checkpoint classification
    -- "step_gate": standard checkpoint at a step-gate evaluation
    -- "approval_boundary": checkpoint where the step required human approval
    checkpoint_type VARCHAR(50) NOT NULL DEFAULT 'step_gate',

    -- Snapshot of the gate decision at this boundary
    gate_decision VARCHAR(50) NOT NULL,
    gate_reason TEXT,
    policies_evaluated JSONB DEFAULT '[]',
    policies_matched JSONB DEFAULT '[]',
    step_input JSONB,

    -- Full context for accurate resume re-evaluation
    tool_context JSONB,
    model VARCHAR(100),
    provider VARCHAR(100),

    -- Resume metadata
    -- is_resumable: false for blocked steps (no point resuming from a hard block)
    is_resumable BOOLEAN DEFAULT true,
    resume_count INTEGER DEFAULT 0,
    last_resumed_at TIMESTAMP WITH TIME ZONE,

    -- Multi-tenant isolation + actor attribution
    org_id VARCHAR(255),
    tenant_id VARCHAR(255),
    user_id VARCHAR(255),
    client_id VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- One checkpoint per step per workflow. Upserts on re-evaluation.
    UNIQUE(workflow_id, step_id)
);

-- Resume queries: find resumable checkpoints efficiently
-- Note: UNIQUE(workflow_id, step_id) already provides an index on workflow_id for primary lookups.
CREATE INDEX IF NOT EXISTS idx_wf_checkpoints_resumable ON workflow_checkpoints(workflow_id, is_resumable)
    WHERE is_resumable = true;

-- Tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_wf_checkpoints_tenant ON workflow_checkpoints(tenant_id);
