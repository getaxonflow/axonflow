// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import "github.com/google/uuid"

// WorkflowIDPrefix is the prefix carried by every control-plane workflow
// identifier. It is the ONE identifier an operator correlates a governed run
// by: it is the path segment of every /api/v1/workflows/{id} route, the
// approve/reject key the portal Approvals queue routes on, the
// workflows/workflow_steps/workflow_checkpoints primary and foreign key, and
// the value stamped into audit_logs policy_details.workflow_id.
//
// Nothing else may mint an identifier under this prefix. The unified
// execution projection of a WCP workflow now carries THIS id rather than a
// second one of its own (see WCPExecutionTracker.StartWorkflowExecution), and
// the in-process declarative workflow engine - a different subsystem, with
// disjoint storage and no relationship to a `workflows` row - mints `wfe_`
// (see orchestrator.newEngineExecutionID). Issue #3442.
const WorkflowIDPrefix = "wf_"

// NewWorkflowID mints a control-plane workflow identifier.
//
// ENTROPY: 122 random bits (a full RFC 4122 v4 UUID: 128 bits less the 4
// version and 2 variant bits). Until #3442 this was `uuid.New().String()[:8]`,
// which kept the first 8 hex characters - 32 bits. Truncating a UUID does not
// preserve its collision properties: by the birthday bound a 32-bit space
// collides with probability ~1% at ~9,300 ids and ~50% at ~77,000, and
// `workflows.workflow_id` is a database-wide PRIMARY KEY that nothing ever
// prunes, so the population only grows. At 122 bits the bound is not
// reachable by any deployment.
//
// The generator lives here, and not inline at its call sites, because there
// were TWO of them (Service.CreateWorkflow and PostgresRepository.Create's
// empty-id fallback) and they were separate copies of the same truncation:
// fixing one would have left the other minting 32-bit ids with no signal.
func NewWorkflowID() string {
	return WorkflowIDPrefix + uuid.NewString()
}
