// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// #4312: five of the eight workflow lifecycle audit sites wrote their row with
// an empty org_id, so an org-keyed read of audit_logs could not see them. The
// sites are fixed and pinned by a census in workflow_control; this counter is
// the runtime backstop for a writer the census cannot see (the legacy HITL
// engine, a future plane). It COUNTS AND NEVER REFUSES: the row is still
// written, because an audit row lost is worse than one mis-keyed.
//
// Registered with the manual prometheus.NewXxx + MustRegister pattern this
// package already uses (dynamic_policy_metrics.go), not promauto.
var workflowAuditEmptyOrgTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_orchestrator_workflow_audit_empty_org_total",
		Help: "Workflow lifecycle audit rows written with an empty org_id, labeled by operation. The row is still written. #4312.",
	},
	[]string{"operation"},
)

// workflowAuditOperationOther is the label for an operation outside the closed
// set below, so a caller-chosen string can never widen the label cardinality.
const workflowAuditOperationOther = "other"

// workflowAuditOperations is the closed operation vocabulary
// (WorkflowAuditEntry.Operation) the counter labels by.
var workflowAuditOperations = []string{
	"created", "step_gate", "step_completed", "step_approved", "step_rejected",
	"completed", "aborted", "failed",
}

// workflowAuditEmptyOrgLogged logs the first empty-org row of each operation
// once per process; the counter carries every later one.
var workflowAuditEmptyOrgLogged = func() map[string]*sync.Once {
	m := make(map[string]*sync.Once, len(workflowAuditOperations)+1)
	for _, op := range workflowAuditOperations {
		m[op] = &sync.Once{}
	}
	m[workflowAuditOperationOther] = &sync.Once{}
	return m
}()

func init() {
	prometheus.MustRegister(workflowAuditEmptyOrgTotal)
}

// workflowAuditOperationLabel maps op onto the closed label set.
func workflowAuditOperationLabel(op string) string {
	if _, ok := workflowAuditEmptyOrgLogged[op]; ok && op != workflowAuditOperationOther {
		return op
	}
	return workflowAuditOperationOther
}

// recordWorkflowAuditEmptyOrg counts a workflow audit row about to be written
// with an empty org_id and logs the first one per operation.
func recordWorkflowAuditEmptyOrg(operation, workflowID string) {
	label := workflowAuditOperationLabel(operation)
	workflowAuditEmptyOrgTotal.WithLabelValues(label).Inc()
	workflowAuditEmptyOrgLogged[label].Do(func() {
		log.Printf("[audit] workflow_%s audit row for workflow %q has an empty org_id; the row is written, but an org-keyed audit read cannot see it "+
			"(logged once per operation; counted on axonflow_orchestrator_workflow_audit_empty_org_total)", label, workflowID)
	})
}
