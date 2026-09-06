// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

package orchestrator

// The pool the HITL expiry sweeper runs on (#3520).
//
// EDITION (HARD RULE 11, by reachability): tag-free and under platform/, and the
// first version of this comment was WRONG about why (#3520 R3). It claimed
// hitl_wcp_community.go and hitl_wcp_enterprise.go "both need it". They do not:
//
//	the expiry sweeper - runEvalApprovalExpiryLoop, expireEvalApprovals,
//	evalExpiryBatchSize, StopEvalApprovalExpiry - is defined ONLY in
//	hitl_wcp_community.go, under `//go:build !enterprise`. It was that way on
//	ca9fccefd and it is that way now. The enterprise InitializeWCPHITL starts no
//	sweeper at all, so under `-tags enterprise` this function has ZERO callers.
//
// Recorded rather than corrected-away, because the consequence outlives the
// comment: THE ENTERPRISE BUILD RUNS NO WCP APPROVAL-EXPIRY SWEEPER. That is
// pre-existing and is not what #3520 is about - the enterprise plane expires
// through hitl.Repository.ExpireStaleReturning on its own admin pool, which is
// the agent-side path and already correct - but a reader who takes this file's
// presence as evidence the orchestrator sweeps on both editions would be wrong,
// and #3520's own framing ("the SaaS stacks are app-role deployments") invites
// exactly that reading.
//
// SO THE FILE CARRIES `//go:build !enterprise`, which is what is TRUE rather
// than what would be tidy. Measured: under `-tags enterprise` golangci-lint
// reports `func hitlExpirySweepPool is unused`, because it is. A comment
// claiming edition-neutrality that the compiler contradicts is worse than a
// tag stating the fact - and CI lints the untagged arm only, so the finding
// would have sat unread under a tag nothing checks.
//
// The day the enterprise orchestrator wants a sweeper, DELETE THIS TAG rather
// than growing a second copy - that is the twin arrangement this whole change
// removes. Nothing in the function is edition-specific; only its callers are.

import (
	"context"
	"database/sql"
	"log"
	"os"

	"axonflow/platform/agent"
)

// hitlExpirySweepPool returns the pool the expiry sweeper must use, or nil when
// there is none and the sweeper must therefore NOT start.
//
// WHY A NIL RETURN AND NOT A FALLBACK TO db.
//
// Every statement in expireEvalApprovals is cross-tenant: it expires pending
// approvals for all orgs, updates their workflow_steps and aborts their
// workflows. Under AXONFLOW_DB_USE_APP_ROLE=true the pool the orchestrator
// hands InitializeWCPHITL is axonflow_app_role, and with FORCE RLS and no org
// GUC set a cross-tenant UPDATE MATCHES ZERO ROWS AND REPORTS SUCCESS - the
// #3048 shape. That is not a degraded sweeper, it is a sweeper that runs every
// five minutes, logs nothing, and lets every Evaluation-tier approval sit
// `pending` for ever while looking healthy. #3520 recorded it; before this
// change it had been the state of every SaaS stack since v9.
//
// So the choice is between a silent no-op and a loud refusal, and a guard that
// degrades into "no check" is the failure mode the whole class is about. When
// app-role is OFF the main pool is the owner role, which IS cross-tenant, and
// the sweeper runs on it exactly as it always has - no behaviour change for a
// self-hosted owner-pool deployment.
func hitlExpirySweepPool(db *sql.DB) *sql.DB {
	if db == nil {
		return nil
	}

	// App-role OFF: `db` is the owner pool and sees every tenant. This is the
	// path every pre-v9 and every non-app-role deployment takes, and it is why
	// this function is not simply "always open an admin pool".
	if !agent.UseAppRoleEnabled() {
		return db
	}

	adminDB, err := agent.OpenPlatformAdminConnection(context.Background(), 3)
	if err != nil || adminDB == nil {
		// nil-with-nil-err means the DSN is unset. Both cases are named,
		// because "the admin DSN is not configured" and "the admin DSN is
		// wrong" need different fixes and a diagnostic must not claim a cause
		// it cannot observe.
		log.Printf("⚠️  [HITL-Expiry] NOT STARTING the approval expiry sweeper: "+
			"AXONFLOW_DB_USE_APP_ROLE=true and no BYPASSRLS pool is available "+
			"(err=%v, %s configured=%v). The sweep is cross-tenant, and on the app-role pool it "+
			"would match ZERO rows and report success (#3048/#3520) - every Evaluation-tier "+
			"approval would sit pending for ever while this log line said nothing. Configure %s "+
			"to enable 24h auto-expiry.",
			err, agent.EnvPlatformAdminURL, os.Getenv(agent.EnvPlatformAdminURL) != "",
			agent.EnvPlatformAdminURL)
		return nil
	}

	// Two connections: the sweeper is a single goroutine on a five-minute
	// ticker, so a large pool would hold idle BYPASSRLS connections open for
	// nothing. Matches the sizing the gate-cache refresh pool uses for the same
	// reason.
	adminDB.SetMaxOpenConns(2)
	adminDB.SetMaxIdleConns(1)

	var role string
	if err := adminDB.QueryRowContext(context.Background(), "SELECT current_user").Scan(&role); err == nil {
		log.Printf("✅ [HITL-Expiry] approval expiry sweeper on the BYPASSRLS pool as current_user=%s", role)
	}
	return adminDB
}
