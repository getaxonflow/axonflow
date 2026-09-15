// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package detectionposture is the one write path of an organization's
// detection posture: the per-(org, category) action in
// detection_action_overrides (migration core/120), written together with the
// admin_audit_log row that makes the change attributable.
//
// It has two callers, and they write through the same function:
//
//   - the customer portal's detection-posture API (PUT and DELETE
//     /api/v1/detection-posture/{category}), for an operator's change;
//   - the Community SaaS registration (POST /api/v1/register), which records
//     sqli=block for every organization it creates (#4017).
//
// ONE TRANSACTION. Set and Delete take the caller's *sql.Tx and write the
// override and its audit row on it, so a posture change never commits without
// its row, and a row never records a change that did not commit. This is the
// §1.12 rule typed_policy_audit follows.
//
// ORG SCOPE IS THE CALLER'S. detection_action_overrides is ENABLE + FORCE ROW
// LEVEL SECURITY, and its policy admits a row only when org_id equals the
// transaction's app.current_org_id. The caller opens the transaction with that
// setting (rls.WithOrgScope in the agent, withOrgScope in the portal); Set and
// Delete write the org explicitly, so the WITH CHECK predicate admits the
// caller's own organization and refuses any other.
//
// NO GOVERNANCE-OFF. Every legal action keeps enforcement on (log is the
// weakest), and anything outside the closed sets below is refused before the
// database is touched.
package detectionposture

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"axonflow/platform/shared/adminaudit"
)

// Detection categories addressable by a per-org override: the `category`
// column values, matching the CHECK constraint in migrations core/120 and
// core/144.
const (
	CategoryPII              = "pii"
	CategorySQLI             = "sqli"
	CategoryDangerousQuery   = "dangerous_query"
	CategoryDangerousCommand = "dangerous_command"

	// CategoryObligationFallback (#2958, core/144) is NOT a detector. It is
	// the organization's answer to "a policy decided this request body must
	// be redacted, but the PEP's seam cannot rewrite a body - now what?" Only
	// block and log are meaningful for it; see ValidActionForCategory.
	CategoryObligationFallback = "obligation_fallback"
)

// Override actions: the `action` column values, matching the CHECK constraint
// in migration core/120.
//
// There is intentionally NO "off" or "disable" action. Every legal value keeps
// governance active; `log` is the weakest (audit-only, no block or redact),
// not a bypass.
const (
	ActionBlock  = "block"
	ActionRedact = "redact"
	ActionWarn   = "warn"
	ActionLog    = "log"
)

// The admin_audit_log actions a posture change records.
const (
	AuditActionSet    = "DETECTION_POSTURE_SET"
	AuditActionDelete = "DETECTION_POSTURE_DELETE"
)

var validCategories = map[string]bool{
	CategoryPII:                true,
	CategorySQLI:               true,
	CategoryDangerousQuery:     true,
	CategoryDangerousCommand:   true,
	CategoryObligationFallback: true,
}

var validActions = map[string]bool{
	ActionBlock:  true,
	ActionRedact: true,
	ActionWarn:   true,
	ActionLog:    true,
}

// categoryActions narrows the legal actions for categories where the full
// four-action set is not meaningful. A category absent here accepts every
// action in validActions: all four are real enforcement strengths for a
// detector.
//
// obligation_fallback (#2958) accepts only block and log:
//   - `redact` is precisely what the seam cannot do. Wanting a redaction that
//     cannot be performed is the situation this posture resolves, so accepting
//     it would store a value with no meaning.
//   - `warn` has no enforcement distinct from `log` on this axis: there is no
//     content to annotate, so the decision is allow-and-audit or deny.
//
// Refusing them here is what keeps the agent-side resolver's "unexpected value
// -> default + WARN" branch a hand-edited-database diagnostic rather than a
// state the product can be talked into.
var categoryActions = map[string]map[string]bool{
	CategoryObligationFallback: {
		ActionBlock: true,
		ActionLog:   true,
	},
}

// ValidCategory reports whether category is an addressable posture category.
func ValidCategory(category string) bool { return validCategories[category] }

// ValidAction reports whether action is one of the four legal enforcement
// actions. It is category-AGNOSTIC; a caller that knows the category uses
// ValidActionForCategory, which also refuses actions that are legal in
// general but meaningless for that category.
func ValidAction(action string) bool { return validActions[action] }

// ValidActionForCategory reports whether action is legal AND meaningful for
// category.
func ValidActionForCategory(category, action string) bool {
	if !ValidAction(action) {
		return false
	}
	if allowed, narrowed := categoryActions[category]; narrowed {
		return allowed[action]
	}
	return true
}

// Categories returns the sorted set of addressable posture categories, so an
// API error can enumerate them without a hand-maintained copy.
func Categories() []string {
	out := make([]string, 0, len(validCategories))
	for c := range validCategories {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// ActionsForCategory returns the sorted set of actions ValidActionForCategory
// accepts for category, so an API error can say what IS allowed.
func ActionsForCategory(category string) []string {
	set := validActions
	if narrowed, ok := categoryActions[category]; ok {
		set = narrowed
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Actor is who recorded a posture change, and from where.
type Actor struct {
	// Identifier names the actor: the operator's email on the portal, or a
	// "system:" identity for an automated write. It is stored as the
	// override's updated_by and as the audit row's admin_identifier, and it
	// must not be empty: an unattributed override is what #3961 retired.
	Identifier string
	// IPAddress and UserAgent describe the request that caused the change.
	// Either may be empty.
	IPAddress string
	UserAgent string
}

// Set records action for category on org, replacing any action recorded
// before, and writes its DETECTION_POSTURE_SET audit row, both on tx. tx must
// carry app.current_org_id = org.
func Set(ctx context.Context, tx *sql.Tx, org, category, action string, actor Actor) error {
	if err := checkWrite(tx, org, category, actor); err != nil {
		return err
	}
	if !ValidActionForCategory(category, action) {
		return fmt.Errorf("detectionposture: action %q is not valid for category %q (allowed: %v)", action, category, ActionsForCategory(category))
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO detection_action_overrides (org_id, category, action, updated_by, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, NOW(), NOW())
		 ON CONFLICT (org_id, category)
		 DO UPDATE SET action = EXCLUDED.action,
		               updated_by = EXCLUDED.updated_by,
		               updated_at = NOW()`,
		org, category, action, actor.Identifier); err != nil {
		return fmt.Errorf("detectionposture: record %s=%s for org %q: %w", category, action, org, err)
	}
	return audit(ctx, tx, AuditActionSet, org, actor, map[string]any{"category": category, "action": action})
}

// Delete removes org's recorded action for category, so the category's
// shipped policy actions decide again, and writes its DETECTION_POSTURE_DELETE
// audit row, both on tx. tx must carry app.current_org_id = org. Deleting an
// absent override is not an error; its audit row is still written, because
// the request was made.
func Delete(ctx context.Context, tx *sql.Tx, org, category string, actor Actor) error {
	if err := checkWrite(tx, org, category, actor); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM detection_action_overrides WHERE org_id = $1 AND category = $2`,
		org, category); err != nil {
		return fmt.Errorf("detectionposture: clear %s for org %q: %w", category, org, err)
	}
	return audit(ctx, tx, AuditActionDelete, org, actor, map[string]any{"category": category})
}

func checkWrite(tx *sql.Tx, org, category string, actor Actor) error {
	switch {
	case tx == nil:
		return fmt.Errorf("detectionposture: no transaction; a posture change and its audit row commit together or not at all")
	case org == "":
		return fmt.Errorf("detectionposture: organization must be non-empty")
	case actor.Identifier == "":
		return fmt.Errorf("detectionposture: actor must be named; an override records who set it")
	case !ValidCategory(category):
		return fmt.Errorf("detectionposture: invalid category %q (allowed: %v)", category, Categories())
	}
	return nil
}

func audit(ctx context.Context, tx *sql.Tx, action, org string, actor Actor, details map[string]any) error {
	if err := adminaudit.Insert(ctx, tx, adminaudit.Entry{
		Action:     action,
		OrgID:      org,
		Identifier: actor.Identifier,
		IPAddress:  actor.IPAddress,
		UserAgent:  actor.UserAgent,
		Details:    details,
		Success:    true,
	}); err != nil {
		return fmt.Errorf("detectionposture: audit %s for org %q: %w", action, org, err)
	}
	return nil
}
