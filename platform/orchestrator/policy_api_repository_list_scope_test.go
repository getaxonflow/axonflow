// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestTheTenantPolicyListReadsTheCallersTenantAndItsOrganization pins #3894's
// fix to PolicyRepository.List, which the export pages through. Its
// organization pass bound only the organization id as the tenant, so a row
// whose tenant is the calling client's id was never listed: every row a
// Community client writes (Community stamps the client id as the tenant and the
// deployment's organization as the organization), and in Enterprise the rows of
// an API client whose client id is not its organization's. GetByID bound the
// tenant, so the same row was readable by id and missing from the list.
// Identical at v10.2.0.
//
// The organization pass now reads tenant_id IN (the caller's tenant, its
// organization), never 'global', under the organization's row-level-security
// scope; the global pass reads 'global' once. So no caller loses a row the old
// binding listed, and a tenant named 'global' is not listed twice.
func TestTheTenantPolicyListReadsTheCallersTenantAndItsOrganization(t *testing.T) {
	cols := []string{"policy_id", "name", "description", "policy_type", "category", "tier",
		"conditions", "actions", "tenant_id", "org_id", "priority", "enabled", "version",
		"created_by", "updated_by", "created_at", "updated_at"}
	now := time.Now()
	row := func(rows *sqlmock.Rows, id, tenant, org, tier string) *sqlmock.Rows {
		return rows.AddRow(id, id, "", "content", "dynamic-security", tier, []byte("[]"), []byte("[]"),
			tenant, org, 10, true, 1, "", "", now, now)
	}
	setConfig := regexp.QuoteMeta(`SELECT set_config('app.current_org_id', $1, true)`)

	for _, c := range []struct {
		name, tenant, org string
		// orgPass is the pair the organization pass binds; nil when it must not run.
		orgPass []string
		// orgRows are what the organization pass returns; want is the listed set.
		orgRows [][3]string
		want    []string
	}{
		{
			name:   "a client whose tenant is not its organization lists its own rows and the organization's",
			tenant: "community-client", org: "local-dev-org",
			orgPass: []string{"community-client", "local-dev-org"},
			orgRows: [][3]string{{"client_row", "community-client", "local-dev-org"}, {"org_row", "local-dev-org", "local-dev-org"}},
			want:    []string{"client_row", "org_row", "global_row"},
		},
		{
			name:   "an organization that is its own tenant reads it once",
			tenant: "org-acme", org: "org-acme",
			orgPass: []string{"org-acme", "org-acme"},
			orgRows: [][3]string{{"org_row", "org-acme", "org-acme"}},
			want:    []string{"org_row", "global_row"},
		},
		{
			name:   "a tenant named global is not read on the organization pass, so no global row is listed twice",
			tenant: GlobalTenantSentinel, org: "org-acme",
			orgPass: []string{"org-acme", "org-acme"},
			orgRows: [][3]string{{"org_row", "org-acme", "org-acme"}},
			want:    []string{"org_row", "global_row"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			orgRows := sqlmock.NewRows(cols)
			for _, r := range c.orgRows {
				orgRows = row(orgRows, r[0], r[1], r[2], "tenant")
			}
			mock.ExpectBegin()
			mock.ExpectExec(setConfig).WithArgs(c.org).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery(`FROM dynamic_policies\s+WHERE tenant_id IN \(\$1, \$2\)`).WithArgs(c.orgPass[0], c.orgPass[1]).WillReturnRows(orgRows)
			mock.ExpectCommit()
			mock.ExpectBegin()
			mock.ExpectExec(setConfig).WithArgs(GlobalTenantSentinel).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery(`FROM dynamic_policies\s+WHERE tenant_id IN \(\$1, \$2\)`).WithArgs(GlobalTenantSentinel, GlobalTenantSentinel).
				WillReturnRows(row(sqlmock.NewRows(cols), "global_row", GlobalTenantSentinel, "", "system"))
			mock.ExpectCommit()

			policies, total, err := NewPolicyRepository(db).List(context.Background(), c.tenant, c.org, ListPoliciesParams{})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the passes did not bind (organization %q: %v) and ('global', 'global'): %v", c.org, c.orgPass, err)
			}
			got := map[string]int{}
			for _, p := range policies {
				got[p.ID]++
			}
			if total != len(c.want) || len(got) != len(c.want) {
				t.Fatalf("listed %v (total %d); want exactly %v, each once", got, total, c.want)
			}
			for _, id := range c.want {
				if got[id] != 1 {
					t.Fatalf("listed %v; want %s exactly once", got, id)
				}
			}
		})
	}
}
