// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"strings"
	"testing"

	"axonflow/platform/shared/capabilityresolution"
)

func TestOutcomeModuleImplementationsStayOutOfCommunity(t *testing.T) {
	want := map[string]string{
		capabilityresolution.PaymentExceptionWorkflowCapabilityID: capabilityresolution.PaymentExceptionCasesLimitID,
		capabilityresolution.SupportRefundWorkflowCapabilityID:    capabilityresolution.SupportRefundCasesLimitID,
	}
	for capabilityID, limitID := range want {
		var entry *Entry
		for index := range Load().Entries {
			if Load().Entries[index].ID == capabilityID {
				entry = &Load().Entries[index]
				break
			}
		}
		if entry == nil {
			t.Fatalf("%s is absent from the capability registry", capabilityID)
		}
		if entry.MinimumEdition != EditionEnterprise || entry.Classification != ClassEnterpriseImplementation || entry.Sync != SyncExcluded {
			t.Fatalf("%s boundary=%+v", capabilityID, *entry)
		}
		for _, implementation := range entry.Implementation {
			if !strings.HasPrefix(implementation, "ee/") {
				t.Fatalf("%s implementation leaked outside ee/: %s", capabilityID, implementation)
			}
		}
		if len(entry.Limits) != 1 || entry.Limits[0].ID != limitID || entry.Limits[0].Scope != LimitScopeTenant || entry.Limits[0].Window != LimitWindowCalendarMonth {
			t.Fatalf("%s limit=%+v", capabilityID, entry.Limits)
		}
	}
}
