// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-PostgreSQL proof that the OCR text scan runs the platform's PII detector
// SET, not a hand-picked list (#4300): over the policy rows the core migrations
// seed, every sys_pii_* detector the census binds to a plane runs on the
// extracted text, and an SSN in it is found by sys_pii_ssn.
//
// Gating: TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).

package media

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/decision/registry"
	sharedpolicy "axonflow/platform/shared/policy"
)

// observingEngine is the real engine, keeping the last result so the detector
// facts of the adapter's pass can be read.
type observingEngine struct {
	engine *sharedpolicy.UnifiedPolicyEngine
	last   *sharedpolicy.RequestResult
}

func (o *observingEngine) EnabledPIICategories(ctx context.Context, tenantID string, orgID *string, phase sharedpolicy.Phase) []sharedpolicy.PolicyCategory {
	return o.engine.EnabledPIICategories(ctx, tenantID, orgID, phase)
}

func (o *observingEngine) EvaluateRequest(ctx context.Context, input string, opts sharedpolicy.EvalOptions) *sharedpolicy.RequestResult {
	o.last = o.engine.EvaluateRequest(ctx, input, opts)
	return o.last
}

func TestTheOCRScanRunsEveryPlanedPIIDetector_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../../migrations/core")
	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	eng := &observingEngine{engine: sharedpolicy.NewUnifiedPolicyEngine(db, cfg, nil)}
	t.Cleanup(eng.engine.Stop)

	detect := NewEnginePIIDetector(func() PIIEngine { return eng }, "local-ocr")
	ctx := WithScanScope(context.Background(), ScanScope{OrgID: "ocr-census-org", TenantID: "ocr-census-tenant"})
	findings, err := detect(ctx, "Employee SSN 123-45-6789, contact jane.doe@example.com")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if eng.last == nil || eng.last.EvaluationError {
		t.Fatalf("PREMISE: the engine did not evaluate the seeded policies: %+v", eng.last)
	}

	found := map[string]bool{}
	for _, f := range findings {
		found[f.Type] = true
	}
	if !found["sys_pii_ssn"] {
		t.Errorf("findings %+v do not include sys_pii_ssn for an SSN in the text", findings)
	}

	ran := map[string]bool{}
	for _, row := range eng.last.Observation.Rows {
		if row.Ran {
			ran[row.PolicyID] = true
		}
	}
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("read the detector census: %v", err)
	}
	var expected, missing []string
	for _, row := range census {
		if !strings.HasPrefix(row.PolicyID, "sys_pii_") || len(row.Planes) == 0 {
			continue
		}
		expected = append(expected, row.PolicyID)
		if !ran[row.PolicyID] {
			missing = append(missing, row.PolicyID)
		}
	}
	if len(expected) == 0 {
		t.Fatal("PREMISE: the census names no planed sys_pii_* detector; the cell would pin nothing")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d of %d planed sys_pii_* detectors did not run on the OCR text: %v", len(missing), len(expected), missing)
	}
	t.Logf("the OCR scan ran %d planed sys_pii_* detectors", len(expected))
}
