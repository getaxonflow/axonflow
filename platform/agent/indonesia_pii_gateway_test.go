// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"sync"
	"testing"

	"axonflow/platform/agent/indonesia"
)

func TestCheckIndonesiaPII_NilDetector(t *testing.T) {
	indonesiaPIIDetector = nil
	indonesiaPIIDetectorOnce = sync.Once{}
	result := checkIndonesiaPII("anything", true)
	if result.HasPII || result.BlockRecommended {
		t.Error("nil detector should return safe result")
	}
}

func TestCheckIndonesiaPII_NIK_Block(t *testing.T) {
	detector := indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	indonesiaPIIDetector = detector

	result := checkIndonesiaPII("Customer NIK is 3174042506780001", true)
	if !result.HasPII {
		t.Error("should detect PII")
	}
	if !result.CriticalPII {
		t.Error("NIK should be critical PII")
	}
	if !result.BlockRecommended {
		t.Error("should recommend block for critical PII")
	}
}

func TestCheckIndonesiaPII_NIK_NoBlock_WhenRedactMode(t *testing.T) {
	detector := indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	indonesiaPIIDetector = detector

	result := checkIndonesiaPII("Customer NIK is 3174042506780001", false)
	if !result.HasPII {
		t.Error("should detect PII")
	}
	if result.BlockRecommended {
		t.Error("should not block when blockOnCritical=false")
	}
}

func TestCheckIndonesiaPII_CleanQuery(t *testing.T) {
	detector := indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	indonesiaPIIDetector = detector

	result := checkIndonesiaPII("What is the weather in Jakarta?", true)
	if result.HasPII {
		t.Error("clean query should not trigger PII detection")
	}
	if result.BlockRecommended {
		t.Error("clean query should not be blocked")
	}
}

func TestCheckIndonesiaPII_NPWP_Block(t *testing.T) {
	detector := indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	indonesiaPIIDetector = detector

	result := checkIndonesiaPII("NPWP: 01.234.567.8-901.234", true)
	if !result.HasPII {
		t.Error("should detect NPWP")
	}
	if !result.CriticalPII {
		t.Error("NPWP should be critical PII")
	}
	if !result.BlockRecommended {
		t.Error("should recommend block for NPWP")
	}
}

func TestCheckIndonesiaPII_Phone_NonCritical(t *testing.T) {
	detector := indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	indonesiaPIIDetector = detector

	result := checkIndonesiaPII("Call me at +6281234567890", true)
	if !result.HasPII {
		t.Error("should detect phone")
	}
	if result.CriticalPII {
		t.Error("phone should not be critical PII")
	}
	if result.BlockRecommended {
		t.Error("phone should not trigger block")
	}
}

func TestGetIndonesiaPIIDetector(t *testing.T) {
	indonesiaPIIDetector = nil
	indonesiaPIIDetectorOnce = sync.Once{}
	detector := getIndonesiaPIIDetector()
	if detector == nil {
		t.Error("detector should not be nil — IsEnabled returns true")
	}
}

func TestCheckIndonesiaPII_BankAccount_NonCritical(t *testing.T) {
	detector := indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	indonesiaPIIDetector = detector

	result := checkIndonesiaPII("Transfer to BCA: 1234567890", true)
	if !result.HasPII {
		t.Error("should detect BCA account")
	}
	if result.CriticalPII {
		t.Error("bank account should not be critical PII")
	}
}
