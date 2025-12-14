//go:build !enterprise

// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rbi

import (
	"testing"
)

func TestOSSStubIsDisabled(t *testing.T) {
	if IsEnabled() {
		t.Error("Expected OSS stub to return IsEnabled() = false")
	}
}

func TestOSSStubDetectorReturnsNil(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	if detector == nil {
		t.Error("Expected detector to not be nil even in OSS mode")
	}

	// Test that detection returns no results in OSS mode
	results := detector.DetectAll("My Aadhaar is 2234 5678 9012")
	if len(results) != 0 {
		t.Errorf("Expected OSS stub to return 0 detections, got %d", len(results))
	}

	// Test HasIndiaPII returns false in OSS mode
	if detector.HasIndiaPII("My PAN is ABCDE1234F") {
		t.Error("Expected OSS stub HasIndiaPII to return false")
	}

	// Test HasCriticalPII returns false in OSS mode
	if detector.HasCriticalPII("Payment to user@paytm") {
		t.Error("Expected OSS stub HasCriticalPII to return false")
	}
}

func TestOSSStubCheckRequestForPII(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	// OSS stub should return no PII found
	result := CheckRequestForPII(detector, "My Aadhaar is 2234 5678 9012", true)

	if result.HasPII {
		t.Error("Expected OSS stub to return HasPII = false")
	}
	if result.CriticalPII {
		t.Error("Expected OSS stub to return CriticalPII = false")
	}
	if result.BlockRecommended {
		t.Error("Expected OSS stub to return BlockRecommended = false")
	}
	if len(result.DetectedTypes) != 0 {
		t.Errorf("Expected 0 detected types, got %d", len(result.DetectedTypes))
	}
}

func TestOSSStubGetRBISensitiveData(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	// OSS stub should return empty map
	data := detector.GetRBISensitiveData("PAN: ABCDE1234F, Aadhaar: 2234 5678 9012")

	if len(data) != 0 {
		t.Errorf("Expected OSS stub to return empty map, got %d categories", len(data))
	}
}

func TestOSSStubPatternStats(t *testing.T) {
	config := DefaultIndiaPIIDetectorConfig()
	detector := NewIndiaPIIDetector(config)

	stats := detector.GetPatternStats()

	// Check OSS-specific fields
	if ossMode, ok := stats["oss_mode"].(bool); !ok || !ossMode {
		t.Error("Expected oss_mode = true in OSS stub stats")
	}
	if enterprise, ok := stats["enterprise"].(bool); !ok || enterprise {
		t.Error("Expected enterprise = false in OSS stub stats")
	}
	if totalPatterns, ok := stats["total_patterns"].(int); !ok || totalPatterns != 0 {
		t.Errorf("Expected 0 total_patterns in OSS stub, got %d", totalPatterns)
	}
}

func TestOSSFilterFunctions(t *testing.T) {
	// All filter functions should return nil/empty in OSS mode
	var emptyResults []IndiaPIIDetectionResult

	filtered := FilterIndiaPIIBySeverity(emptyResults, IndiaPIISeverityCritical)
	if filtered != nil && len(filtered) != 0 {
		t.Error("Expected FilterIndiaPIIBySeverity to return nil/empty")
	}

	filtered = FilterIndiaPIIByConfidence(emptyResults, 0.8)
	if filtered != nil && len(filtered) != 0 {
		t.Error("Expected FilterIndiaPIIByConfidence to return nil/empty")
	}

	filtered = GetCriticalFinancialPII(emptyResults)
	if filtered != nil && len(filtered) != 0 {
		t.Error("Expected GetCriticalFinancialPII to return nil/empty")
	}
}
