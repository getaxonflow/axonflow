// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"strings"
	"testing"
)

// =============================================================================
// Benchmark Tests for PII Detection Performance
// =============================================================================

// BenchmarkDetectAll_NoPII benchmarks detection on clean text
func BenchmarkDetectAll_NoPII(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "This is a normal sentence with no personal information. It talks about weather and other things."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectAll(text)
	}
}

// BenchmarkDetectAll_WithPII benchmarks detection with multiple PII types
func BenchmarkDetectAll_WithPII(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := `
		Customer: John Doe
		SSN: 123-45-6789
		Email: john.doe@example.com
		Phone: (555) 123-4567
		Card: 4532015112830366
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectAll(text)
	}
}

// BenchmarkDetectAll_LongText benchmarks detection on longer documents
func BenchmarkDetectAll_LongText(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())

	// Create a 10KB document with PII scattered throughout
	var builder strings.Builder
	for i := 0; i < 100; i++ {
		builder.WriteString("This is paragraph ")
		builder.WriteString(string(rune('0' + i%10)))
		builder.WriteString(" of the document. It contains normal text. ")
		if i%20 == 0 {
			builder.WriteString("SSN: 123-45-6789. ")
		}
		if i%25 == 0 {
			builder.WriteString("Email: test@example.com. ")
		}
		if i%30 == 0 {
			builder.WriteString("Card: 4532015112830366. ")
		}
	}
	text := builder.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectAll(text)
	}
}

// BenchmarkHasPII_NoPII benchmarks quick check on clean text
func BenchmarkHasPII_NoPII(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "This is a normal sentence with no personal information."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.HasPII(text)
	}
}

// BenchmarkHasPII_WithPII benchmarks quick check with PII present
func BenchmarkHasPII_WithPII(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "Customer SSN: 123-45-6789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.HasPII(text)
	}
}

// BenchmarkDetectType_SSN benchmarks SSN-specific detection
func BenchmarkDetectType_SSN(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "The social security number is 123-45-6789 for this customer."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectType(text, PIITypeSSN)
	}
}

// BenchmarkDetectType_CreditCard benchmarks credit card detection
func BenchmarkDetectType_CreditCard(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "Payment card number: 4532015112830366"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectType(text, PIITypeCreditCard)
	}
}

// BenchmarkDetectType_Email benchmarks email detection
func BenchmarkDetectType_Email(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "Contact us at support@company.example.com for assistance."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectType(text, PIITypeEmail)
	}
}

// BenchmarkDetectType_Phone benchmarks phone detection
func BenchmarkDetectType_Phone(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "Call us at (555) 123-4567 for support."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectType(text, PIITypePhone)
	}
}

// BenchmarkDetectType_IBAN benchmarks IBAN detection
func BenchmarkDetectType_IBAN(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "Bank account IBAN: DE89370400440532013000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectType(text, PIITypeIBAN)
	}
}

// BenchmarkLuhnCheck benchmarks the Luhn algorithm
func BenchmarkLuhnCheck(b *testing.B) {
	number := "4532015112830366"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		luhnCheck(number)
	}
}

// BenchmarkValidateSSN benchmarks SSN validation
func BenchmarkValidateSSN(b *testing.B) {
	match := "123-45-6789"
	context := "The customer SSN is 123-45-6789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validateSSN(match, context)
	}
}

// BenchmarkValidateCreditCard benchmarks credit card validation
func BenchmarkValidateCreditCard(b *testing.B) {
	match := "4532015112830366"
	context := "Payment card: 4532015112830366"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validateCreditCard(match, context)
	}
}

// BenchmarkValidateIBAN benchmarks IBAN validation
func BenchmarkValidateIBAN(b *testing.B) {
	match := "DE89370400440532013000"
	context := "IBAN: DE89370400440532013000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validateIBAN(match, context)
	}
}

// BenchmarkValidateABARoutingNumber benchmarks ABA routing number validation
func BenchmarkValidateABARoutingNumber(b *testing.B) {
	routing := "021000021"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validateABARoutingNumber(routing)
	}
}

// =============================================================================
// Comparison Benchmarks - Old vs New Detector
// =============================================================================

// BenchmarkOldPIIDetector benchmarks the legacy PIIDetector
func BenchmarkOldPIIDetector(b *testing.B) {
	detector := NewPIIDetector() // Legacy detector
	text := `
		Customer: John Doe
		SSN: 123-45-6789
		Email: john.doe@example.com
		Phone: (555) 123-4567
		Card: 4532-0151-1283-0366
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pattern := range detector.patterns {
			pattern.FindAllString(text, -1)
		}
	}
}

// BenchmarkNewEnhancedPIIDetector benchmarks the new enhanced detector
func BenchmarkNewEnhancedPIIDetector(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := `
		Customer: John Doe
		SSN: 123-45-6789
		Email: john.doe@example.com
		Phone: (555) 123-4567
		Card: 4532-0151-1283-0366
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectAll(text)
	}
}

// BenchmarkNewEnhancedPIIDetector_NoValidation benchmarks without validation
func BenchmarkNewEnhancedPIIDetector_NoValidation(b *testing.B) {
	config := PIIDetectorConfig{
		ContextWindow:    50,
		MinConfidence:    0.0,
		EnableValidation: false,
	}
	detector := NewEnhancedPIIDetector(config)
	text := `
		Customer: John Doe
		SSN: 123-45-6789
		Email: john.doe@example.com
		Phone: (555) 123-4567
		Card: 4532-0151-1283-0366
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectAll(text)
	}
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================

// BenchmarkDetectAll_Allocs measures memory allocations
func BenchmarkDetectAll_Allocs(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "SSN: 123-45-6789, Email: test@example.com"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.DetectAll(text)
	}
}

// BenchmarkHasPII_Allocs measures memory allocations for quick check
func BenchmarkHasPII_Allocs(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "SSN: 123-45-6789"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.HasPII(text)
	}
}

// =============================================================================
// Parallel Benchmarks
// =============================================================================

// BenchmarkDetectAll_Parallel tests concurrent detection performance
func BenchmarkDetectAll_Parallel(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "SSN: 123-45-6789, Email: test@example.com, Phone: 555-123-4567"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			detector.DetectAll(text)
		}
	})
}

// BenchmarkHasPII_Parallel tests concurrent quick check performance
func BenchmarkHasPII_Parallel(b *testing.B) {
	detector := NewEnhancedPIIDetector(DefaultPIIDetectorConfig())
	text := "SSN: 123-45-6789"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			detector.HasPII(text)
		}
	})
}
