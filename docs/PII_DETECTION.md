# PII Detection System

AxonFlow's PII (Personally Identifiable Information) detection system provides comprehensive protection for sensitive data in LLM interactions. The system uses a hybrid approach combining fast regex-based pattern matching with intelligent validation to minimize false positives while maintaining sub-millisecond latency.

## Overview

### Detection Approaches

| Approach | Latency | Best For | Accuracy |
|----------|---------|----------|----------|
| **Regex (Static Engine)** | <1ms | Structured PII (SSN, cards, emails) | Good |
| **Enhanced Detector** | <2ms | All PII with validation | Excellent |
| **Hybrid (Default)** | <2ms | Best of both | Excellent |

### Supported PII Types

| Type | Severity | Validation | Example |
|------|----------|------------|---------|
| SSN | Critical | Area/group/serial rules | `123-45-6789` |
| Credit Card | Critical | Luhn algorithm | `4532-0151-1283-0366` |
| Email | Medium | RFC 5322 format | `user@example.com` |
| Phone | Medium | Format + context | `(555) 123-4567` |
| IP Address | Medium | IPv4 range validation | `192.168.1.100` |
| IBAN | Critical | MOD 97 checksum | `DE89370400440532013000` |
| Passport | High | Format + context | `AB1234567` |
| Date of Birth | High | Context-dependent | `01/15/1990` |
| Bank Account | Critical | ABA routing checksum | `021000021-123456789012` |
| Driver's License | High | Context-dependent | `D12345678` |
| **PAN (India)** | Critical | Entity type, format | `ABCPD1234E` |
| **Aadhaar (India)** | Critical | Starting digit, format | `1234 5678 9012` |

## Architecture

### Two-Layer Detection

```
┌─────────────────────────────────────────────────────────────────┐
│                        Agent Layer                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            Static Policy Engine                          │   │
│  │  • Fast regex-based detection (<1ms)                     │   │
│  │  • 10 PII patterns (SSN, CC, Email, Phone, etc.)        │   │
│  │  • Triggers policy but doesn't block                     │   │
│  │  • Flags for downstream redaction                        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Orchestrator Layer                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │          Enhanced PII Detector                           │   │
│  │  • Validation (Luhn, MOD 97, ABA routing)               │   │
│  │  • Context-aware confidence scoring                      │   │
│  │  • False positive prevention                             │   │
│  │  • Deep nested structure scanning                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │            Response Processor                            │   │
│  │  • Permission-based redaction                            │   │
│  │  • Strategy-based masking (keep last 4, hash, etc.)     │   │
│  │  • Audit logging                                         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Validation Algorithms

### Credit Card - Luhn Algorithm

The Luhn algorithm validates credit card numbers by computing a checksum:

```go
// From right to left, double every second digit
// If result > 9, subtract 9
// Sum all digits - must be divisible by 10

4532015112830366  // Valid Visa
4532015112830367  // Invalid (fails Luhn)
```

Supported networks:
- Visa (4xxx)
- MasterCard (51-55xx, 22-27xx)
- American Express (34xx, 37xx)
- Discover (6011xx, 65xx)
- Diners Club (30xx, 36xx, 38xx)
- JCB (35xx)

### SSN Validation

US Social Security Numbers are validated against known rules:

```
Area (3 digits):
  ✗ Cannot be 000
  ✗ Cannot be 666
  ✗ Cannot be 900-999

Group (2 digits):
  ✗ Cannot be 00

Serial (4 digits):
  ✗ Cannot be 0000
```

### IBAN - MOD 97 Algorithm

International Bank Account Numbers use MOD 97 validation:

```
1. Move first 4 chars to end: DE89370400440532013000 → 370400440532013000DE89
2. Convert letters to numbers: A=10, B=11, ..., Z=35
3. Compute MOD 97 - result must equal 1
```

### ABA Routing Number

US bank routing numbers use a weighted checksum:

```
Weights: 3, 7, 1, 3, 7, 1, 3, 7, 1
Sum = (d1×3 + d2×7 + d3×1 + ...) mod 10 must equal 0
```

## Context-Aware Detection

The enhanced detector uses surrounding text to improve accuracy and reduce false positives:

### Confidence Scoring

| Context | Confidence Adjustment |
|---------|----------------------|
| `"SSN:"`, `"social security"` | +0.25 (high) |
| `"order"`, `"invoice"`, `"ref"` | -0.4 (reduces SSN false positives) |
| `"card"`, `"payment"`, `"visa"` | +0.10 (credit card) |
| `"phone"`, `"call"`, `"tel"` | +0.25 (phone) |

### Example: Order Numbers vs SSNs

```
Input: "Order number: 123-45-6789"
       ↳ Context contains "order" → confidence reduced to 0.3
       ↳ Below 0.5 threshold → NOT flagged as SSN

Input: "Customer SSN: 123-45-6789"
       ↳ Context contains "SSN" → confidence raised to 0.95
       ↳ Above 0.5 threshold → Flagged as SSN
```

## Usage

### Basic Detection

```go
import "axonflow/platform/orchestrator"

// Create detector with default config
detector := orchestrator.NewEnhancedPIIDetector(
    orchestrator.DefaultPIIDetectorConfig(),
)

// Detect all PII types
text := "Customer SSN: 123-45-6789, Card: 4532015112830366"
results := detector.DetectAll(text)

for _, r := range results {
    fmt.Printf("Type: %s, Value: %s, Confidence: %.2f\n",
        r.Type, r.Value, r.Confidence)
}
```

### Quick Check

```go
// Fast check if any PII exists (short-circuit on first match)
if detector.HasPII(text) {
    // Handle PII presence
}
```

### Type-Specific Detection

```go
// Detect only credit cards
results := detector.DetectType(text, orchestrator.PIITypeCreditCard)
```

### Custom Configuration

```go
config := orchestrator.PIIDetectorConfig{
    ContextWindow:    100,    // Characters around match for context
    MinConfidence:    0.7,    // Higher threshold = fewer false positives
    EnableValidation: true,   // Enable Luhn, MOD 97, etc.
    EnabledTypes: []orchestrator.PIIType{
        orchestrator.PIITypeSSN,
        orchestrator.PIITypeCreditCard,
        orchestrator.PIITypeEmail,
    },
}

detector := orchestrator.NewEnhancedPIIDetector(config)
```

## Permission-Based Redaction

The Response Processor applies redactions based on user permissions:

| Permission | Allowed PII Types |
|------------|-------------------|
| `view_full_pii` | SSN, credit card, bank account, email, phone, address |
| `view_basic_pii` | Email, phone |
| `view_financial` | Credit card, bank account |
| `view_medical` | Medical record, diagnosis |
| Admin role | All PII (wildcard) |

### Redaction Strategies

| PII Type | Strategy | Example |
|----------|----------|---------|
| SSN | Mask last 4 | `XXX-XX-6789` |
| Credit Card | Mask last 4 | `****-****-****-0366` |
| Email | Hash | `[HASHED_16]` |
| Phone | Mask last 4 | `***-***-4567` |
| IP Address | Full mask | `***.***.***.***` |
| Bank Account | Mask last 4 | `****5678` |

## Performance

Benchmark results on M1 MacBook Pro:

| Operation | Latency | Allocations |
|-----------|---------|-------------|
| DetectAll (no PII) | 17μs | 6 B/op |
| DetectAll (with PII) | 25μs | 2.1 KB/op |
| DetectType (single) | ~1μs | ~400 B/op |
| Long text (10KB) | 1.4ms | 7.6 KB/op |
| Parallel (12 cores) | 2.3μs | 1.7 KB/op |

## Best Practices

### 1. Use Appropriate Confidence Thresholds

```go
// Production: Higher threshold for fewer false positives
config.MinConfidence = 0.7

// Development/Testing: Lower threshold to catch more
config.MinConfidence = 0.5
```

### 2. Filter by Severity for Critical Operations

```go
results := detector.DetectAll(text)
critical := orchestrator.FilterBySeverity(results, orchestrator.PIISeverityCritical)
```

### 3. Enable Validation for Financial Data

```go
// Always validate credit cards and bank accounts
config.EnableValidation = true
```

### 4. Use Type-Specific Detection When Possible

```go
// More efficient than DetectAll when you only need specific types
if len(detector.DetectType(text, PIITypeCreditCard)) > 0 {
    // Handle credit card
}
```

## Integration with Gateway Mode

The PII detector is automatically used in Gateway Mode's `pre-check` and `audit-llm-call` endpoints:

```go
// Pre-check detects PII in prompts
POST /api/policy/pre-check
{
    "prompt": "Customer SSN: 123-45-6789",
    "context": { ... }
}

// Response includes PII warnings
{
    "approved": true,
    "policies": ["ssn_detection"],
    "pii_detected": {
        "ssn": ["123-45-6789"]
    }
}
```

## Extending Detection

### Adding New PII Types

```go
// Define new pattern in pii_detector.go loadPatterns()
{
    Type:      PIITypeCustom,
    Pattern:   regexp.MustCompile(`your-pattern-here`),
    Severity:  PIISeverityHigh,
    Validator: validateCustom,  // Optional validation function
    MinLength: 5,
    MaxLength: 20,
}

// Implement validator
func validateCustom(match string, context string) (bool, float64) {
    // Return (isValid, confidence)
    return true, 0.8
}
```

## Compliance Considerations

| Regulation | PII Types | Redaction Required |
|------------|-----------|-------------------|
| PCI-DSS | Credit card, bank account | Yes - mask/tokenize |
| HIPAA | SSN, DOB, medical records | Yes - unless authorized |
| GDPR | Email, phone, address, IP | Yes - consent required |
| CCPA | SSN, driver's license | Yes - consumer rights |

## Troubleshooting

### False Positives

If legitimate data is being flagged:
1. Increase `MinConfidence` threshold
2. Check if context words are triggering low confidence
3. Use `FilterByConfidence()` to filter results

### Missed Detections

If PII is not being detected:
1. Verify pattern matches the format
2. Check `MinLength`/`MaxLength` constraints
3. Ensure validation isn't failing (e.g., invalid Luhn)
4. Review context for negative indicators

### Performance Issues

If detection is slow:
1. Use `HasPII()` for quick checks
2. Use type-specific detection when possible
3. Enable parallel processing for batch operations
