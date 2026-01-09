package policy

import (
	"testing"
)

func TestValidateCreditCard(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
		minConf    float64
	}{
		// Valid cards with Luhn check
		{"Valid Visa", "4111111111111111", "card number", true, 0.9},
		{"Valid Mastercard", "5500000000000004", "credit card payment", true, 0.9},
		{"Valid Amex", "340000000000009", "amex card", true, 0.9},
		{"Valid with spaces", "4111 1111 1111 1111", "card details", true, 0.8},
		{"Valid with dashes", "4111-1111-1111-1111", "payment method", true, 0.8},

		// Invalid cards (Luhn fails)
		{"Invalid Luhn", "4111111111111112", "", false, 0},
		{"Invalid random", "1234567890123456", "", false, 0},

		// Edge cases
		{"Too short", "411111111111", "", false, 0},
		{"Too long", "41111111111111111111", "", false, 0},

		// Context effects
		{"With card context", "4111111111111111", "Please enter your card number", true, 0.9},
		{"With phone context", "4111111111111111", "phone number for contact", true, 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, conf := ValidateCreditCard(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidateCreditCard(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
			if valid && conf < tt.minConf {
				t.Errorf("ValidateCreditCard(%q) confidence = %v, want >= %v", tt.match, conf, tt.minConf)
			}
		})
	}
}

func TestValidateSSN(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
		minConf    float64
	}{
		// Valid SSNs
		{"Valid SSN with dashes", "123-45-6789", "ssn field", true, 0.9},
		{"Valid SSN no dashes", "123456789", "social security number", true, 0.9},
		{"Valid SSN with spaces", "123 45 6789", "SSN:", true, 0.9},

		// Invalid area codes
		{"Invalid area 000", "000-12-3456", "", false, 0},
		{"Invalid area 666", "666-12-3456", "", false, 0},
		{"Invalid area 900", "900-12-3456", "", false, 0},
		{"Invalid area 999", "999-12-3456", "", false, 0},

		// Invalid group/serial
		{"Invalid group 00", "123-00-4567", "", false, 0},
		{"Invalid serial 0000", "123-45-0000", "", false, 0},

		// Context effects
		{"With SSN context", "123-45-6789", "Please provide your SSN", true, 0.9},
		{"With order context", "123-45-6789", "order number", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, conf := ValidateSSN(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidateSSN(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
			if valid && conf < tt.minConf {
				t.Errorf("ValidateSSN(%q) confidence = %v, want >= %v", tt.match, conf, tt.minConf)
			}
		})
	}
}

func TestValidateIBAN(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
		minConf    float64
	}{
		// Valid IBANs (MOD 97 verified)
		{"Valid DE IBAN", "DE89370400440532013000", "bank account", true, 0.9},
		{"Valid GB IBAN", "GB82WEST12345698765432", "transfer to", true, 0.9},
		{"Valid FR IBAN", "FR7630006000011234567890189", "", true, 0.8},

		// Invalid IBANs
		{"Invalid checksum", "DE89370400440532013001", "", false, 0},
		{"Too short", "DE8937040044", "", false, 0},
		{"Invalid country", "XX89370400440532013000", "", false, 0},
		{"Missing check digits", "DEAB370400440532013000", "", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, conf := ValidateIBAN(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidateIBAN(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
			if valid && conf < tt.minConf {
				t.Errorf("ValidateIBAN(%q) confidence = %v, want >= %v", tt.match, conf, tt.minConf)
			}
		})
	}
}

func TestValidateAadhaar(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
		minConf    float64
	}{
		// Valid Aadhaar numbers
		{"Valid Aadhaar", "234567890123", "aadhaar number", true, 0.9},
		{"Valid with spaces", "2345 6789 0123", "Aadhaar:", true, 0.9},
		{"Valid starts with 9", "912345678901", "UID", true, 0.9},

		// Invalid Aadhaar numbers
		{"Starts with 0", "012345678901", "", false, 0},
		{"Starts with 1", "112345678901", "", false, 0},
		{"All same digit", "222222222222", "", false, 0},
		{"Too short", "23456789012", "", false, 0},
		{"Too long", "2345678901234", "", false, 0},

		// Context effects
		{"With credit card context", "234567890123", "credit card number", true, 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, conf := ValidateAadhaar(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidateAadhaar(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
			if valid && conf < tt.minConf {
				t.Errorf("ValidateAadhaar(%q) confidence = %v, want >= %v", tt.match, conf, tt.minConf)
			}
		})
	}
}

func TestValidatePAN(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
		minConf    float64
	}{
		// Valid PAN numbers
		{"Valid Person PAN", "ABCPD1234E", "PAN card", true, 0.9},
		{"Valid Company PAN", "ABCCD1234E", "pan number", true, 0.9},
		{"Valid HUF PAN", "ABCHD1234E", "", true, 0.7},
		{"Valid Trust PAN", "ABCTD1234E", "", true, 0.7},

		// Invalid PAN numbers
		{"Invalid 4th char", "ABCXD1234E", "", false, 0},
		{"Numbers in first 3", "A1CPD1234E", "", false, 0},
		{"Too short", "ABCPD123E", "", false, 0},
		{"Too long", "ABCPD12345E", "", false, 0},
		{"Letter in digits", "ABCPDABCDE", "", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, conf := ValidatePAN(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidatePAN(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
			if valid && conf < tt.minConf {
				t.Errorf("ValidatePAN(%q) confidence = %v, want >= %v", tt.match, conf, tt.minConf)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
	}{
		{"Valid email", "user@example.com", "", true},
		{"Valid with dots", "user.name@example.com", "", true},
		{"Valid with plus", "user+tag@example.com", "", true},
		{"Valid subdomain", "user@mail.example.com", "", true},
		{"Invalid no @", "userexample.com", "", false},
		{"Invalid no domain", "user@", "", false},
		{"Invalid no TLD", "user@example", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, _ := ValidateEmail(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidateEmail(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
		})
	}
}

func TestValidatePhone(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
	}{
		{"US format", "555-123-4567", "phone", true},
		{"US with area", "(555) 123-4567", "call us", true},
		{"International", "+1-555-123-4567", "tel:", true},
		{"Too short", "12345", "", false},
		{"Repeated digits", "1111111111", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, _ := ValidatePhone(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidatePhone(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
	}{
		{"Valid public IP", "8.8.8.8", "ip address", true},
		{"Valid IP", "192.168.1.1", "server", true},
		{"Localhost", "127.0.0.1", "", true},
		{"Invalid octet", "256.1.1.1", "", false},
		{"Invalid format", "1.2.3", "", false},
		{"Invalid negative", "-1.2.3.4", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, _ := ValidateIPAddress(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidateIPAddress(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
		})
	}
}

func TestValidateBankAccount(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		context    string
		wantValid  bool
	}{
		// Valid routing + account (ABA checksum)
		{"Valid routing 322271627", "322271627123456789", "bank account", true},
		{"Valid with separator", "322271627-123456789", "wire transfer", true},

		// Invalid routing number
		{"Invalid ABA checksum", "123456789-12345678", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, _ := ValidateBankAccount(tt.match, tt.context)
			if valid != tt.wantValid {
				t.Errorf("ValidateBankAccount(%q) valid = %v, want %v", tt.match, valid, tt.wantValid)
			}
		})
	}
}

func TestExtractDigits(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"123-45-6789", "123456789"},
		{"(555) 123-4567", "5551234567"},
		{"4111 1111 1111 1111", "4111111111111111"},
		{"no digits here", ""},
		{"mixed 1a2b3c", "123"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractDigits(tt.input)
			if got != tt.want {
				t.Errorf("extractDigits(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAllSameDigit(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"111111", true},
		{"000000", true},
		{"123456", false},
		{"111112", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := allSameDigit(tt.input)
			if got != tt.want {
				t.Errorf("allSameDigit(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetValidatorByType(t *testing.T) {
	tests := []string{
		"credit_card", "ssn", "iban", "aadhaar", "pan",
		"email", "phone", "ip_address", "bank_account",
	}

	for _, piiType := range tests {
		t.Run(piiType, func(t *testing.T) {
			validator := GetValidatorByType(piiType)
			if validator == nil {
				t.Errorf("GetValidatorByType(%q) returned nil", piiType)
			}
		})
	}

	// Test unknown type
	if GetValidatorByType("unknown_type") != nil {
		t.Error("GetValidatorByType(unknown_type) should return nil")
	}
}
