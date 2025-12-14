package sqli

import (
	"context"
	"testing"
)

func TestMode_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		mode  Mode
		valid bool
	}{
		{"off is valid", ModeOff, true},
		{"basic is valid", ModeBasic, true},
		{"advanced is valid", ModeAdvanced, true},
		{"empty is invalid", Mode(""), false},
		{"unknown is invalid", Mode("unknown"), false},
		{"BASIC uppercase is invalid", Mode("BASIC"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.valid {
				t.Errorf("Mode(%q).IsValid() = %v, want %v", tt.mode, got, tt.valid)
			}
		})
	}
}

func TestMode_String(t *testing.T) {
	tests := []struct {
		mode Mode
		want string
	}{
		{ModeOff, "off"},
		{ModeBasic, "basic"},
		{ModeAdvanced, "advanced"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("Mode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Mode
		wantErr bool
	}{
		{"parse off", "off", ModeOff, false},
		{"parse basic", "basic", ModeBasic, false},
		{"parse advanced", "advanced", ModeAdvanced, false},
		{"parse empty", "", Mode(""), true},
		{"parse invalid", "invalid", Mode(""), true},
		{"parse uppercase", "BASIC", Mode(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidModes(t *testing.T) {
	modes := ValidModes()
	if len(modes) != 3 {
		t.Errorf("ValidModes() returned %d modes, want 3", len(modes))
	}

	expected := map[Mode]bool{ModeOff: true, ModeBasic: true, ModeAdvanced: true}
	for _, m := range modes {
		if !expected[m] {
			t.Errorf("unexpected mode in ValidModes(): %v", m)
		}
	}
}

func TestNoOpScanner(t *testing.T) {
	scanner := &NoOpScanner{}

	t.Run("Mode returns off", func(t *testing.T) {
		if got := scanner.Mode(); got != ModeOff {
			t.Errorf("NoOpScanner.Mode() = %v, want %v", got, ModeOff)
		}
	})

	t.Run("IsEnterprise returns false", func(t *testing.T) {
		if got := scanner.IsEnterprise(); got != false {
			t.Errorf("NoOpScanner.IsEnterprise() = %v, want false", got)
		}
	})

	t.Run("Scan returns clean result for input", func(t *testing.T) {
		result := scanner.Scan(context.Background(), "SELECT * FROM users", ScanTypeInput)
		if result.Detected {
			t.Error("NoOpScanner should never detect")
		}
		if result.Blocked {
			t.Error("NoOpScanner should never block")
		}
		if result.ScanType != ScanTypeInput {
			t.Errorf("result.ScanType = %v, want %v", result.ScanType, ScanTypeInput)
		}
		if result.Mode != ModeOff {
			t.Errorf("result.Mode = %v, want %v", result.Mode, ModeOff)
		}
	})

	t.Run("Scan returns clean result for response", func(t *testing.T) {
		result := scanner.Scan(context.Background(), "malicious content", ScanTypeResponse)
		if result.Detected {
			t.Error("NoOpScanner should never detect")
		}
		if result.ScanType != ScanTypeResponse {
			t.Errorf("result.ScanType = %v, want %v", result.ScanType, ScanTypeResponse)
		}
	})
}

func TestNewScanner_Off(t *testing.T) {
	scanner, err := NewScanner(ModeOff)
	if err != nil {
		t.Fatalf("NewScanner(ModeOff) error = %v", err)
	}
	if scanner == nil {
		t.Fatal("NewScanner(ModeOff) returned nil")
	}
	if _, ok := scanner.(*NoOpScanner); !ok {
		t.Errorf("NewScanner(ModeOff) returned %T, want *NoOpScanner", scanner)
	}
}

func TestNewScanner_InvalidMode(t *testing.T) {
	_, err := NewScanner(Mode("invalid"))
	if err == nil {
		t.Error("NewScanner with invalid mode should return error")
	}
}

func TestNewScanner_AdvancedWithoutLicense(t *testing.T) {
	// Advanced scanner is not registered in community edition
	// First, ensure we don't have it registered
	delete(scannerRegistry, ModeAdvanced)

	_, err := NewScanner(ModeAdvanced)
	if err == nil {
		t.Error("NewScanner(ModeAdvanced) should return error without enterprise license")
	}
	if err.Error() != "advanced scanning mode requires enterprise license" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMustNewScanner_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustNewScanner with invalid mode should panic")
		}
	}()

	MustNewScanner(Mode("invalid"))
}

func TestMustNewScanner_Success(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustNewScanner(ModeOff) panicked: %v", r)
		}
	}()

	scanner := MustNewScanner(ModeOff)
	if scanner == nil {
		t.Error("MustNewScanner(ModeOff) returned nil")
	}
}

func TestRegisterScanner(t *testing.T) {
	// Create a mock scanner
	mockScanner := &NoOpScanner{}
	mockFactory := func() Scanner { return mockScanner }

	// Register for a custom mode (using basic for test since advanced requires license check)
	// Save original and restore after test
	original := scannerRegistry[ModeBasic]
	defer func() {
		if original != nil {
			scannerRegistry[ModeBasic] = original
		} else {
			delete(scannerRegistry, ModeBasic)
		}
	}()

	RegisterScanner(ModeBasic, mockFactory)

	scanner, err := NewScanner(ModeBasic)
	if err != nil {
		t.Fatalf("NewScanner after RegisterScanner error = %v", err)
	}
	if scanner != mockScanner {
		t.Error("NewScanner did not return registered scanner")
	}
}

func TestCategory_Values(t *testing.T) {
	// Ensure all categories are distinct
	categories := []Category{
		CategoryUnionBased,
		CategoryBooleanBlind,
		CategoryTimeBased,
		CategoryErrorBased,
		CategoryStackedQueries,
		CategoryCommentInjection,
		CategoryGeneric,
	}

	seen := make(map[Category]bool)
	for _, c := range categories {
		if seen[c] {
			t.Errorf("duplicate category: %v", c)
		}
		seen[c] = true
		if c == "" {
			t.Error("category should not be empty")
		}
	}
}

func TestScanType_Values(t *testing.T) {
	if ScanTypeInput != "input" {
		t.Errorf("ScanTypeInput = %q, want %q", ScanTypeInput, "input")
	}
	if ScanTypeResponse != "response" {
		t.Errorf("ScanTypeResponse = %q, want %q", ScanTypeResponse, "response")
	}
}

func TestDefaultMode(t *testing.T) {
	if DefaultMode != ModeBasic {
		t.Errorf("DefaultMode = %v, want %v", DefaultMode, ModeBasic)
	}
}
