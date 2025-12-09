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

package logger

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

// TestNew tests logger initialization
func TestNew(t *testing.T) {
	tests := []struct {
		name           string
		component      string
		instanceID     string
		expectedComp   string
		expectedInstID string
	}{
		{
			name:           "with instance ID set",
			component:      "test-component",
			instanceID:     "instance-123",
			expectedComp:   "test-component",
			expectedInstID: "instance-123",
		},
		{
			name:           "without instance ID",
			component:      "agent",
			instanceID:     "",
			expectedComp:   "agent",
			expectedInstID: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable for test
			if tt.instanceID != "" {
				if err := os.Setenv("INSTANCE_ID", tt.instanceID); err != nil {
					t.Fatalf("Failed to set INSTANCE_ID: %v", err)
				}
				defer func() {
					if err := os.Unsetenv("INSTANCE_ID"); err != nil {
						t.Errorf("Failed to unset INSTANCE_ID: %v", err)
					}
				}()
			} else {
				if err := os.Unsetenv("INSTANCE_ID"); err != nil {
					t.Fatalf("Failed to unset INSTANCE_ID: %v", err)
				}
			}

			logger := New(tt.component)

			if logger.Component != tt.expectedComp {
				t.Errorf("Expected component %s, got %s", tt.expectedComp, logger.Component)
			}

			if logger.InstanceID != tt.expectedInstID {
				t.Errorf("Expected instance ID %s, got %s", tt.expectedInstID, logger.InstanceID)
			}

			if logger.Container == "" {
				t.Error("Expected container to be set from hostname")
			}
		})
	}
}

// TestLogLevels tests all log level methods
func TestLogLevels(t *testing.T) {
	tests := []struct {
		name      string
		logFunc   func(*Logger, string, string, string, map[string]interface{})
		level     LogLevel
		message   string
		clientID  string
		requestID string
		fields    map[string]interface{}
	}{
		{
			name:      "Info log",
			logFunc:   (*Logger).Info,
			level:     INFO,
			message:   "Test info message",
			clientID:  "client-123",
			requestID: "req-456",
			fields:    map[string]interface{}{"key": "value"},
		},
		{
			name:      "Error log",
			logFunc:   (*Logger).Error,
			level:     ERROR,
			message:   "Test error message",
			clientID:  "client-789",
			requestID: "req-012",
			fields:    map[string]interface{}{"error_code": 500},
		},
		{
			name:      "Warn log",
			logFunc:   (*Logger).Warn,
			level:     WARN,
			message:   "Test warning message",
			clientID:  "client-abc",
			requestID: "req-def",
			fields:    nil,
		},
		{
			name:      "Debug log",
			logFunc:   (*Logger).Debug,
			level:     DEBUG,
			message:   "Test debug message",
			clientID:  "client-xyz",
			requestID: "req-uvw",
			fields:    map[string]interface{}{"debug_info": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer log.SetOutput(os.Stderr)

			logger := New("test-component")
			tt.logFunc(logger, tt.clientID, tt.requestID, tt.message, tt.fields)

			output := buf.String()

			// Parse JSON output
			var entry LogEntry
			// Extract JSON from log output (skip timestamp prefix)
			jsonStart := strings.Index(output, "{")
			if jsonStart == -1 {
				t.Fatal("No JSON found in log output")
			}
			jsonStr := output[jsonStart:]
			jsonStr = strings.TrimSpace(jsonStr)

			if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
				t.Fatalf("Failed to parse JSON log: %v\nOutput: %s", err, output)
			}

			// Verify log entry fields
			if entry.Level != tt.level {
				t.Errorf("Expected level %s, got %s", tt.level, entry.Level)
			}

			if entry.Message != tt.message {
				t.Errorf("Expected message '%s', got '%s'", tt.message, entry.Message)
			}

			if entry.ClientID != tt.clientID {
				t.Errorf("Expected client ID '%s', got '%s'", tt.clientID, entry.ClientID)
			}

			if entry.RequestID != tt.requestID {
				t.Errorf("Expected request ID '%s', got '%s'", tt.requestID, entry.RequestID)
			}

			if entry.Component != "test-component" {
				t.Errorf("Expected component 'test-component', got '%s'", entry.Component)
			}

			// Verify timestamp format
			if _, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err != nil {
				t.Errorf("Invalid timestamp format: %s", entry.Timestamp)
			}

			// Verify fields if present
			if tt.fields != nil {
				for key, expectedValue := range tt.fields {
					if actualValue, ok := entry.Fields[key]; !ok {
						t.Errorf("Expected field '%s' not found", key)
					} else {
						// Handle type conversions for numeric values (JSON unmarshals numbers as float64)
						switch expected := expectedValue.(type) {
						case int:
							if actual, ok := actualValue.(float64); ok {
								if int(actual) != expected {
									t.Errorf("Field '%s': expected %v, got %v", key, expectedValue, actualValue)
								}
							} else if actualValue != expectedValue {
								t.Errorf("Field '%s': expected %v, got %v", key, expectedValue, actualValue)
							}
						default:
							if actualValue != expectedValue {
								t.Errorf("Field '%s': expected %v, got %v", key, expectedValue, actualValue)
							}
						}
					}
				}
			}
		})
	}
}

// TestInfoWithDuration tests the InfoWithDuration helper method
func TestInfoWithDuration(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := New("test-component")
	logger.InfoWithDuration("client-123", "req-456", "Request completed", 123.45, map[string]interface{}{
		"endpoint": "/api/query",
	})

	output := buf.String()
	jsonStart := strings.Index(output, "{")
	jsonStr := output[jsonStart:]
	jsonStr = strings.TrimSpace(jsonStr)

	var entry LogEntry
	if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Verify duration field
	durationMS, ok := entry.Fields["duration_ms"]
	if !ok {
		t.Error("Expected duration_ms field not found")
	}

	if durationMS != 123.45 {
		t.Errorf("Expected duration_ms 123.45, got %v", durationMS)
	}

	// Verify other fields are preserved
	endpoint, ok := entry.Fields["endpoint"]
	if !ok {
		t.Error("Expected endpoint field not found")
	}

	if endpoint != "/api/query" {
		t.Errorf("Expected endpoint '/api/query', got %v", endpoint)
	}

	// Verify it's an INFO level log
	if entry.Level != INFO {
		t.Errorf("Expected INFO level, got %s", entry.Level)
	}
}

// TestErrorWithCode tests the ErrorWithCode helper method
func TestErrorWithCode(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		err            error
		fields         map[string]interface{}
		expectError    bool
		expectedErrMsg string
	}{
		{
			name:           "with error",
			statusCode:     500,
			err:            &testError{msg: "database connection failed"},
			fields:         map[string]interface{}{"db": "postgres"},
			expectError:    true,
			expectedErrMsg: "database connection failed",
		},
		{
			name:        "without error",
			statusCode:  404,
			err:         nil,
			fields:      nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer log.SetOutput(os.Stderr)

			logger := New("test-component")
			logger.ErrorWithCode("client-123", "req-456", "Request failed", tt.statusCode, tt.err, tt.fields)

			output := buf.String()
			jsonStart := strings.Index(output, "{")
			jsonStr := output[jsonStart:]
			jsonStr = strings.TrimSpace(jsonStr)

			var entry LogEntry
			if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
				t.Fatalf("Failed to parse JSON: %v", err)
			}

			// Verify status code field
			statusCode, ok := entry.Fields["status_code"]
			if !ok {
				t.Error("Expected status_code field not found")
			}

			// Type assertion for numeric comparison
			statusCodeFloat, ok := statusCode.(float64)
			if !ok {
				t.Errorf("status_code is not a number: %v", statusCode)
			}

			if int(statusCodeFloat) != tt.statusCode {
				t.Errorf("Expected status_code %d, got %v", tt.statusCode, statusCode)
			}

			// Verify error field if error is present
			if tt.expectError {
				errMsg, ok := entry.Fields["error"]
				if !ok {
					t.Error("Expected error field not found")
				}

				if errMsg != tt.expectedErrMsg {
					t.Errorf("Expected error message '%s', got '%v'", tt.expectedErrMsg, errMsg)
				}
			}

			// Verify it's an ERROR level log
			if entry.Level != ERROR {
				t.Errorf("Expected ERROR level, got %s", entry.Level)
			}

			// Verify other fields are preserved
			if tt.fields != nil {
				for key, expectedValue := range tt.fields {
					if actualValue, ok := entry.Fields[key]; !ok {
						t.Errorf("Expected field '%s' not found", key)
					} else {
						// Handle type conversions for numeric values (JSON unmarshals numbers as float64)
						switch expected := expectedValue.(type) {
						case int:
							if actual, ok := actualValue.(float64); ok {
								if int(actual) != expected {
									t.Errorf("Field '%s': expected %v, got %v", key, expectedValue, actualValue)
								}
							} else if actualValue != expectedValue {
								t.Errorf("Field '%s': expected %v, got %v", key, expectedValue, actualValue)
							}
						default:
							if actualValue != expectedValue {
								t.Errorf("Field '%s': expected %v, got %v", key, expectedValue, actualValue)
							}
						}
					}
				}
			}
		})
	}
}

// TestJSONMarshalError tests behavior when JSON marshaling fails
func TestJSONMarshalError(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := New("test-component")

	// Create a field with an unmarshalable value (channel)
	ch := make(chan int)
	logger.Info("client-123", "req-456", "Test message", map[string]interface{}{
		"channel": ch, // Channels cannot be marshaled to JSON
	})

	output := buf.String()

	// Should log an error about marshaling failure
	if !strings.Contains(output, "Failed to marshal log entry") {
		t.Error("Expected error message about JSON marshaling failure")
	}
}

// Helper type for testing errors
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// BenchmarkLog benchmarks the logging performance
func BenchmarkLog(b *testing.B) {
	logger := New("benchmark-component")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	fields := map[string]interface{}{
		"user_id":   "user-123",
		"action":    "query",
		"duration":  45.67,
		"success":   true,
		"row_count": 150,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("client-123", "req-456", "Processing request", fields)
	}
}

// BenchmarkLogWithoutFields benchmarks logging without extra fields
func BenchmarkLogWithoutFields(b *testing.B) {
	logger := New("benchmark-component")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("client-123", "req-456", "Simple log message", nil)
	}
}
