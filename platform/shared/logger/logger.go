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

package logger

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// LogLevel represents the severity of a log entry
type LogLevel string

const (
	DEBUG LogLevel = "DEBUG"
	INFO  LogLevel = "INFO"
	WARN  LogLevel = "WARN"
	ERROR LogLevel = "ERROR"
)

// Logger provides structured logging with multi-tenant support
type Logger struct {
	Component  string
	InstanceID string
	Container  string
}

// LogEntry represents a structured log entry with required fields for multi-tenant logging
type LogEntry struct {
	Timestamp  string                 `json:"timestamp"`
	Level      LogLevel               `json:"level"`
	Component  string                 `json:"component"`
	InstanceID string                 `json:"instance_id"`
	Container  string                 `json:"container"`
	ClientID   string                 `json:"client_id"`
	RequestID  string                 `json:"request_id,omitempty"`
	Message    string                 `json:"message"`
	Fields     map[string]interface{} `json:"fields,omitempty"`
}

// New creates a new Logger for the specified component
func New(component string) *Logger {
	// Get instance ID from environment (set during deployment)
	instanceID := os.Getenv("INSTANCE_ID")
	if instanceID == "" {
		instanceID = "unknown"
	}

	// Get container name from hostname
	container, err := os.Hostname()
	if err != nil {
		container = "unknown"
	}

	return &Logger{
		Component:  component,
		InstanceID: instanceID,
		Container:  container,
	}
}

// Log creates a structured log entry and writes it to stdout
func (l *Logger) Log(level LogLevel, clientID, requestID, message string, fields map[string]interface{}) {
	entry := LogEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Level:      level,
		Component:  l.Component,
		InstanceID: l.InstanceID,
		Container:  l.Container,
		ClientID:   clientID,
		RequestID:  requestID,
		Message:    message,
		Fields:     fields,
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		// Fallback to plain text if JSON marshaling fails
		log.Printf("ERROR: Failed to marshal log entry: %v", err)
		return
	}

	// Write JSON log to stdout (Docker will capture this)
	log.Println(string(jsonBytes))
}

// Info logs an informational message
func (l *Logger) Info(clientID, requestID, message string, fields map[string]interface{}) {
	l.Log(INFO, clientID, requestID, message, fields)
}

// Error logs an error message
func (l *Logger) Error(clientID, requestID, message string, fields map[string]interface{}) {
	l.Log(ERROR, clientID, requestID, message, fields)
}

// Warn logs a warning message
func (l *Logger) Warn(clientID, requestID, message string, fields map[string]interface{}) {
	l.Log(WARN, clientID, requestID, message, fields)
}

// Debug logs a debug message
func (l *Logger) Debug(clientID, requestID, message string, fields map[string]interface{}) {
	l.Log(DEBUG, clientID, requestID, message, fields)
}

// InfoWithDuration logs an info message with duration field
func (l *Logger) InfoWithDuration(clientID, requestID, message string, durationMS float64, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["duration_ms"] = durationMS
	l.Info(clientID, requestID, message, fields)
}

// ErrorWithCode logs an error with status code
func (l *Logger) ErrorWithCode(clientID, requestID, message string, statusCode int, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["status_code"] = statusCode
	if err != nil {
		fields["error"] = err.Error()
	}
	l.Error(clientID, requestID, message, fields)
}
