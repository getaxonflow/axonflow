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

//go:build enterprise

package node_enforcement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNewMultiChannelAlerter(t *testing.T) {
	// Test with no environment variables
	alerter := NewMultiChannelAlerter()
	if alerter == nil {
		t.Fatal("NewMultiChannelAlerter returned nil")
	}

	if alerter.cloudwatchEnabled != true {
		t.Error("cloudwatchEnabled should be true by default")
	}

	// Test with environment variables
	if err := os.Setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"); err != nil {
		t.Fatalf("Failed to set SLACK_WEBHOOK_URL: %v", err)
	}
	if err := os.Setenv("EMAIL_ALERTS_ENABLED", "true"); err != nil {
		t.Fatalf("Failed to set EMAIL_ALERTS_ENABLED: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("SLACK_WEBHOOK_URL")
		_ = os.Unsetenv("EMAIL_ALERTS_ENABLED")
	}()

	alerter = NewMultiChannelAlerter()
	if alerter.slackWebhookURL != "https://hooks.slack.com/test" {
		t.Errorf("slack webhook URL not set correctly: %s", alerter.slackWebhookURL)
	}

	if !alerter.emailEnabled {
		t.Error("email alerts should be enabled")
	}
}

func TestMultiChannelAlerter_SendNodeViolationAlert(t *testing.T) {
	// Create mock Slack server
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode payload: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create alerter with mock server URL
	alerter := &MultiChannelAlerter{
		slackWebhookURL:   server.URL,
		emailEnabled:      false,
		cloudwatchEnabled: true,
	}

	violation := &ViolationInfo{
		OrgID:           "test_org",
		Tier:            "Professional",
		MaxNodesAllowed: 10,
		ActualNodeCount: 15,
		ExcessNodes:     5,
	}

	ctx := context.Background()
	err := alerter.SendNodeViolationAlert(ctx, violation)
	if err != nil {
		t.Errorf("SendNodeViolationAlert failed: %v", err)
	}

	// Verify Slack payload was sent
	if receivedPayload == nil {
		t.Error("No payload received by mock Slack server")
	}

	// Verify payload structure
	if attachments, ok := receivedPayload["attachments"].([]interface{}); ok {
		if len(attachments) == 0 {
			t.Error("Expected at least one attachment")
		} else {
			attachment := attachments[0].(map[string]interface{})
			if attachment["color"] != "danger" {
				t.Errorf("Expected danger color, got %v", attachment["color"])
			}
			if attachment["title"] != "Node Limit Violation" {
				t.Errorf("Expected 'Node Limit Violation' title, got %v", attachment["title"])
			}
		}
	} else {
		t.Error("Expected attachments in payload")
	}
}

func TestMultiChannelAlerter_SendNodeCountWarning(t *testing.T) {
	// Create mock Slack server
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := &MultiChannelAlerter{
		slackWebhookURL:   server.URL,
		emailEnabled:      false,
		cloudwatchEnabled: true,
	}

	ctx := context.Background()
	err := alerter.SendNodeCountWarning(ctx, "test_org", 0.85)
	if err != nil {
		t.Errorf("SendNodeCountWarning failed: %v", err)
	}

	// Verify Slack payload
	if receivedPayload != nil {
		if attachments, ok := receivedPayload["attachments"].([]interface{}); ok {
			attachment := attachments[0].(map[string]interface{})
			if attachment["color"] != "warning" {
				t.Errorf("Expected warning color, got %v", attachment["color"])
			}
		}
	}
}

func TestMultiChannelAlerter_sendSlackAlert_Error(t *testing.T) {
	// Test with server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	alerter := &MultiChannelAlerter{
		slackWebhookURL: server.URL,
	}

	ctx := context.Background()
	err := alerter.sendSlackAlert(ctx, "Test", "Test message", "danger")
	if err == nil {
		t.Error("Expected error when Slack returns 500, got nil")
	}
}

func TestMultiChannelAlerter_sendSlackAlert_InvalidURL(t *testing.T) {
	alerter := &MultiChannelAlerter{
		slackWebhookURL: "http://invalid-url-that-does-not-exist-12345.com",
	}

	ctx := context.Background()
	err := alerter.sendSlackAlert(ctx, "Test", "Test message", "danger")
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestMultiChannelAlerter_sendEmailAlert(t *testing.T) {
	alerter := &MultiChannelAlerter{
		emailEnabled: true,
	}

	violation := &ViolationInfo{
		OrgID:           "test_org",
		Tier:            "Professional",
		MaxNodesAllowed: 10,
		ActualNodeCount: 15,
		ExcessNodes:     5,
	}

	ctx := context.Background()
	// Should not error (it's a placeholder implementation)
	err := alerter.sendEmailAlert(ctx, violation)
	if err != nil {
		t.Errorf("sendEmailAlert failed: %v", err)
	}
}

func TestNewCloudWatchMetricsReporter(t *testing.T) {
	reporter := NewCloudWatchMetricsReporter()
	if reporter == nil {
		t.Fatal("NewCloudWatchMetricsReporter returned nil")
	}

	if reporter.namespace != "AxonFlow/NodeEnforcement" {
		t.Errorf("Expected namespace 'AxonFlow/NodeEnforcement', got %s", reporter.namespace)
	}
}

func TestCloudWatchMetricsReporter_PublishNodeCountMetric(t *testing.T) {
	reporter := NewCloudWatchMetricsReporter()

	ctx := context.Background()
	// Should not error (it's a placeholder implementation)
	err := reporter.PublishNodeCountMetric(ctx, "test_org", 8, 10)
	if err != nil {
		t.Errorf("PublishNodeCountMetric failed: %v", err)
	}
}

func TestMultiChannelAlerter_SendNodeViolationAlert_NoSlack(t *testing.T) {
	// Test without Slack webhook
	alerter := &MultiChannelAlerter{
		slackWebhookURL:   "",
		emailEnabled:      false,
		cloudwatchEnabled: true,
	}

	violation := &ViolationInfo{
		OrgID:           "test_org",
		Tier:            "Enterprise",
		MaxNodesAllowed: 50,
		ActualNodeCount: 60,
		ExcessNodes:     10,
	}

	ctx := context.Background()
	// Should not error even without Slack configured
	err := alerter.SendNodeViolationAlert(ctx, violation)
	if err != nil {
		t.Errorf("SendNodeViolationAlert failed: %v", err)
	}
}

func TestMultiChannelAlerter_SendNodeCountWarning_NoSlack(t *testing.T) {
	alerter := &MultiChannelAlerter{
		slackWebhookURL: "",
	}

	ctx := context.Background()
	err := alerter.SendNodeCountWarning(ctx, "test_org", 0.9)
	if err != nil {
		t.Errorf("SendNodeCountWarning failed: %v", err)
	}
}

func TestMultiChannelAlerter_ViolationAlertMessage(t *testing.T) {
	// Capture stdout to verify message format
	var capturedMessages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)

		if attachments, ok := payload["attachments"].([]interface{}); ok {
			if len(attachments) > 0 {
				attachment := attachments[0].(map[string]interface{})
				if text, ok := attachment["text"].(string); ok {
					capturedMessages = append(capturedMessages, text)
				}
			}
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := &MultiChannelAlerter{
		slackWebhookURL: server.URL,
	}

	violation := &ViolationInfo{
		OrgID:           "healthcare-eu",
		Tier:            "Enterprise",
		MaxNodesAllowed: 50,
		ActualNodeCount: 65,
		ExcessNodes:     15,
	}

	ctx := context.Background()
	err := alerter.SendNodeViolationAlert(ctx, violation)
	if err != nil {
		t.Errorf("Failed to send alert: %v", err)
	}

	if len(capturedMessages) == 0 {
		t.Error("No messages captured")
		return
	}

	message := capturedMessages[0]

	// Verify message contains key information
	expectedStrings := []string{
		"healthcare-eu",
		"Enterprise",
		"50",
		"65",
		"15",
	}

	for _, expected := range expectedStrings {
		if !contains(message, expected) {
			t.Errorf("Expected message to contain '%s', got: %s", expected, message)
		}
	}
}

func TestMultiChannelAlerter_WarningAlertMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := &MultiChannelAlerter{
		slackWebhookURL: server.URL,
	}

	ctx := context.Background()
	// 0.85 = 85%
	err := alerter.SendNodeCountWarning(ctx, "ecommerce-eu", 0.85)
	if err != nil {
		t.Errorf("Failed to send warning: %v", err)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}

// Benchmark tests
func BenchmarkSendSlackAlert(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := &MultiChannelAlerter{
		slackWebhookURL: server.URL,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alerter.sendSlackAlert(ctx, "Test", "Test message", "info")
	}
}

func BenchmarkSendNodeViolationAlert(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	alerter := &MultiChannelAlerter{
		slackWebhookURL: server.URL,
		emailEnabled:    false,
	}

	violation := &ViolationInfo{
		OrgID:           "benchmark_org",
		Tier:            "Professional",
		MaxNodesAllowed: 10,
		ActualNodeCount: 15,
		ExcessNodes:     5,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alerter.SendNodeViolationAlert(ctx, violation)
	}
}
