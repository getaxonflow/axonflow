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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// MultiChannelAlerter sends alerts to multiple channels (Slack, email, CloudWatch)
type MultiChannelAlerter struct {
	slackWebhookURL string
	emailEnabled    bool
	cloudwatchEnabled bool
}

// NewMultiChannelAlerter creates a new alerter
func NewMultiChannelAlerter() *MultiChannelAlerter {
	return &MultiChannelAlerter{
		slackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		emailEnabled:    os.Getenv("EMAIL_ALERTS_ENABLED") == "true",
		cloudwatchEnabled: true, // Always enabled
	}
}

// SendNodeViolationAlert sends a critical alert for node limit violations
func (a *MultiChannelAlerter) SendNodeViolationAlert(ctx context.Context, violation *ViolationInfo) error {
	message := fmt.Sprintf(
		"🚨 **NODE LIMIT VIOLATION**\n\n"+
			"**Organization:** %s\n"+
			"**Tier:** %s\n"+
			"**Licensed Nodes:** %d\n"+
			"**Actual Nodes:** %d\n"+
			"**Excess Nodes:** %d\n\n"+
			"**Action Required:** Contact customer to upgrade license or reduce node count.",
		violation.OrgID,
		violation.Tier,
		violation.MaxNodesAllowed,
		violation.ActualNodeCount,
		violation.ExcessNodes,
	)

	// Send to Slack
	if a.slackWebhookURL != "" {
		if err := a.sendSlackAlert(ctx, "Node Limit Violation", message, "danger"); err != nil {
			fmt.Printf("Failed to send Slack alert: %v\n", err)
		}
	}

	// Send to email (if enabled)
	if a.emailEnabled {
		if err := a.sendEmailAlert(ctx, violation); err != nil {
			fmt.Printf("Failed to send email alert: %v\n", err)
		}
	}

	// Log to CloudWatch (via stdout, captured by CloudWatch Logs)
	fmt.Printf("[VIOLATION] %s\n", message)

	return nil
}

// SendNodeCountWarning sends a warning when node count reaches 80% of limit
func (a *MultiChannelAlerter) SendNodeCountWarning(ctx context.Context, orgID string, usage float64) error {
	message := fmt.Sprintf(
		"⚠️  **NODE COUNT WARNING**\n\n"+
			"**Organization:** %s\n"+
			"**Usage:** %.1f%%\n\n"+
			"Node count is approaching the licensed limit. Consider upgrading license.",
		orgID,
		usage*100,
	)

	// Send to Slack
	if a.slackWebhookURL != "" {
		if err := a.sendSlackAlert(ctx, "Node Count Warning", message, "warning"); err != nil {
			fmt.Printf("Failed to send Slack warning: %v\n", err)
		}
	}

	// Log to CloudWatch
	fmt.Printf("[WARNING] %s\n", message)

	return nil
}

// sendSlackAlert sends an alert to Slack webhook
func (a *MultiChannelAlerter) sendSlackAlert(ctx context.Context, title, message, color string) error {
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":     color,
				"title":     title,
				"text":      message,
				"footer":    "AxonFlow Node Enforcement",
				"ts":        time.Now().Unix(),
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.slackWebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create Slack request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Slack request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

// sendEmailAlert sends an email alert (placeholder - integrate with SES/SendGrid)
func (a *MultiChannelAlerter) sendEmailAlert(ctx context.Context, violation *ViolationInfo) error {
	// TODO: Integrate with AWS SES or SendGrid
	fmt.Printf("[EMAIL] Would send email alert for org %s\n", violation.OrgID)

	// Example AWS SES integration:
	/*
	svc := ses.New(session.New())
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{
				aws.String("ops@getaxonflow.com"),
			},
		},
		Message: &ses.Message{
			Subject: &ses.Content{
				Data: aws.String("Node Limit Violation - " + violation.OrgID),
			},
			Body: &ses.Body{
				Text: &ses.Content{
					Data: aws.String(message),
				},
			},
		},
		Source: aws.String("alerts@getaxonflow.com"),
	}
	_, err := svc.SendEmail(input)
	*/

	return nil
}

// CloudWatchMetricsReporter publishes node count metrics to CloudWatch
type CloudWatchMetricsReporter struct {
	namespace string
}

// NewCloudWatchMetricsReporter creates a new CloudWatch metrics reporter
func NewCloudWatchMetricsReporter() *CloudWatchMetricsReporter {
	return &CloudWatchMetricsReporter{
		namespace: "AxonFlow/NodeEnforcement",
	}
}

// PublishNodeCountMetric publishes node count to CloudWatch
func (r *CloudWatchMetricsReporter) PublishNodeCountMetric(ctx context.Context, orgID string, nodeCount int, maxNodes int) error {
	// TODO: Integrate with AWS CloudWatch SDK
	fmt.Printf("[CLOUDWATCH] Metric: Namespace=%s, OrgID=%s, NodeCount=%d, MaxNodes=%d\n",
		r.namespace, orgID, nodeCount, maxNodes)

	// Example CloudWatch integration:
	/*
	svc := cloudwatch.New(session.New())
	input := &cloudwatch.PutMetricDataInput{
		Namespace: aws.String(r.namespace),
		MetricData: []*cloudwatch.MetricDatum{
			{
				MetricName: aws.String("ActiveNodeCount"),
				Dimensions: []*cloudwatch.Dimension{
					{
						Name:  aws.String("OrgID"),
						Value: aws.String(orgID),
					},
				},
				Value:     aws.Float64(float64(nodeCount)),
				Timestamp: aws.Time(time.Now()),
				Unit:      aws.String("Count"),
			},
			{
				MetricName: aws.String("NodeUsagePercent"),
				Dimensions: []*cloudwatch.Dimension{
					{
						Name:  aws.String("OrgID"),
						Value: aws.String(orgID),
					},
				},
				Value:     aws.Float64(float64(nodeCount) / float64(maxNodes) * 100),
				Timestamp: aws.Time(time.Now()),
				Unit:      aws.String("Percent"),
			},
		},
	}
	_, err := svc.PutMetricData(input)
	*/

	return nil
}
