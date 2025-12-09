// Package cloudflare provides a client for managing Cloudflare Access resources.
package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AccessClient is a client for the Cloudflare Access API.
type AccessClient struct {
	apiToken   string
	accountID  string
	groupID    string
	httpClient *http.Client
	baseURL    string
}

// AccessMember represents a member in an Access Group.
type AccessMember struct {
	Email     string    `json:"email"`
	AddedAt   time.Time `json:"added_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// AccessGroup represents a Cloudflare Access Group.
type AccessGroup struct {
	ID        string                   `json:"id"`
	Name      string                   `json:"name"`
	UID       string                   `json:"uid"`
	Include   []map[string]interface{} `json:"include"`
	Exclude   []map[string]interface{} `json:"exclude"`
	Require   []map[string]interface{} `json:"require"`
	CreatedAt time.Time                `json:"created_at"`
	UpdatedAt time.Time                `json:"updated_at"`
}

// APIResponse is the standard Cloudflare API response wrapper.
type APIResponse struct {
	Success  bool            `json:"success"`
	Errors   []APIError      `json:"errors"`
	Messages []string        `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

// APIError represents a Cloudflare API error.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewAccessClient creates a new Cloudflare Access client.
func NewAccessClient(apiToken, accountID, groupID string) *AccessClient {
	return &AccessClient{
		apiToken:  apiToken,
		accountID: accountID,
		groupID:   groupID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.cloudflare.com/client/v4",
	}
}

// GetGroup retrieves the current state of the Access Group.
func (c *AccessClient) GetGroup() (*AccessGroup, error) {
	url := fmt.Sprintf("%s/accounts/%s/access/groups/%s", c.baseURL, c.accountID, c.groupID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("API error: %v", apiResp.Errors)
	}

	var group AccessGroup
	if err := json.Unmarshal(apiResp.Result, &group); err != nil {
		return nil, fmt.Errorf("unmarshaling group: %w", err)
	}

	return &group, nil
}

// AddEmail adds an email to the Access Group.
func (c *AccessClient) AddEmail(email string) error {
	// Get current group to preserve existing members
	group, err := c.GetGroup()
	if err != nil {
		return fmt.Errorf("getting current group: %w", err)
	}

	// Check if email already exists
	for _, rule := range group.Include {
		if emailRule, ok := rule["email"].(map[string]interface{}); ok {
			if emailRule["email"] == email {
				return fmt.Errorf("email %s already exists in group", email)
			}
		}
	}

	// Add new email to include rules
	newRule := map[string]interface{}{
		"email": map[string]interface{}{
			"email": email,
		},
	}
	group.Include = append(group.Include, newRule)

	// Update the group
	return c.updateGroup(group)
}

// RemoveEmail removes an email from the Access Group.
func (c *AccessClient) RemoveEmail(email string) error {
	// Get current group
	group, err := c.GetGroup()
	if err != nil {
		return fmt.Errorf("getting current group: %w", err)
	}

	// Find and remove the email
	found := false
	newInclude := make([]map[string]interface{}, 0)
	for _, rule := range group.Include {
		if emailRule, ok := rule["email"].(map[string]interface{}); ok {
			if emailRule["email"] == email {
				found = true
				continue // Skip this email (remove it)
			}
		}
		newInclude = append(newInclude, rule)
	}

	if !found {
		return fmt.Errorf("email %s not found in group", email)
	}

	group.Include = newInclude

	// Update the group
	return c.updateGroup(group)
}

// ListEmails returns all emails in the Access Group.
func (c *AccessClient) ListEmails() ([]string, error) {
	group, err := c.GetGroup()
	if err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}

	var emails []string
	for _, rule := range group.Include {
		if emailRule, ok := rule["email"].(map[string]interface{}); ok {
			if email, ok := emailRule["email"].(string); ok {
				emails = append(emails, email)
			}
		}
	}

	return emails, nil
}

// updateGroup updates the Access Group with new include rules.
func (c *AccessClient) updateGroup(group *AccessGroup) error {
	url := fmt.Sprintf("%s/accounts/%s/access/groups/%s", c.baseURL, c.accountID, c.groupID)

	payload := map[string]interface{}{
		"name":    group.Name,
		"include": group.Include,
		"exclude": group.Exclude,
		"require": group.Require,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if !apiResp.Success {
		return fmt.Errorf("API error: %v", apiResp.Errors)
	}

	return nil
}

// setHeaders sets the common headers for Cloudflare API requests.
func (c *AccessClient) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")
}
