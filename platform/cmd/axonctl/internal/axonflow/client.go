package axonflow

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the AxonFlow API.
type Client struct {
	endpoint     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// NewClient creates a new AxonFlow API client.
func NewClient(endpoint, clientID, clientSecret string) *Client {
	return &Client{
		endpoint:     endpoint,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// do executes an HTTP request with auth headers and returns the response body.
func (c *Client) do(method, path string) ([]byte, int, error) {
	url := c.endpoint + path

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("X-Client-ID", c.clientID)
	req.Header.Set("X-Client-Secret", c.clientSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}

	return body, resp.StatusCode, nil
}

// checkError returns an error if the status code indicates a failure.
func checkError(body []byte, statusCode int) error {
	if statusCode >= 200 && statusCode < 300 {
		return nil
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Message != "" {
		return fmt.Errorf("API error (%d): %s", statusCode, errResp.Message)
	}

	return fmt.Errorf("API error (%d): %s", statusCode, string(body))
}
