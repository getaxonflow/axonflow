# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The AxonFlow team takes security bugs seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**security@getaxonflow.com**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., authentication bypass, code injection, etc.)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### What to Expect

After submitting a vulnerability report:

1. **Acknowledgment**: We'll acknowledge receipt within 48 hours
2. **Investigation**: We'll investigate and validate the vulnerability
3. **Updates**: We'll keep you informed of our progress
4. **Resolution**: We'll work on a fix and coordinate disclosure timing with you
5. **Credit**: With your permission, we'll publicly credit you for the discovery

### Disclosure Policy

- We'll work with you to understand and resolve the issue quickly
- We'll keep you informed throughout the process
- We'll publicly disclose the vulnerability once a fix is released
- We request that you keep the vulnerability confidential until we've had a chance to address it

## Security Best Practices

When using the AxonFlow Go SDK:

### 1. Credential Management

**Never** hardcode credentials in your source code:

```go
// ❌ BAD - Credentials in code
client := axonflow.NewClientSimple(
    "https://staging-eu.getaxonflow.com",
    "client-id-here",
    "secret-here",
)

// ✅ GOOD - Use environment variables
client := axonflow.NewClientSimple(
    os.Getenv("AXONFLOW_AGENT_URL"),
    os.Getenv("AXONFLOW_CLIENT_ID"),
    os.Getenv("AXONFLOW_CLIENT_SECRET"),
)
```

### 2. TLS/SSL Configuration

Always use HTTPS endpoints for production:

```go
// ✅ GOOD - HTTPS endpoint
client := axonflow.NewClientSimple("https://api.getaxonflow.com", clientID, secret)

// ⚠️ WARNING - HTTP should only be used for local development
client := axonflow.NewClientSimple("http://localhost:8080", clientID, secret)
```

### 3. Timeout Configuration

Set appropriate timeouts to prevent resource exhaustion:

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     agentURL,
    ClientID:     clientID,
    ClientSecret: clientSecret,
    Timeout:      30 * time.Second, // Reasonable timeout
})
```

### 4. Input Validation

Always validate and sanitize user inputs before sending to AxonFlow:

```go
func processUserQuery(userInput string) error {
    // Validate input length
    if len(userInput) > 10000 {
        return errors.New("input too long")
    }

    // Sanitize input
    sanitized := sanitizeInput(userInput)

    // Send to AxonFlow
    resp, err := client.ExecuteQuery("user-token", sanitized, "chat", nil)
    // ...
}
```

### 5. Error Handling

Never expose sensitive information in error messages:

```go
resp, err := client.ExecuteQuery(token, query, "chat", nil)
if err != nil {
    // ❌ BAD - Exposes details
    return fmt.Errorf("query failed with token %s: %v", token, err)

    // ✅ GOOD - Generic error message
    log.Printf("Query failed: %v", err)
    return errors.New("query failed, please try again")
}
```

### 6. Dependency Management

Keep dependencies up to date:

```bash
# Check for updates
go list -m -u all

# Update dependencies
go get -u github.com/getaxonflow/axonflow-go
go mod tidy
```

### 7. Production Mode

Use production mode for production deployments to enable fail-open strategy:

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     agentURL,
    ClientID:     clientID,
    ClientSecret: clientSecret,
    Mode:         "production", // Fail-open if AxonFlow unavailable
})
```

### 8. Debug Mode

**Never** enable debug mode in production:

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     agentURL,
    ClientID:     clientID,
    ClientSecret: clientSecret,
    Debug:        os.Getenv("ENV") != "production", // Only in dev
})
```

## Known Security Considerations

### 1. Client Credentials

Client credentials (`ClientID` and `ClientSecret`) provide access to your AxonFlow account. Treat them like passwords:

- Store in environment variables or secure vaults
- Rotate regularly
- Never commit to version control
- Use different credentials for development and production

### 2. User Tokens

User tokens identify end-users in your application. Ensure:

- Tokens are unique per user
- Tokens are properly authenticated before use
- Tokens don't contain sensitive information
- Tokens are transmitted securely

### 3. Caching

The SDK's caching feature stores responses in memory:

- Cache is per-instance (not shared across processes)
- Cache entries expire based on TTL
- Sensitive data in cache is not encrypted
- Consider disabling cache for highly sensitive operations

### 4. Retry Logic

The SDK's retry logic will retry failed requests:

- Retries use exponential backoff
- Failed requests may be logged
- Consider disabling retries for non-idempotent operations

## Security Updates

We'll announce security updates through:

1. GitHub Security Advisories
2. Email notifications to package consumers (if possible via pkg.go.dev)
3. Release notes in GitHub releases

To receive security updates:

- Watch this repository for releases
- Subscribe to security advisories
- Check https://pkg.go.dev/github.com/getaxonflow/axonflow-go regularly

## Questions?

If you have questions about this security policy, please email security@getaxonflow.com.

Thank you for helping keep AxonFlow and our users safe!
