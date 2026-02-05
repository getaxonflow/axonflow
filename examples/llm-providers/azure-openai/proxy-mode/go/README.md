# Azure OpenAI Proxy Mode - Go

Demonstrates AxonFlow Proxy Mode with Azure OpenAI as the backend LLM provider.

## Proxy Mode vs Gateway Mode

| Mode | Your App Manages | AxonFlow Manages |
|------|-----------------|------------------|
| **Proxy** | Nothing | LLM credentials, routing, policies, audit |
| **Gateway** | LLM credentials | Policies, audit |

Proxy Mode is the simplest integration - your app just sends queries to AxonFlow.

## Prerequisites

- AxonFlow running with `PII_ACTION=block` (for PII blocking test)
- Go 1.21+

## Run

```bash
# Start AxonFlow with PII blocking enabled
PII_ACTION=block docker compose up -d

go mod tidy
go run main.go
```

## How It Works

1. Your app sends query to AxonFlow with `provider: "azure-openai"`
2. AxonFlow enforces policies (PII, SQLi, etc.)
3. AxonFlow routes to Azure OpenAI using server-side credentials
4. Response returned to your app (with audit logged automatically)
