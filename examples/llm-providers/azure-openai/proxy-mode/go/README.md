# Azure OpenAI Proxy Mode - Go

Demonstrates AxonFlow Proxy Mode with Azure OpenAI as the backend LLM provider.

## Proxy Mode vs Gateway Mode

| Mode | Your App Manages | AxonFlow Manages |
|------|-----------------|------------------|
| **Proxy** | Nothing | LLM credentials, routing, policies, audit |
| **Gateway** | LLM credentials | Policies, audit |

Proxy Mode is the simplest integration - your app just sends queries to AxonFlow.

## Prerequisites

- AxonFlow running
- Go 1.21+

## Run

```bash
docker compose up -d

go mod tidy
go run main.go
```

## How It Works

1. Your app sends query to AxonFlow with `provider: "azure-openai"`
2. AxonFlow enforces policies (PII, SQLi, etc.). The stored policy action decides: with the shipped actions and no organization override, the SQL injection and PII examples are detected and warned, not blocked. To block them, record an organization override (`sqli=block`, `pii=block`) through the customer portal API (Enterprise) or change the policy's action. `PII_ACTION` no longer sets an action (v11)
3. AxonFlow routes to Azure OpenAI using server-side credentials
4. Response returned to your app (with audit logged automatically)
