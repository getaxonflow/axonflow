---
name: Bug Report
about: Report a bug or unexpected behavior in AxonFlow
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ''
---

## Bug Description

<!-- A clear and concise description of what the bug is -->

## Environment

**AxonFlow Version:**
<!-- e.g., v1.0.12, or commit SHA if using main branch -->

**Deployment Method:**
- [ ] AWS Marketplace CloudFormation
- [ ] Docker Compose
- [ ] ECS Fargate (custom deployment)
- [ ] Local development
- [ ] Other: <!-- specify -->

**Operating System:**
<!-- e.g., Ubuntu 22.04, macOS 14.0, Amazon Linux 2023 -->

**Go Version (if building from source):**
<!-- Output of `go version` -->

**Database:**
- [ ] PostgreSQL (version: )
- [ ] Other: <!-- specify -->

## Steps to Reproduce

<!-- Provide detailed steps to reproduce the behavior -->

1.
2.
3.
4.

## Expected Behavior

<!-- A clear description of what you expected to happen -->

## Actual Behavior

<!-- What actually happened instead -->

## Logs and Error Messages

<!-- Include relevant logs from agent, orchestrator, or other components -->

```
Paste logs here
```

**Agent Logs:**
<!-- If applicable, include agent logs from /var/log/axonflow/ or docker logs -->

**Orchestrator Logs:**
<!-- If applicable, include orchestrator logs -->

**Database Errors:**
<!-- If applicable, include PostgreSQL errors -->

## Configuration

<!-- Share relevant configuration (REDACT any secrets, API keys, or sensitive data) -->

**Environment Variables:**
```bash
# REDACT sensitive values before sharing
DATABASE_URL=postgresql://user:***@host:5432/dbname
AGENT_PORT=8443
# ... other relevant config
```

**CloudFormation Parameters (if applicable):**
<!-- Share relevant parameters used during stack creation -->

## Component(s) Affected

- [ ] Agent (service execution)
- [ ] Orchestrator (workflow coordination)
- [ ] Database (PostgreSQL)
- [ ] MCP Integration (LLM context protocol)
- [ ] Multi-tenant System
- [ ] AWS Marketplace Integration
- [ ] License Management
- [ ] Service Identity System
- [ ] Other: <!-- specify -->

## Severity

<!-- How critical is this issue? -->

- [ ] Critical - System is unusable
- [ ] High - Major feature broken
- [ ] Medium - Feature partially working
- [ ] Low - Minor issue or cosmetic

## Additional Context

<!-- Add any other context, screenshots, or relevant information -->

## Possible Solution

<!-- Optional: If you have suggestions on how to fix the bug -->

## Checklist

- [ ] I have searched existing issues to avoid duplicates
- [ ] I have included all relevant logs and error messages
- [ ] I have redacted any sensitive data (API keys, passwords, tokens)
- [ ] I have provided clear steps to reproduce
- [ ] I am using a supported version of AxonFlow
