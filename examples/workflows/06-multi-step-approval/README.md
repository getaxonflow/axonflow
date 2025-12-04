# Example 6: Multi-Step Approval Workflow

This example demonstrates implementing approval workflows with multiple stakeholders and conditional routing.

## What You'll Learn

- How to implement approval chains
- How to handle approvals/rejections at each stage
- How to route based on approval rules

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Initiating purchase request: $15,000 for new servers
✅ Manager approval: APPROVED
📤 Escalating to Director level...
✅ Director approval: APPROVED
📤 Final Finance approval...
✅ Finance approval: APPROVED
✅ Purchase request fully approved!
```

## How It Works

1. **Submit Request:** Employee creates purchase request
2. **Manager Approval:** < $5K auto-approve, else escalate
3. **Director Approval:** < $20K approve, else escalate to CFO
4. **Finance Approval:** Final verification and compliance check
5. **Execute:** If all approved, proceed with purchase

**Approval Rules:**
```
Amount < $5K    → Manager only
Amount < $20K   → Manager + Director
Amount >= $20K  → Manager + Director + CFO + Finance
```

## Key Concepts

**Workflow State Machine:**
- Each approval is a state transition
- Track approval history
- Handle rejections gracefully
- Conditional routing based on business rules

## Next Steps

- Try Example 7 for healthcare workflows
- Add timeout handling (auto-reject after 48h)
- Implement delegation (approve on behalf of)
