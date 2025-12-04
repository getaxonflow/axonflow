# Example 7: Healthcare Diagnosis Workflow

This example demonstrates a healthcare diagnostic workflow with symptom analysis and treatment recommendations.

## What You'll Learn

- How to build medical decision support workflows
- How to handle sensitive healthcare data
- How to implement multi-factor diagnostic logic

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Analyzing patient symptoms...
✅ Preliminary assessment complete
📤 Running diagnostic protocol...
✅ Diagnosis identified: Acute Sinusitis
📤 Generating treatment plan...
✅ Treatment plan created
📥 Recommendation: Antibiotics + Rest (7-10 days recovery)
```

## How It Works

1. **Symptom Collection:** Gather patient symptoms, vitals, medical history
2. **Preliminary Assessment:** Rule out emergency conditions
3. **Diagnostic Analysis:** Apply clinical decision rules
4. **Treatment Plan:** Generate evidence-based recommendations
5. **Follow-up:** Schedule appropriate follow-up care

## Key Concepts

**Clinical Decision Support:**
- Multi-step diagnostic reasoning
- Differential diagnosis consideration
- Evidence-based treatment protocols
- Safety checks and contraindications

**Disclaimer:** This is a simplified educational example. Real medical diagnosis requires licensed healthcare professionals.

## Next Steps

- Try Example 8 for e-commerce workflows
- Add drug interaction checks
- Implement referral logic
