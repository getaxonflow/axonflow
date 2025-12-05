package main

import (
	"fmt"
	"log"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		log.Fatal("❌ AXONFLOW_LICENSE_KEY must be set in .env file")
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:   agentURL,
		LicenseKey: licenseKey,
	})

	fmt.Println("✅ Connected to AxonFlow")
	fmt.Println("🏥 Starting clinical decision support workflow...")
	fmt.Println()
	fmt.Println("⚠️  DISCLAIMER: Educational example only. Not for actual medical use.")
	fmt.Println()

	// Patient case
	symptoms := "Patient presents with: persistent cough (7 days), fever 101°F, " +
		"chest congestion, shortness of breath on exertion, fatigue. " +
		"No known allergies. Age: 45, Non-smoker."

	fmt.Println("📋 Patient Case:")
	fmt.Println(symptoms)
	fmt.Println()

	// Step 1: Emergency Screening
	fmt.Println("🚨 Step 1: Emergency screening for critical conditions...")
	emergencyQuery := fmt.Sprintf("Analyze these symptoms for emergency red flags: %s. "+
		"Check for: severe respiratory distress, chest pain, confusion, high fever (>103°F). "+
		"Respond with EMERGENCY or NON-EMERGENCY and reasoning.", symptoms)

	emergencyResp, err := client.ExecuteQuery("user-123", emergencyQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Emergency screening failed: %v", err)
	}

	fmt.Println("📥 Emergency Assessment:", emergencyResp.Data)
	fmt.Println()

	// Step 2: Differential Diagnosis
	fmt.Println("🔍 Step 2: Generating differential diagnosis...")
	diagnosisQuery := fmt.Sprintf("Based on symptoms: %s, "+
		"provide differential diagnosis list ranked by likelihood. "+
		"Consider: pneumonia, bronchitis, COVID-19, flu, common cold. "+
		"Include key distinguishing features.", symptoms)

	diagnosisResp, err := client.ExecuteQuery("user-123", diagnosisQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Diagnosis failed: %v", err)
	}

	fmt.Println("📥 Differential Diagnosis:")
	fmt.Println(diagnosisResp.Data)
	fmt.Println()

	// Step 3: Recommended Tests
	fmt.Println("🧪 Step 3: Recommending diagnostic tests...")
	testsQuery := "Based on the differential diagnosis above, what diagnostic tests " +
		"would help confirm or rule out the top conditions? Prioritize by importance."

	testsResp, err := client.ExecuteQuery("user-123", testsQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Test recommendation failed: %v", err)
	}

	fmt.Println("📥 Recommended Tests:")
	fmt.Println(testsResp.Data)
	fmt.Println()

	// Step 4: Treatment Plan
	fmt.Println("💊 Step 4: Generating evidence-based treatment plan...")
	treatmentQuery := "Assuming test results confirm acute bronchitis, create a treatment plan including:\n" +
		"1. Medications (with dosages)\n" +
		"2. Symptom management\n" +
		"3. Activity recommendations\n" +
		"4. When to seek emergency care\n" +
		"5. Expected recovery timeline"

	treatmentResp, err := client.ExecuteQuery("user-123", treatmentQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Treatment planning failed: %v", err)
	}

	fmt.Println("=" + "=")
	fmt.Println("📋 TREATMENT PLAN")
	fmt.Println("=" + "=")
	fmt.Println(treatmentResp.Data)
	fmt.Println()
	fmt.Println("=" + "=")
	fmt.Println()
	fmt.Println("✅ Clinical decision support workflow completed")
	fmt.Println("💡 Workflow: Emergency Screen → Diagnosis → Tests → Treatment")
	fmt.Println()
	fmt.Println("⚠️  Remember: This is educational only. Real diagnosis requires licensed physicians.")
}
