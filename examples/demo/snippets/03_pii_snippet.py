# PII blocked in real-time
try:
    response = await ax.execute_query(query="My SSN is 123-45-6789")
except PolicyViolationError as e:
    print(f"Blocked: {e.policy}")  # pii_ssn_detection
    print(f"Audit ID: {e.request_id}")  # Logged for compliance
