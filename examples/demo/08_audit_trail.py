"""
Part 6.1: Audit Trail Query

Every request through AxonFlow is logged:
- Who made the request (user, client)
- What was requested (query, context)
- What policies were evaluated
- What was the decision (allowed, blocked, flagged)
- Timing and token usage

Query the audit trail for compliance, debugging, and analytics.
"""

import asyncio
import json
import os
from datetime import datetime, timedelta

import httpx


async def query_audit_logs():
    """Query recent audit logs from the Agent API."""
    print("Audit Trail Query")
    print("=" * 60)
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    # Query audit logs via direct API call
    # The Agent exposes /api/audit/logs endpoint for audit queries
    async with httpx.AsyncClient() as http_client:

        # Get recent logs
        print("-" * 60)
        print("Recent Audit Logs (last 15 minutes)")
        print("-" * 60)
        print()

        try:
            response = await http_client.get(
                f"{agent_url}/api/audit/logs",
                params={
                    "limit": 10,
                    "since": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                },
                timeout=10.0,
            )

            if response.status_code == 200:
                logs = response.json()

                if isinstance(logs, list) and len(logs) > 0:
                    print(f"Found {len(logs)} audit entries:")
                    print()

                    for i, log in enumerate(logs[:5], 1):
                        print(f"Entry {i}:")
                        print(f"  ID: {log.get('id', 'N/A')}")
                        print(f"  Timestamp: {log.get('timestamp', 'N/A')}")
                        print(f"  User: {log.get('user_email', 'N/A')}")
                        print(f"  Decision: {log.get('policy_decision', 'N/A')}")
                        query_preview = str(log.get('query', ''))[:50]
                        print(f"  Query: {query_preview}...")
                        print()

                    if len(logs) > 5:
                        print(f"  ... and {len(logs) - 5} more entries")
                else:
                    print("No audit logs found in the time range.")
                    print()
                    print("Run some demo queries first to generate audit data:")
                    print("  python3 02_pii_detection.py")
                    print("  python3 04_proxy_mode.py")

            elif response.status_code == 404:
                print("Audit endpoint not available.")
                print("This may be expected in some configurations.")
            else:
                print(f"Error querying audit logs: {response.status_code}")

        except httpx.ConnectError:
            print(f"Could not connect to Agent at {agent_url}")
            print("Ensure services are running: docker-compose up -d")
        except Exception as e:
            print(f"Error: {e}")

        print()

        # Show what's captured in audit logs
        print("-" * 60)
        print("Audit Log Fields")
        print("-" * 60)
        print()
        print("Each audit entry captures:")
        print()
        print("  Identity:")
        print("    - request_id: Unique request identifier")
        print("    - user_id, user_email: Who made the request")
        print("    - client_id, tenant_id: Application context")
        print()
        print("  Request:")
        print("    - query: The original query text")
        print("    - request_type: chat, connector, etc.")
        print("    - timestamp: When it happened")
        print()
        print("  Policy:")
        print("    - policy_decision: allowed, blocked, flagged")
        print("    - policy_details: Which policies triggered")
        print("    - redacted_fields: Any PII that was masked")
        print()
        print("  Response:")
        print("    - provider, model: LLM used")
        print("    - response_time_ms: Latency")
        print("    - tokens_used, cost: Usage metrics")
        print()


async def show_blocked_requests():
    """Show recently blocked requests."""
    print("-" * 60)
    print("Blocked Requests Analysis")
    print("-" * 60)
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with httpx.AsyncClient() as http_client:
        try:
            response = await http_client.get(
                f"{agent_url}/api/audit/logs",
                params={
                    "decision": "blocked",
                    "limit": 5,
                },
                timeout=10.0,
            )

            if response.status_code == 200:
                logs = response.json()

                if isinstance(logs, list) and len(logs) > 0:
                    print(f"Found {len(logs)} blocked requests:")
                    print()

                    for log in logs:
                        policy_details = log.get('policy_details', {})
                        if isinstance(policy_details, str):
                            try:
                                policy_details = json.loads(policy_details)
                            except:
                                pass

                        print(f"  Query: {str(log.get('query', ''))[:40]}...")
                        print(f"  Policy: {policy_details.get('policy_violated', 'unknown')}")
                        print(f"  Reason: {policy_details.get('block_reason', 'N/A')}")
                        print()
                else:
                    print("No blocked requests found.")
                    print("This is good - your queries are clean!")

        except Exception as e:
            print(f"Error querying blocked requests: {e}")

    print()


async def main():
    await query_audit_logs()
    await show_blocked_requests()

    print("=" * 60)
    print("Audit Trail Summary")
    print("=" * 60)
    print()
    print("Complete audit trail enables:")
    print("  - Compliance reporting (GDPR, SOC2, etc.)")
    print("  - Security incident investigation")
    print("  - Usage analytics and cost tracking")
    print("  - Policy effectiveness monitoring")
    print()
    print("View in Grafana: http://localhost:3000")
    print("  Dashboard: AxonFlow Community")
    print()


if __name__ == "__main__":
    asyncio.run(main())
