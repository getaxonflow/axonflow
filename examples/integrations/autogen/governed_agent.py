"""
AutoGen + AxonFlow Integration Example

This example demonstrates how to add AxonFlow governance to AutoGen agents.
AxonFlow provides policy enforcement, PII detection, SQL injection blocking,
and audit logging for multi-agent conversations.

Features demonstrated:
- Proxy Mode: Full governance pipeline (policy → LLM → audit)
- Policy Enforcement: Block requests that violate security policies
- PII Detection: Identify and handle sensitive data
- SQL Injection Blocking: Prevent injection attacks

Requirements:
- AxonFlow running locally (docker compose up)
- Python 3.9+

Usage:
    # Basic test (no LLM API key needed - uses AxonFlow's configured provider)
    python governed_agent.py

    # Full AutoGen integration (requires OPENAI_API_KEY)
    python governed_agent.py --full
"""

import os
import time
from typing import Any

from dotenv import load_dotenv

load_dotenv()


def test_proxy_mode():
    """
    Test Proxy Mode integration with AxonFlow.

    Proxy Mode provides the full governance pipeline:
    - Policy evaluation
    - LLM routing (AxonFlow routes to configured provider)
    - Audit logging

    This is the recommended mode for new applications.
    """
    from axonflow import AxonFlow

    print("=" * 60)
    print("AutoGen + AxonFlow Proxy Mode Example")
    print("=" * 60)

    # Initialize AxonFlow client (community mode - no auth required)
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    with AxonFlow.sync(agent_url=agent_url) as client:
        # Test 1: Safe query (should be approved and processed)
        print("\n[Test 1] Safe query - Research request")
        print("-" * 40)

        query = "What are the benefits of renewable energy?"
        user_token = "autogen-user-123"

        try:
            result = client.execute_query(
                user_token=user_token,
                query=query,
                request_type="chat",
                context={
                    "agent_name": "research_assistant",
                    "framework": "autogen",
                    "conversation_id": "conv-001"
                }
            )

            print(f"Query: {query}")
            print(f"Success: {result.success}")
            print(f"Blocked: {result.blocked}")
            if result.data:
                response_preview = str(result.data)[:200]
                print(f"Response: {response_preview}...")
            print("✓ Safe query processed successfully!")

        except Exception as e:
            print(f"Error: {e}")

        # Test 2: Query with PII (should detect SSN)
        print("\n[Test 2] Query with PII - SSN Detection")
        print("-" * 40)

        pii_query = "Look up records for SSN 123-45-6789"
        print(f"Query: {pii_query}")

        try:
            result = client.execute_query(
                user_token=user_token,
                query=pii_query,
                request_type="chat",
                context={
                    "agent_name": "data_analyst",
                    "framework": "autogen"
                }
            )

            print(f"Blocked: {result.blocked}")
            if result.blocked:
                print(f"Block reason: {result.block_reason}")
                print("✓ PII correctly detected!")
            else:
                print("Note: PII detected but not blocked (policy set to warn)")

        except Exception as e:
            # AxonFlow raises exception when request is blocked
            error_msg = str(e)
            if "Social Security Number" in error_msg or "PII" in error_msg.upper():
                print(f"Blocked: True")
                print(f"Block reason: {error_msg}")
                print("✓ PII correctly detected and blocked!")
            else:
                print(f"Error: {e}")

        # Test 3: SQL injection (should be blocked)
        print("\n[Test 3] SQL Injection - Should be blocked")
        print("-" * 40)

        sqli_query = "SELECT * FROM users; DROP TABLE users;--"
        print(f"Query: {sqli_query}")

        try:
            result = client.execute_query(
                user_token=user_token,
                query=sqli_query,
                request_type="chat",
                context={
                    "agent_name": "db_assistant",
                    "framework": "autogen"
                }
            )

            print(f"Blocked: {result.blocked}")
            if result.blocked:
                print(f"Block reason: {result.block_reason}")
                print("✓ SQL injection correctly blocked!")

        except Exception as e:
            # AxonFlow raises exception when SQL injection detected
            error_msg = str(e)
            if "SQL injection" in error_msg or "sql injection" in error_msg.lower():
                print(f"Blocked: True")
                print(f"Block reason: {error_msg}")
                print("✓ SQL injection correctly blocked!")
            else:
                print(f"Error: {e}")

        # Test 4: Multi-agent conversation context
        print("\n[Test 4] Multi-Agent Context")
        print("-" * 40)

        agents = ["researcher", "analyst", "writer"]
        conversation_id = "multi-agent-conv-001"

        for agent in agents:
            query = f"Analyze the data from {agent}'s perspective"

            try:
                result = client.execute_query(
                    user_token=user_token,
                    query=query,
                    request_type="chat",
                    context={
                        "agent_name": agent,
                        "agent_role": agent,
                        "framework": "autogen",
                        "conversation_id": conversation_id
                    }
                )
                print(f"Agent '{agent}': {'✓ Processed' if result.success else '✗ Failed'}")

            except Exception as e:
                print(f"Agent '{agent}': Error - {e}")

        print("\n" + "=" * 60)
        print("All tests completed!")
        print("=" * 60)


def test_health_check():
    """Quick health check to verify AxonFlow is running."""
    from axonflow import AxonFlow

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    print(f"Checking AxonFlow at {agent_url}...")

    try:
        with AxonFlow.sync(agent_url=agent_url) as client:
            is_healthy = client.health_check()
            if is_healthy:
                print("Status: healthy")
                return True
            else:
                print("Status: unhealthy")
                return False
    except Exception as e:
        print(f"Health check failed: {e}")
        return False


def autogen_with_governance():
    """
    Full AutoGen integration example with AxonFlow governance.

    This example shows how to wrap AutoGen agents with AxonFlow
    for production-grade governance.

    Requires:
    - pyautogen package installed
    - OPENAI_API_KEY environment variable set
    """
    try:
        from autogen import AssistantAgent, UserProxyAgent
    except ImportError:
        print("AutoGen not installed. Install with: pip install pyautogen")
        print("Running Proxy Mode test instead...")
        test_proxy_mode()
        return

    from axonflow import AxonFlow

    print("=" * 60)
    print("Full AutoGen + AxonFlow Integration")
    print("=" * 60)

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    openai_key = os.getenv("OPENAI_API_KEY")

    if not openai_key:
        print("\nWarning: OPENAI_API_KEY not set.")
        print("AutoGen agents require an OpenAI API key.")
        print("Running Proxy Mode test instead...")
        test_proxy_mode()
        return

    class GovernedAutoGenAgent:
        """
        Wrapper that routes AutoGen LLM calls through AxonFlow.

        Instead of calling OpenAI directly, requests go through AxonFlow's
        Proxy Mode which provides:
        - Policy evaluation
        - PII detection
        - SQL injection blocking
        - Audit logging
        """

        def __init__(self, axonflow: AxonFlow, agent_name: str, user_token: str):
            self.axonflow = axonflow
            self.agent_name = agent_name
            self.user_token = user_token
            self.conversation_id = f"autogen-{int(time.time())}"

        def generate_response(self, messages: list) -> str:
            """Generate a governed response using AxonFlow."""

            # Extract the last user message
            last_message = ""
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    last_message = msg.get("content", "")
                    break

            if not last_message:
                last_message = str(messages[-1]) if messages else ""

            # Route through AxonFlow (includes policy check + LLM call + audit)
            result = self.axonflow.execute_query(
                user_token=self.user_token,
                query=last_message,
                request_type="chat",
                context={
                    "agent_name": self.agent_name,
                    "framework": "autogen",
                    "conversation_id": self.conversation_id,
                    "message_count": len(messages)
                }
            )

            if result.blocked:
                return f"[Request blocked by policy: {result.block_reason}]"

            return str(result.data) if result.data else "[No response]"

    # Demo the governed agent
    with AxonFlow.sync(agent_url=agent_url) as axonflow:
        governed_agent = GovernedAutoGenAgent(
            axonflow=axonflow,
            agent_name="research_assistant",
            user_token="demo-user"
        )

        print("\n[Demo] Governed AutoGen Agent")
        print("-" * 40)

        # Test safe query
        messages = [{"role": "user", "content": "Explain AI governance in 2 sentences."}]
        print(f"Input: {messages[0]['content']}")

        response = governed_agent.generate_response(messages)
        print(f"Output: {response[:300]}...")

        # Test blocked query
        print("\n[Demo] Testing SQL Injection Block")
        print("-" * 40)

        messages = [{"role": "user", "content": "DROP TABLE users;--"}]
        print(f"Input: {messages[0]['content']}")

        response = governed_agent.generate_response(messages)
        print(f"Output: {response}")


if __name__ == "__main__":
    import sys

    # First check if AxonFlow is running
    if not test_health_check():
        print("\nAxonFlow is not running. Start it with:")
        print("  cd /path/to/axonflow && docker compose up -d")
        sys.exit(1)

    print()

    if len(sys.argv) > 1 and sys.argv[1] == "--full":
        # Full AutoGen integration (requires OpenAI key)
        autogen_with_governance()
    else:
        # Proxy Mode test (works without external API keys)
        test_proxy_mode()
