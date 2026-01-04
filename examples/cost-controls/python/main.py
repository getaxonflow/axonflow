#!/usr/bin/env python3
"""
AxonFlow Cost Controls Example - Python SDK (Comprehensive)

This example covers ALL cost control SDK methods:
- Budget: Create, Get, List, Update, Delete
- Budget Status and Alerts
- Budget Check (pre-flight)
- Usage: Summary, Breakdown, Records
- Pricing
"""

import os
import time

from axonflow import (
    AxonFlow,
    SyncAxonFlow,
    BudgetScope,
    BudgetPeriod,
    BudgetOnExceed,
    CreateBudgetRequest,
    UpdateBudgetRequest,
    BudgetCheckRequest,
    ListBudgetsOptions,
    ListUsageRecordsOptions,
)


def get_env(key: str, default: str) -> str:
    """Get environment variable with default value."""
    return os.getenv(key, default)


def main():
    print("AxonFlow Cost Controls - Python SDK (Comprehensive)")
    print("=" * 52)
    print()

    # Create AxonFlow client (SyncAxonFlow wraps the async client for synchronous usage)
    async_client = AxonFlow(
        agent_url=get_env("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        orchestrator_url=get_env("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081"),
    )
    client = SyncAxonFlow(async_client)

    budget_id = f"demo-budget-python-{int(time.time())}"

    # ========================================
    # BUDGET MANAGEMENT
    # ========================================

    # 1. create_budget
    print("1. create_budget - Creating a monthly budget...")
    try:
        created_budget = client.create_budget(CreateBudgetRequest(
            id=budget_id,
            name="Demo Budget (Python SDK)",
            scope=BudgetScope.ORGANIZATION,
            limit_usd=100.0,
            period=BudgetPeriod.MONTHLY,
            on_exceed=BudgetOnExceed.WARN,
            alert_thresholds=[50, 80, 100],
        ))
        print(f"   Created: {created_budget.id} (limit: ${created_budget.limit_usd:.2f}/month)")
    except Exception as e:
        print(f"   ERROR: {e}")
        return
    print()

    # 2. get_budget
    print("2. get_budget - Retrieving budget by ID...")
    try:
        retrieved_budget = client.get_budget(budget_id)
        print(f"   Retrieved: {retrieved_budget.id} (scope: {retrieved_budget.scope}, period: {retrieved_budget.period})")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # 3. list_budgets
    print("3. list_budgets - Listing all budgets...")
    try:
        budget_list = client.list_budgets(ListBudgetsOptions(limit=10))
        print(f"   Found {len(budget_list.budgets)} budgets (total: {budget_list.total})")
        for i, b in enumerate(budget_list.budgets[:3]):
            print(f"   - {b.id}: ${b.limit_usd:.2f}/{b.period}")
        if len(budget_list.budgets) > 3:
            print(f"   ... and {len(budget_list.budgets) - 3} more")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # 4. update_budget
    print("4. update_budget - Updating budget limit...")
    try:
        updated_budget = client.update_budget(budget_id, UpdateBudgetRequest(
            name="Demo Budget (Python SDK) - Updated",
            limit_usd=150.0,
        ))
        print(f"   Updated: {updated_budget.id} (new limit: ${updated_budget.limit_usd:.2f})")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # ========================================
    # BUDGET STATUS & ALERTS
    # ========================================

    # 5. get_budget_status
    print("5. get_budget_status - Checking current budget status...")
    try:
        status = client.get_budget_status(budget_id)
        print(f"   Used: ${status.used_usd:.2f} / ${status.budget.limit_usd:.2f} ({status.percentage:.1f}%)")
        print(f"   Remaining: ${status.remaining_usd:.2f}")
        print(f"   Exceeded: {status.is_exceeded}, Blocked: {status.is_blocked}")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # 6. get_budget_alerts
    print("6. get_budget_alerts - Getting alerts for budget...")
    try:
        alerts = client.get_budget_alerts(budget_id)
        print(f"   Found {alerts.count} alerts")
        if alerts.alerts:
            for a in alerts.alerts:
                print(f"   - [{a.alert_type}] {a.message} ({a.percentage_reached:.1f}% at ${a.amount_usd:.2f})")
        if alerts.count == 0:
            print("   (no alerts yet)")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # 7. check_budget
    print("7. check_budget - Pre-flight budget check...")
    try:
        decision = client.check_budget(BudgetCheckRequest(org_id="demo-org"))
        print(f"   Allowed: {decision.allowed}")
        if decision.action:
            print(f"   Action: {decision.action}")
        if decision.message:
            print(f"   Message: {decision.message}")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # ========================================
    # USAGE TRACKING
    # ========================================

    # 8. get_usage_summary
    print("8. get_usage_summary - Getting usage summary...")
    try:
        summary = client.get_usage_summary(period="monthly")
        print(f"   Total Cost: ${summary.total_cost_usd:.6f}")
        print(f"   Total Requests: {summary.total_requests}")
        print(f"   Tokens: {summary.total_tokens_in} in, {summary.total_tokens_out} out")
        print(f"   Avg Cost/Request: ${summary.average_cost_per_request:.6f}")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # 9. get_usage_breakdown
    print("9. get_usage_breakdown - Getting usage breakdown by provider...")
    try:
        breakdown = client.get_usage_breakdown(group_by="provider", period="monthly")
        print(f"   Breakdown by: {breakdown.group_by} (total: ${breakdown.total_cost_usd:.6f})")
        if breakdown.items:
            for item in breakdown.items:
                print(f"   - {item.group_value}: ${item.cost_usd:.6f} ({item.percentage:.1f}%, {item.request_count} requests)")
        else:
            print("   (no usage data yet)")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # 10. list_usage_records
    print("10. list_usage_records - Listing recent usage records...")
    try:
        records = client.list_usage_records(ListUsageRecordsOptions(limit=5))
        print(f"   Found {records.total} records (showing up to 5)")
        if records.records:
            for r in records.records:
                print(f"   - {r.provider}/{r.model}: {r.tokens_in + r.tokens_out} tokens, ${r.cost_usd:.6f}")
        else:
            print("   (no usage records yet)")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # ========================================
    # PRICING
    # ========================================

    # 11. get_pricing
    print("11. get_pricing - Getting model pricing...")
    try:
        pricing_resp = client.get_pricing(provider="anthropic", model="claude-sonnet-4")
        if pricing_resp.pricing:
            pricing = pricing_resp.pricing[0]
            print(f"   Provider: {pricing.provider}")
            print(f"   Model: {pricing.model}")
            print(f"   Input: ${pricing.pricing.input_per_1k:.4f}/1K tokens")
            print(f"   Output: ${pricing.pricing.output_per_1k:.4f}/1K tokens")
    except Exception as e:
        print(f"   ERROR: {e}")
    print()

    # ========================================
    # CLEANUP
    # ========================================

    # 12. delete_budget
    print("12. delete_budget - Cleaning up...")
    try:
        client.delete_budget(budget_id)
        print(f"   Deleted budget: {budget_id}")
    except Exception as e:
        print(f"   WARNING: Failed to delete budget: {e}")
    print()

    print("=" * 52)
    print("All 12 Cost Control methods tested!")


if __name__ == "__main__":
    main()
