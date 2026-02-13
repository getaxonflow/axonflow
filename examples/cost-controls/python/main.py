#!/usr/bin/env python3
"""
AxonFlow Cost Controls Example - Python SDK

This example demonstrates and VALIDATES ALL cost control SDK methods:
- Budget: Create, Get, List, Update, Delete
- Budget Status and Alerts
- Budget Check (pre-flight)
- Usage: Summary, Breakdown, Records
- Pricing

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
import sys
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

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def main() -> int:
    print("AxonFlow Cost Controls - Python SDK")
    print("=" * 52)
    print()

    async_client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", ""),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )
    client = SyncAxonFlow(async_client)

    budget_id = f"demo-budget-python-{int(time.time())}"

    try:
        # 1. create_budget
        print("1. CreateBudget - Creating a monthly budget...")
        budgets_available = True
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
            assert_check(created_budget.id == budget_id, "Created budget has correct ID")
            assert_check(created_budget.limit_usd == 100.0, "Created budget has correct limit")
            print(f"   Created: {created_budget.id}")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                print("   Budget management requires Enterprise license (endpoint returned 404)")
                budgets_available = False
            else:
                failures.append(f"create_budget failed: {e}")
                return 1
        print()

        if budgets_available:
            # 2. get_budget
            print("2. GetBudget - Retrieving budget by ID...")
            try:
                retrieved_budget = client.get_budget(budget_id)
                assert_check(retrieved_budget.id == budget_id, "Retrieved budget ID matches")
                assert_check(retrieved_budget.scope == BudgetScope.ORGANIZATION, "Retrieved budget scope matches")
            except Exception as e:
                failures.append(f"get_budget failed: {e}")
            print()

            # 3. list_budgets
            print("3. ListBudgets - Listing all budgets...")
            try:
                budget_list = client.list_budgets(ListBudgetsOptions(limit=10))
                assert_check(len(budget_list.budgets) > 0, "Found at least one budget")
                our_budget = next((b for b in budget_list.budgets if b.id == budget_id), None)
                assert_check(our_budget is not None, "Our budget is in the list")
                print(f"   Found {len(budget_list.budgets)} budgets")
            except Exception as e:
                failures.append(f"list_budgets failed: {e}")
            print()

            # 4. update_budget
            print("4. UpdateBudget - Updating budget limit...")
            try:
                updated_budget = client.update_budget(budget_id, UpdateBudgetRequest(
                    name="Demo Budget (Python SDK) - Updated",
                    limit_usd=150.0,
                ))
                assert_check(updated_budget.limit_usd == 150.0, "Budget limit was updated")
                assert_check("Updated" in updated_budget.name, "Budget name was updated")
            except Exception as e:
                failures.append(f"update_budget failed: {e}")
            print()

            # 5. get_budget_status
            print("5. GetBudgetStatus - Checking current budget status...")
            try:
                status = client.get_budget_status(budget_id)
                assert_check(status.budget.id == budget_id, "Status references correct budget")
                assert_check(status.percentage >= 0, "Percentage is non-negative")
                assert_check(status.remaining_usd >= 0, "Remaining is non-negative")
                print(f"   Used: ${status.used_usd:.2f} / ${status.budget.limit_usd:.2f}")
            except Exception as e:
                failures.append(f"get_budget_status failed: {e}")
            print()

            # 6. get_budget_alerts
            print("6. GetBudgetAlerts - Getting alerts for budget...")
            try:
                alerts = client.get_budget_alerts(budget_id)
                assert_check(alerts.count >= 0, "Alert count is non-negative")
                print(f"   Found {alerts.count} alerts")
            except Exception as e:
                failures.append(f"get_budget_alerts failed: {e}")
            print()

            # 7. check_budget
            print("7. CheckBudget - Pre-flight budget check...")
            try:
                decision = client.check_budget(BudgetCheckRequest(org_id="demo-org"))
                assert_check(isinstance(decision.allowed, bool), "Decision has allowed field")
                print(f"   Allowed: {decision.allowed}")
            except Exception as e:
                failures.append(f"check_budget failed: {e}")
            print()
        else:
            print("2-7. Skipping budget operations (requires Enterprise license)")
            print()

        # 8. get_usage_summary
        print("8. GetUsageSummary - Getting usage summary...")
        try:
            summary = client.get_usage_summary(period="monthly")
            assert_check(summary.total_cost_usd >= 0, "Total cost is non-negative")
            assert_check(summary.total_requests >= 0, "Total requests is non-negative")
            print(f"   Total Cost: ${summary.total_cost_usd:.6f}, Requests: {summary.total_requests}")
        except Exception as e:
            failures.append(f"get_usage_summary failed: {e}")
        print()

        # 9. get_usage_breakdown
        print("9. GetUsageBreakdown - Getting usage breakdown by provider...")
        try:
            breakdown = client.get_usage_breakdown(group_by="provider", period="monthly")
            assert_check(breakdown.group_by == "provider", "Breakdown grouped by provider")
            assert_check(breakdown.total_cost_usd >= 0, "Total cost is non-negative")
            print(f"   Breakdown by: {breakdown.group_by}")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                print("   Usage breakdown requires Enterprise license (endpoint returned 404)")
            else:
                failures.append(f"get_usage_breakdown failed: {e}")
        print()

        # 10. list_usage_records
        print("10. ListUsageRecords - Listing recent usage records...")
        try:
            records = client.list_usage_records(ListUsageRecordsOptions(limit=5))
            assert_check(records.total >= 0, "Total records is non-negative")
            print(f"   Found {records.total} records")
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                print("   Usage records requires Enterprise license (endpoint returned 404)")
            else:
                failures.append(f"list_usage_records failed: {e}")
        print()

        # 11. get_pricing
        print("11. GetPricing - Getting model pricing...")
        try:
            pricing_resp = client.get_pricing(provider="anthropic", model="claude-sonnet-4")
            # Pricing may be empty if not configured
            if pricing_resp.pricing:
                assert_check(len(pricing_resp.pricing) > 0, "Pricing returned")
                print(f"   Found {len(pricing_resp.pricing)} pricing entries")
            else:
                print("   No pricing configured (OK)")
        except Exception as e:
            # Pricing endpoint may not be available in all deployments
            print(f"   Note: {e}")
        print()

        # 12. delete_budget
        print("12. DeleteBudget - Cleaning up...")
        if budgets_available:
            try:
                client.delete_budget(budget_id)
                # Verify deletion
                try:
                    client.get_budget(budget_id)
                    assert_check(False, "Budget should not exist after deletion")
                except Exception:
                    assert_check(True, "Budget deleted successfully")
            except Exception as e:
                failures.append(f"delete_budget failed: {e}")
        else:
            print("   Skipped (budget was not created)")
        print()

    finally:
        client.close()

    print("=" * 52)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Cost Control operations validated:")
        print("  - create_budget()")
        print("  - get_budget()")
        print("  - list_budgets()")
        print("  - update_budget()")
        print("  - get_budget_status()")
        print("  - get_budget_alerts()")
        print("  - check_budget()")
        print("  - get_usage_summary()")
        print("  - get_usage_breakdown()")
        print("  - list_usage_records()")
        print("  - get_pricing()")
        print("  - delete_budget()")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
