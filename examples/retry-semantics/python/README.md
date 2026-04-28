# Execution Boundary Semantics — Python

Demonstrates and validates idempotent retry behavior for WCP step gates:

1. Default retry behavior is idempotent (same step returns cached decision)
2. Explicit `retry_policy="reevaluate"` forces fresh policy evaluation
3. Response includes `cached` (bool) and `decision_source` ("fresh"/"cached")
4. Different steps are evaluated independently

## Prerequisites

- AxonFlow Agent running on `localhost:8080` (`docker compose up -d`)
- **Python 3.10 or newer** — the system Python on older macOS releases (3.9)
  is *not* sufficient. Create a venv on a newer interpreter:
  ```bash
  python3.11 -m venv .venv
  source .venv/bin/activate
  ```
- The current `axonflow` SDK release (`pip install -U axonflow`). The pinned
  `axonflow==4.1.0` from earlier examples does not expose the retry-policy
  fields used here and will fail on import or on a missing attribute.

If you have the SDK checked out locally, install it editable instead:

```bash
pip install -e /path/to/axonflow-sdk-python
```

## Run

```bash
python main.py
```

Exits with code 0 on success and 1 if any assertion fails.
