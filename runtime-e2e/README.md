# Runtime End-to-End Tests

Tests in this directory MUST invoke the feature through the runtime's tool/skill/command surface (or the API path that a real user actually traverses). Importing the AxonFlow SDK client class directly is not a runtime test — that's an SDK test, which lives elsewhere.

If the runtime can't expose your feature yet, the feature isn't ready to ship.

## Why this directory exists

A May 3, 2026 audit found multiple capabilities (audit search, decision explain, override CRUD) where the API endpoint and SDK method existed for months but no plugin or agent surface ever wired them up. End-users could not reach the capability. The fix: every user-facing feature must have a test in this directory that invokes the capability through the runtime where the user lives.

The single rule:

> **If a user cannot reach the feature from their runtime, we did not ship a feature, we shipped a library.**

## Layout

```
runtime-e2e/
  README.md                    # this file
  <feature-name>/              # one folder per feature
    test.sh                    # bash runner; invokes through the runtime
    README.md                  # 5 lines: prereqs, what it asserts, how to run
```

For axonflow-enterprise specifically, the "runtime" is typically:
- The agent + orchestrator + DB stack as exercised through a docker-compose live-test
- Or an end-to-end flow exercised through one of the SDK examples that themselves invoke through the platform API as a real client would

## Running

Each test folder has its own README with prereqs and run instructions. Most tests assume `docker compose up -d` from the repo root has been run and the stack is healthy.

## Adding a test

1. Confirm you can invoke the feature through the runtime, not by importing the SDK client class. If you can't, raise it in PR review — the answer is to fix the runtime exposure, not to write an SDK-import test instead.
2. Create the folder, write `test.sh` and `README.md`.
3. Update `axonflow-internal-docs/engineering/FEATURE_RUNTIME_COVERAGE.md` (private; engineering team only) to mark the new green cell.
4. Reference the test in the PR that wires the feature.
