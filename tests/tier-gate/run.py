#!/usr/bin/env python3
"""
Tier-gate contract runner.

Reads tests/tier-gate/expected.yaml, hits each endpoint against a running
docker-compose stack, and asserts the actual HTTP status matches the manifest
entry for the current AXONFLOW_TIER (community | evaluation | enterprise).

Exits non-zero on any mismatch and prints a per-row diff so failures are
self-explanatory in CI logs.

Usage:
    AXONFLOW_TIER=community ./tests/tier-gate/run.py
    AXONFLOW_TIER=evaluation ./tests/tier-gate/run.py
    AXONFLOW_TIER=enterprise ./tests/tier-gate/run.py

Optional env (passthrough from setup-e2e-testing.sh):
    AGENT_BASE        — defaults to http://localhost:8080
    ORCH_BASE         — defaults to http://localhost:8081
    AXONFLOW_USER_TOKEN — JWT injected as Authorization: Bearer <token>
    AXONFLOW_CLIENT_ID  — used as X-Tenant-ID / X-Org-ID when set
    TIER_GATE_TIMEOUT — per-request timeout in seconds (default: 10)
    TIER_GATE_REPORT  — optional path to write JSON results (for downstream)

The manifest schema is documented in expected.yaml header.
"""

from __future__ import annotations

import base64
import json
import hashlib
import hmac
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

try:
    import yaml
except ImportError as e:
    print(f"ERROR: PyYAML required (pip install pyyaml). {e}", file=sys.stderr)
    sys.exit(2)


VALID_TIERS = ("community", "evaluation", "enterprise")
DEFAULT_AGENT = "http://localhost:8080"
DEFAULT_ORCH = "http://localhost:8081"


def colour(s: str, code: str) -> str:
    if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"


def green(s: str) -> str:
    return colour(s, "32")


def red(s: str) -> str:
    return colour(s, "31")


def yellow(s: str) -> str:
    return colour(s, "33")


def grey(s: str) -> str:
    return colour(s, "90")


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    if not isinstance(manifest, dict):
        raise ValueError("manifest root must be a mapping")
    if manifest.get("version") != 1:
        raise ValueError(f"unsupported manifest version: {manifest.get('version')}")
    if "endpoints" not in manifest or not isinstance(manifest["endpoints"], list):
        raise ValueError("manifest must contain 'endpoints' list")
    return manifest


def orchestrator_proxy_token() -> str:
    """Mint the internal-service token the orchestrator requires (#3068).

    The orchestrator gained a router-level authentication gate: every route
    except /health, /metrics and /prometheus needs a valid HMAC-signed
    X-Axonflow-Proxy-Auth header. This harness talks to port 8081 directly, so
    it must sign its own requests.

    Mirrors platform/shared/serviceauth/serviceauth.go exactly:
        AXON-INTERNAL-<ts>-<first 16 hex of HMAC-SHA256(secret, "orchestrator-internal:<ts>")>

    Returns "" when no secret is configured, in which case no header is added
    and the orchestrator will (correctly) refuse the call.
    """
    secret = os.environ.get("AXONFLOW_INTERNAL_SERVICE_SECRET", "").strip()
    if not secret:
        return ""
    ts = int(time.time())
    msg = f"orchestrator-internal:{ts}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()[:16]
    return f"AXON-INTERNAL-{ts}-{sig}"


def build_url(port: int, path: str, agent_base: str, orch_base: str) -> str:
    base = agent_base if port == 8080 else orch_base if port == 8081 else None
    if base is None:
        raise ValueError(f"port {port} not mapped (only 8080 agent / 8081 orchestrator)")
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path


def merged_headers(defaults: dict[str, Any], row: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    headers.update(defaults.get("headers") or {})
    headers.update(row.get("headers") or {})

    # #3068: rows targeting the orchestrator (port 8081) must carry a valid
    # internal-service token or the orchestrator's authentication gate refuses
    # them with 403 before routing. Minted per row so it stays inside the
    # 5-minute replay window on long runs. Never overrides an explicit header.
    #
    # A row sets `proxy_auth: false` when its ASSERTION IS the unauthenticated
    # refusal — those rows must keep arriving without a token or they would stop
    # testing the thing they exist to test.
    want_proxy_auth = row.get("proxy_auth", defaults.get("proxy_auth", True))
    if want_proxy_auth and int(row.get("port") or defaults.get("port") or 0) == 8081:
        tok = orchestrator_proxy_token()
        if tok:
            headers.setdefault("X-Axonflow-Proxy-Auth", tok)

    client_id = os.environ.get("AXONFLOW_CLIENT_ID", "").strip()
    if client_id:
        headers.setdefault("X-Tenant-ID", client_id)
        headers.setdefault("X-Org-ID", client_id)

    # Auth scheme: rows can opt into "basic" (clientId:clientSecret from
    # AXONFLOW_CLIENT_ID + AXONFLOW_CLIENT_SECRET) or default to bearer JWT.
    auth_scheme = (row.get("auth") or defaults.get("auth") or "bearer").lower()

    if auth_scheme == "basic":
        cid = os.environ.get("AXONFLOW_CLIENT_ID", "").strip()
        sec = os.environ.get("AXONFLOW_CLIENT_SECRET", "").strip()
        if cid and sec:
            token = base64.b64encode(f"{cid}:{sec}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
    elif auth_scheme == "none":
        # explicit no-op: row asks runner not to send Authorization
        pass
    else:
        bearer_env = row.get("bearer_env", defaults.get("bearer_env"))
        if bearer_env:
            token = os.environ.get(bearer_env, "").strip()
            if token:
                headers["Authorization"] = f"Bearer {token}"
    return headers


def resolve_body(defaults: dict[str, Any], row: dict[str, Any]) -> bytes | None:
    method = row["method"].upper()
    if method in ("GET", "HEAD", "DELETE", "OPTIONS"):
        return None
    body = row.get("body")
    if body is None:
        body = defaults.get("body_default")
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return json.dumps(body).encode("utf-8")
    if isinstance(body, str):
        return body.encode("utf-8")
    return str(body).encode("utf-8")


def do_request(
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, str]:
    req = urlrequest.Request(url=url, data=body, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(2048).decode("utf-8", errors="replace")
    except urlerror.HTTPError as e:
        snippet = ""
        try:
            snippet = e.read(2048).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, snippet
    except urlerror.URLError as e:
        return -1, f"transport error: {e.reason}"
    except TimeoutError as e:
        return -1, f"timeout: {e}"
    except Exception as e:
        return -1, f"unexpected: {e}"


def expected_for(row: dict[str, Any], tier: str) -> tuple[int, str]:
    expected = row.get("expected") or {}
    cell = expected.get(tier)
    if not isinstance(cell, dict):
        raise ValueError(f"row {row.get('id')!r}: missing expected.{tier}")
    if "status" not in cell:
        raise ValueError(f"row {row.get('id')!r}: expected.{tier}.status missing")
    return int(cell["status"]), str(cell.get("reason", ""))


def short_body(body: str) -> str:
    s = body.strip().replace("\n", " ")
    if len(s) > 240:
        return s[:240] + "..."
    return s


def main() -> int:
    tier = os.environ.get("AXONFLOW_TIER", "").strip().lower()
    if tier not in VALID_TIERS:
        print(
            red(
                f"ERROR: AXONFLOW_TIER must be one of {VALID_TIERS}; got {tier!r}"
            ),
            file=sys.stderr,
        )
        return 2

    manifest_path_env = os.environ.get("TIER_GATE_MANIFEST")
    if manifest_path_env:
        manifest_path = Path(manifest_path_env).resolve()
    else:
        manifest_path = (Path(__file__).resolve().parent / "expected.yaml").resolve()
    if not manifest_path.is_file():
        print(red(f"ERROR: manifest not found: {manifest_path}"), file=sys.stderr)
        return 2

    manifest = load_manifest(manifest_path)
    defaults = manifest.get("defaults") or {}
    endpoints = manifest["endpoints"]

    agent_base = os.environ.get("AGENT_BASE", DEFAULT_AGENT)
    orch_base = os.environ.get("ORCH_BASE", DEFAULT_ORCH)
    timeout = float(os.environ.get("TIER_GATE_TIMEOUT", "10"))

    print(grey(f"# tier-gate runner | tier={tier} | manifest={manifest_path}"))
    print(grey(f"# agent={agent_base}  orchestrator={orch_base}  timeout={timeout}s"))
    print(grey(f"# {len(endpoints)} endpoints"))

    fails: list[dict[str, Any]] = []
    passes = 0
    results: list[dict[str, Any]] = []

    start = time.monotonic()
    for row in endpoints:
        rid = row.get("id") or f"{row.get('method')} {row.get('path')}"
        method = row["method"]
        port = int(row["port"])
        path = row["path"]
        url = build_url(port, path, agent_base, orch_base)
        headers = merged_headers(defaults, row)
        body = resolve_body(defaults, row)

        try:
            exp_status, exp_reason = expected_for(row, tier)
        except ValueError as e:
            fails.append({"id": rid, "error": str(e)})
            print(red(f"FAIL {rid}: {e}"))
            continue

        actual_status, actual_body = do_request(url, method, headers, body, timeout)
        ok = actual_status == exp_status

        results.append(
            {
                "id": rid,
                "method": method,
                "url": url,
                "tier": tier,
                "expected": exp_status,
                "actual": actual_status,
                "ok": ok,
                "reason": exp_reason,
            }
        )

        if ok:
            passes += 1
            print(green(f"PASS {rid:<48s} {method:<6s} {actual_status} ({path})"))
        else:
            fails.append(
                {
                    "id": rid,
                    "method": method,
                    "url": url,
                    "expected": exp_status,
                    "actual": actual_status,
                    "reason": exp_reason,
                    "body_snippet": short_body(actual_body),
                }
            )
            print(
                red(
                    f"FAIL {rid:<48s} {method:<6s} expected={exp_status} actual={actual_status}"
                )
            )
            print(grey(f"     url:    {url}"))
            print(grey(f"     reason: {exp_reason}"))
            if actual_body:
                print(grey(f"     body:   {short_body(actual_body)}"))

    elapsed = time.monotonic() - start

    print()
    print(grey("=" * 70))
    summary = (
        f"tier-gate {tier}: {passes}/{len(endpoints)} pass, "
        f"{len(fails)} fail, {elapsed:.1f}s"
    )
    if fails:
        print(red(summary))
    else:
        print(green(summary))
    print(grey("=" * 70))

    report_path = os.environ.get("TIER_GATE_REPORT")
    if report_path:
        out = {
            "tier": tier,
            "manifest": str(manifest_path),
            "passed": passes,
            "failed": len(fails),
            "total": len(endpoints),
            "elapsed_seconds": elapsed,
            "results": results,
        }
        Path(report_path).write_text(json.dumps(out, indent=2))
        print(grey(f"# report written to {report_path}"))

    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
