#!/usr/bin/env python3
# Copyright 2026 AxonFlow
# SPDX-License-Identifier: BUSL-1.1
"""Exercise HTTP query merging through the real Community Agent MCP route."""

import argparse
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import ProxyHandler, Request, build_opener


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-regression", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    database_url = os.environ["AXONFLOW_E2E_DATABASE_URL"]
    args.output.mkdir(parents=True, exist_ok=True)
    captured = queue.Queue()

    class EchoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            captured.put(query)
            body = json.dumps({"query": query}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    # Loopback only: no external API or provider is used.
    echo = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    worker = threading.Thread(target=echo.serve_forever, daemon=True)
    worker.start()
    opener = build_opener(ProxyHandler({}))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        agent_port = sock.getsockname()[1]
    endpoint = f"http://127.0.0.1:{agent_port}"
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="axonflow-http-query-") as tmp:
            config = Path(tmp) / "axonflow.json"
            config.write_text(json.dumps({
                "version": "1.0",
                "connectors": {"query-echo": {
                    "type": "http", "enabled": True, "tenant_id": "*",
                    "options": {
                        "base_url": f"http://127.0.0.1:{echo.server_port}",
                        "allow_private_ips": True,
                    },
                }},
            }))
            # Match the documented local Community posture. Do not inherit
            # production provider keys, external DSNs, or enterprise settings.
            env = {name: os.environ[name] for name in ("PATH", "HOME", "LANG")
                   if name in os.environ}
            env.update({
                "PORT": str(agent_port), "DEPLOYMENT_MODE": "community",
                "DATABASE_URL": database_url,
                "AXONFLOW_DB_USE_APP_ROLE": "false",
                "AXONFLOW_CONFIG_FILE": str(config),
                "AXONFLOW_MIGRATIONS_PATH": str(root / "migrations"),
                "AXONFLOW_TELEMETRY": "off", "CI": "true",
                "JWT_SECRET": "local-e2e-only-not-a-production-secret",
                "AUDIT_FALLBACK_PATH": str(Path(tmp) / "audit_fallback.jsonl"),
            })
            if os.environ.get("AXONFLOW_E2E_REDIS_URL"):
                env["REDIS_URL"] = os.environ["AXONFLOW_E2E_REDIS_URL"]
            with (args.output / "agent.log").open("w") as log:
                process = subprocess.Popen([str(args.agent.resolve())],
                                           cwd=root, env=env, stdout=log,
                                           stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 90
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError("Agent exited; inspect agent.log")
                        try:
                            with opener.open(endpoint + "/health", timeout=2) as response:
                                health = json.load(response)
                                if response.status == 200 and health.get("status") == "healthy":
                                    (args.output / "health.json").write_text(json.dumps(health, indent=2) + "\n")
                                    break
                        except (URLError, TimeoutError):
                            pass
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Agent health deadline exceeded")
                        time.sleep(0.25)

                    original = {"status": ["active"], "tag": ["first", "second"]}
                    cases = [
                        ("URL-only control", None, original),
                        ("internal-only metadata", {"_trace_id": "trace-123"}, original),
                        ("additional parameter", {"page": 2, "_trace_id": "trace-123"},
                         dict(original, page=["2"])),
                        ("explicit-key override control",
                         {"status": "pending review", "tag": "replacement"},
                         {"status": ["pending review"], "tag": ["replacement"]}),
                    ]
                    for name, parameters, expected in cases:
                        payload = {"connector": "query-echo", "client_id": "community",
                                   "statement": "/records?status=active&tag=first&tag=second"}
                        if parameters is not None:
                            payload["parameters"] = parameters
                        request = Request(endpoint + "/mcp/resources/query",
                                          data=json.dumps(payload).encode(),
                                          headers={"Content-Type": "application/json"})
                        try:
                            with opener.open(request, timeout=30) as response:
                                result = json.load(response)
                        except HTTPError as error:
                            raise RuntimeError(f"MCP HTTP {error.code}: {error.read().decode()}") from error
                        if result.get("success") is not True:
                            raise RuntimeError(f"MCP did not return success: {result}")
                        if result.get("engine") != "anchored":
                            raise RuntimeError(f"Expected normal policy enforcement: {result}")
                        actual = captured.get(timeout=5)
                        if result.get("data") != [{"query": actual}]:
                            raise RuntimeError(f"MCP response lost echo data: {result}")
                        passed = actual == expected
                        results.append({"case": name, "passed": passed,
                                        "expected": expected, "received": actual,
                                        "mcp_response": result})
                        print(f"{'PASS' if passed else 'FAIL'}: {name}: {actual}", flush=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    finally:
        echo.shutdown()
        echo.server_close()
        worker.join(timeout=5)
        (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    failures = [result["case"] for result in results if not result["passed"]]
    expected_failures = (["internal-only metadata", "additional parameter"]
                         if args.expect_regression else [])
    if len(results) != 4 or failures != expected_failures:
        raise SystemExit(f"Unexpected result: failures={failures}")
    print("Expected baseline regressions confirmed" if args.expect_regression
          else "All four Agent -> MCP -> HTTP connector cases passed")


if __name__ == "__main__":
    main()
