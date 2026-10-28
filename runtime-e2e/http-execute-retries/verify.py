#!/usr/bin/env python3
# Copyright 2026 AxonFlow
# SPDX-License-Identifier: BUSL-1.1
"""Exercise idempotent HTTP retries through the real Community Agent MCP route."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
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
    cases = [
        ("put-503", "PUT", [503, 200], 2, 1),
        ("delete-429", "DELETE", [429, 204], 2, 1),
        ("put-budget", "PUT", [500], 3, 0),
        ("put-404", "PUT", [404], 1, 0),
        ("post-503", "POST", [503], 1, 0),
        ("patch-429", "PATCH", [429], 1, 0),
        ("put-200", "PUT", [200], 1, 1),
    ]
    scenarios = {case[0]: case for case in cases}
    requests = {case[0]: [] for case in cases}
    lock = threading.Lock()

    class EchoHandler(BaseHTTPRequestHandler):
        def handle_write(self):
            case = urlsplit(self.path).path.rsplit("/", 1)[-1]
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with lock:
                requests[case].append({"method": self.command, "body": body.decode()})
                attempt = len(requests[case])
                statuses = scenarios[case][2]
                status = statuses[min(attempt - 1, len(statuses) - 1)]
            response = json.dumps({"attempt": attempt}).encode() if status != 204 else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        do_PUT = handle_write
        do_DELETE = handle_write
        do_POST = handle_write
        do_PATCH = handle_write

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
                    "type": "http", "enabled": True, "tenant_id": "*", "max_retries": 2,
                    "options": {
                        "base_url": f"http://127.0.0.1:{echo.server_port}",
                        "allow_private_ips": True, "retry_delay": "1ms",
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

                    for name, method, statuses, expected_attempts, expected_rows in cases:
                        payload = {"connector": "query-echo", "client_id": "community",
                                   "action": method, "statement": "/items/" + name,
                                   "parameters": {"value": "retained"}}
                        request = Request(endpoint + "/mcp/tools/execute",
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
                        with lock:
                            actual = list(requests[name])
                        passed = (len(actual) == expected_attempts
                                  and result.get("rows_affected") == expected_rows
                                  and all(request["method"] == method
                                          and json.loads(request["body"]) == {"value": "retained"}
                                          for request in actual)
                                  and result.get("message", "").startswith("HTTP " + str(statuses[-1])))
                        results.append({"case": name, "passed": passed,
                                        "expected_attempts": expected_attempts,
                                        "expected_rows": expected_rows,
                                        "requests": actual, "mcp_response": result})
                        print(f"{'PASS' if passed else 'FAIL'}: {name}: {len(actual)} attempts, "
                              f"rows={result.get('rows_affected')}", flush=True)
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
    expected_failures = (["put-503", "delete-429", "put-budget"]
                         if args.expect_regression else [])
    if len(results) != 7 or failures != expected_failures:
        raise SystemExit(f"Unexpected result: failures={failures}")
    print("Expected baseline regressions confirmed" if args.expect_regression
          else "All seven Agent -> MCP -> HTTP execute retry cases passed")


if __name__ == "__main__":
    main()
