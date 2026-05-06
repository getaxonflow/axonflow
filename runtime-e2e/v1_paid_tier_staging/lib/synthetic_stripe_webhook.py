#!/usr/bin/env python3
"""Synthetic Stripe webhook trigger.

Bypasses the Stripe Dashboard / Payment Link UI entirely. The agent's
webhook handler validates the HMAC-SHA256 Stripe-Signature header
against the body using the webhook signing secret — that's the ONLY
Stripe-side gate. Where the request originates from doesn't matter.

Two event modes are supported:

  --event=checkout.session.completed   (default; PR1894 / W4 path)
      Signs a synthetic V1 Payment Link payload (custom_fields[].tenantid)
      and POSTs to /api/v1/billing/stripe-webhook. Captures the agent's
      response which contains the freshly-minted AXON-… token (V1 design
      for operator recovery).

  --event=charge.refunded                (PR1895 / refund auto-revoke)
      Signs a synthetic charge.refunded payload that maps to a known
      previously-issued license via Charge.payment_intent (NOT metadata —
      Stripe Payment Links don't propagate session metadata onto the
      Charge; see #1895). Use --refund-amount to control full vs partial:
      pass the same value as --charge-amount for a full refund (license
      revoked); pass a smaller value for a partial refund (license
      retained).

Usage (checkout.session.completed):
    python3 synthetic_stripe_webhook.py \\
        --tenant-id cs_<uuid> \\
        --email dev@getaxonflow.com \\
        --agent-url https://try-staging.getaxonflow.com \\
        --secret-name axonflow/community-saas-staging/stripe-webhook-signing-secret

Usage (charge.refunded — full refund, same charge-amount + refund-amount):
    python3 synthetic_stripe_webhook.py \\
        --event=charge.refunded \\
        --payment-intent pi_test_<id_from_prior_issuance> \\
        --charge-amount 999 \\
        --refund-amount 999 \\
        --agent-url https://try-staging.getaxonflow.com \\
        --secret-name axonflow/community-saas-staging/stripe-webhook-signing-secret

Usage (charge.refunded — partial refund, smaller refund-amount):
    python3 synthetic_stripe_webhook.py \\
        --event=charge.refunded \\
        --payment-intent pi_test_<id> \\
        --charge-amount 999 \\
        --refund-amount 500

Outputs JSON to stdout with the agent's response.

Stdlib only.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.request
import uuid


def fetch_webhook_secret(secret_name: str, region: str) -> str:
    """Fetch the webhook signing secret value from AWS Secrets Manager."""
    proc = subprocess.run(
        [
            "aws", "secretsmanager", "get-secret-value",
            "--region", region,
            "--secret-id", secret_name,
            "--query", "SecretString",
            "--output", "text",
        ],
        capture_output=True, text=True, check=True,
    )
    secret = proc.stdout.strip()
    if not secret.startswith("whsec_"):
        raise SystemExit(
            f"::error:: secret {secret_name} value doesn't start with whsec_; "
            f"got prefix: {secret[:8]!r}"
        )
    return secret


def build_payment_link_event(
    tenant_id: str,
    email: str,
    payment_intent: str | None = None,
) -> dict:
    """Build a checkout.session.completed event matching the V1 Payment Link
    path — tenant_id arrives via custom_fields[].key="tenantid".

    Stripe constrains custom_fields[].key to alphanumeric only, so a
    Dashboard label "tenant_id" sluggifies to "tenantid". Real Live and
    Test webhook deliveries always carry "tenantid"; this synthetic tool
    matches that shape so it exercises the same agent code path.

    payment_intent (pi_test_<uuid>) is included on the session object so the
    agent persists it onto plugin_user_licenses.stripe_payment_intent_id at
    issuance — that's the reverse-lookup key for charge.refunded auto-revoke
    (#1895). Real Stripe deliveries always include payment_intent on
    checkout.session.completed for one-time-payment Sessions; we mirror
    that here. Caller can pass an explicit value to pair a synthetic
    issuance with a later refund event.
    """
    now_ts = int(time.time())
    session_id = f"cs_test_{uuid.uuid4().hex[:24]}"
    customer_id = f"cus_test_{uuid.uuid4().hex[:14]}"
    if payment_intent is None:
        payment_intent = f"pi_test_{uuid.uuid4().hex[:24]}"
    # NOTE: Real Stripe Test/Live Payment-Link payloads have
    # customer_email=null and customer=null (because customer_creation is
    # "if_required" and Stripe doesn't create a Customer for one-time
    # payments). The buyer's email lives in customer_details.email instead.
    # Mirror that exact shape here so the synthetic test exercises the
    # same code path as a real buyer (this gap caused the V1 launch
    # showstopper on 2026-05-06).
    return {
        "id": f"evt_test_{now_ts}_{os.getpid()}",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": session_id,
                "customer": None,
                "customer_email": None,
                "customer_details": {
                    "email": email,
                    "name": "Synthetic Test Buyer",
                },
                "mode": "payment",
                "payment_status": "paid",
                "amount_total": 999,
                "currency": "usd",
                "payment_intent": payment_intent,
                "custom_fields": [
                    {
                        "key": "tenantid",
                        "type": "text",
                        "text": {"value": tenant_id},
                    },
                ],
            },
        },
    }


def build_refund_event(
    payment_intent: str,
    charge_amount: int,
    refund_amount: int,
    charge_id: str | None = None,
) -> dict:
    """Build a charge.refunded event whose Charge.payment_intent points
    back to a previously-issued license row's stripe_payment_intent_id.

    Lookup key is payment_intent — NOT Charge.metadata. Empirically, Stripe
    Payment Link deliveries don't propagate session metadata onto the
    underlying Charge object (verified live against
    plink_1TTPnJCokRiQkpTDBXXIDmqy via GET /v1/payment_links/<id>); see
    issue #1895 for the orchestrator's reproduction. Real Live + Test
    charge.refunded deliveries always carry payment_intent because the
    Charge was created via a PaymentIntent under the hood.

    Full vs partial decision rule (matches handleChargeRefunded):
      - refund_amount == charge_amount AND status="succeeded" → full refund
      - refund_amount  < charge_amount → partial refund (no-op)
    """
    now_ts = int(time.time())
    if charge_id is None:
        charge_id = f"ch_test_{uuid.uuid4().hex[:24]}"
    refund_id = f"re_test_{uuid.uuid4().hex[:24]}"
    return {
        "id": f"evt_refund_{now_ts}_{os.getpid()}",
        "type": "charge.refunded",
        "data": {
            "object": {
                "id": charge_id,
                "amount": charge_amount,
                "amount_refunded": refund_amount,
                "currency": "usd",
                # Stripe sets the boolean once the cumulative refund amount
                # equals the charge amount; mirror that.
                "refunded": refund_amount >= charge_amount,
                "payment_intent": payment_intent,
                # Empty metadata — matches real Live Payment Link refund
                # payloads. Agent code reads payment_intent regardless.
                "metadata": {},
                "refunds": {
                    "data": [
                        {
                            "id": refund_id,
                            "amount": refund_amount,
                            "status": "succeeded",
                        },
                    ],
                },
            },
        },
    }


def stripe_sign(body: bytes, secret: str, ts: int | None = None) -> str:
    """Compute the Stripe-Signature header value: t=<ts>,v1=<hmac_sha256_hex>."""
    if ts is None:
        ts = int(time.time())
    signed_payload = f"{ts}.".encode("utf-8") + body
    sig = hmac.new(
        secret.encode("utf-8"), signed_payload, hashlib.sha256
    ).hexdigest()
    return f"t={ts},v1={sig}"


def post_webhook(agent_url: str, body: bytes, sig_header: str) -> tuple[int, str]:
    """POST the signed body to the agent's webhook endpoint.

    Sets X-Forwarded-For to a known Stripe webhook IP so the agent's
    IP allowlist accepts the request when AXONFLOW_TRUST_PROXY=1 is set.
    Without this, posting directly from a developer machine fails the
    allowlist (only Stripe's public IPs are whitelisted by default).
    """
    url = agent_url.rstrip("/") + "/api/v1/billing/stripe-webhook"
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Stripe-Signature": sig_header,
            # Spoof a Stripe webhook source IP — agent reads X-Forwarded-For
            # when TRUST_PROXY=1 (which is set in CFN as of #1870).
            "X-Forwarded-For": "3.18.12.63",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8") if e.fp else ""


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--event",
        default="checkout.session.completed",
        choices=["checkout.session.completed", "charge.refunded"],
        help="which Stripe event type to synthesize (default: checkout.session.completed)",
    )
    # checkout.session.completed args
    p.add_argument("--tenant-id", help="cs_<uuid> — required for checkout.session.completed")
    p.add_argument("--email", default="dev@getaxonflow.com")
    p.add_argument(
        "--payment-intent",
        default=None,
        help=(
            "explicit Stripe PaymentIntent ID (pi_<id>). For "
            "checkout.session.completed: optional — generates a synthetic "
            "pi_test_<uuid> if omitted. For charge.refunded: REQUIRED — "
            "must match the payment_intent surfaced by a prior "
            "checkout.session.completed run (printed in the response JSON)."
        ),
    )
    # charge.refunded args
    p.add_argument(
        "--charge-amount",
        type=int,
        default=999,
        help="original charge amount in cents (default: 999 = $9.99 V1 Pro)",
    )
    p.add_argument(
        "--refund-amount",
        type=int,
        help="cumulative amount_refunded in cents; if equal to --charge-amount → full refund (revoke), if less → partial refund (no-op)",
    )
    p.add_argument(
        "--charge-id",
        default=None,
        help="optional Stripe Charge ID (default: synthetic ch_test_<uuid>); set this to the SAME value across replays to test event-replay idempotency",
    )
    # Common args
    p.add_argument("--agent-url", default="https://try-staging.getaxonflow.com")
    p.add_argument(
        "--secret-name",
        default="axonflow/community-saas-staging/stripe-webhook-signing-secret",
    )
    p.add_argument("--region", default="us-east-1")
    args = p.parse_args()

    secret = fetch_webhook_secret(args.secret_name, args.region)

    if args.event == "checkout.session.completed":
        if not args.tenant_id:
            raise SystemExit(
                "::error:: --tenant-id is required for --event=checkout.session.completed"
            )
        event = build_payment_link_event(
            args.tenant_id, args.email, payment_intent=args.payment_intent
        )
        request_summary = {
            "session_id": event["data"]["object"]["id"],
            "tenant_id": args.tenant_id,
            "email": args.email,
            "payment_intent": event["data"]["object"]["payment_intent"],
        }
    else:  # charge.refunded
        if not args.payment_intent:
            raise SystemExit(
                "::error:: --payment-intent is required for --event=charge.refunded "
                "(use the value surfaced by the prior checkout.session.completed run)"
            )
        refund_amount = args.refund_amount
        if refund_amount is None:
            # Default = full refund (matches the most common operational
            # case: buyer requests a refund of the entire $9.99 purchase).
            refund_amount = args.charge_amount
        event = build_refund_event(
            payment_intent=args.payment_intent,
            charge_amount=args.charge_amount,
            refund_amount=refund_amount,
            charge_id=args.charge_id,
        )
        request_summary = {
            "payment_intent": args.payment_intent,
            "charge_id": event["data"]["object"]["id"],
            "charge_amount": args.charge_amount,
            "refund_amount": refund_amount,
            "is_full_refund": refund_amount >= args.charge_amount,
        }

    body = json.dumps(event, separators=(",", ":")).encode("utf-8")
    sig_header = stripe_sign(body, secret)

    status, resp_body = post_webhook(args.agent_url, body, sig_header)

    out = {
        "request": {
            "url": f"{args.agent_url}/api/v1/billing/stripe-webhook",
            "event": args.event,
            **request_summary,
        },
        "response": {
            "http_status": status,
            "body": resp_body,
        },
    }

    # Try to surface the AXON token at the top of the JSON for easy capture
    # (only meaningful for checkout.session.completed; refund responses
    # don't carry tokens).
    try:
        body_json = json.loads(resp_body)
        if isinstance(body_json, dict):
            for k in ("token", "license_token", "access_token"):
                if k in body_json:
                    out["captured_axon_token"] = body_json[k]
                    break
    except json.JSONDecodeError:
        pass

    print(json.dumps(out, indent=2))
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
