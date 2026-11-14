#!/usr/bin/env python3
"""Resolve the single reviewed publication region for client images."""

from __future__ import annotations

import argparse


CLIENTS = {"ecommerce", "travel", "healthcare", "banking"}
IMAGE_REGION = "us-east-1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True, choices=sorted(CLIENTS))
    parser.add_argument("--environment", choices=("staging", "production"))
    parser.add_argument("--expected-region")
    args = parser.parse_args()

    if args.expected_region and args.expected_region != IMAGE_REGION:
        parser.error(
            f"client image region mismatch: expected {args.expected_region}, "
            f"contract requires {IMAGE_REGION}"
        )
    print(IMAGE_REGION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
