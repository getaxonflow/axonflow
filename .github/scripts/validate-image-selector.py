#!/usr/bin/env python3
"""Validate an immutable deployment image selector."""

from __future__ import annotations

import argparse
import re


GIT_SHA_TAG = re.compile(r"^[0-9a-f]{7,40}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag-only", action="store_true")
    parser.add_argument("--full-sha-only", action="store_true")
    parser.add_argument("selector")
    args = parser.parse_args()

    if args.full_sha_only:
        valid = COMMIT.fullmatch(args.selector)
    else:
        valid = GIT_SHA_TAG.fullmatch(args.selector) or (
            not args.tag_only and IMAGE_DIGEST.fullmatch(args.selector)
        )
    if not valid:
        if args.full_sha_only:
            parser.error("image selector must be a full lowercase 40-character Git SHA")
        parser.error("image selector must be a lowercase 7-40 character Git SHA or sha256 digest")
    print(args.selector)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
